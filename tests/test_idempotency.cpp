#include "fixture.hpp"
#include "test_harness.hpp"

using namespace pdu_control;

namespace {

BranchControlRequest request_for(const pdu_test::Scenario& scenario, CommandIntent intent,
                                 const std::string& key, LogicalTick tick) {
  BranchControlRequest request;
  request.key = IdempotencyKey::parse(key).value();
  request.pdu = scenario.pdu;
  request.branch = scenario.branch;
  request.pdu_generation = scenario.pdu_generation;
  request.branch_generation = scenario.branch_generation;
  request.epoch = scenario.epoch;
  request.intent = intent;
  request.actor = ActorId::parse("tester").value();
  request.requested_at = tick;
  return request;
}

SyntheticPduAdapter adapter_for(const pdu_test::Scenario& scenario, SyntheticMode mode,
                                LogicalTick start_tick) {
  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("idem-adapter").value();
  config.vendor = IssuerId::parse("test").value();
  config.model = "test-synthetic";
  config.firmware = "0";
  config.pdu = scenario.pdu;
  config.branch = scenario.branch;
  config.pdu_generation = scenario.pdu_generation;
  config.branch_generation = scenario.branch_generation;
  config.mode = mode;
  config.initial_condition = BranchCondition::de_energized;
  config.reading_taken_at = Instant::logical(start_tick);
  config.reading_tick_step = LogicalTick::from(1);
  config.read_at_request_instant = true;
  return SyntheticPduAdapter(config);
}

}  // namespace

PDU_TEST(idempotency, a_retry_returns_the_prior_result_and_never_actuates_again) {
  pdu_test::TempDir directory("idempotency-replay");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("replay", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::honor, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);

  const auto first = engine.issue(request_for(scenario, CommandIntent::energize, "enable-1",
                                              LogicalTick::from(4)),
                                  adapter);
  PDU_REQUIRE_STATUS(first, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(first).replayed);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});

  const auto retry = engine.issue(request_for(scenario, CommandIntent::energize, "enable-1",
                                              LogicalTick::from(4)),
                                  adapter);
  PDU_REQUIRE_STATUS(retry, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(retry).replayed);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(retry).id, PDU_REQUIRE_OK(first).id);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(retry).outcome, PDU_REQUIRE_OK(first).outcome);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});
  PDU_CHECK_EQ(engine.status().attempt_count, std::size_t{1});
}

PDU_TEST(idempotency, a_retry_replays_even_when_the_branch_would_now_refuse) {
  pdu_test::TempDir directory("idempotency-precedence");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("precedence", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::no_readback, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto first = engine.issue(request_for(scenario, CommandIntent::energize, "k1",
                                              LogicalTick::from(4)),
                                  adapter);
  PDU_REQUIRE_STATUS(first, StatusCode::ok);

  // The branch now has an unresolved attempt and is moved to a lifecycle state
  // that forbids control. A fresh command would be refused twice over, but a
  // retry of the accepted attempt must still return the prior result.
  const auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  LifecycleRequest lifecycle;
  lifecycle.pdu = scenario.pdu;
  lifecycle.branch = scenario.branch;
  lifecycle.pdu_generation = scenario.pdu_generation;
  lifecycle.branch_generation = scenario.branch_generation;
  lifecycle.planned_revision = PDU_REQUIRE_OK(snapshot).revision;
  lifecycle.epoch = scenario.epoch;
  lifecycle.to = LifecycleState::isolated;
  lifecycle.actor = ActorId::parse("operator").value();
  lifecycle.requested_at = LogicalTick::from(5);
  PDU_REQUIRE_STATUS(engine.transition_lifecycle(lifecycle), StatusCode::ok);

  const auto retry = engine.issue(request_for(scenario, CommandIntent::energize, "k1",
                                              LogicalTick::from(4)),
                                  adapter);
  PDU_REQUIRE_STATUS(retry, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(retry).replayed);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(retry).id, PDU_REQUIRE_OK(first).id);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});

  // A new key on the same branch is refused, and it is refused for the reason
  // the documented precedence puts first.
  const auto fresh = engine.issue(request_for(scenario, CommandIntent::energize, "k2",
                                              LogicalTick::from(6)),
                                  adapter);
  PDU_REQUIRE_STATUS(fresh, StatusCode::lifecycle_forbidden);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});
}

PDU_TEST(idempotency, reusing_a_key_for_a_different_request_is_a_conflict) {
  pdu_test::TempDir directory("idempotency-conflict");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("conflict", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::no_readback, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.issue(request_for(scenario, CommandIntent::energize, "shared",
                                              LogicalTick::from(4)),
                                  adapter),
                     StatusCode::ok);
  // Same key, different intent: a different request.
  PDU_REQUIRE_STATUS(engine.issue(request_for(scenario, CommandIntent::de_energize, "shared",
                                              LogicalTick::from(5)),
                                  adapter),
                     StatusCode::idempotency_conflict);
  // Same key, different projected load: also a different request.
  BranchControlRequest projected =
      request_for(scenario, CommandIntent::energize, "shared", LogicalTick::from(4));
  projected.projected_current = CurrentSample::known(Current::from_raw(10));
  PDU_REQUIRE_STATUS(engine.issue(projected, adapter), StatusCode::idempotency_conflict);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});
}

PDU_TEST(idempotency, the_window_is_bounded_and_eviction_is_observable) {
  EngineOptions options = pdu_test::base_options();
  options.idempotency_window = 2;
  pdu_test::TempDir directory("idempotency-window");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("window", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new, options);
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  PDU_CHECK_EQ(engine.options().idempotency_window, std::size_t{2});
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::honor, LogicalTick::from(1));

  // Three accepted and verified attempts: each one resolves the branch so the
  // next is not blocked.
  for (int index = 0; index < 3; ++index) {
    const LogicalTick issue_tick = LogicalTick::from(static_cast<std::uint64_t>(4 + index * 4));
    PDU_REQUIRE_STATUS(engine.advance_tick(issue_tick), StatusCode::ok);
    const auto issued = engine.issue(
        request_for(scenario, index % 2 == 0 ? CommandIntent::energize : CommandIntent::de_energize,
                    "key-" + std::to_string(index), issue_tick),
        adapter);
    PDU_REQUIRE_STATUS(issued, StatusCode::ok);
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(issue_tick.value() + 1)), StatusCode::ok);
    const auto verified = engine.verify_with_adapter(PDU_REQUIRE_OK(issued).id, adapter);
    PDU_REQUIRE_STATUS(verified, StatusCode::ok);
    PDU_CHECK(PDU_REQUIRE_OK(verified).state_updated);
  }
  PDU_CHECK_EQ(engine.status().idempotency_entries, std::size_t{2});

  // The oldest key has been evicted, so it is no longer a replay: the request is
  // evaluated again and accepted as new work.
  const auto evicted = engine.issue(
      request_for(scenario, CommandIntent::energize, "key-0", LogicalTick::from(20)), adapter);
  PDU_REQUIRE_STATUS(evicted, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(evicted).replayed);
  // The most recent key is still retained.
  const auto retained = engine.issue(
      request_for(scenario, CommandIntent::energize, "key-2", LogicalTick::from(20)), adapter);
  PDU_REQUIRE_STATUS(retained, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(retained).replayed);
  // A key that was never used is simply not found.
  PDU_REQUIRE_STATUS(engine.attempt_by_key(IdempotencyKey::parse("never-used").value()),
                     StatusCode::not_found);
  PDU_REQUIRE_STATUS(engine.attempt_by_key(IdempotencyKey::unset()), StatusCode::invalid_argument);
}

PDU_TEST(idempotency, every_retained_key_names_an_attempt_in_the_journal) {
  EngineOptions options = pdu_test::base_options();
  options.idempotency_window = 8;
  options.bounds.max_attempt_journal = 4;
  pdu_test::TempDir directory("idempotency-journal");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("journal", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new, options);
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::honor, LogicalTick::from(1));
  std::uint64_t tick = 4;
  for (int index = 0; index < 10; ++index) {
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(tick)), StatusCode::ok);
    const auto issued = engine.issue(
        request_for(scenario, index % 2 == 0 ? CommandIntent::energize : CommandIntent::de_energize,
                    "k" + std::to_string(index), LogicalTick::from(tick)),
        adapter);
    if (issued.ok()) {
      PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(tick + 1)), StatusCode::ok);
      (void)engine.verify_with_adapter(PDU_REQUIRE_OK(issued).id, adapter);
    }
    tick += 4;
  }
  for (const AttemptRecord& record : engine.attempts(0)) {
    PDU_CHECK(record.id.is_set());
  }
  // The in-memory state must satisfy the same referential integrity rule the
  // durable decoder enforces, so a store that round-trips can never be rejected
  // by its own contents.
  const auto status = engine.status();
  // The journal bound is raised to at least the window size, because a retained
  // key must always name an attempt the journal still holds.
  PDU_CHECK(status.attempt_count <= engine.options().bounds.max_attempt_journal);
  PDU_CHECK(status.idempotency_entries <= engine.options().idempotency_window);
  PDU_REQUIRE_STATUS(engine.flush(), StatusCode::ok);
}

PDU_TEST(idempotency, replay_survives_a_reopen) {
  pdu_test::TempDir directory("idempotency-reopen");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("reopen", 1);
  AttemptId first_id;
  {
    auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                         pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
    SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::no_readback, LogicalTick::from(1));
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
    const auto issued = engine.issue(
        request_for(scenario, CommandIntent::energize, "durable-key", LogicalTick::from(4)), adapter);
    PDU_REQUIRE_STATUS(issued, StatusCode::ok);
    first_id = PDU_REQUIRE_OK(issued).id;
    PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  }
  {
    auto reopened = PduControlEngine::open(directory.store_path(), OpenMode::open_existing,
                                           pdu_test::base_options());
    PDU_REQUIRE_STATUS(reopened, StatusCode::ok);
    PduControlEngine& engine = reopened.value();
    SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::no_readback, LogicalTick::from(1));
    const auto retry = engine.issue(
        request_for(scenario, CommandIntent::energize, "durable-key", LogicalTick::from(4)), adapter);
    PDU_REQUIRE_STATUS(retry, StatusCode::ok);
    PDU_CHECK(PDU_REQUIRE_OK(retry).replayed);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(retry).id, first_id);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(retry).outcome, AttemptOutcome::recovery_required);
    PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});
  }
}
