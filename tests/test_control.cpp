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
                                BranchCondition initial, LogicalTick start_tick) {
  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("test-adapter").value();
  config.vendor = IssuerId::parse("test").value();
  config.model = "test-synthetic";
  config.firmware = "0";
  config.pdu = scenario.pdu;
  config.branch = scenario.branch;
  config.pdu_generation = scenario.pdu_generation;
  config.branch_generation = scenario.branch_generation;
  config.mode = mode;
  config.initial_condition = initial;
  config.reading_taken_at = Instant::logical(start_tick);
  config.reading_tick_step = LogicalTick::from(1);
  config.read_at_request_instant = true;
  return SyntheticPduAdapter(config);
}

struct Harness {
  pdu_test::TempDir directory;
  pdu_test::Scenario scenario;
  PduControlEngine engine;

  Harness(const std::string& name, std::uint64_t start_tick)
      : directory(name), scenario(pdu_test::make_scenario(name, start_tick)) {}

  Status open() {
    auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                         pdu_test::base_options());
    if (!opened.ok()) {
      return opened.status();
    }
    engine = std::move(opened.value());
    return pdu_test::apply_scenario(engine, scenario);
  }
};

}  // namespace

PDU_TEST(control, happy_path_establishes_the_effect_from_fresh_evidence) {
  Harness harness("control-happy", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;

  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);

  const auto decision =
      harness.engine.evaluate(request_for(scenario, CommandIntent::energize, "enable-1",
                                          LogicalTick::from(4)));
  PDU_CHECK(PDU_REQUIRE_OK(decision).eligible);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(decision).trace.size() >= std::size_t{10});

  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "enable-1", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  const AttemptRecord& attempt = PDU_REQUIRE_OK(issued);
  PDU_CHECK_EQ(attempt.outcome, AttemptOutcome::acknowledged);
  PDU_CHECK(attempt.dispatched);
  PDU_CHECK(attempt.applied_command);
  PDU_CHECK(attempt.authorization.complete_for_control());
  PDU_CHECK_EQ(attempt.authorization.attempt(), attempt.id);
  PDU_CHECK_EQ(attempt.effect, EffectState::pending);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});

  auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).commanded.condition.value(), BranchCondition::energized);
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).verified.established());
  PDU_CHECK(PDU_REQUIRE_OK(snapshot).unresolved_attempt);

  // The acknowledgement is not the effect: verification needs new evidence.
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(6)), StatusCode::ok);
  const auto verified = harness.engine.verify_with_adapter(attempt.id, adapter);
  PDU_REQUIRE_STATUS(verified, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(verified).effect, EffectState::effective);
  PDU_CHECK(PDU_REQUIRE_OK(verified).state_updated);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});
  PDU_CHECK_EQ(adapter.read_count(), std::size_t{1});

  snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).commanded.condition.value(), BranchCondition::energized);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).verified.condition.value(), BranchCondition::energized);
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).unresolved_attempt);
  PDU_CHECK(PDU_REQUIRE_OK(snapshot).verified.observation.is_set());

  // The reverse direction works through the same path.
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(8)), StatusCode::ok);
  const auto off = harness.engine.issue(
      request_for(scenario, CommandIntent::de_energize, "disable-1", LogicalTick::from(8)), adapter);
  PDU_REQUIRE_STATUS(off, StatusCode::ok);
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(10)), StatusCode::ok);
  const auto off_verified = harness.engine.verify_with_adapter(PDU_REQUIRE_OK(off).id, adapter);
  PDU_REQUIRE_STATUS(off_verified, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(off_verified).effect, EffectState::effective);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{2});
}

PDU_TEST(control, acknowledgement_without_effect_is_observed_as_ineffective) {
  Harness harness("control-ack-no-effect", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::ack_without_effect,
                                            BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).outcome, AttemptOutcome::acknowledged);

  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(6)), StatusCode::ok);
  const auto verified = harness.engine.verify_with_adapter(PDU_REQUIRE_OK(issued).id, adapter);
  PDU_REQUIRE_STATUS(verified, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(verified).effect, EffectState::ineffective);
  PDU_CHECK(PDU_REQUIRE_OK(verified).state_updated);

  const auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  // The desired state stays where the operator put it; what changed is that the
  // runtime now knows the device never followed.
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).commanded.condition.value(), BranchCondition::energized);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).verified.condition.value(), BranchCondition::de_energized);
  const auto record = harness.engine.attempt(PDU_REQUIRE_OK(issued).id);
  PDU_REQUIRE_STATUS(record, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(record).outcome, AttemptOutcome::observed_ineffective);
}

PDU_TEST(control, verification_without_evidence_changes_nothing) {
  Harness harness("control-no-evidence", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::no_readback, BranchCondition::de_energized,
                  LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  const auto verified = harness.engine.verify(PDU_REQUIRE_OK(issued).id);
  PDU_REQUIRE_STATUS(verified, StatusCode::ok);
  // The only observation on the branch was taken before the command, so it
  // cannot be evidence of the command's effect.
  PDU_CHECK_EQ(PDU_REQUIRE_OK(verified).code, StatusCode::evidence_stale);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(verified).effect, EffectState::pending);
  PDU_CHECK(!PDU_REQUIRE_OK(verified).state_updated);
  const auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).verified.established());
  PDU_CHECK(PDU_REQUIRE_OK(snapshot).unresolved_attempt);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).commanded.condition.value(), BranchCondition::energized);
}

PDU_TEST(control, stale_telemetry_requires_revalidation_before_it_proves_anything) {
  Harness harness("control-revalidate", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::frozen_readings,
                                            BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);

  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(6)), StatusCode::ok);
  const auto stale = harness.engine.verify_with_adapter(PDU_REQUIRE_OK(issued).id, adapter);
  PDU_REQUIRE_STATUS(stale, StatusCode::ok);
  // The adapter did apply the command, but its readings never advance past the
  // command, so they cannot prove the effect.
  PDU_CHECK_EQ(PDU_REQUIRE_OK(stale).code, StatusCode::evidence_stale);
  PDU_CHECK(!PDU_REQUIRE_OK(stale).state_updated);

  TelemetryObservation fresh =
      pdu_test::make_observation(scenario, LogicalTick::from(7), 100, BranchCondition::energized);
  fresh.source = SourceId::parse("field-source").value();
  PDU_REQUIRE_STATUS(harness.engine.revalidate(scenario.pdu, scenario.branch, fresh), StatusCode::ok);
  const auto verified = harness.engine.verify(PDU_REQUIRE_OK(issued).id);
  PDU_REQUIRE_STATUS(verified, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(verified).effect, EffectState::effective);
  PDU_CHECK(PDU_REQUIRE_OK(verified).state_updated);
}

PDU_TEST(control, revalidation_refuses_a_reading_that_is_not_later) {
  Harness harness("control-revalidate-order", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  TelemetryObservation older =
      pdu_test::make_observation(scenario, LogicalTick::from(1), 1, BranchCondition::energized);
  PDU_REQUIRE_STATUS(harness.engine.revalidate(scenario.pdu, scenario.branch, older),
                     StatusCode::evidence_stale);
  TelemetryObservation mismatched =
      pdu_test::make_observation(scenario, LogicalTick::from(9), 50, BranchCondition::energized);
  mismatched.branch = BranchId::parse("another-branch").value();
  PDU_REQUIRE_STATUS(harness.engine.revalidate(scenario.pdu, scenario.branch, mismatched),
                     StatusCode::identity_mismatch);
}

PDU_TEST(control, quiescent_lifecycles_cannot_be_controlled) {
  for (const LifecycleState lifecycle : {LifecycleState::provisioned, LifecycleState::isolated,
                                         LifecycleState::faulted, LifecycleState::retired}) {
    pdu_test::TempDir directory(std::string("control-lifecycle-") + std::string(to_token(lifecycle)));
    const pdu_test::Scenario scenario =
        pdu_test::make_scenario(std::string("lc-") + std::string(to_token(lifecycle)), 1);
    auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                         pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario, lifecycle), StatusCode::ok);
    SyntheticPduAdapter adapter =
        adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
    const auto issued = engine.issue(
        request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(1)), adapter);
    PDU_REQUIRE_STATUS(issued, StatusCode::lifecycle_forbidden);
    PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});
    const auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
    PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
    PDU_CHECK(!PDU_REQUIRE_OK(snapshot).commanded.condition.has_value());
  }
}

PDU_TEST(control, maintenance_control_requires_an_explicit_override) {
  pdu_test::TempDir directory("control-maintenance");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("maint", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario, LifecycleState::maintenance),
                     StatusCode::ok);
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(3)), StatusCode::ok);
  auto issued = engine.issue(request_for(scenario, CommandIntent::energize, "k1", LogicalTick::from(3)),
                             adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::permission_missing);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});

  MaintenanceOverride override_value;
  override_value.id = AuthorityId::parse("override-1").value();
  override_value.issuer = scenario.issuer;
  override_value.epoch = scenario.epoch;
  override_value.pdu = scenario.pdu;
  override_value.branch = scenario.branch;
  override_value.pdu_generation = scenario.pdu_generation;
  override_value.branch_generation = scenario.branch_generation;
  override_value.issued_at = LogicalTick::from(1);
  override_value.not_after = LogicalTick::from(100);
  PDU_REQUIRE_STATUS(engine.record_maintenance_override(override_value), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  issued = engine.issue(request_for(scenario, CommandIntent::energize, "k2", LogicalTick::from(4)),
                        adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(issued).maintenance_override_used);
  PDU_CHECK(PDU_REQUIRE_OK(issued).authorization.maintenance_override());
}

PDU_TEST(control, an_unresolved_attempt_blocks_new_control) {
  Harness harness("control-unresolved", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::no_readback, BranchCondition::de_energized,
                  LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  PDU_REQUIRE_STATUS(harness.engine.issue(request_for(scenario, CommandIntent::energize, "k1",
                                                      LogicalTick::from(4)),
                                          adapter),
                     StatusCode::ok);
  const auto second = harness.engine.issue(
      request_for(scenario, CommandIntent::de_energize, "k2", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(second, StatusCode::attempt_unresolved);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});
}

PDU_TEST(control, limits_are_enforced_with_checked_arithmetic) {
  Harness harness("control-limits", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);

  BranchControlRequest request =
      request_for(scenario, CommandIntent::energize, "k1", LogicalTick::from(4));
  request.projected_current = CurrentSample::known(Current::from_raw(20000));
  auto issued = harness.engine.issue(request, adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::limit_exceeded);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});

  request.key = IdempotencyKey::parse("k2").value();
  request.projected_current = CurrentSample::known(Current::from_raw(-5));
  issued = harness.engine.issue(request, adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::out_of_range);

  request.key = IdempotencyKey::parse("k3").value();
  request.projected_current = CurrentSample::known(Current::from_raw(1000));
  issued = harness.engine.issue(request, adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
}

PDU_TEST(control, a_projection_with_an_unknown_limit_is_refused) {
  pdu_test::TempDir directory("control-unknown-limit");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("nolimit", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(3)), StatusCode::ok);

  // A branch whose continuous limit is not established cannot accept a stated
  // projection: missing evidence is not permission.
  BranchDefinition branch;
  branch.id = BranchId::parse("branch-nolimit-2").value();
  branch.pdu = scenario.pdu;
  branch.generation = BranchGeneration::from(1);
  branch.lifecycle = LifecycleState::active;
  branch.registered_at = LogicalTick::from(3);
  PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::ok);
  PermissionGrant grant;
  grant.id = AuthorityId::parse("grant-nolimit-2").value();
  grant.issuer = scenario.issuer;
  grant.epoch = scenario.epoch;
  grant.pdu = scenario.pdu;
  grant.branch = branch.id;
  grant.pdu_generation = scenario.pdu_generation;
  grant.branch_generation = branch.generation;
  grant.actions = action_mask(PermissionAction::control_energize);
  grant.issued_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.record_grant(grant), StatusCode::ok);
  BranchControlRequest request = request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(3));
  request.branch = branch.id;
  request.projected_current = CurrentSample::known(Current::from_raw(10));
  const auto decision = engine.evaluate(request);
  PDU_CHECK(!PDU_REQUIRE_OK(decision).eligible);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::limit_invalid);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).limit, LimitVerdict::limit_unknown);
}

PDU_TEST(control, stale_generations_and_revisions_are_refused) {
  Harness harness("control-stale", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);

  BranchControlRequest request =
      request_for(scenario, CommandIntent::energize, "k1", LogicalTick::from(4));
  request.pdu_generation = PduGeneration::from(2);
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::generation_mismatch);

  request = request_for(scenario, CommandIntent::energize, "k2", LogicalTick::from(4));
  request.branch_generation = BranchGeneration::from(2);
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::generation_mismatch);

  request = request_for(scenario, CommandIntent::energize, "k3", LogicalTick::from(4));
  request.planned_revision = StateRevision::from(999);
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::revision_mismatch);

  request = request_for(scenario, CommandIntent::energize, "k4", LogicalTick::from(4));
  request.epoch = AuthorityEpoch::from(7);
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::permission_stale);

  // A request that is wrong in several ways at once reports the first failure in
  // the documented order every time, so a caller is never told a different
  // reason on a retry of the same invalid request.
  request = request_for(scenario, CommandIntent::energize, "k5", LogicalTick::from(4));
  request.pdu_generation = PduGeneration::from(2);
  request.planned_revision = StateRevision::from(999);
  request.epoch = AuthorityEpoch::from(7);
  for (int attempt = 0; attempt < 3; ++attempt) {
    const auto decision = harness.engine.evaluate(request);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::generation_mismatch);
  }
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});
  const auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).commanded.condition.has_value());
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).verified.established());
}

PDU_TEST(control, identity_errors_are_distinguished) {
  Harness harness("control-identity", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  BranchControlRequest request =
      request_for(scenario, CommandIntent::energize, "k1", LogicalTick::from(2));
  request.pdu = PduId::parse("no-such-pdu").value();
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::not_found);
  request = request_for(scenario, CommandIntent::energize, "k2", LogicalTick::from(2));
  request.branch = BranchId::parse("no-such-branch").value();
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::not_found);
  request = request_for(scenario, CommandIntent::energize, "k3", LogicalTick::from(2));
  request.key = IdempotencyKey::unset();
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::invalid_argument);
  request = request_for(scenario, CommandIntent::energize, "k4", LogicalTick::from(2));
  request.actor = ActorId::unset();
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::invalid_argument);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});
}

PDU_TEST(control, a_fenced_adapter_answer_leaves_the_attempt_unresolved) {
  Harness harness("control-fenced", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::mismatched_echo,
                                            BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).code, StatusCode::adapter_fenced);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).outcome, AttemptOutcome::unanswered);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).effect, EffectState::unknown);
  const auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(snapshot).unresolved_attempt);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).commanded.condition.value(), BranchCondition::energized);
}

PDU_TEST(control, an_adapter_refusal_repairs_the_desired_state) {
  Harness harness("control-refused", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::refuse, BranchCondition::de_energized, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).outcome, AttemptOutcome::rejected);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).code, StatusCode::adapter_refused);
  PDU_CHECK(!PDU_REQUIRE_OK(issued).applied_command);
  const auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  // The adapter stated that nothing was applied, so the desired state is
  // restored and the branch is free again.
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).commanded.condition.has_value());
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).unresolved_attempt);
}

PDU_TEST(control, verification_is_refused_for_attempts_with_no_effect_to_establish) {
  Harness harness("control-unverifiable", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  BranchControlRequest request =
      request_for(scenario, CommandIntent::energize, "k1", LogicalTick::from(2));
  request.epoch = AuthorityEpoch::from(11);
  PDU_REQUIRE_STATUS(harness.engine.issue(request, adapter), StatusCode::permission_stale);
  const auto refused = harness.engine.attempts(0);
  PDU_CHECK(!refused.empty());
  PDU_CHECK_EQ(refused.back().outcome, AttemptOutcome::refused);
  PDU_REQUIRE_STATUS(harness.engine.verify(refused.back().id), StatusCode::attempt_not_verifiable);
  PDU_REQUIRE_STATUS(harness.engine.verify(AttemptId::from(9999)), StatusCode::not_found);
}

PDU_TEST(control, resolving_an_attempt_requires_recovery_authority_and_clears_knowledge) {
  Harness harness("control-resolve", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::no_readback, BranchCondition::de_energized,
                  LogicalTick::from(1));
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  const AttemptId id = PDU_REQUIRE_OK(issued).id;
  PDU_REQUIRE_STATUS(harness.engine.resolve_attempt(id, AttemptResolution::cancelled, ActorId::unset(),
                                                    scenario.epoch, LogicalTick::from(5)),
                     StatusCode::invalid_argument);
  PDU_REQUIRE_STATUS(harness.engine.resolve_attempt(id, AttemptResolution::cancelled,
                                                    ActorId::parse("operator").value(),
                                                    AuthorityEpoch::from(9), LogicalTick::from(5)),
                     StatusCode::permission_stale);
  PDU_REQUIRE_STATUS(harness.engine.resolve_attempt(id, AttemptResolution::cancelled,
                                                    ActorId::parse("operator").value(), scenario.epoch,
                                                    LogicalTick::from(5)),
                     StatusCode::ok);
  const auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).unresolved_attempt);
  // Resolving does not invent knowledge: the verified condition becomes unknown,
  // while the desired state stays where the operator asked for it.
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).verified.established());
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).commanded.condition.value(), BranchCondition::energized);
  PDU_REQUIRE_STATUS(harness.engine.resolve_attempt(id, AttemptResolution::superseded,
                                                    ActorId::parse("operator").value(), scenario.epoch,
                                                    LogicalTick::from(6)),
                     StatusCode::attempt_not_verifiable);
}

PDU_TEST(control, lifecycle_transitions_are_checked_against_the_table_and_authority) {
  Harness harness("control-transition", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(3)), StatusCode::ok);
  const auto snapshot = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);

  LifecycleRequest request;
  request.pdu = scenario.pdu;
  request.branch = scenario.branch;
  request.pdu_generation = scenario.pdu_generation;
  request.branch_generation = scenario.branch_generation;
  request.planned_revision = PDU_REQUIRE_OK(snapshot).revision;
  request.epoch = scenario.epoch;
  request.actor = ActorId::parse("operator").value();
  request.requested_at = LogicalTick::from(3);

  // No transition from active back to provisioned is declared.
  request.to = LifecycleState::provisioned;
  PDU_REQUIRE_STATUS(harness.engine.transition_lifecycle(request), StatusCode::transition_invalid);

  request.to = LifecycleState::isolated;
  PDU_REQUIRE_STATUS(harness.engine.transition_lifecycle(request), StatusCode::ok);
  auto isolated = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(isolated, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(isolated).lifecycle, LifecycleState::isolated);

  // A stale revision is refused rather than merged.
  request.to = LifecycleState::active;
  PDU_REQUIRE_STATUS(harness.engine.transition_lifecycle(request), StatusCode::revision_mismatch);

  request.planned_revision = PDU_REQUIRE_OK(isolated).revision;
  PDU_REQUIRE_STATUS(harness.engine.transition_lifecycle(request), StatusCode::ok);
  const auto recovered = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(recovered, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(recovered).lifecycle, LifecycleState::active);

  // Retiring is terminal: nothing leaves it.
  request.to = LifecycleState::retired;
  request.planned_revision = PDU_REQUIRE_OK(recovered).revision;
  PDU_REQUIRE_STATUS(harness.engine.transition_lifecycle(request), StatusCode::ok);
  const auto retired = harness.engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(retired, StatusCode::ok);
  request.to = LifecycleState::active;
  request.planned_revision = PDU_REQUIRE_OK(retired).revision;
  PDU_REQUIRE_STATUS(harness.engine.transition_lifecycle(request), StatusCode::transition_invalid);
}

PDU_TEST(control, a_pdu_level_lifecycle_gate_applies_to_its_branches) {
  Harness harness("control-pdu-gate", 1);
  PDU_REQUIRE_STATUS(harness.open(), StatusCode::ok);
  const auto& scenario = harness.scenario;
  PDU_REQUIRE_STATUS(harness.engine.advance_tick(LogicalTick::from(3)), StatusCode::ok);
  const auto pdu = harness.engine.inspect_pdu(scenario.pdu);
  PDU_REQUIRE_STATUS(pdu, StatusCode::ok);
  LifecycleRequest request;
  request.pdu = scenario.pdu;
  request.pdu_generation = scenario.pdu_generation;
  request.planned_revision = PDU_REQUIRE_OK(pdu).revision;
  request.epoch = scenario.epoch;
  request.actor = ActorId::parse("operator").value();
  request.requested_at = LogicalTick::from(3);
  request.to = LifecycleState::maintenance;
  PDU_REQUIRE_STATUS(harness.engine.transition_lifecycle(request), StatusCode::ok);

  SyntheticPduAdapter adapter =
      adapter_for(scenario, SyntheticMode::honor, BranchCondition::de_energized, LogicalTick::from(1));
  const auto issued = harness.engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(3)), adapter);
  // The branch is active, but the PDU it hangs from is in maintenance, so the
  // override requirement applies to both.
  PDU_REQUIRE_STATUS(issued, StatusCode::permission_missing);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});
}
