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
  config.id = AdapterId::parse("adapter-tests").value();
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

PDU_TEST(adapter, descriptors_are_validated) {
  AdapterDescriptor descriptor;
  PDU_REQUIRE_STATUS(validate_descriptor(descriptor), StatusCode::invalid_argument);
  descriptor.id = AdapterId::parse("a").value();
  PDU_REQUIRE_STATUS(validate_descriptor(descriptor), StatusCode::invalid_argument);
  descriptor.vendor = IssuerId::parse("v").value();
  PDU_CHECK(validate_descriptor(descriptor).ok());
  descriptor.model = std::string(65, 'x');
  PDU_REQUIRE_STATUS(validate_descriptor(descriptor), StatusCode::out_of_range);
  descriptor.model = "line\nbreak";
  PDU_REQUIRE_STATUS(validate_descriptor(descriptor), StatusCode::malformed_input);
}

PDU_TEST(adapter, outcomes_must_echo_the_command_they_answer) {
  // An adapter cannot have its answer attributed to another command.
  pdu_test::TempDir directory("adapter-fencing");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("fencing", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);

  SyntheticPduAdapter echoing = adapter_for(scenario, SyntheticMode::honor, LogicalTick::from(1));
  const auto issued = engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), echoing);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  const AdapterCommandTrace& trace = echoing.commands().back();
  PDU_CHECK_EQ(trace.attempt, PDU_REQUIRE_OK(issued).id);
  PDU_CHECK(trace.complete_preconditions);
  PDU_CHECK(includes(trace.validated, PreconditionKind::permission));
  PDU_CHECK(includes(trace.validated, PreconditionKind::interlock));
  PDU_CHECK(includes(trace.validated, PreconditionKind::lifecycle));
}

PDU_TEST(adapter, a_mismatched_echo_is_fenced_and_leaves_the_effect_unknown) {
  pdu_test::TempDir directory("adapter-mismatch");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("mismatch", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::mismatched_echo, LogicalTick::from(1));
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
  const auto issued = engine.issue(
      request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(4)), adapter);
  PDU_REQUIRE_STATUS(issued, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).code, StatusCode::adapter_fenced);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(issued).outcome, AttemptOutcome::unanswered);
}

PDU_TEST(adapter, an_adapter_is_never_invoked_when_a_precondition_fails) {
  pdu_test::TempDir directory("adapter-not-invoked");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("notinvoked", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::honor, LogicalTick::from(1));

  // Wrong generation, wrong epoch, wrong revision, unknown branch, missing key,
  // and a lifecycle that forbids control: none of them may reach the adapter.
  BranchControlRequest request =
      request_for(scenario, CommandIntent::energize, "k1", LogicalTick::from(3));
  request.pdu_generation = PduGeneration::from(2);
  PDU_REQUIRE_STATUS(engine.issue(request, adapter), StatusCode::generation_mismatch);

  request = request_for(scenario, CommandIntent::energize, "k2", LogicalTick::from(3));
  request.epoch = AuthorityEpoch::from(5);
  PDU_REQUIRE_STATUS(engine.issue(request, adapter), StatusCode::permission_stale);

  request = request_for(scenario, CommandIntent::energize, "k3", LogicalTick::from(3));
  request.planned_revision = StateRevision::from(42);
  PDU_REQUIRE_STATUS(engine.issue(request, adapter), StatusCode::revision_mismatch);

  request = request_for(scenario, CommandIntent::energize, "k4", LogicalTick::from(3));
  request.branch = BranchId::parse("ghost").value();
  PDU_REQUIRE_STATUS(engine.issue(request, adapter), StatusCode::not_found);

  request = request_for(scenario, CommandIntent::energize, "k5", LogicalTick::from(3));
  request.key = IdempotencyKey::unset();
  PDU_REQUIRE_STATUS(engine.issue(request, adapter), StatusCode::invalid_argument);

  InterlockStatus open;
  open.id = scenario.interlock;
  open.state = InterlockState::open;
  open.epoch = scenario.epoch;
  open.updated_at = LogicalTick::from(3);
  PDU_REQUIRE_STATUS(engine.report_interlock(open), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.issue(request_for(scenario, CommandIntent::energize, "k6",
                                              LogicalTick::from(3)),
                                  adapter),
                     StatusCode::interlock_open);

  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});
  PDU_CHECK(adapter.commands().empty());
}

PDU_TEST(adapter, a_synthetic_adapter_reports_itself_as_synthetic) {
  const pdu_test::Scenario scenario = pdu_test::make_scenario("descriptor", 1);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::honor, LogicalTick::from(1));
  const AdapterDescriptor descriptor = adapter.describe();
  PDU_CHECK(descriptor.synthetic);
  PDU_CHECK_EQ(descriptor.kind, AdapterKind::synthetic);
  PDU_CHECK(descriptor.supports_readback);
  PDU_CHECK(validate_descriptor(descriptor).ok());
  SyntheticPduAdapter silent = adapter_for(scenario, SyntheticMode::no_readback, LogicalTick::from(1));
  PDU_CHECK(!silent.describe().supports_readback);
  PDU_REQUIRE_STATUS(silent.read(AdapterReadRequest{}), StatusCode::adapter_unavailable);
}

PDU_TEST(adapter, adapter_command_trace_is_bounded) {
  pdu_test::TempDir directory("adapter-trace-bound");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("tracebound", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::honor, LogicalTick::from(1));
  for (std::uint64_t index = 0; index < 300; ++index) {
    const std::uint64_t tick = 4 + index * 4;
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(tick)), StatusCode::ok);
    const auto issued = engine.issue(
        request_for(scenario,
                    index % 2 == 0 ? CommandIntent::energize : CommandIntent::de_energize,
                    "k" + std::to_string(index), LogicalTick::from(tick)),
        adapter);
    if (!issued.ok()) {
      continue;
    }
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(tick + 1)), StatusCode::ok);
    (void)engine.verify_with_adapter(PDU_REQUIRE_OK(issued).id, adapter);
  }
  PDU_CHECK(adapter.commands().size() <= synthetic_command_trace_capacity);
  PDU_CHECK(adapter.execute_count() >= adapter.commands().size());
}
