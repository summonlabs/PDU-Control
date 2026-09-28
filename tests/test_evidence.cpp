#include "fixture.hpp"
#include "test_harness.hpp"

using namespace pdu_control;

PDU_TEST(evidence, observation_shape_is_validated) {
  auto engine = PDU_REQUIRE_OK(PduControlEngine::in_memory(pdu_test::base_options()));
  TelemetryObservation observation;
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::invalid_argument);
  observation.pdu = PduId::parse("p").value();
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::invalid_argument);
  observation.branch = BranchId::parse("b").value();
  observation.source = SourceId::parse("s").value();
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::invalid_argument);
  observation.sequence = SequenceNumber::from(1);
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::invalid_argument);
  observation.pdu_generation = PduGeneration::from(1);
  observation.branch_generation = BranchGeneration::from(1);
  observation.taken_at = Instant::logical(LogicalTick::from(1));
  // Now the shape is valid, so the failure is about identity, not structure.
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::not_found);
}

PDU_TEST(evidence, generation_mismatch_is_refused) {
  pdu_test::TempDir directory("evidence-generation");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("generation", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  TelemetryObservation observation =
      pdu_test::make_observation(scenario, LogicalTick::from(2), 2, BranchCondition::energized);
  observation.branch_generation = BranchGeneration::from(9);
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::generation_mismatch);
  observation.branch_generation = scenario.branch_generation;
  observation.pdu_generation = PduGeneration::from(9);
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::generation_mismatch);
}

PDU_TEST(evidence, a_reordered_arrival_does_not_become_the_current_fact) {
  pdu_test::TempDir directory("evidence-reorder");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("reorder", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);

  // Sequence 5 arrives first and becomes current.
  PDU_REQUIRE_STATUS(
      engine.record_observation(
          pdu_test::make_observation(scenario, LogicalTick::from(3), 5, BranchCondition::energized)),
      StatusCode::ok);
  // Sequence 4 arrives late. It is kept for audit but must not replace the
  // newer fact.
  PDU_REQUIRE_STATUS(
      engine.record_observation(pdu_test::make_observation(scenario, LogicalTick::from(4), 4,
                                                           BranchCondition::de_energized)),
      StatusCode::ok);
  const auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(snapshot).observation.present);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.sequence, SequenceNumber::from(5));
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.condition, BranchCondition::energized);
}

PDU_TEST(evidence, freshness_decays_with_the_logical_clock) {
  EngineOptions options = pdu_test::base_options();
  options.evidence.max_age_ticks = LogicalTick::from(5);
  pdu_test::TempDir directory("evidence-freshness");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("freshness", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new, options);
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.freshness, FreshnessState::fresh);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.age_ticks, LogicalTick::from(0));

  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(6)), StatusCode::ok);
  snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.freshness, FreshnessState::fresh);
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(7)), StatusCode::ok);
  snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.freshness, FreshnessState::stale);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.age_ticks, LogicalTick::from(6));
}

PDU_TEST(evidence, an_observation_without_a_logical_instant_cannot_be_aged) {
  pdu_test::TempDir directory("evidence-wallclock");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("wallclock", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  TelemetryObservation observation =
      pdu_test::make_observation(scenario, LogicalTick::from(1), 9, BranchCondition::energized);
  observation.taken_at = Instant::unix_nanoseconds(1700000000000000000LL);
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::ok);
  const auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
  PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.freshness, FreshnessState::unknown);
  PDU_CHECK(!PDU_REQUIRE_OK(snapshot).observation.age_known);
}

PDU_TEST(evidence, an_impossible_instant_is_refused) {
  auto engine = PDU_REQUIRE_OK(PduControlEngine::in_memory(pdu_test::base_options()));
  TelemetryObservation observation;
  observation.pdu = PduId::parse("p").value();
  observation.branch = BranchId::parse("b").value();
  observation.source = SourceId::parse("s").value();
  observation.sequence = SequenceNumber::from(1);
  observation.pdu_generation = PduGeneration::from(1);
  observation.branch_generation = BranchGeneration::from(1);
  observation.taken_at = Instant::unix_nanoseconds(max_unix_nanoseconds + 1);
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::out_of_range);
  observation.taken_at = Instant::unix_nanoseconds(-1);
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::out_of_range);
  observation.taken_at = Instant::logical(LogicalTick::unset());
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::invalid_argument);
}
