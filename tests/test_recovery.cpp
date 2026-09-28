#include "fixture.hpp"
#include "proc.hpp"
#include "test_harness.hpp"

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "detail/file_io.hpp"

using namespace pdu_control;

namespace {

bool wait_for_file(const std::string& path) {
  // A bounded wait for a condition the child signals, not a timeout on the
  // test: if the condition never arrives the check below fails and the failure
  // is diagnosed, and the test never declares a pass it did not earn.
  for (int attempt = 0; attempt < 20000; ++attempt) {
    if (::pdu_control::detail::path_exists(path)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return ::pdu_control::detail::path_exists(path);
}

BranchControlRequest request_for(const PduId& pdu, const BranchId& branch,
                                 const PduGeneration& pdu_generation,
                                 const BranchGeneration& branch_generation,
                                 const AuthorityEpoch& epoch, CommandIntent intent,
                                 const std::string& key, LogicalTick tick) {
  BranchControlRequest request;
  request.key = IdempotencyKey::parse(key).value();
  request.pdu = pdu;
  request.branch = branch;
  request.pdu_generation = pdu_generation;
  request.branch_generation = branch_generation;
  request.epoch = epoch;
  request.intent = intent;
  // The retry must be the *same* request the crashed process made, actor
  // included: a different actor is a different request, and reusing the key for
  // it is an idempotency conflict rather than a replay.
  request.actor = ActorId::parse("probe").value();
  request.requested_at = tick;
  return request;
}

SyntheticPduAdapter adapter_for(const PduId& pdu, const BranchId& branch,
                                const PduGeneration& pdu_generation,
                                const BranchGeneration& branch_generation) {
  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("recovery-adapter").value();
  config.vendor = IssuerId::parse("test").value();
  config.model = "synthetic";
  config.firmware = "0";
  config.pdu = pdu;
  config.branch = branch;
  config.pdu_generation = pdu_generation;
  config.branch_generation = branch_generation;
  config.mode = SyntheticMode::honor;
  config.initial_condition = BranchCondition::de_energized;
  config.reading_taken_at = Instant::logical(LogicalTick::from(1));
  config.reading_tick_step = LogicalTick::from(1);
  config.read_at_request_instant = true;
  return SyntheticPduAdapter(config);
}

}  // namespace

PDU_TEST(recovery, a_death_before_the_boundary_leaves_no_command_behind) {
  pdu_test::TempDir directory("recovery-before");
  const std::string store = directory.store_path();
  auto child = pdu_test::Process::spawn(pdu_test::probe_executable(),
                                        {"crash-before-boundary", store, "pdu-r1", "branch-r1",
                                         "key-before", "10"});
  PDU_REQUIRE_STATUS(child, StatusCode::ok);
  const int code = child.value().wait();
  PDU_CHECK_EQ(code, 40);

  auto opened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_CHECK_EQ(engine.status().attempt_count, std::size_t{0});
  PDU_CHECK_EQ(engine.status().unresolved_attempt_count, std::size_t{0});
  const auto branch = engine.inspect_branch(PduId::parse("pdu-r1").value(),
                                            BranchId::parse("branch-r1").value());
  PDU_REQUIRE_STATUS(branch, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(branch).commanded.condition.has_value());
  PDU_CHECK(!PDU_REQUIRE_OK(branch).unresolved_attempt);
  // The branch is still controllable, because nothing was ever dispatched.
  const auto pending = engine.attempts(0);
  PDU_CHECK(pending.empty());
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
}

PDU_TEST(recovery, a_death_after_the_boundary_never_reissues_the_command) {
  pdu_test::TempDir directory("recovery-after");
  const std::string store = directory.store_path();
  auto child = pdu_test::Process::spawn(pdu_test::probe_executable(),
                                        {"crash-in-adapter", store, "pdu-r2", "branch-r2",
                                         "key-after", "10"});
  PDU_REQUIRE_STATUS(child, StatusCode::ok);
  const int code = child.value().wait();
  PDU_CHECK_EQ(code, 41);

  const PduId pdu = PduId::parse("pdu-r2").value();
  const BranchId branch_id = BranchId::parse("branch-r2").value();
  auto opened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_CHECK_EQ(engine.status().attempt_count, std::size_t{1});
  PDU_CHECK_EQ(engine.status().unresolved_attempt_count, std::size_t{1});
  const auto attempts = engine.attempts(0);
  PDU_REQUIRE_STATUS(attempts.empty() ? Status::failure(StatusCode::not_found) : Status::success(),
                     StatusCode::ok);
  const AttemptRecord orphan = attempts.back();
  PDU_CHECK_EQ(orphan.outcome, AttemptOutcome::recovery_required);
  PDU_CHECK_EQ(orphan.code, StatusCode::attempt_unresolved);
  PDU_CHECK(orphan.dispatched);
  PDU_CHECK_EQ(orphan.effect, EffectState::unknown);

  const auto branch = engine.inspect_branch(pdu, branch_id);
  PDU_REQUIRE_STATUS(branch, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(branch).unresolved_attempt);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(branch).commanded.condition.value(), BranchCondition::energized);

  SyntheticPduAdapter adapter = adapter_for(pdu, branch_id, PduGeneration::from(1),
                                           BranchGeneration::from(1));
  // A retry of the original key returns the adopted record and never reaches an
  // adapter: the previous process may already have actuated the branch, and this
  // runtime does not send a second command to find out.
  const auto retry = engine.issue(
      request_for(pdu, branch_id, PduGeneration::from(1), BranchGeneration::from(1),
                  AuthorityEpoch::from(1), CommandIntent::energize, "key-after", LogicalTick::from(10)),
      adapter);
  PDU_REQUIRE_STATUS(retry, StatusCode::ok);
  PDU_CHECK(PDU_REQUIRE_OK(retry).replayed);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(retry).id, orphan.id);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(retry).outcome, AttemptOutcome::recovery_required);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});

  // A new key is refused until the effect is established or the attempt is
  // explicitly resolved.
  const auto fresh = engine.issue(
      request_for(pdu, branch_id, PduGeneration::from(1), BranchGeneration::from(1),
                  AuthorityEpoch::from(1), CommandIntent::de_energize, "key-new", LogicalTick::from(10)),
      adapter);
  PDU_REQUIRE_STATUS(fresh, StatusCode::attempt_unresolved);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{0});

  // Evidence establishes what actually happened, and the branch is released.
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(11)), StatusCode::ok);
  TelemetryObservation observation;
  observation.pdu = pdu;
  observation.branch = branch_id;
  observation.pdu_generation = PduGeneration::from(1);
  observation.branch_generation = BranchGeneration::from(1);
  observation.source = SourceId::parse("field").value();
  observation.sequence = SequenceNumber::from(77);
  observation.taken_at = Instant::logical(LogicalTick::from(11));
  observation.quality = EvidenceQuality::good;
  observation.condition = BranchCondition::energized;
  PDU_REQUIRE_STATUS(engine.record_observation(observation), StatusCode::ok);
  const auto verified = engine.verify(orphan.id);
  PDU_REQUIRE_STATUS(verified, StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(verified).effect, EffectState::effective);
  PDU_CHECK(PDU_REQUIRE_OK(verified).state_updated);
  const auto resolved_branch = engine.inspect_branch(pdu, branch_id);
  PDU_REQUIRE_STATUS(resolved_branch, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(resolved_branch).unresolved_attempt);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(resolved_branch).verified.condition.value(), BranchCondition::energized);

  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(12)), StatusCode::ok);
  const auto now_allowed = engine.issue(
      request_for(pdu, branch_id, PduGeneration::from(1), BranchGeneration::from(1),
                  AuthorityEpoch::from(1), CommandIntent::de_energize, "key-new", LogicalTick::from(12)),
      adapter);
  PDU_REQUIRE_STATUS(now_allowed, StatusCode::ok);
  PDU_CHECK_EQ(adapter.execute_count(), std::size_t{1});
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
}

PDU_TEST(recovery, resolving_an_orphan_attempt_releases_the_branch_without_inventing_state) {
  pdu_test::TempDir directory("recovery-resolve");
  const std::string store = directory.store_path();
  PDU_REQUIRE_STATUS(pdu_test::Process::spawn(pdu_test::probe_executable(),
                                              {"setup", store, "pdu-r3", "branch-r3"})
                         .value()
                         .wait() == 0
                         ? Status::success()
                         : Status::failure(StatusCode::internal),
                     StatusCode::ok);
  PDU_REQUIRE_STATUS(pdu_test::Process::spawn(pdu_test::probe_executable(),
                                              {"crash-in-adapter", store, "pdu-r3", "branch-r3",
                                               "key-r3", "10"})
                         .value()
                         .wait() == 41
                         ? Status::success()
                         : Status::failure(StatusCode::internal),
                     StatusCode::ok);

  const PduId pdu = PduId::parse("pdu-r3").value();
  const BranchId branch_id = BranchId::parse("branch-r3").value();
  auto opened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  const auto attempts = engine.attempts(0);
  PDU_CHECK(!attempts.empty());
  const AttemptId orphan = attempts.back().id;
  PDU_REQUIRE_STATUS(engine.resolve_attempt(orphan, AttemptResolution::superseded,
                                            ActorId::parse("operator").value(),
                                            AuthorityEpoch::from(1), LogicalTick::from(12)),
                     StatusCode::ok);
  const auto branch = engine.inspect_branch(pdu, branch_id);
  PDU_REQUIRE_STATUS(branch, StatusCode::ok);
  PDU_CHECK(!PDU_REQUIRE_OK(branch).unresolved_attempt);
  PDU_CHECK(!PDU_REQUIRE_OK(branch).verified.established());
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
}
