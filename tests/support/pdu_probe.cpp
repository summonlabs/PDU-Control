// The probe is a real program started as an independent operating-system
// process by the crash and multiprocess tests. It either performs one step of a
// scenario and reports it on stdout, or terminates itself at a chosen durable
// stage so that a test can observe what a process death leaves behind.

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "detail/file_io.hpp"
#include "detail/process.hpp"
#include "pdu_control/engine.hpp"
#include "pdu_control/synthetic_adapter.hpp"

using namespace pdu_control;

namespace {

EngineOptions probe_options() {
  EngineOptions options;
  options.evidence.max_age_ticks = LogicalTick::from(1000);
  options.idempotency_window = 16;
  options.audit_capacity = 64;
  return options;
}

struct ProbeIds {
  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation{PduGeneration::from(1)};
  BranchGeneration branch_generation{BranchGeneration::from(1)};
  InterlockId interlock;
  AuthorityId grant;
  IssuerId issuer;
  AuthorityEpoch epoch{AuthorityEpoch::from(1)};
  SourceId source;
};

ProbeIds make_ids(const std::string& pdu_text, const std::string& branch_text,
                  std::uint64_t pdu_generation, std::uint64_t branch_generation) {
  ProbeIds ids;
  ids.pdu = PduId::parse(pdu_text).value();
  ids.branch = BranchId::parse(branch_text).value();
  ids.pdu_generation = PduGeneration::from(pdu_generation);
  ids.branch_generation = BranchGeneration::from(branch_generation);
  ids.interlock = InterlockId::parse("site-safe").value();
  ids.grant = AuthorityId::parse("grant-site").value();
  ids.issuer = IssuerId::parse("probe-authority").value();
  ids.source = SourceId::parse("probe-source").value();
  return ids;
}

/// Registers the scenario if it is not there yet. Re-running against an existing
/// store is a no-op, so a test can call it from a child process and from the
/// parent without coordinating.
Status ensure_scenario(PduControlEngine& engine, const ProbeIds& ids) {
  Status status = engine.adopt_authority_epoch(ids.epoch);
  if (!status.ok() && status.code() != StatusCode::permission_stale) {
    return status;
  }

  PduDefinition pdu;
  pdu.id = ids.pdu;
  pdu.generation = ids.pdu_generation;
  pdu.lifecycle = LifecycleState::active;
  pdu.label = "probe pdu";
  pdu.registered_at = LogicalTick::from(1);
  status = engine.register_pdu(pdu);
  if (!status.ok() && status.code() != StatusCode::duplicate_identity) {
    return status;
  }
  const bool fresh_pdu = status.ok();

  BranchDefinition branch;
  branch.id = ids.branch;
  branch.pdu = ids.pdu;
  branch.generation = ids.branch_generation;
  branch.lifecycle = LifecycleState::active;
  branch.label = "probe branch";
  branch.registered_at = LogicalTick::from(1);
  branch.required_interlocks.push_back(ids.interlock);
  branch.limits.continuous_current = CurrentSample::known(Current::from_raw(16000));
  branch.limits.provenance.issuer = ids.issuer;
  branch.limits.provenance.authority = ids.grant;
  branch.limits.provenance.epoch = ids.epoch;
  branch.limits.provenance.stated_at = LogicalTick::from(1);
  branch.limits.revision = StateRevision::from(1);
  status = engine.register_branch(branch);
  if (!status.ok() && status.code() != StatusCode::duplicate_identity) {
    return status;
  }

  InterlockDeclaration declaration;
  declaration.id = ids.interlock;
  declaration.pdu = ids.pdu;
  declaration.branch = ids.branch;
  declaration.klass = ObligationClass::protected_obligation;
  declaration.declared_at = LogicalTick::from(1);
  declaration.epoch = ids.epoch;
  status = engine.declare_interlock(declaration);
  if (!status.ok() && status.code() != StatusCode::duplicate_identity) {
    return status;
  }

  InterlockStatus interlock_status;
  interlock_status.id = ids.interlock;
  interlock_status.state = InterlockState::satisfied;
  interlock_status.epoch = ids.epoch;
  interlock_status.updated_at = LogicalTick::from(1);
  status = engine.report_interlock(interlock_status);
  if (!status.ok() && status.code() != StatusCode::evidence_stale) {
    return status;
  }

  PermissionGrant grant;
  grant.id = ids.grant;
  grant.issuer = ids.issuer;
  grant.epoch = ids.epoch;
  grant.pdu = ids.pdu;
  grant.branch = ids.branch;
  grant.pdu_generation = ids.pdu_generation;
  grant.branch_generation = ids.branch_generation;
  grant.actions = action_mask(PermissionAction::control_energize) |
                  action_mask(PermissionAction::control_de_energize) |
                  action_mask(PermissionAction::lifecycle_service) |
                  action_mask(PermissionAction::lifecycle_recovery) |
                  action_mask(PermissionAction::lifecycle_administrative) |
                  action_mask(PermissionAction::maintenance_override);
  grant.issued_at = LogicalTick::from(1);
  status = engine.record_grant(grant);
  if (!status.ok() && status.code() != StatusCode::duplicate_identity) {
    return status;
  }

  if (fresh_pdu) {
    TelemetryObservation observation;
    observation.pdu = ids.pdu;
    observation.branch = ids.branch;
    observation.pdu_generation = ids.pdu_generation;
    observation.branch_generation = ids.branch_generation;
    observation.source = ids.source;
    observation.sequence = SequenceNumber::from(1);
    observation.taken_at = Instant::logical(LogicalTick::from(1));
    observation.quality = EvidenceQuality::good;
    observation.condition = BranchCondition::de_energized;
    const auto recorded = engine.record_observation(observation);
    if (!recorded.ok()) {
      return recorded.status();
    }
  }
  return Status::success();
}

class CrashingAdapter final : public PowerAdapter {
 public:
  explicit CrashingAdapter(ProbeIds ids) : ids_(std::move(ids)) {}

  [[nodiscard]] AdapterDescriptor describe() const override {
    AdapterDescriptor descriptor;
    descriptor.id = AdapterId::parse("crashing-adapter").value();
    descriptor.vendor = IssuerId::parse("probe").value();
    descriptor.model = "crash-on-execute";
    descriptor.firmware = "0";
    descriptor.kind = AdapterKind::synthetic;
    descriptor.supports_readback = false;
    descriptor.synthetic = true;
    return descriptor;
  }

  [[nodiscard]] AdapterOutcome execute(const AdapterCommand&) override {
    // The engine published the accepted attempt durably before this call, so
    // this is a death strictly after the durable command-attempt boundary.
    ::pdu_control::detail::terminate_now(41);
  }

  [[nodiscard]] Result<TelemetryObservation> read(const AdapterReadRequest&) override {
    return Status::failure(StatusCode::adapter_unavailable, "the crashing adapter does not read");
  }

 private:
  ProbeIds ids_;
};

SyntheticPduAdapter make_synthetic(const ProbeIds& ids, BranchCondition initial) {
  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("probe-adapter").value();
  config.vendor = IssuerId::parse("probe").value();
  config.model = "probe-synthetic";
  config.firmware = "0";
  config.pdu = ids.pdu;
  config.branch = ids.branch;
  config.pdu_generation = ids.pdu_generation;
  config.branch_generation = ids.branch_generation;
  config.mode = SyntheticMode::honor;
  config.initial_condition = initial;
  config.reading_taken_at = Instant::logical(LogicalTick::from(1));
  config.reading_tick_step = LogicalTick::from(1);
  return SyntheticPduAdapter(config);
}

BranchCondition verified_condition(const PduControlEngine& engine, const ProbeIds& ids) {
  const auto snapshot = engine.inspect_branch(ids.pdu, ids.branch);
  if (!snapshot.ok()) {
    return BranchCondition::unknown;
  }
  if (!snapshot.value().verified.established()) {
    return BranchCondition::unknown;
  }
  return snapshot.value().verified.condition.value();
}

int fail(const std::string& detail) {
  std::cout << "error=" << detail << "\n";
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cout << "usage: pdu_probe <mode> [args]\n";
    return 2;
  }
  const std::string mode = argv[1];
  const auto argument = [&](int index) -> std::string {
    return index < argc ? std::string(argv[index]) : std::string();
  };
  const auto number = [&](int index, std::uint64_t fallback) -> std::uint64_t {
    if (index >= argc) {
      return fallback;
    }
    char* end = nullptr;
    const unsigned long long value = std::strtoull(argv[index], &end, 10);
    if (end == nullptr || *end != '\0') {
      return fallback;
    }
    return static_cast<std::uint64_t>(value);
  };

  if (mode == "setup") {
    if (argc < 5) {
      std::cout << "usage: pdu_probe setup <store> <pdu> <branch>\n";
      return 2;
    }
    const ProbeIds ids = make_ids(argument(3), argument(4), 1, 1);
    auto opened = PduControlEngine::open(argument(2), OpenMode::open_or_create, probe_options());
    if (!opened.ok()) {
      return fail(std::string(opened.status().token()) + ": " + opened.status().message());
    }
    PduControlEngine& engine = opened.value();
    const Status status = ensure_scenario(engine, ids);
    if (!status.ok()) {
      return fail(std::string(status.token()) + ": " + status.message());
    }
    const auto snapshot = engine.inspect_branch(ids.pdu, ids.branch);
    if (!snapshot.ok()) {
      return fail("the branch is missing after setup");
    }
    std::cout << "pdu-generation=" << snapshot.value().pdu_generation.value() << "\n";
    std::cout << "branch-generation=" << snapshot.value().generation.value() << "\n";
    std::cout << "branch-revision=" << snapshot.value().revision.value() << "\n";
    std::cout << "tick=" << engine.current_tick().value() << "\n";
    std::cout << "generation=" << engine.store_generation().value() << "\n";
    const Status closed = engine.close();
    if (!closed.ok()) {
      return fail("close failed");
    }
    return 0;
  }

  if (mode == "crash-before-boundary") {
    if (argc < 7) {
      std::cout << "usage: pdu_probe crash-before-boundary <store> <pdu> <branch> <key> <tick>\n";
      return 2;
    }
    const ProbeIds ids = make_ids(argument(3), argument(4), 1, 1);
    auto opened = PduControlEngine::open(argument(2), OpenMode::open_or_create, probe_options());
    if (!opened.ok()) {
      return fail("open failed");
    }
    PduControlEngine& engine = opened.value();
    const Status status = ensure_scenario(engine, ids);
    if (!status.ok()) {
      return fail("setup failed");
    }
    if (!engine.advance_tick(LogicalTick::from(number(6, 10))).ok()) {
      return fail("tick failed");
    }
    // Nothing about a command has been written: the process dies before the
    // durable command-attempt boundary is reached.
    ::pdu_control::detail::terminate_now(40);
  }

  if (mode == "crash-in-adapter") {
    if (argc < 7) {
      std::cout << "usage: pdu_probe crash-in-adapter <store> <pdu> <branch> <key> <tick>\n";
      return 2;
    }
    const ProbeIds ids = make_ids(argument(3), argument(4), 1, 1);
    auto opened = PduControlEngine::open(argument(2), OpenMode::open_or_create, probe_options());
    if (!opened.ok()) {
      return fail("open failed");
    }
    PduControlEngine& engine = opened.value();
    const Status status = ensure_scenario(engine, ids);
    if (!status.ok()) {
      return fail("setup failed");
    }
    const LogicalTick tick = LogicalTick::from(number(6, 10));
    if (engine.current_tick() < tick) {
      const Status advanced = engine.advance_tick(tick);
      if (!advanced.ok()) {
        return fail("tick failed");
      }
    }
    BranchControlRequest request;
    request.key = IdempotencyKey::parse(argument(5)).value();
    request.pdu = ids.pdu;
    request.branch = ids.branch;
    request.pdu_generation = ids.pdu_generation;
    request.branch_generation = ids.branch_generation;
    request.epoch = ids.epoch;
    request.intent = CommandIntent::energize;
    request.actor = ActorId::parse("probe").value();
    request.requested_at = engine.current_tick();
    CrashingAdapter adapter(ids);
    const auto issued = engine.issue(request, adapter);
    if (!issued.ok()) {
      return fail(std::string(issued.status().token()) + ": " + issued.status().message());
    }
    std::cout << "unexpected-return\n";
    return 3;
  }

  if (mode == "hold") {
    if (argc < 5) {
      std::cout << "usage: pdu_probe hold <store> <ready-file> <release-file>\n";
      return 2;
    }
    auto opened = PduControlEngine::open(argument(2), OpenMode::open_or_create, probe_options());
    if (!opened.ok()) {
      return fail(std::string(opened.status().token()) + ": " + opened.status().message());
    }
    std::ofstream(argument(3)) << "ready\n";
    while (!::pdu_control::detail::path_exists(argument(4))) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const Status closed = opened.value().close();
    return closed.ok() ? 0 : 1;
  }

  if (mode == "report" || mode == "reopen-report") {
    if (argc < 3) {
      std::cout << "usage: pdu_probe report <store>\n";
      return 2;
    }
    auto opened = PduControlEngine::open(argument(2), OpenMode::open_existing, probe_options());
    if (!opened.ok()) {
      return fail(std::string(opened.status().token()) + ": " + opened.status().message());
    }
    PduControlEngine& engine = opened.value();
    const EngineStatus status = engine.status();
    std::cout << "generation=" << status.store_generation.value() << "\n";
    std::cout << "incarnation=" << status.incarnation.value() << "\n";
    std::cout << "pdus=" << status.pdu_count << "\n";
    std::cout << "branches=" << status.branch_count << "\n";
    std::cout << "attempts=" << status.attempt_count << "\n";
    std::cout << "unresolved=" << status.unresolved_attempt_count << "\n";
    const auto snapshot = engine.inspect_all();
    for (const PduSnapshot& pdu : snapshot) {
      for (const BranchSnapshot& branch : pdu.branches) {
        std::cout << "branch-state=" << to_token(branch.lifecycle) << "/"
                  << to_token(branch.commanded.condition.state()) << "/"
                  << to_token(branch.verified.condition.state()) << "\n";
      }
    }
    const auto attempts = engine.attempts(0);
    if (!attempts.empty()) {
      std::cout << "attempt-outcome=" << to_token(attempts.back().outcome) << "\n";
      std::cout << "attempt-effect=" << to_token(attempts.back().effect) << "\n";
    }
    if (mode == "reopen-report") {
      std::cout << "reopened=1\n";
    }
    const Status closed = engine.close();
    if (!closed.ok()) {
      return fail("close failed");
    }
    return 0;
  }

  std::cout << "usage: pdu_probe <setup|crash-before-boundary|crash-in-adapter|hold|report|"
               "reopen-report> [args]\n";
  return 2;
}
