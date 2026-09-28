// Benchmark of the completed control operation.
//
// The timed operation is one whole accepted control command through a durable
// store: request validation, precondition evaluation, encoding of the entire
// model, staging write, flush to the device, read-back verification, head
// publication, and the head commit flush, plus the adapter call itself. Nothing
// that belongs to the operation is left outside the measurement, and submission
// latency is never reported as completion.
//
// Labeling: the durable store path measured here is REAL file and device I/O.
// The adapter is SYNTHETIC: it is a deterministic simulator that drives no
// hardware. No result below is hardware evidence.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "pdu_control/engine.hpp"
#include "pdu_control/synthetic_adapter.hpp"
#include "pdu_control/version.hpp"

using namespace pdu_control;

namespace {

constexpr std::uint64_t kDefaultOperations = 200;
constexpr std::uint64_t kDefaultBranches = 8;
constexpr std::uint64_t kDefaultRepetitions = 5;

struct Workload {
  std::uint64_t operations{kDefaultOperations};
  std::uint64_t branches{kDefaultBranches};
  std::uint64_t repetitions{kDefaultRepetitions};
  std::string store{"build/bench/control-bench.pdustore"};
};

Result<Workload> parse_workload(int argc, char** argv) {
  Workload workload;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    const auto number = [&](std::uint64_t fallback) -> Result<std::uint64_t> {
      if (index + 1 >= argc) {
        return Status::failure(StatusCode::invalid_argument, argument + " needs a value");
      }
      const std::string text = argv[++index];
      std::uint64_t value = 0;
      for (const char digit : text) {
        if (digit < '0' || digit > '9') {
          return Status::failure(StatusCode::malformed_input, "not a count: " + text);
        }
        value = value * 10 + static_cast<std::uint64_t>(digit - '0');
      }
      (void)fallback;
      return value;
    };
    if (argument == "--operations") {
      const auto value = number(workload.operations);
      if (!value.ok()) {
        return value.status();
      }
      workload.operations = value.value();
    } else if (argument == "--branches") {
      const auto value = number(workload.branches);
      if (!value.ok()) {
        return value.status();
      }
      workload.branches = value.value();
    } else if (argument == "--repetitions") {
      const auto value = number(workload.repetitions);
      if (!value.ok()) {
        return value.status();
      }
      workload.repetitions = value.value();
    } else if (argument == "--store") {
      if (index + 1 >= argc) {
        return Status::failure(StatusCode::invalid_argument, "--store needs a path");
      }
      workload.store = argv[++index];
    } else {
      return Status::failure(StatusCode::invalid_argument, "unknown option " + argument);
    }
  }
  if (workload.operations == 0 || workload.branches == 0 || workload.repetitions == 0) {
    return Status::failure(StatusCode::invalid_argument, "counts must be positive");
  }
  return workload;
}

EngineOptions bench_options() {
  EngineOptions options;
  // The benchmark measures the control path, not the growth of the audit ring,
  // so the ring and the idempotency window are deliberately small. The exact
  // configuration is printed with the results.
  options.audit_capacity = 64;
  options.idempotency_window = 64;
  options.evidence.max_age_ticks = LogicalTick::from(1000000000ULL);
  return options;
}

/// One repetition: build the workload, then time the accepted control commands.
struct RunResult {
  std::uint64_t operations{0};
  double seconds{0.0};
  std::uint64_t publications{0};
  std::uint64_t bytes_written{0};
  std::string final_digest;
  bool verified{false};
};

Result<RunResult> run_once(const Workload& workload, std::uint64_t seed) {
  RunResult result;
  // A benchmark run starts from nothing; any residue of an interrupted earlier
  // run is removed first, and it is removed again at the end.
  std::remove(workload.store.c_str());
  std::remove((workload.store + ".lock").c_str());
  auto opened = PduControlEngine::open(workload.store, OpenMode::create_new, bench_options());
  if (!opened.ok()) {
    return opened.status();
  }
  PduControlEngine& engine = opened.value();
  if (!engine.adopt_authority_epoch(AuthorityEpoch::from(1)).ok()) {
    return Status::failure(StatusCode::internal, "epoch adoption failed");
  }
  const PduId pdu = PduId::parse("bench-pdu").value();
  PduDefinition pdu_definition;
  pdu_definition.id = pdu;
  pdu_definition.generation = PduGeneration::from(1);
  pdu_definition.lifecycle = LifecycleState::active;
  pdu_definition.registered_at = LogicalTick::from(1);
  if (!engine.register_pdu(pdu_definition).ok()) {
    return Status::failure(StatusCode::internal, "PDU registration failed");
  }
  std::vector<BranchId> branches;
  for (std::uint64_t index = 0; index < workload.branches; ++index) {
    const BranchId id = BranchId::parse("bench-branch-" + std::to_string(index)).value();
    branches.push_back(id);
    BranchDefinition definition;
    definition.id = id;
    definition.pdu = pdu;
    definition.generation = BranchGeneration::from(1);
    definition.lifecycle = LifecycleState::active;
    definition.registered_at = LogicalTick::from(1);
    definition.limits.continuous_current = CurrentSample::known(Current::from_raw(16000));
    definition.limits.provenance.issuer = IssuerId::parse("bench-authority").value();
    definition.limits.provenance.authority = AuthorityId::parse("bench-capacity").value();
    definition.limits.provenance.epoch = AuthorityEpoch::from(1);
    definition.limits.provenance.stated_at = LogicalTick::from(1);
    definition.limits.revision = StateRevision::from(1);
    if (!engine.register_branch(definition).ok()) {
      return Status::failure(StatusCode::internal, "branch registration failed");
    }
    PermissionGrant grant;
    grant.id = AuthorityId::parse("bench-grant-" + std::to_string(index)).value();
    grant.issuer = IssuerId::parse("bench-authority").value();
    grant.epoch = AuthorityEpoch::from(1);
    grant.pdu = pdu;
    grant.branch = id;
    grant.pdu_generation = PduGeneration::from(1);
    grant.branch_generation = BranchGeneration::from(1);
    grant.actions = action_mask(PermissionAction::control_energize) |
                    action_mask(PermissionAction::control_de_energize);
    grant.issued_at = LogicalTick::from(1);
    if (!engine.record_grant(grant).ok()) {
      return Status::failure(StatusCode::internal, "grant recording failed");
    }
    TelemetryObservation observation;
    observation.pdu = pdu;
    observation.branch = id;
    observation.pdu_generation = PduGeneration::from(1);
    observation.branch_generation = BranchGeneration::from(1);
    observation.source = SourceId::parse("bench-source").value();
    observation.sequence = SequenceNumber::from(1);
    observation.taken_at = Instant::logical(LogicalTick::from(1));
    observation.quality = EvidenceQuality::good;
    observation.condition = BranchCondition::de_energized;
    if (!engine.record_observation(observation).ok()) {
      return Status::failure(StatusCode::internal, "observation recording failed");
    }
  }

  // One simulator per branch: a synthetic adapter models one branch circuit, and
  // sharing one across branches would model a device that cannot exist.
  std::vector<SyntheticPduAdapter> adapters;
  for (const BranchId& branch : branches) {
    SyntheticPduAdapter::Config config;
    config.id = AdapterId::parse("bench-adapter").value();
    config.vendor = IssuerId::parse("synthetic").value();
    config.model = "bench-synthetic";
    config.firmware = "0";
    config.pdu = pdu;
    config.branch = branch;
    config.pdu_generation = PduGeneration::from(1);
    config.branch_generation = BranchGeneration::from(1);
    config.mode = SyntheticMode::honor;
    config.initial_condition = BranchCondition::de_energized;
    config.reading_taken_at = Instant::logical(LogicalTick::from(1));
    config.reading_tick_step = LogicalTick::from(1);
    // A read-back measures now, so the reading is reported at the instant the
    // caller asked for it.
    config.read_at_request_instant = true;
    adapters.push_back(SyntheticPduAdapter(config));
  }

  const std::uint64_t before_publications = engine.store_audit().publication_count;
  const std::uint64_t before_bytes = engine.store_audit().bytes_written;
  const auto started = std::chrono::steady_clock::now();
  std::uint64_t completed = 0;
  std::uint64_t tick = 2;
  for (std::uint64_t index = 0; index < workload.operations; ++index) {
    const std::size_t slot = static_cast<std::size_t>((index + seed) % branches.size());
    const BranchId branch = branches[slot];
    SyntheticPduAdapter& adapter = adapters[slot];
    const CommandIntent intent =
        (index % 2) == 0 ? CommandIntent::energize : CommandIntent::de_energize;
    if (!engine.advance_tick(LogicalTick::from(tick)).ok()) {
      return Status::failure(StatusCode::internal, "tick advance failed");
    }
    BranchControlRequest request;
    request.key = IdempotencyKey::parse("bench-key-" + std::to_string(index)).value();
    request.pdu = pdu;
    request.branch = branch;
    request.pdu_generation = PduGeneration::from(1);
    request.branch_generation = BranchGeneration::from(1);
    request.epoch = AuthorityEpoch::from(1);
    request.intent = intent;
    request.actor = ActorId::parse("bench").value();
    request.requested_at = LogicalTick::from(tick);
    request.projected_current = CurrentSample::known(Current::from_raw(1000));
    const auto issued = engine.issue(request, adapter);
    if (!issued.ok()) {
      return issued.status();
    }
    // A command is complete only when its effect has been established, so the
    // verification step belongs to the measured operation.
    const auto verified = engine.verify_with_adapter(issued.value().id, adapter);
    if (!verified.ok()) {
      return verified.status();
    }
    if (verified.value().effect != EffectState::effective) {
      return Status::failure(StatusCode::internal,
                             "the benchmark operation did not reach a verified effect");
    }
    completed += 1;
    tick += 2;
  }
  const auto finished = std::chrono::steady_clock::now();
  const StoreAudit audit = engine.store_audit();
  result.operations = completed;
  result.seconds = std::chrono::duration<double>(finished - started).count();
  result.publications = audit.publication_count - before_publications;
  result.bytes_written = audit.bytes_written - before_bytes;
  result.final_digest = engine.state_digest().to_hex();
  // Verify the resulting state before reporting anything: a benchmark that does
  // not check what it produced is measuring nothing.
  result.verified = engine.status().branch_count == workload.branches &&
                    engine.status().unresolved_attempt_count == 0;
  const Status closed = engine.close();
  if (!closed.ok()) {
    return closed;
  }
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  const auto workload = parse_workload(argc, argv);
  if (!workload.ok()) {
    std::cout << "workload error: " << workload.status().to_string() << "\n";
    return 2;
  }
  std::cout << "pdu-control benchmark\n";
  std::cout << "version=" << version_string << " pointer-bytes=" << sizeof(void*)
            << " store-format=" << store_format_version << "\n";
  std::cout << "workload operations=" << workload.value().operations
            << " branches=" << workload.value().branches
            << " repetitions=" << workload.value().repetitions << "\n";
  std::cout << "configuration audit-capacity=64 idempotency-window=64 evidence-max-age-ticks="
               "1000000000\n";
  std::cout << "methodology timed-operation=clock-advance + issue(validate+preconditions+encode+"
               "stage+flush+readback+publish+commit)+adapter-execute + verify(read-back+verify)\n";
  std::cout << "label store=REAL adapter=SYNTHETIC (no hardware is driven)\n";

  std::vector<double> throughputs;
  for (std::uint64_t repetition = 0; repetition < workload.value().repetitions; ++repetition) {
    const std::string store =
        workload.value().store + "-" + std::to_string(repetition) + ".tmp";
    Workload local = workload.value();
    local.store = store;
    const auto result = run_once(local, repetition);
    if (!result.ok()) {
      std::cout << "run failed: " << result.status().to_string() << "\n";
      return 1;
    }
    const double throughput =
        result.value().seconds > 0.0
            ? static_cast<double>(result.value().operations) / result.value().seconds
            : 0.0;
    throughputs.push_back(throughput);
    std::cout << "run=" << repetition << " completed=" << result.value().operations
              << " seconds=" << result.value().seconds
              << " operations-per-second=" << throughput
              << " publications=" << result.value().publications
              << " bytes-written=" << result.value().bytes_written
              << " state-verified=" << (result.value().verified ? "true" : "false")
              << " digest=" << result.value().final_digest << "\n";
    std::cout << "cleanup=" << store << " removed\n";
    std::remove(store.c_str());
    std::remove((store + ".lock").c_str());
  }
  std::sort(throughputs.begin(), throughputs.end());
  double total = 0.0;
  for (const double value : throughputs) {
    total += value;
  }
  const double mean = throughputs.empty() ? 0.0 : total / static_cast<double>(throughputs.size());
  const double median = throughputs.empty()
                            ? 0.0
                            : throughputs[throughputs.size() / 2];
  std::cout << "summary statistic=median-and-mean median-operations-per-second=" << median
            << " mean-operations-per-second=" << mean
            << " minimum=" << (throughputs.empty() ? 0.0 : throughputs.front())
            << " maximum=" << (throughputs.empty() ? 0.0 : throughputs.back()) << "\n";
  return 0;
}
