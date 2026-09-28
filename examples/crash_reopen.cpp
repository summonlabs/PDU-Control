// Example: a process death after the durable command-attempt boundary.
//
// The program re-executes itself with --child so that a real operating-system
// process dies inside the adapter call, strictly after the engine has committed
// the accepted attempt. The parent then proves that recovering the store does
// not re-send the command, that a retry of the original key replays the adopted
// record without touching an adapter, and that a new key is refused until the
// effect is established.
//
// Everything here is SYNTHETIC with respect to the device: the child never
// reaches a physical PDU.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "pdu_control/engine.hpp"
#include "pdu_control/synthetic_adapter.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace pdu_control;

namespace {

const char* kPduText = "site-pdu-1";
const char* kBranchText = "row-a-branch-1";
const char* kKey = "enable-1";

int failures = 0;

void expect(bool condition, const std::string& description) {
  if (!condition) {
    std::cout << "EXPECTATION FAILED: " << description << "\n";
    failures += 1;
  } else {
    std::cout << "ok: " << description << "\n";
  }
}

EngineOptions example_options() {
  EngineOptions options;
  options.evidence.max_age_ticks = LogicalTick::from(1000);
  options.audit_capacity = 128;
  return options;
}

Status build_scenario(PduControlEngine& engine, const PduId& pdu, const BranchId& branch,
                      bool fresh) {
  Status status = engine.adopt_authority_epoch(AuthorityEpoch::from(1));
  if (!status.ok() && status.code() != StatusCode::permission_stale) {
    return status;
  }
  if (fresh) {
    PduDefinition pdu_definition;
    pdu_definition.id = pdu;
    pdu_definition.generation = PduGeneration::from(1);
    pdu_definition.lifecycle = LifecycleState::active;
    pdu_definition.registered_at = LogicalTick::from(1);
    status = engine.register_pdu(pdu_definition);
    if (!status.ok() && status.code() != StatusCode::duplicate_identity) {
      return status;
    }
    BranchDefinition branch_definition;
    branch_definition.id = branch;
    branch_definition.pdu = pdu;
    branch_definition.generation = BranchGeneration::from(1);
    branch_definition.lifecycle = LifecycleState::active;
    branch_definition.registered_at = LogicalTick::from(1);
    branch_definition.limits.continuous_current = CurrentSample::known(Current::from_raw(16000));
    branch_definition.limits.provenance.issuer = IssuerId::parse("power-capacity").value();
    branch_definition.limits.provenance.stated_at = LogicalTick::from(1);
    status = engine.register_branch(branch_definition);
    if (!status.ok() && status.code() != StatusCode::duplicate_identity) {
      return status;
    }
    PermissionGrant grant;
    grant.id = AuthorityId::parse("grant-1").value();
    grant.issuer = IssuerId::parse("power-control-plane").value();
    grant.epoch = AuthorityEpoch::from(1);
    grant.pdu = pdu;
    grant.branch = branch;
    grant.pdu_generation = PduGeneration::from(1);
    grant.branch_generation = BranchGeneration::from(1);
    grant.actions = action_mask(PermissionAction::control_energize) |
                    action_mask(PermissionAction::control_de_energize) |
                    action_mask(PermissionAction::lifecycle_recovery);
    grant.issued_at = LogicalTick::from(1);
    status = engine.record_grant(grant);
    if (!status.ok() && status.code() != StatusCode::duplicate_identity) {
      return status;
    }
    TelemetryObservation observation;
    observation.pdu = pdu;
    observation.branch = branch;
    observation.pdu_generation = PduGeneration::from(1);
    observation.branch_generation = BranchGeneration::from(1);
    observation.source = SourceId::parse("field").value();
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

/// The child's adapter: it dies inside the adapter call, which is strictly after
/// the engine published the accepted attempt.
class DyingAdapter final : public PowerAdapter {
 public:
  DyingAdapter() = default;
  [[nodiscard]] AdapterDescriptor describe() const override {
    AdapterDescriptor descriptor;
    descriptor.id = AdapterId::parse("dying-adapter").value();
    descriptor.vendor = IssuerId::parse("synthetic").value();
    descriptor.model = "synthetic-dying";
    descriptor.firmware = "0";
    descriptor.kind = AdapterKind::synthetic;
    descriptor.supports_readback = false;
    descriptor.synthetic = true;
    return descriptor;
  }
  [[nodiscard]] AdapterOutcome execute(const AdapterCommand&) override {
#ifdef _WIN32
    // TerminateProcess runs no destructors and no atexit handlers, so this is a
    // real abrupt death rather than a cooperative exit.
    TerminateProcess(GetCurrentProcess(), 41);
    std::_Exit(41);
#else
    _exit(41);
#endif
  }
  [[nodiscard]] Result<TelemetryObservation> read(const AdapterReadRequest&) override {
    return Status::failure(StatusCode::adapter_unavailable, "the dying adapter does not read");
  }
};

int run_child(const std::string& store) {
  const PduId pdu = PduId::parse(kPduText).value();
  const BranchId branch = BranchId::parse(kBranchText).value();
  auto opened = PduControlEngine::open(store, OpenMode::open_or_create, example_options());
  if (!opened.ok()) {
    std::cout << "child open failed: " << opened.status().to_string() << "\n";
    return 2;
  }
  PduControlEngine& engine = opened.value();
  const Status setup = build_scenario(engine, pdu, branch, true);
  if (!setup.ok()) {
    std::cout << "child setup failed: " << setup.to_string() << "\n";
    return 2;
  }
  if (engine.current_tick() < LogicalTick::from(4)) {
    if (!engine.advance_tick(LogicalTick::from(4)).ok()) {
      return 2;
    }
  }
  BranchControlRequest request;
  request.key = IdempotencyKey::parse(kKey).value();
  request.pdu = pdu;
  request.branch = branch;
  request.pdu_generation = PduGeneration::from(1);
  request.branch_generation = BranchGeneration::from(1);
  request.epoch = AuthorityEpoch::from(1);
  request.intent = CommandIntent::energize;
  request.actor = ActorId::parse("operator-1").value();
  request.requested_at = engine.current_tick();
  DyingAdapter adapter;
  const auto issued = engine.issue(request, adapter);
  std::cout << "child returned unexpectedly: " << issued.status().to_string() << "\n";
  return 3;
}

int run_parent(const std::string& store, const std::string& self) {
  // The child is started with the same executable and a single extra argument.
  std::string command = "\"" + self + "\" --child \"" + store + "\"";
#ifdef _WIN32
  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  std::string mutable_command = command;
  if (CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                     &startup, &info) == FALSE) {
    std::cout << "could not start the child process\n";
    return 1;
  }
  WaitForSingleObject(info.hProcess, INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(info.hProcess, &code);
  CloseHandle(info.hThread);
  CloseHandle(info.hProcess);
  const int exit_code = static_cast<int>(code);
#else
  const int status = std::system(command.c_str());
  const int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
#endif
  std::cout << "child exit code: " << exit_code << "\n";
  expect(exit_code == 41, "the child died inside the adapter call");

  const PduId pdu = PduId::parse(kPduText).value();
  const BranchId branch = BranchId::parse(kBranchText).value();
  auto opened = PduControlEngine::open(store, OpenMode::open_existing, example_options());
  if (!opened.ok()) {
    std::cout << "reopen failed: " << opened.status().to_string() << "\n";
    return 1;
  }
  PduControlEngine& engine = opened.value();
  const EngineStatus status = engine.status();
  std::cout << "attempts after recovery: " << status.attempt_count
            << " unresolved: " << status.unresolved_attempt_count << "\n";
  expect(status.attempt_count == 1, "exactly one attempt survived the death");
  const auto attempts = engine.attempts(0);
  expect(!attempts.empty() && attempts.back().outcome == AttemptOutcome::recovery_required,
         "the attempt was adopted as recovery_required");
  expect(!attempts.empty() && attempts.back().dispatched,
         "the adopted attempt records that a command may have reached the branch");
  const AttemptId orphan = attempts.back().id;
  const auto snapshot = engine.inspect_branch(pdu, branch);
  expect(snapshot.ok() && snapshot.value().unresolved_attempt,
         "the branch is blocked while the effect is unknown");
  expect(snapshot.ok() &&
             snapshot.value().commanded.condition.value() == BranchCondition::energized,
         "the desired state survived the death");

  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("parent-adapter").value();
  config.vendor = IssuerId::parse("synthetic").value();
  config.model = "synthetic-parent";
  config.firmware = "0";
  config.pdu = pdu;
  config.branch = branch;
  config.pdu_generation = PduGeneration::from(1);
  config.branch_generation = BranchGeneration::from(1);
  config.mode = SyntheticMode::honor;
  config.initial_condition = BranchCondition::de_energized;
  config.read_at_request_instant = true;
  SyntheticPduAdapter adapter(config);

  BranchControlRequest retry;
  retry.key = IdempotencyKey::parse(kKey).value();
  retry.pdu = pdu;
  retry.branch = branch;
  retry.pdu_generation = PduGeneration::from(1);
  retry.branch_generation = BranchGeneration::from(1);
  retry.epoch = AuthorityEpoch::from(1);
  retry.intent = CommandIntent::energize;
  retry.actor = ActorId::parse("operator-1").value();
  retry.requested_at = engine.current_tick();
  const auto replayed = engine.issue(retry, adapter);
  expect(replayed.ok() && replayed.value().replayed,
         "a retry of the original key replays the adopted record");
  expect(replayed.ok() && replayed.value().id == orphan,
         "the replay names the same attempt");
  expect(adapter.execute_count() == 0,
         "the retry never reached an adapter: the command is not sent twice");

  BranchControlRequest fresh = retry;
  fresh.key = IdempotencyKey::parse("enable-2").value();
  fresh.intent = CommandIntent::de_energize;
  const auto blocked = engine.issue(fresh, adapter);
  expect(!blocked.ok() && blocked.status().code() == StatusCode::attempt_unresolved,
         "a new command is refused while an attempt has no established effect");
  expect(adapter.execute_count() == 0, "the refused command never reached an adapter");

  // Field telemetry establishes what actually happened.
  if (!engine.advance_tick(LogicalTick::from(engine.current_tick().value() + 1)).ok()) {
    return 1;
  }
  TelemetryObservation observation;
  observation.pdu = pdu;
  observation.branch = branch;
  observation.pdu_generation = PduGeneration::from(1);
  observation.branch_generation = BranchGeneration::from(1);
  observation.source = SourceId::parse("field-telemetry").value();
  observation.sequence = SequenceNumber::from(9);
  observation.taken_at = Instant::logical(engine.current_tick());
  observation.quality = EvidenceQuality::good;
  observation.condition = BranchCondition::energized;
  const auto recorded = engine.record_observation(observation);
  expect(recorded.ok(), "a fresh observation was recorded");
  const auto verified = engine.verify(orphan);
  expect(verified.ok() && verified.value().effect == EffectState::effective,
         "the effect of the adopted attempt is established from fresh evidence");
  const auto resolved = engine.inspect_branch(pdu, branch);
  expect(resolved.ok() && !resolved.value().unresolved_attempt, "the branch is released");
  expect(engine.close().ok(), "the store closed cleanly");
  std::cout << "SYNTHETIC: the adapter was a deterministic simulator; no hardware was involved.\n";
  if (failures != 0) {
    std::cout << failures << " expectation(s) failed\n";
    return 1;
  }
  std::cout << "no command was re-sent after the process died\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::string store = "example-crash-reopen/site.pdustore";
  bool child = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--child") {
      child = true;
    } else {
      store = argument;
    }
  }
  if (child) {
    return run_child(store);
  }
  // The example starts from nothing so that it can be run repeatedly: an
  // existing store from an earlier run would make the child's command a replay
  // instead of a fresh dispatch, and the demonstration would prove nothing.
  std::remove(store.c_str());
  std::remove((store + ".lock").c_str());
  std::cout << "parent store: " << store << "\n";
  return run_parent(store, argv[0]);
}
