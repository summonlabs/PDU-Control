// Example: safe branch enable and disable through a synthetic adapter.
//
// Everything this example prints comes from a deterministic simulator. It is
// SYNTHETIC evidence about the control semantics of this library, and it is not
// evidence about any physical device.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "pdu_control/engine.hpp"
#include "pdu_control/synthetic_adapter.hpp"

using namespace pdu_control;

namespace {

const char* kPdu = "site-pdu-1";
const char* kBranch = "row-a-branch-1";

EngineOptions example_options() {
  EngineOptions options;
  options.evidence.max_age_ticks = LogicalTick::from(1000);
  options.idempotency_window = 16;
  options.audit_capacity = 128;
  return options;
}

SyntheticPduAdapter make_adapter(const PduId& pdu, const BranchId& branch, BranchCondition initial) {
  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("example-adapter").value();
  config.vendor = IssuerId::parse("synthetic").value();
  config.model = "synthetic-example";
  config.firmware = "0";
  config.pdu = pdu;
  config.branch = branch;
  config.pdu_generation = PduGeneration::from(1);
  config.branch_generation = BranchGeneration::from(1);
  config.mode = SyntheticMode::honor;
  config.initial_condition = initial;
  config.reading_taken_at = Instant::logical(LogicalTick::from(1));
  config.reading_tick_step = LogicalTick::from(1);
  config.read_at_request_instant = true;
  return SyntheticPduAdapter(config);
}

void report(PduControlEngine& engine, const PduId& pdu, const BranchId& branch,
            const char* step) {
  const auto snapshot = engine.inspect_branch(pdu, branch);
  if (!snapshot.ok()) {
    std::cout << step << ": inspection failed: " << snapshot.status().to_string() << "\n";
    std::exit(1);
  }
  const BranchSnapshot& value = snapshot.value();
  std::cout << step << ": commanded=" << to_token(value.commanded.condition.state());
  if (value.commanded.condition.has_value()) {
    std::cout << "(" << to_token(value.commanded.condition.value()) << ")";
  }
  std::cout << " verified=" << to_token(value.verified.condition.state());
  if (value.verified.condition.has_value()) {
    std::cout << "(" << to_token(value.verified.condition.value()) << ")";
  }
  std::cout << " observed=" << to_token(value.observation.condition)
            << " freshness=" << to_token(value.observation.freshness)
            << " revision=" << value.revision.value()
            << " unresolved=" << (value.unresolved_attempt ? "yes" : "no") << "\n";
}

Status build_scenario(PduControlEngine& engine, const PduId& pdu, const BranchId& branch) {
  Status status = engine.adopt_authority_epoch(AuthorityEpoch::from(1));
  if (!status.ok()) {
    return status;
  }
  PduDefinition pdu_definition;
  pdu_definition.id = pdu;
  pdu_definition.generation = PduGeneration::from(1);
  pdu_definition.lifecycle = LifecycleState::active;
  pdu_definition.label = "site pdu";
  pdu_definition.owner = IssuerId::parse("facility").value();
  pdu_definition.registered_at = LogicalTick::from(1);
  status = engine.register_pdu(pdu_definition);
  if (!status.ok()) {
    return status;
  }
  BranchDefinition branch_definition;
  branch_definition.id = branch;
  branch_definition.pdu = pdu;
  branch_definition.generation = BranchGeneration::from(1);
  branch_definition.lifecycle = LifecycleState::active;
  branch_definition.label = "row A branch 1";
  branch_definition.registered_at = LogicalTick::from(1);
  branch_definition.required_interlocks.push_back(InterlockId::parse("site-safe").value());
  branch_definition.limits.continuous_current = CurrentSample::known(Current::from_raw(16000));
  branch_definition.limits.provenance.issuer = IssuerId::parse("power-capacity").value();
  branch_definition.limits.provenance.authority = AuthorityId::parse("capacity-grant-1").value();
  branch_definition.limits.provenance.epoch = AuthorityEpoch::from(1);
  branch_definition.limits.provenance.stated_at = LogicalTick::from(1);
  branch_definition.limits.revision = StateRevision::from(1);
  status = engine.register_branch(branch_definition);
  if (!status.ok()) {
    return status;
  }
  InterlockDeclaration declaration;
  declaration.id = InterlockId::parse("site-safe").value();
  declaration.pdu = pdu;
  declaration.branch = branch;
  declaration.klass = ObligationClass::protected_obligation;
  declaration.declared_at = LogicalTick::from(1);
  declaration.epoch = AuthorityEpoch::from(1);
  status = engine.declare_interlock(declaration);
  if (!status.ok()) {
    return status;
  }
  InterlockStatus interlock_status;
  interlock_status.id = declaration.id;
  interlock_status.state = InterlockState::satisfied;
  interlock_status.epoch = AuthorityEpoch::from(1);
  interlock_status.updated_at = LogicalTick::from(1);
  status = engine.report_interlock(interlock_status);
  if (!status.ok()) {
    return status;
  }
  PermissionGrant grant;
  grant.id = AuthorityId::parse("control-grant-1").value();
  grant.issuer = IssuerId::parse("power-control-plane").value();
  grant.epoch = AuthorityEpoch::from(1);
  grant.pdu = pdu;
  grant.branch = branch;
  grant.pdu_generation = PduGeneration::from(1);
  grant.branch_generation = BranchGeneration::from(1);
  grant.actions = action_mask(PermissionAction::control_energize) |
                  action_mask(PermissionAction::control_de_energize) |
                  action_mask(PermissionAction::lifecycle_service) |
                  action_mask(PermissionAction::lifecycle_recovery);
  grant.issued_at = LogicalTick::from(1);
  status = engine.record_grant(grant);
  if (!status.ok()) {
    return status;
  }
  TelemetryObservation observation;
  observation.pdu = pdu;
  observation.branch = branch;
  observation.pdu_generation = PduGeneration::from(1);
  observation.branch_generation = BranchGeneration::from(1);
  observation.source = SourceId::parse("field-telemetry").value();
  observation.sequence = SequenceNumber::from(1);
  observation.taken_at = Instant::logical(LogicalTick::from(2));
  observation.quality = EvidenceQuality::good;
  observation.condition = BranchCondition::de_energized;
  observation.current = CurrentSample::known(Current::from_raw(0));
  const auto recorded = engine.record_observation(observation);
  return recorded.ok() ? Status::success() : recorded.status();
}

Status command_and_verify(PduControlEngine& engine, SyntheticPduAdapter& adapter, const PduId& pdu,
                          const BranchId& branch, CommandIntent intent, const std::string& key,
                          std::uint64_t tick) {
  Status status = engine.advance_tick(LogicalTick::from(tick));
  if (!status.ok()) {
    return status;
  }
  BranchControlRequest request;
  request.key = IdempotencyKey::parse(key).value();
  request.pdu = pdu;
  request.branch = branch;
  request.pdu_generation = PduGeneration::from(1);
  request.branch_generation = BranchGeneration::from(1);
  request.epoch = AuthorityEpoch::from(1);
  request.intent = intent;
  request.actor = ActorId::parse("operator-1").value();
  request.requested_at = LogicalTick::from(tick);
  request.projected_current = CurrentSample::known(Current::from_raw(4200));
  const auto decision = engine.evaluate(request);
  if (!decision.value().eligible) {
    return Status::failure(decision.value().code, decision.value().detail);
  }
  const auto issued = engine.issue(request, adapter);
  if (!issued.ok()) {
    return issued.status();
  }
  std::cout << "issued attempt " << issued.value().id.value()
            << " disposition=" << to_token(issued.value().disposition)
            << " outcome=" << to_token(issued.value().outcome)
            << " (an acknowledgement is not an effect)\n";
  const auto verified = engine.verify_with_adapter(issued.value().id, adapter);
  if (!verified.ok()) {
    return verified.status();
  }
  std::cout << "verified attempt " << issued.value().id.value()
            << " effect=" << to_token(verified.value().effect)
            << " state-updated=" << (verified.value().state_updated ? "yes" : "no") << "\n";
  return Status::success();
}

}  // namespace

int main(int argc, char** argv) {
  const std::string store = argc > 1 ? argv[1] : "example-branch-control/site.pdustore";
  const PduId pdu = PduId::parse(kPdu).value();
  const BranchId branch = BranchId::parse(kBranch).value();

  // The example starts from nothing so that it can be run repeatedly.
  std::remove(store.c_str());
  std::remove((store + ".lock").c_str());
  auto opened = PduControlEngine::open(store, OpenMode::create_new, example_options());
  if (!opened.ok()) {
    std::cout << "open failed: " << opened.status().to_string() << "\n";
    return 1;
  }
  PduControlEngine& engine = opened.value();
  Status status = build_scenario(engine, pdu, branch);
  if (!status.ok()) {
    std::cout << "setup failed: " << status.to_string() << "\n";
    return 1;
  }
  SyntheticPduAdapter adapter = make_adapter(pdu, branch, BranchCondition::de_energized);
  report(engine, pdu, branch, "before");

  status = command_and_verify(engine, adapter, pdu, branch, CommandIntent::energize, "enable-1", 5);
  if (!status.ok()) {
    std::cout << "enable failed: " << status.to_string() << "\n";
    return 1;
  }
  report(engine, pdu, branch, "after enable");

  status = command_and_verify(engine, adapter, pdu, branch, CommandIntent::de_energize, "disable-1", 9);
  if (!status.ok()) {
    std::cout << "disable failed: " << status.to_string() << "\n";
    return 1;
  }
  report(engine, pdu, branch, "after disable");

  const Digest64 digest = engine.state_digest();
  if (!engine.close().ok()) {
    std::cout << "close failed\n";
    return 1;
  }

  auto reopened = PduControlEngine::open(store, OpenMode::open_existing, example_options());
  if (!reopened.ok()) {
    std::cout << "reopen failed: " << reopened.status().to_string() << "\n";
    return 1;
  }
  report(reopened.value(), pdu, branch, "after reopen");
  const bool stable = reopened.value().state_digest() == digest;
  std::cout << "canonical state survived the round trip: " << (stable ? "yes" : "no") << "\n";
  const Status closed = reopened.value().close();
  if (!closed.ok() || !stable) {
    return 1;
  }
  std::cout << "SYNTHETIC: this example drove a deterministic simulator, not hardware.\n";
  return 0;
}
