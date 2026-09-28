// Example: an acknowledgement that produces no effect.
//
// The adapter acknowledges every command and changes nothing. The runtime must
// report the acknowledgement as an acknowledgement and the effect as whatever
// fresh evidence establishes -- here, that the requested condition is absent.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "pdu_control/engine.hpp"
#include "pdu_control/synthetic_adapter.hpp"

using namespace pdu_control;

namespace {

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

Status build_scenario(PduControlEngine& engine, const PduId& pdu, const BranchId& branch) {
  Status status = engine.adopt_authority_epoch(AuthorityEpoch::from(1));
  if (!status.ok()) {
    return status;
  }
  PduDefinition pdu_definition;
  pdu_definition.id = pdu;
  pdu_definition.generation = PduGeneration::from(1);
  pdu_definition.lifecycle = LifecycleState::active;
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
  branch_definition.registered_at = LogicalTick::from(1);
  branch_definition.limits.continuous_current = CurrentSample::known(Current::from_raw(16000));
  branch_definition.limits.provenance.issuer = IssuerId::parse("power-capacity").value();
  branch_definition.limits.provenance.stated_at = LogicalTick::from(1);
  status = engine.register_branch(branch_definition);
  if (!status.ok()) {
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
  grant.actions = action_mask(PermissionAction::control_energize);
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
  observation.source = SourceId::parse("field").value();
  observation.sequence = SequenceNumber::from(1);
  observation.taken_at = Instant::logical(LogicalTick::from(1));
  observation.quality = EvidenceQuality::good;
  observation.condition = BranchCondition::de_energized;
  const auto recorded = engine.record_observation(observation);
  return recorded.ok() ? Status::success() : recorded.status();
}

}  // namespace

int main(int argc, char** argv) {
  const std::string store = argc > 1 ? argv[1] : "example-ack-without-effect/site.pdustore";
  const PduId pdu = PduId::parse("site-pdu-1").value();
  const BranchId branch = BranchId::parse("row-a-branch-1").value();
  // The example starts from nothing so that it can be run repeatedly.
  std::remove(store.c_str());
  std::remove((store + ".lock").c_str());
  auto opened = PduControlEngine::open(store, OpenMode::create_new, example_options());
  if (!opened.ok()) {
    std::cout << "open failed: " << opened.status().to_string() << "\n";
    return 1;
  }
  PduControlEngine& engine = opened.value();
  const Status setup = build_scenario(engine, pdu, branch);
  if (!setup.ok()) {
    std::cout << "setup failed: " << setup.to_string() << "\n";
    return 1;
  }

  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("ack-only-adapter").value();
  config.vendor = IssuerId::parse("synthetic").value();
  config.model = "synthetic-ack-only";
  config.firmware = "0";
  config.pdu = pdu;
  config.branch = branch;
  config.pdu_generation = PduGeneration::from(1);
  config.branch_generation = BranchGeneration::from(1);
  config.mode = SyntheticMode::ack_without_effect;
  config.initial_condition = BranchCondition::de_energized;
  config.read_at_request_instant = true;
  SyntheticPduAdapter adapter(config);

  if (!engine.advance_tick(LogicalTick::from(4)).ok()) {
    return 1;
  }
  BranchControlRequest request;
  request.key = IdempotencyKey::parse("enable-1").value();
  request.pdu = pdu;
  request.branch = branch;
  request.pdu_generation = PduGeneration::from(1);
  request.branch_generation = BranchGeneration::from(1);
  request.epoch = AuthorityEpoch::from(1);
  request.intent = CommandIntent::energize;
  request.actor = ActorId::parse("operator-1").value();
  request.requested_at = LogicalTick::from(4);
  const auto issued = engine.issue(request, adapter);
  if (!issued.ok()) {
    std::cout << "issue failed: " << issued.status().to_string() << "\n";
    return 1;
  }
  std::cout << "adapter disposition: " << to_token(issued.value().disposition) << "\n";
  std::cout << "attempt outcome:     " << to_token(issued.value().outcome) << "\n";
  std::cout << "attempt effect:      " << to_token(issued.value().effect) << "\n";
  expect(issued.value().disposition == AdapterDisposition::acknowledged,
         "the adapter acknowledged the command");
  expect(issued.value().outcome == AttemptOutcome::acknowledged,
         "the acknowledgement is recorded as an acknowledgement, not as success");
  expect(issued.value().effect == EffectState::pending,
         "no effect is claimed at the moment of acknowledgement");

  const auto verified = engine.verify_with_adapter(issued.value().id, adapter);
  if (!verified.ok()) {
    std::cout << "verify failed: " << verified.status().to_string() << "\n";
    return 1;
  }
  std::cout << "verification effect: " << to_token(verified.value().effect) << "\n";
  std::cout << "verification detail: " << verified.value().detail << "\n";
  expect(verified.value().effect == EffectState::ineffective,
         "fresh evidence establishes that the requested condition is absent");
  expect(verified.value().state_updated, "the verified state was updated from evidence");

  const auto snapshot = engine.inspect_branch(pdu, branch);
  expect(snapshot.ok() &&
             snapshot.value().commanded.condition.value() == BranchCondition::energized,
         "the desired state still records what the operator asked for");
  expect(snapshot.ok() &&
             snapshot.value().verified.condition.value() == BranchCondition::de_energized,
         "the verified state records what the device actually does");
  const auto record = engine.attempt(issued.value().id);
  expect(record.ok() && record.value().outcome == AttemptOutcome::observed_ineffective,
         "the attempt is closed as observed_ineffective");
  expect(engine.close().ok(), "the store closed cleanly");
  std::cout << "SYNTHETIC: this example drove a deterministic simulator, not hardware.\n";
  if (failures != 0) {
    std::cout << failures << " expectation(s) failed\n";
    return 1;
  }
  std::cout << "an acknowledgement was never mistaken for an effect\n";
  return 0;
}
