// Example: the effect exists, but the telemetry is stale.
//
// The adapter applies the command and then keeps reporting readings stamped at
// an instant that never advances. Because a reading taken before the command can
// never be evidence of its effect, verification refuses with evidence_stale.
// Recording a fresh reading as a revalidation is what makes verification
// possible, and the runtime never promotes the old reading back to fresh.

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
  observation.source = SourceId::parse("stuck-telemetry").value();
  observation.sequence = SequenceNumber::from(1);
  observation.taken_at = Instant::logical(LogicalTick::from(1));
  observation.quality = EvidenceQuality::good;
  observation.condition = BranchCondition::de_energized;
  const auto recorded = engine.record_observation(observation);
  return recorded.ok() ? Status::success() : recorded.status();
}

}  // namespace

int main(int argc, char** argv) {
  const std::string store = argc > 1 ? argv[1] : "example-revalidation/site.pdustore";
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
  config.id = AdapterId::parse("frozen-adapter").value();
  config.vendor = IssuerId::parse("synthetic").value();
  config.model = "synthetic-frozen";
  config.firmware = "0";
  config.pdu = pdu;
  config.branch = branch;
  config.pdu_generation = PduGeneration::from(1);
  config.branch_generation = BranchGeneration::from(1);
  config.mode = SyntheticMode::frozen_readings;
  config.initial_condition = BranchCondition::de_energized;
  config.reading_taken_at = Instant::logical(LogicalTick::from(1));
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
  std::cout << "the adapter applied the command: "
            << to_token(adapter.reported_condition()) << "\n";

  const auto stale = engine.verify_with_adapter(issued.value().id, adapter);
  if (!stale.ok()) {
    std::cout << "verify failed: " << stale.status().to_string() << "\n";
    return 1;
  }
  std::cout << "verification code:   " << to_token(stale.value().code) << "\n";
  std::cout << "verification detail: " << stale.value().detail << "\n";
  expect(stale.value().code == StatusCode::evidence_stale,
         "stale telemetry is refused rather than accepted as proof");
  expect(!stale.value().state_updated, "no state was updated from stale evidence");
  const auto before = engine.inspect_branch(pdu, branch);
  expect(before.ok() && !before.value().verified.established(),
         "the branch still has no established verified condition");
  expect(before.ok() && before.value().unresolved_attempt,
         "the attempt is still open, because its effect is not established");

  if (!engine.advance_tick(LogicalTick::from(7)).ok()) {
    return 1;
  }
  TelemetryObservation fresh;
  fresh.pdu = pdu;
  fresh.branch = branch;
  fresh.pdu_generation = PduGeneration::from(1);
  fresh.branch_generation = BranchGeneration::from(1);
  fresh.source = SourceId::parse("field-telemetry").value();
  fresh.sequence = SequenceNumber::from(50);
  fresh.taken_at = Instant::logical(LogicalTick::from(7));
  fresh.quality = EvidenceQuality::good;
  fresh.condition = BranchCondition::energized;
  const auto revalidated = engine.revalidate(pdu, branch, fresh);
  if (!revalidated.ok()) {
    std::cout << "revalidate failed: " << revalidated.status().to_string() << "\n";
    return 1;
  }
  std::cout << "revalidated with observation " << revalidated.value().value() << "\n";

  const auto verified = engine.verify(issued.value().id);
  if (!verified.ok()) {
    std::cout << "verify failed: " << verified.status().to_string() << "\n";
    return 1;
  }
  std::cout << "verification effect: " << to_token(verified.value().effect) << "\n";
  expect(verified.value().effect == EffectState::effective,
         "the effect is established once fresh evidence exists");
  expect(verified.value().state_updated, "the verified state was updated from the fresh reading");
  const auto after = engine.inspect_branch(pdu, branch);
  expect(after.ok() && after.value().verified.condition.value() == BranchCondition::energized,
         "the verified condition is the energized condition");
  expect(after.ok() && !after.value().unresolved_attempt, "the attempt is no longer unresolved");
  expect(engine.close().ok(), "the store closed cleanly");
  std::cout << "SYNTHETIC: this example drove a deterministic simulator, not hardware.\n";
  if (failures != 0) {
    std::cout << failures << " expectation(s) failed\n";
    return 1;
  }
  std::cout << "stale telemetry never became proof, and revalidation is what changed that\n";
  return 0;
}
