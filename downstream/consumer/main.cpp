// Out-of-tree consumer of the installed PDU Control package.
//
// This program is not part of the PDU Control build tree. It is configured and
// built separately against an install prefix with find_package(PDUControl), and
// it exercises the installed headers and library through a real lifecycle:
// create a durable store, register a PDU and a branch, record authority and
// telemetry, evaluate and issue a control command through a synthetic adapter,
// verify the effect, close, reopen, and confirm that the verified state and the
// attempt journal survived.

#include <cstdint>
#include <iostream>
#include <string>

#include <pdu_control/engine.hpp>
#include <pdu_control/synthetic_adapter.hpp>
#include <pdu_control/version.hpp>

int main(int argc, char** argv) {
  using namespace pdu_control;
  const std::string store = argc > 1 ? argv[1] : "consumer-store/site.pdustore";
  const PduId pdu = PduId::parse("consumer-pdu").value();
  const BranchId branch = BranchId::parse("consumer-branch").value();

  EngineOptions options;
  options.evidence.max_age_ticks = LogicalTick::from(1000);
  options.audit_capacity = 64;
  options.idempotency_window = 8;

  std::cout << "PDU Control " << version_string << " consumer\n";

  BranchCondition verified_condition = BranchCondition::unknown;
  {
    auto opened = PduControlEngine::open(store, OpenMode::create_new, options);
    if (!opened.ok()) {
      std::cout << "open failed: " << opened.status().to_string() << "\n";
      return 1;
    }
    PduControlEngine& engine = opened.value();
    if (!engine.adopt_authority_epoch(AuthorityEpoch::from(1)).ok()) {
      return 1;
    }
    PduDefinition pdu_definition;
    pdu_definition.id = pdu;
    pdu_definition.generation = PduGeneration::from(1);
    pdu_definition.lifecycle = LifecycleState::active;
    pdu_definition.registered_at = LogicalTick::from(1);
    if (!engine.register_pdu(pdu_definition).ok()) {
      return 1;
    }
    BranchDefinition branch_definition;
    branch_definition.id = branch;
    branch_definition.pdu = pdu;
    branch_definition.generation = BranchGeneration::from(1);
    branch_definition.lifecycle = LifecycleState::active;
    branch_definition.registered_at = LogicalTick::from(1);
    branch_definition.required_interlocks.push_back(InterlockId::parse("consumer-safe").value());
    branch_definition.limits.continuous_current = CurrentSample::known(Current::from_raw(16000));
    branch_definition.limits.provenance.issuer = IssuerId::parse("power-capacity").value();
    branch_definition.limits.provenance.stated_at = LogicalTick::from(1);
    if (!engine.register_branch(branch_definition).ok()) {
      return 1;
    }
    InterlockDeclaration declaration;
    declaration.id = InterlockId::parse("consumer-safe").value();
    declaration.pdu = pdu;
    declaration.branch = branch;
    declaration.declared_at = LogicalTick::from(1);
    declaration.epoch = AuthorityEpoch::from(1);
    if (!engine.declare_interlock(declaration).ok()) {
      return 1;
    }
    InterlockStatus interlock_status;
    interlock_status.id = declaration.id;
    interlock_status.state = InterlockState::satisfied;
    interlock_status.epoch = AuthorityEpoch::from(1);
    interlock_status.updated_at = LogicalTick::from(1);
    if (!engine.report_interlock(interlock_status).ok()) {
      return 1;
    }
    PermissionGrant grant;
    grant.id = AuthorityId::parse("consumer-grant").value();
    grant.issuer = IssuerId::parse("power-control-plane").value();
    grant.epoch = AuthorityEpoch::from(1);
    grant.pdu = pdu;
    grant.branch = branch;
    grant.pdu_generation = PduGeneration::from(1);
    grant.branch_generation = BranchGeneration::from(1);
    grant.actions = action_mask(PermissionAction::control_energize) |
                    action_mask(PermissionAction::control_de_energize);
    grant.issued_at = LogicalTick::from(1);
    if (!engine.record_grant(grant).ok()) {
      return 1;
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
      return 1;
    }
    if (!engine.advance_tick(LogicalTick::from(5)).ok()) {
      return 1;
    }

    SyntheticPduAdapter::Config config;
    config.id = AdapterId::parse("consumer-adapter").value();
    config.vendor = IssuerId::parse("synthetic").value();
    config.model = "synthetic-consumer";
    config.firmware = "0";
    config.pdu = pdu;
    config.branch = branch;
    config.pdu_generation = PduGeneration::from(1);
    config.branch_generation = BranchGeneration::from(1);
    config.mode = SyntheticMode::honor;
    config.initial_condition = BranchCondition::de_energized;
    config.read_at_request_instant = true;
    SyntheticPduAdapter adapter(config);

    BranchControlRequest request;
    request.key = IdempotencyKey::parse("consumer-key").value();
    request.pdu = pdu;
    request.branch = branch;
    request.pdu_generation = PduGeneration::from(1);
    request.branch_generation = BranchGeneration::from(1);
    request.epoch = AuthorityEpoch::from(1);
    request.intent = CommandIntent::energize;
    request.actor = ActorId::parse("consumer").value();
    request.requested_at = LogicalTick::from(5);
    const auto decision = engine.evaluate(request);
    if (!decision.value().eligible) {
      std::cout << "the request was refused: " << decision.value().detail << "\n";
      return 1;
    }
    const auto issued = engine.issue(request, adapter);
    if (!issued.ok()) {
      std::cout << "issue failed: " << issued.status().to_string() << "\n";
      return 1;
    }
    std::cout << "attempt " << issued.value().id.value()
              << " disposition=" << to_token(issued.value().disposition) << "\n";
    const auto verified = engine.verify_with_adapter(issued.value().id, adapter);
    if (!verified.ok()) {
      std::cout << "verify failed: " << verified.status().to_string() << "\n";
      return 1;
    }
    std::cout << "effect=" << to_token(verified.value().effect)
              << " state-updated=" << (verified.value().state_updated ? "yes" : "no") << "\n";
    const auto snapshot = engine.inspect_branch(pdu, branch);
    if (!snapshot.ok() || !snapshot.value().verified.established()) {
      std::cout << "the branch has no verified condition\n";
      return 1;
    }
    verified_condition = snapshot.value().verified.condition.value();
    std::cout << "state-digest=" << engine.state_digest().to_hex() << "\n";
    const Status closed = engine.close();
    if (!closed.ok()) {
      std::cout << "close failed: " << closed.to_string() << "\n";
      return 1;
    }
  }

  auto reopened = PduControlEngine::open(store, OpenMode::open_existing, options);
  if (!reopened.ok()) {
    std::cout << "reopen failed: " << reopened.status().to_string() << "\n";
    return 1;
  }
  PduControlEngine& engine = reopened.value();
  const auto snapshot = engine.inspect_branch(pdu, branch);
  if (!snapshot.ok()) {
    return 1;
  }
  std::cout << "after reopen: attempts=" << engine.status().attempt_count
            << " verified=" << to_token(snapshot.value().verified.condition.state())
            << " incarnation=" << engine.incarnation().value() << "\n";
  const bool survived = snapshot.value().verified.established() &&
                        snapshot.value().verified.condition.value() == verified_condition &&
                        engine.status().attempt_count == 1;
  const Status closed = engine.close();
  if (!closed.ok() || !survived) {
    std::cout << "the installed package did not preserve the verified state\n";
    return 1;
  }
  std::cout << "the installed package preserved the verified state and the attempt journal\n";
  std::cout << "SYNTHETIC: the adapter was a deterministic simulator; no hardware was involved.\n";
  return 0;
}
