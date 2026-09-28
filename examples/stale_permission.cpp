// Example: refused stale authority.
//
// Every refusal below is produced by the library. The example asserts the exact
// status code it expects and asserts that the adapter was never called, so a
// regression that let a stale request through would fail this program rather
// than merely print something different.

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
  grant.actions = action_mask(PermissionAction::control_energize) |
                  action_mask(PermissionAction::control_de_energize);
  grant.issued_at = LogicalTick::from(1);
  grant.not_after = LogicalTick::from(20);
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

BranchControlRequest request_for(const PduId& pdu, const BranchId& branch, const std::string& key,
                                 LogicalTick tick) {
  BranchControlRequest request;
  request.key = IdempotencyKey::parse(key).value();
  request.pdu = pdu;
  request.branch = branch;
  request.pdu_generation = PduGeneration::from(1);
  request.branch_generation = BranchGeneration::from(1);
  request.epoch = AuthorityEpoch::from(1);
  request.intent = CommandIntent::energize;
  request.actor = ActorId::parse("operator-1").value();
  request.requested_at = tick;
  return request;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string store = argc > 1 ? argv[1] : "example-stale-permission/site.pdustore";
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
  config.id = AdapterId::parse("example-adapter").value();
  config.vendor = IssuerId::parse("synthetic").value();
  config.model = "synthetic-example";
  config.firmware = "0";
  config.pdu = pdu;
  config.branch = branch;
  config.pdu_generation = PduGeneration::from(1);
  config.branch_generation = BranchGeneration::from(1);
  config.mode = SyntheticMode::honor;
  config.initial_condition = BranchCondition::de_energized;
  config.read_at_request_instant = true;
  SyntheticPduAdapter adapter(config);

  // (a) an epoch the runtime no longer honours.
  if (!engine.advance_tick(LogicalTick::from(4)).ok()) {
    return 1;
  }
  BranchControlRequest stale_epoch = request_for(pdu, branch, "k-epoch", LogicalTick::from(4));
  stale_epoch.epoch = AuthorityEpoch::from(7);
  const auto epoch_result = engine.issue(stale_epoch, adapter);
  expect(!epoch_result.ok() && epoch_result.code() == StatusCode::permission_stale,
         "a request planned in another authority epoch is refused with permission_stale");
  std::cout << "   code=" << to_token(epoch_result.code()) << " detail="
            << epoch_result.status().message() << "\n";

  // (b) an older device generation.
  BranchControlRequest stale_device = request_for(pdu, branch, "k-device", LogicalTick::from(4));
  stale_device.branch_generation = BranchGeneration::from(2);
  const auto device_result = engine.issue(stale_device, adapter);
  expect(!device_result.ok() && device_result.code() == StatusCode::generation_mismatch,
         "a request planned against an older branch generation is refused");
  std::cout << "   code=" << to_token(device_result.code()) << " detail="
            << device_result.status().message() << "\n";

  // (c) a grant that has expired.
  if (!engine.advance_tick(LogicalTick::from(25)).ok()) {
    return 1;
  }
  const auto expired_result =
      engine.issue(request_for(pdu, branch, "k-expired", LogicalTick::from(25)), adapter);
  expect(!expired_result.ok() && expired_result.code() == StatusCode::permission_stale,
         "a request whose only grant has expired is refused");
  std::cout << "   code=" << to_token(expired_result.code()) << " detail="
            << expired_result.status().message() << "\n";

  // (d) a revoked grant.
  if (!engine.revoke_grant(AuthorityId::parse("grant-1").value(), AuthorityEpoch::from(1),
                           LogicalTick::from(26))
           .ok()) {
    return 1;
  }
  const auto revoked_result =
      engine.issue(request_for(pdu, branch, "k-revoked", LogicalTick::from(26)), adapter);
  expect(!revoked_result.ok() && revoked_result.code() == StatusCode::permission_stale,
         "a request whose grant was revoked is refused");
  std::cout << "   code=" << to_token(revoked_result.code()) << " detail="
            << revoked_result.status().message() << "\n";

  expect(adapter.execute_count() == 0, "the adapter was never invoked for any refused request");
  const auto snapshot = engine.inspect_branch(pdu, branch);
  expect(snapshot.ok() && !snapshot.value().commanded.condition.has_value(),
         "the authoritative desired state never moved");
  expect(snapshot.ok() && !snapshot.value().verified.established(),
         "the authoritative verified state never moved");
  expect(snapshot.ok() && !snapshot.value().unresolved_attempt,
         "no unresolved attempt was left behind");
  const auto status = engine.status();
  expect(status.refusal_count == 4, "exactly the four refusals were counted");
  expect(status.dispatch_count == 0, "nothing was dispatched");
  expect(engine.close().ok(), "the store closed cleanly");
  std::cout << "SYNTHETIC: this example drove a deterministic simulator, not hardware.\n";
  if (failures != 0) {
    std::cout << failures << " expectation(s) failed\n";
    return 1;
  }
  std::cout << "every stale-authority path was refused exactly as documented\n";
  return 0;
}
