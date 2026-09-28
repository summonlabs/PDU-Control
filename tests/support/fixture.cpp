#include "fixture.hpp"

#include <cstdint>
#include <cstdlib>
#include <string>

#include "detail/file_io.hpp"
#include "detail/process.hpp"
#include "pdu_control/synthetic_adapter.hpp"

namespace pdu_test {
namespace {

template <typename Tag>
Identifier<Tag> parse_id(const std::string& text) {
  const auto parsed = Identifier<Tag>::parse(text);
  return parsed.ok() ? parsed.value() : Identifier<Tag>::unset();
}

}  // namespace

Scenario make_scenario(const std::string& suffix, std::uint64_t start_tick) {
  Scenario scenario;
  scenario.pdu = parse_id<PduIdTag>("pdu-" + suffix);
  scenario.pdu_generation = PduGeneration::from(1);
  scenario.branch = parse_id<BranchIdTag>("branch-" + suffix);
  scenario.branch_generation = BranchGeneration::from(1);
  scenario.interlock = parse_id<InterlockIdTag>("interlock-" + suffix);
  scenario.grant = parse_id<AuthorityIdTag>("grant-" + suffix);
  scenario.issuer = parse_id<IssuerIdTag>("test-authority");
  scenario.epoch = AuthorityEpoch::from(1);
  scenario.source = parse_id<SourceIdTag>("test-source");
  scenario.continuous_limit = Current::from_raw(16000);
  scenario.start_tick = LogicalTick::from(start_tick);
  return scenario;
}

EngineOptions base_options() {
  EngineOptions options;
  options.evidence.max_age_ticks = LogicalTick::from(1000);
  options.evidence.require_good_quality = true;
  options.idempotency_window = 16;
  options.audit_capacity = 64;
  return options;
}

Status apply_scenario(PduControlEngine& engine, const Scenario& scenario,
                      LifecycleState lifecycle) {
  Status status = engine.adopt_authority_epoch(scenario.epoch);
  if (!status.ok()) {
    return status;
  }

  PduDefinition pdu;
  pdu.id = scenario.pdu;
  pdu.generation = scenario.pdu_generation;
  pdu.lifecycle = LifecycleState::active;
  pdu.label = "test pdu";
  pdu.registered_at = scenario.start_tick;
  status = engine.register_pdu(pdu);
  if (!status.ok()) {
    return status;
  }

  BranchDefinition branch;
  branch.id = scenario.branch;
  branch.pdu = scenario.pdu;
  branch.generation = scenario.branch_generation;
  branch.lifecycle = lifecycle;
  branch.label = "test branch";
  branch.registered_at = scenario.start_tick;
  branch.required_interlocks.push_back(scenario.interlock);
  branch.limits.continuous_current = CurrentSample::known(scenario.continuous_limit);
  branch.limits.provenance.issuer = scenario.issuer;
  branch.limits.provenance.authority = scenario.grant;
  branch.limits.provenance.epoch = scenario.epoch;
  branch.limits.provenance.stated_at = scenario.start_tick;
  branch.limits.revision = StateRevision::from(1);
  status = engine.register_branch(branch);
  if (!status.ok()) {
    return status;
  }

  InterlockDeclaration declaration;
  declaration.id = scenario.interlock;
  declaration.pdu = scenario.pdu;
  declaration.branch = scenario.branch;
  declaration.klass = ObligationClass::protected_obligation;
  declaration.declared_at = scenario.start_tick;
  declaration.epoch = scenario.epoch;
  status = engine.declare_interlock(declaration);
  if (!status.ok()) {
    return status;
  }

  InterlockStatus interlock_status;
  interlock_status.id = scenario.interlock;
  interlock_status.state = InterlockState::satisfied;
  interlock_status.epoch = scenario.epoch;
  interlock_status.updated_at = scenario.start_tick;
  status = engine.report_interlock(interlock_status);
  if (!status.ok()) {
    return status;
  }

  PermissionGrant grant;
  grant.id = scenario.grant;
  grant.issuer = scenario.issuer;
  grant.epoch = scenario.epoch;
  grant.pdu = scenario.pdu;
  grant.branch = scenario.branch;
  grant.pdu_generation = scenario.pdu_generation;
  grant.branch_generation = scenario.branch_generation;
  grant.actions = action_mask(PermissionAction::control_energize) |
                  action_mask(PermissionAction::control_de_energize) |
                  action_mask(PermissionAction::lifecycle_service) |
                  action_mask(PermissionAction::lifecycle_recovery) |
                  action_mask(PermissionAction::lifecycle_administrative) |
                  action_mask(PermissionAction::maintenance_override);
  grant.issued_at = scenario.start_tick;
  status = engine.record_grant(grant);
  if (!status.ok()) {
    return status;
  }

  const auto observation = make_observation(scenario, scenario.start_tick, 1,
                                            BranchCondition::de_energized);
  const auto recorded = engine.record_observation(observation);
  if (!recorded.ok()) {
    return recorded.status();
  }
  return Status::success();
}

TelemetryObservation make_observation(const Scenario& scenario, LogicalTick tick,
                                      std::uint64_t sequence, BranchCondition condition,
                                      EvidenceQuality quality) {
  TelemetryObservation observation;
  observation.pdu = scenario.pdu;
  observation.branch = scenario.branch;
  observation.pdu_generation = scenario.pdu_generation;
  observation.branch_generation = scenario.branch_generation;
  observation.source = scenario.source;
  observation.sequence = SequenceNumber::from(sequence);
  observation.taken_at = Instant::logical(tick);
  observation.quality = quality;
  observation.condition = condition;
  return observation;
}

TempDir::TempDir(const std::string& name) {
  path_ = "scratch/" + name + "-" + std::to_string(::pdu_control::detail::current_process_id());
  (void)::pdu_control::detail::ensure_parent_directory(path_ + "/placeholder");
}

TempDir::~TempDir() {
  // The scratch tree is removed through the operating system, bounded to the
  // directory this object created.
  std::string command;
#ifdef _WIN32
  command = "cmd /c rmdir /s /q \"" + path_ + "\" >nul 2>&1";
#else
  command = "rm -rf \"" + path_ + "\"";
#endif
  (void)std::system(command.c_str());
}

Status TempDir::file(const std::string& leaf, std::string& out) const {
  if (leaf.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a scratch file needs a name");
  }
  if (leaf.find('/') != std::string::npos || leaf.find('\\') != std::string::npos ||
      leaf == "." || leaf == "..") {
    return Status::failure(StatusCode::path_invalid,
                           "a scratch file name must not contain a path separator or be a "
                           "traversal component");
  }
  out = path_ + "/" + leaf;
  return Status::success();
}

std::string TempDir::store_path() const { return path_ + "/site.pdustore"; }

}  // namespace pdu_test
