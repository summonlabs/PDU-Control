#include "pdu_control/engine.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "detail/access.hpp"
#include "detail/records.hpp"
#include "detail/serialization.hpp"
#include "detail/store_file.hpp"
#include "pdu_control/version.hpp"

namespace pdu_control {
namespace {

/// The instant an audit entry is stamped with when the caller never supplied a
/// wall clock. The library never reads a clock itself.
Instant audit_instant(const detail::ModelState& model) { return model.wall; }

std::string truncate_bytes(std::string text, std::size_t limit) {
  if (text.size() <= limit) {
    return text;
  }
  text.resize(limit);
  text.append("...");
  return text;
}

/// Effective freshness of a stored observation at a given logical instant.
///
/// The stored freshness records what was known when the observation was
/// accepted; this recomputes it against the current tick. A recovered
/// observation is never fresh, and an observation that carries no logical tick
/// cannot be aged at all and is therefore reported as unknown rather than
/// assumed to be current.
FreshnessState effective_freshness(const TelemetryObservation& observation, LogicalTick now,
                                   const EvidencePolicy& policy) {
  if (observation.freshness == FreshnessState::recovered) {
    return FreshnessState::recovered;
  }
  if (observation.freshness == FreshnessState::unknown) {
    return FreshnessState::unknown;
  }
  if (!observation.taken_at.is_logical()) {
    return FreshnessState::unknown;
  }
  if (observation.taken_at.tick > now) {
    // An observation from the future is contradictory, not fresh.
    return FreshnessState::stale;
  }
  const auto age = now.value() - observation.taken_at.tick.value();
  if (age > policy.max_age_ticks.value()) {
    return FreshnessState::stale;
  }
  return FreshnessState::fresh;
}

bool quality_usable(EvidenceQuality quality, const EvidencePolicy& policy) {
  if (!policy.require_good_quality) {
    return quality != EvidenceQuality::bad;
  }
  return quality == EvidenceQuality::good;
}

/// The instant an observation is considered accepted at: the later of the
/// engine's current tick and the tick the source measured at.
LogicalTick acceptance_tick(const TelemetryObservation& observation, LogicalTick now) {
  if (observation.taken_at.is_logical() && observation.taken_at.tick > now) {
    return observation.taken_at.tick;
  }
  return now;
}

Digest64 request_digest(const BranchControlRequest& request) {
  DigestBuilder builder;
  builder.update(request.key.value());
  builder.update(request.pdu.value());
  builder.update(request.branch.value());
  builder.update_u64(request.pdu_generation.value());
  builder.update_u64(request.branch_generation.value());
  builder.update_u64(request.planned_revision.value());
  builder.update_u64(request.epoch.value());
  builder.update_byte(static_cast<std::uint8_t>(request.intent));
  builder.update(request.actor.value());
  // The instant the caller asked at is deliberately excluded: a retry after a
  // lost response is the same request, and it must replay rather than conflict.
  builder.update_byte(static_cast<std::uint8_t>(request.projected_current.state()));
  if (request.projected_current.has_value()) {
    builder.update_i64(request.projected_current.value().raw());
  }
  return builder.finish();
}

/// Ranking used to pick the single reason reported when several grants could
/// have applied. Lower is more specific, so the caller learns the narrowest
/// reason available rather than an arbitrary one.
int permission_rank(PermissionVerdict verdict) {
  switch (verdict) {
    case PermissionVerdict::usable:
      return 0;
    case PermissionVerdict::action_missing:
      return 1;
    case PermissionVerdict::generation_mismatch:
      return 2;
    case PermissionVerdict::scope_mismatch:
      return 3;
    case PermissionVerdict::expired:
      return 4;
    case PermissionVerdict::revoked:
      return 5;
    case PermissionVerdict::stale_epoch:
      return 6;
    case PermissionVerdict::malformed:
      return 7;
    case PermissionVerdict::missing:
      return 8;
  }
  return 8;
}

int override_rank(OverrideVerdict verdict) {
  switch (verdict) {
    case OverrideVerdict::usable:
      return 0;
    case OverrideVerdict::generation_mismatch:
      return 1;
    case OverrideVerdict::scope_mismatch:
      return 2;
    case OverrideVerdict::expired:
      return 3;
    case OverrideVerdict::revoked:
      return 4;
    case OverrideVerdict::stale_epoch:
      return 5;
    case OverrideVerdict::missing:
      return 6;
  }
  return 6;
}

/// True for an attempt whose effect may still be established.
bool verifiable(AttemptOutcome outcome) {
  switch (outcome) {
    case AttemptOutcome::dispatched:
    case AttemptOutcome::acknowledged:
    case AttemptOutcome::rejected:
    case AttemptOutcome::unavailable:
    case AttemptOutcome::unanswered:
    case AttemptOutcome::recovery_required:
    case AttemptOutcome::verified_effective:
    case AttemptOutcome::observed_ineffective:
      return true;
    case AttemptOutcome::refused:
    case AttemptOutcome::superseded:
    case AttemptOutcome::cancelled:
      return false;
  }
  return false;
}

/// True for an attempt that can still be closed by an explicit resolution.
bool resolvable(AttemptOutcome outcome) {
  return outcome == AttemptOutcome::dispatched || outcome == AttemptOutcome::acknowledged ||
         outcome == AttemptOutcome::recovery_required;
}

Status validate_observation_shape(const TelemetryObservation& observation) {
  if (observation.pdu.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an observation requires a PDU");
  }
  if (observation.branch.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an observation requires a branch");
  }
  if (observation.source.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an observation requires a source");
  }
  if (!observation.sequence.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "an observation requires a nonzero source sequence");
  }
  if (!observation.pdu_generation.is_set() || !observation.branch_generation.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "an observation requires the device generations it was taken against");
  }
  if (observation.current.has_value() && observation.current.value().is_negative()) {
    return Status::failure(StatusCode::out_of_range, "an observed current must not be negative");
  }
  if (observation.power.has_value() && observation.power.value().is_negative()) {
    return Status::failure(StatusCode::out_of_range, "an observed power must not be negative");
  }
  return validate_instant(observation.taken_at);
}

ModelBounds normalize_bounds(const ModelBounds& bounds) {
  ModelBounds result = bounds;
  if (result.max_pdus == 0) {
    result.max_pdus = 1;
  }
  if (result.max_branches_per_pdu == 0) {
    result.max_branches_per_pdu = 1;
  }
  if (result.max_attempt_journal == 0) {
    result.max_attempt_journal = 1;
  }
  if (result.max_idempotency_window == 0) {
    result.max_idempotency_window = 1;
  }
  if (result.max_audit_entries < 16) {
    result.max_audit_entries = 16;
  }
  return result;
}

EngineOptions normalize_options(const EngineOptions& options) {
  EngineOptions result = options;
  result.bounds = normalize_bounds(options.bounds);
  result.idempotency_window = std::max<std::size_t>(1, options.idempotency_window);
  result.idempotency_window = std::min(result.idempotency_window, result.bounds.max_idempotency_window);
  result.audit_capacity = std::max<std::size_t>(16, options.audit_capacity);
  result.audit_capacity = std::min(result.audit_capacity, result.bounds.max_audit_entries);
  // The idempotency window may never outlive the journal it points into, because
  // an entry that names an evicted attempt is not a state this runtime can hold.
  result.bounds.max_attempt_journal =
      std::max(result.bounds.max_attempt_journal, result.idempotency_window);
  return result;
}

TelemetryView make_view(const detail::ModelState& model, const EvidencePolicy& policy,
                        const TelemetryObservation& observation) {
  TelemetryView view;
  view.present = true;
  view.id = observation.id;
  view.source = observation.source;
  view.sequence = observation.sequence;
  view.taken_at = observation.taken_at;
  view.received_at = observation.received_at;
  view.accepted_tick = observation.accepted_tick;
  view.quality = observation.quality;
  view.freshness = effective_freshness(observation, model.current_tick, policy);
  view.condition = observation.condition;
  view.current = observation.current;
  view.voltage = observation.voltage;
  view.power = observation.power;
  if (observation.taken_at.is_logical() && observation.taken_at.tick <= model.current_tick) {
    view.age_ticks = LogicalTick::from(model.current_tick.value() - observation.taken_at.tick.value());
    view.age_known = true;
  }
  return view;
}

/// Builds the immutable branch snapshot handed out by the inspection API.
BranchSnapshot build_snapshot(const detail::ModelState& model, const detail::BranchRecord& branch,
                              const detail::PduRecord& pdu, const EvidencePolicy& policy,
                              std::vector<InterlockView> interlocks,
                              const InterlockSummary& summary, const PermissionView& permission) {
  BranchSnapshot snapshot;
  snapshot.id = branch.definition.id;
  snapshot.pdu = branch.definition.pdu;
  snapshot.generation = branch.definition.generation;
  snapshot.pdu_generation = pdu.definition.generation;
  snapshot.revision = branch.state.revision;
  snapshot.lifecycle = branch.state.lifecycle;
  snapshot.pdu_lifecycle = pdu.state.lifecycle;
  snapshot.label = branch.definition.label;
  const ControlScope branch_scope = control_scope(branch.state.lifecycle);
  const ControlScope pdu_scope = control_scope(pdu.state.lifecycle);
  snapshot.control_scope = branch_scope == ControlScope::forbidden ? branch_scope : pdu_scope;
  snapshot.commanded = branch.state.commanded;
  snapshot.verified = branch.state.verified;
  if (branch.observations.has_current) {
    snapshot.observation = make_view(model, policy, branch.observations.current);
  }
  snapshot.limits = branch.definition.limits;
  snapshot.interlocks = std::move(interlocks);
  snapshot.interlocks_summary = summary;
  snapshot.permission = permission;
  snapshot.last_attempt = branch.state.last_attempt;
  snapshot.unresolved_attempt = branch.state.unresolved_attempt;
  return snapshot;
}

}  // namespace

struct PduControlEngine::Impl {
  EngineOptions options;
  detail::ModelState model;
  std::unique_ptr<detail::StoreFile> store;
  bool open{false};
  bool durable{false};
  bool read_only{false};
  std::string path;
  std::uint64_t refusal_count{0};
  std::uint64_t dispatch_count{0};
  std::uint64_t verification_count{0};

  // -- lookups --------------------------------------------------------------

  detail::PduRecord* find_pdu(const PduId& id) {
    for (detail::PduRecord& record : model.pdus) {
      if (record.definition.id == id) {
        return &record;
      }
    }
    return nullptr;
  }
  const detail::PduRecord* find_pdu(const PduId& id) const {
    for (const detail::PduRecord& record : model.pdus) {
      if (record.definition.id == id) {
        return &record;
      }
    }
    return nullptr;
  }
  detail::BranchRecord* find_branch(const PduId& pdu, const BranchId& branch) {
    for (detail::BranchRecord& record : model.branches) {
      if (record.definition.id == branch && record.definition.pdu == pdu) {
        return &record;
      }
    }
    return nullptr;
  }
  const detail::BranchRecord* find_branch(const PduId& pdu, const BranchId& branch) const {
    for (const detail::BranchRecord& record : model.branches) {
      if (record.definition.id == branch && record.definition.pdu == pdu) {
        return &record;
      }
    }
    return nullptr;
  }
  detail::BranchRecord* find_branch_any(const BranchId& branch) {
    for (detail::BranchRecord& record : model.branches) {
      if (record.definition.id == branch) {
        return &record;
      }
    }
    return nullptr;
  }
  const detail::BranchRecord* find_branch_any(const BranchId& branch) const {
    for (const detail::BranchRecord& record : model.branches) {
      if (record.definition.id == branch) {
        return &record;
      }
    }
    return nullptr;
  }
  AttemptRecord* find_attempt(const AttemptId& id) {
    for (AttemptRecord& record : model.attempts) {
      if (record.id == id) {
        return &record;
      }
    }
    return nullptr;
  }
  const AttemptRecord* find_attempt(const AttemptId& id) const {
    for (const AttemptRecord& record : model.attempts) {
      if (record.id == id) {
        return &record;
      }
    }
    return nullptr;
  }
  detail::GrantRecord* find_grant(const AuthorityId& id) {
    for (detail::GrantRecord& record : model.grants) {
      if (record.grant.id == id) {
        return &record;
      }
    }
    return nullptr;
  }
  detail::OverrideRecord* find_override(const AuthorityId& id) {
    for (detail::OverrideRecord& record : model.overrides) {
      if (record.value.id == id) {
        return &record;
      }
    }
    return nullptr;
  }
  detail::InterlockRecord* find_interlock(const InterlockId& id) {
    for (detail::InterlockRecord& record : model.interlocks) {
      if (record.declaration.id == id) {
        return &record;
      }
    }
    return nullptr;
  }
  const detail::InterlockRecord* find_interlock(const InterlockId& id) const {
    for (const detail::InterlockRecord& record : model.interlocks) {
      if (record.declaration.id == id) {
        return &record;
      }
    }
    return nullptr;
  }

  // -- unresolved-attempt bookkeeping ---------------------------------------

  /// True when some *other* attempt on the branch still has no established
  /// effect.
  ///
  /// A branch is blocked while any command sent to it is unaccounted for, so the
  /// flag may only be cleared when the last such attempt is closed. Verifying an
  /// old attempt says nothing about a newer one, and clearing the flag there
  /// would let a second command be sent to a branch whose first command is still
  /// unexplained.
  bool branch_has_other_unresolved(const PduId& pdu, const BranchId& branch,
                                   AttemptId except) const {
    for (const AttemptRecord& other : model.attempts) {
      if (other.id == except || other.pdu != pdu || other.branch != branch) {
        continue;
      }
      if (is_unresolved(other.outcome)) {
        return true;
      }
    }
    return false;
  }

  /// Recomputes the branch's blocking flag from the journal after one attempt
  /// has been closed. The flag ends up set exactly when some other attempt on the
  /// branch is still unresolved.
  void settle_branch(detail::BranchRecord& branch, AttemptId closed) {
    const bool blocked =
        branch_has_other_unresolved(branch.definition.pdu, branch.definition.id, closed);
    branch.state.unresolved_attempt = blocked;
    if (!blocked) {
      branch.state.unresolved_since = LogicalTick{};
    }
  }

  // -- guards, publication, audit -------------------------------------------

  Status ensure_writable() const {
    if (!open) {
      return Status::failure(StatusCode::store_io, "the engine is not open");
    }
    if (read_only) {
      return Status::failure(StatusCode::store_locked,
                             "the engine was opened read-only and refuses mutation");
    }
    return Status::success();
  }

  Status publish() {
    if (!durable) {
      return Status::success();
    }
    if (store == nullptr) {
      return Status::failure(StatusCode::internal, "a durable engine has no store");
    }
    const Status status = store->publish(model);
    if (status.ok()) {
      model.generation = store->head().generation;
    }
    return status;
  }

  void audit(AuditKind kind, StatusCode code, std::string detail, const PduId& pdu = PduId{},
             const BranchId& branch = BranchId{}, AttemptId attempt = AttemptId{},
             ObservationId observation = ObservationId{}) {
    AuditEntry entry;
    entry.sequence = model.next_audit_sequence;
    const Result<SequenceNumber> next = model.next_audit_sequence.next();
    if (next.ok()) {
      model.next_audit_sequence = next.value();
    }
    entry.kind = kind;
    entry.tick = model.current_tick;
    entry.wall = audit_instant(model);
    entry.pdu = pdu;
    entry.branch = branch;
    entry.attempt = attempt;
    entry.observation = observation;
    entry.code = code;
    entry.detail = truncate_bytes(std::move(detail), max_audit_detail_bytes);
    model.audit.push_back(std::move(entry));
    while (model.audit.size() > options.audit_capacity) {
      model.audit.pop_front();
      model.audit_dropped += 1;
    }
  }

  // -- recovery -------------------------------------------------------------

  /// Adopts attempts left non-terminal by a previous incarnation.
  ///
  /// The attempt is *not* re-sent and is never treated as new work. It becomes
  /// \`recovery_required\` and the branch it targets stays blocked from further
  /// control until its effect is established from evidence or the attempt is
  /// explicitly resolved.
  void recover() {
    bool changed = false;
    for (AttemptRecord& attempt : model.attempts) {
      if (!is_unresolved(attempt.outcome)) {
        continue;
      }
      attempt.outcome = AttemptOutcome::recovery_required;
      attempt.code = StatusCode::attempt_unresolved;
      attempt.effect = EffectState::unknown;
      attempt.detail = truncate_bytes(
          "the process that dispatched this attempt ended before the effect was established",
          max_adapter_detail_bytes);
      if (detail::BranchRecord* branch = find_branch(attempt.pdu, attempt.branch)) {
        branch->state.unresolved_attempt = true;
        if (!branch->state.unresolved_since.is_set()) {
          branch->state.unresolved_since = model.current_tick;
        }
      }
      audit(AuditKind::recovery_adopted, StatusCode::attempt_unresolved,
            "adopted an attempt left unresolved by a previous process incarnation", attempt.pdu,
            attempt.branch, attempt.id);
      changed = true;
    }
    (void)changed;
  }

  // -- shared sub-evaluations ----------------------------------------------

  PermissionVerdict grant_verdict(const PermissionGrant& grant, const PduId& pdu,
                                  const BranchId& branch, PduGeneration pdu_generation,
                                  BranchGeneration branch_generation, PermissionAction action,
                                  AuthorityEpoch epoch, LogicalTick now) const {
    if (!validate_grant(grant).ok()) {
      return PermissionVerdict::malformed;
    }
    if (grant.pdu != pdu || grant.branch != branch) {
      return PermissionVerdict::scope_mismatch;
    }
    if (grant.epoch != epoch) {
      return PermissionVerdict::stale_epoch;
    }
    if (grant.revoked) {
      return PermissionVerdict::revoked;
    }
    if (grant.not_after.is_set() && now >= grant.not_after) {
      return PermissionVerdict::expired;
    }
    if (grant.pdu_generation != pdu_generation || grant.branch_generation != branch_generation) {
      return PermissionVerdict::generation_mismatch;
    }
    if (!has_action(grant.actions, action)) {
      return PermissionVerdict::action_missing;
    }
    return PermissionVerdict::usable;
  }

  /// The best available verdict for one required action, and the grant that
  /// produced it.
  PermissionVerdict permission_verdict(const PduId& pdu, const BranchId& branch,
                                       PduGeneration pdu_generation,
                                       BranchGeneration branch_generation,
                                       PermissionAction action, AuthorityEpoch epoch,
                                       LogicalTick now, const PermissionGrant** deciding) const {
    const PermissionGrant* best = nullptr;
    PermissionVerdict best_verdict = PermissionVerdict::missing;
    for (const detail::GrantRecord& record : model.grants) {
      const PermissionGrant& grant = record.grant;
      if (grant.pdu != pdu || grant.branch != branch) {
        continue;
      }
      const PermissionVerdict verdict =
          grant_verdict(grant, pdu, branch, pdu_generation, branch_generation, action, epoch, now);
      if (verdict == PermissionVerdict::usable) {
        if (deciding != nullptr) {
          *deciding = &grant;
        }
        return verdict;
      }
      if (best == nullptr || permission_rank(verdict) < permission_rank(best_verdict)) {
        best = &grant;
        best_verdict = verdict;
      }
    }
    if (deciding != nullptr) {
      *deciding = best;
    }
    return best_verdict;
  }

  /// The best available verdict for a *PDU-level* transition.
  ///
  /// A PDU-level lifecycle transition is not scoped to one branch, so the branch
  /// scope of a grant does not apply; what has to match is the PDU, the PDU
  /// generation, the epoch, and the action.
  PermissionVerdict permission_verdict_pdu(const PduId& pdu, PduGeneration pdu_generation,
                                           PermissionAction action, AuthorityEpoch epoch,
                                           LogicalTick now,
                                           const PermissionGrant** deciding) const {
    const PermissionGrant* best = nullptr;
    PermissionVerdict best_verdict = PermissionVerdict::missing;
    for (const detail::GrantRecord& record : model.grants) {
      const PermissionGrant& grant = record.grant;
      if (grant.pdu != pdu) {
        continue;
      }
      PermissionVerdict verdict = PermissionVerdict::usable;
      if (!validate_grant(grant).ok()) {
        verdict = PermissionVerdict::malformed;
      } else if (grant.epoch != epoch) {
        verdict = PermissionVerdict::stale_epoch;
      } else if (grant.revoked) {
        verdict = PermissionVerdict::revoked;
      } else if (grant.not_after.is_set() && now >= grant.not_after) {
        verdict = PermissionVerdict::expired;
      } else if (grant.pdu_generation != pdu_generation) {
        verdict = PermissionVerdict::generation_mismatch;
      } else if (!has_action(grant.actions, action)) {
        verdict = PermissionVerdict::action_missing;
      }
      if (verdict == PermissionVerdict::usable) {
        if (deciding != nullptr) {
          *deciding = &grant;
        }
        return verdict;
      }
      if (best == nullptr || permission_rank(verdict) < permission_rank(best_verdict)) {
        best = &grant;
        best_verdict = verdict;
      }
    }
    if (deciding != nullptr) {
      *deciding = best;
    }
    return best_verdict;
  }

  OverrideVerdict override_verdict(const PduId& pdu, const BranchId& branch,
                                   PduGeneration pdu_generation,
                                   BranchGeneration branch_generation, AuthorityEpoch epoch,
                                   LogicalTick now) const {
    OverrideVerdict best = OverrideVerdict::missing;
    bool have = false;
    for (const detail::OverrideRecord& record : model.overrides) {
      const MaintenanceOverride& value = record.value;
      if (value.pdu != pdu || value.branch != branch) {
        continue;
      }
      OverrideVerdict verdict = OverrideVerdict::usable;
      if (value.epoch != epoch) {
        verdict = OverrideVerdict::stale_epoch;
      } else if (value.revoked) {
        verdict = OverrideVerdict::revoked;
      } else if (value.not_after.is_set() && now >= value.not_after) {
        verdict = OverrideVerdict::expired;
      } else if (value.pdu_generation != pdu_generation ||
                 value.branch_generation != branch_generation) {
        verdict = OverrideVerdict::generation_mismatch;
      }
      if (verdict == OverrideVerdict::usable) {
        return verdict;
      }
      if (!have || override_rank(verdict) < override_rank(best)) {
        best = verdict;
        have = true;
      }
    }
    return best;
  }

  /// The interpolate ids that gate one branch, in a deterministic order: the
  /// interlocks the branch declares first, then any other interlock declared
  /// against the branch.
  std::vector<InterlockId> gating_interlocks(const detail::BranchRecord& branch) const {
    std::vector<InterlockId> ids;
    for (const InterlockId& id : branch.definition.required_interlocks) {
      ids.push_back(id);
    }
    for (const detail::InterlockRecord& record : model.interlocks) {
      if (record.declaration.pdu != branch.definition.pdu ||
          record.declaration.branch != branch.definition.id) {
        continue;
      }
      if (std::find(ids.begin(), ids.end(), record.declaration.id) == ids.end()) {
        ids.push_back(record.declaration.id);
      }
    }
    return ids;
  }

  std::vector<InterlockView> interlock_views(const detail::BranchRecord& branch,
                                             InterlockSummary& summary) const {
    std::vector<InterlockView> views;
    InterlockId blocked;
    InterlockId unknown;
    bool have_blocked = false;
    bool have_unknown = false;
    for (const InterlockId& id : gating_interlocks(branch)) {
      InterlockView view;
      view.id = id;
      const detail::InterlockRecord* record = find_interlock(id);
      if (record == nullptr) {
        // Named but never declared: there is nothing to establish the
        // obligation, so it fails closed as unknown.
        view.klass = ObligationClass::protected_obligation;
        view.reported_state = InterlockState::unknown;
        view.effective_state = InterlockState::unknown;
        view.report_current = false;
      } else {
        view.klass = record->declaration.klass;
        view.reported_state = record->status.state;
        view.updated_at = record->status.updated_at;
        view.report_current =
            record->has_status && record->status.epoch == model.authority_epoch &&
            model.authority_epoch.is_set();
        view.effective_state =
            view.report_current ? record->status.state : InterlockState::unknown;
      }
      if (view.klass == ObligationClass::protected_obligation) {
        summary.protected_count += 1;
        if (view.effective_state == InterlockState::satisfied) {
          summary.satisfied_count += 1;
        } else if (view.effective_state == InterlockState::open && !have_blocked) {
          blocked = id;
          have_blocked = true;
        } else if (view.effective_state == InterlockState::unknown && !have_unknown) {
          unknown = id;
          have_unknown = true;
        }
      }
      views.push_back(std::move(view));
    }
    if (have_blocked) {
      summary.verdict = InterlockVerdict::blocked;
      summary.deciding = blocked;
      summary.has_deciding = true;
    } else if (have_unknown) {
      summary.verdict = InterlockVerdict::unknown;
      summary.deciding = unknown;
      summary.has_deciding = true;
    } else {
      summary.verdict = InterlockVerdict::clear;
      summary.has_deciding = false;
    }
    return views;
  }

  /// The permission view presented for a branch: the most usable verdict across
  /// the two control actions, with the grant that produced it.
  PermissionView permission_view(const detail::PduRecord& pdu,
                                 const detail::BranchRecord& branch) const {
    PermissionView view;
    const PermissionAction actions[] = {PermissionAction::control_energize,
                                        PermissionAction::control_de_energize};
    const PermissionGrant* chosen = nullptr;
    PermissionVerdict best = PermissionVerdict::missing;
    bool have = false;
    for (const PermissionAction action : actions) {
      const PermissionGrant* candidate = nullptr;
      const PermissionVerdict verdict =
          permission_verdict(pdu.definition.id, branch.definition.id, pdu.definition.generation,
                             branch.definition.generation, action, model.authority_epoch,
                             model.current_tick, &candidate);
      if (verdict == PermissionVerdict::usable) {
        chosen = candidate;
        best = verdict;
        have = true;
        break;
      }
      if (!have || permission_rank(verdict) < permission_rank(best)) {
        chosen = candidate;
        best = verdict;
        have = true;
      }
    }
    view.present = chosen != nullptr;
    view.verdict = best;
    if (chosen != nullptr) {
      view.id = chosen->id;
      view.issuer = chosen->issuer;
      view.epoch = chosen->epoch;
      view.actions = chosen->actions;
      view.issued_at = chosen->issued_at;
      view.not_after = chosen->not_after;
      view.revoked = chosen->revoked;
    }
    return view;
  }

  BranchSnapshot snapshot_of(const detail::BranchRecord& branch,
                             const detail::PduRecord& pdu) const {
    InterlockSummary summary;
    std::vector<InterlockView> views = interlock_views(branch, summary);
    return build_snapshot(model, branch, pdu, options.evidence, std::move(views), summary,
                          permission_view(pdu, branch));
  }

  static void note(Decision& decision, PreconditionKind kind, bool satisfied, StatusCode code,
                   std::string detail) {
    PreconditionCheck check;
    check.kind = kind;
    check.satisfied = satisfied;
    check.code = code;
    check.detail = std::move(detail);
    decision.trace.push_back(std::move(check));
  }

  /// Adjudicates a control request without mutating anything. This is the only
  /// place the control preconditions are decided, and it is shared by
  /// \`evaluate\` and \`issue\` so the two can never disagree.
  Decision evaluate_control(const BranchControlRequest& request) const {
    Decision decision;
    decision.pdu = request.pdu;
    decision.branch = request.branch;
    decision.pdu_generation = request.pdu_generation;
    decision.branch_generation = request.branch_generation;
    decision.revision = request.planned_revision;
    decision.epoch = request.epoch;
    decision.intent = request.intent;
    decision.code = StatusCode::ok;

    const auto fail = [&decision](StatusCode code, std::string detail) {
      decision.eligible = false;
      decision.code = code;
      decision.detail = std::move(detail);
    };

    // 1. request shape.
    if (request.pdu.empty() || request.branch.empty()) {
      note(decision, PreconditionKind::identity, false, StatusCode::invalid_argument,
           "a control request must name both a PDU and a branch");
      fail(StatusCode::invalid_argument, "a control request must name both a PDU and a branch");
      return decision;
    }
    if (request.key.empty()) {
      note(decision, PreconditionKind::identity, false, StatusCode::invalid_argument,
           "a control request must carry an idempotency key");
      fail(StatusCode::invalid_argument, "a control request must carry an idempotency key");
      return decision;
    }
    if (request.actor.empty()) {
      note(decision, PreconditionKind::identity, false, StatusCode::invalid_argument,
           "a control request must name the actor that asked for it");
      fail(StatusCode::invalid_argument, "a control request must name the actor that asked for it");
      return decision;
    }
    if (!request.epoch.is_set() || !request.pdu_generation.is_set() ||
        !request.branch_generation.is_set()) {
      note(decision, PreconditionKind::authority_epoch, false, StatusCode::invalid_argument,
           "a control request must state its authority epoch and both device generations");
      fail(StatusCode::invalid_argument,
           "a control request must state its authority epoch and both device generations");
      return decision;
    }
    if (request.projected_current.has_value() && request.projected_current.value().is_negative()) {
      note(decision, PreconditionKind::limits, false, StatusCode::out_of_range,
           "a projected current must not be negative");
      fail(StatusCode::out_of_range, "a projected current must not be negative");
      return decision;
    }
    note(decision, PreconditionKind::identity, true, StatusCode::ok, "the request is well formed");

    // 3. identity resolution.
    const detail::PduRecord* pdu = find_pdu(request.pdu);
    if (pdu == nullptr) {
      note(decision, PreconditionKind::identity, false, StatusCode::not_found,
           "no PDU with this identity is registered");
      fail(StatusCode::not_found, "no PDU with this identity is registered");
      return decision;
    }
    const detail::BranchRecord* branch = find_branch(request.pdu, request.branch);
    if (branch == nullptr) {
      const detail::BranchRecord* elsewhere = find_branch_any(request.branch);
      if (elsewhere != nullptr) {
        note(decision, PreconditionKind::branch_binding, false, StatusCode::identity_mismatch,
             "the named branch belongs to another PDU");
        fail(StatusCode::identity_mismatch, "the named branch belongs to another PDU");
        return decision;
      }
      note(decision, PreconditionKind::identity, false, StatusCode::not_found,
           "no branch circuit with this identity is registered on this PDU");
      fail(StatusCode::not_found,
           "no branch circuit with this identity is registered on this PDU");
      return decision;
    }
    note(decision, PreconditionKind::branch_binding, true, StatusCode::ok,
         "the branch belongs to the named PDU");

    // 4. lifecycle gate.
    const ControlScope branch_scope = control_scope(branch->state.lifecycle);
    const ControlScope pdu_scope = control_scope(pdu->state.lifecycle);
    bool override_used = false;
    if (branch_scope == ControlScope::forbidden || pdu_scope == ControlScope::forbidden) {
      const LifecycleState blocking =
          branch_scope == ControlScope::forbidden ? branch->state.lifecycle : pdu->state.lifecycle;
      note(decision, PreconditionKind::lifecycle, false, StatusCode::lifecycle_forbidden,
           std::string("control is refused while the lifecycle is ") +
               std::string(to_token(blocking)));
      fail(StatusCode::lifecycle_forbidden,
           std::string("control is refused while the lifecycle is ") +
               std::string(to_token(blocking)));
      return decision;
    }
    if (branch_scope == ControlScope::maintenance_override ||
        pdu_scope == ControlScope::maintenance_override) {
      const OverrideVerdict verdict =
          override_verdict(request.pdu, request.branch, request.pdu_generation,
                           request.branch_generation, request.epoch, model.current_tick);
      decision.override_verdict = verdict;
      if (verdict != OverrideVerdict::usable) {
        const StatusCode code = status_for(verdict);
        note(decision, PreconditionKind::lifecycle, false, code,
             std::string("control in maintenance requires a current maintenance override (") +
                 std::string(to_token(verdict)) + ")");
        fail(code, std::string("control in maintenance requires a current maintenance override (") +
                       std::string(to_token(verdict)) + ")");
        return decision;
      }
      override_used = true;
      decision.maintenance_override_used = true;
      note(decision, PreconditionKind::lifecycle, true, StatusCode::ok,
           "control in maintenance is authorized by a current maintenance override");
    } else {
      note(decision, PreconditionKind::lifecycle, true, StatusCode::ok,
           "the lifecycle state permits control");
    }

    // 5. an unresolved attempt blocks new control on the branch.
    if (branch->state.unresolved_attempt) {
      note(decision, PreconditionKind::no_unresolved_attempt, false, StatusCode::attempt_unresolved,
           "an earlier attempt on this branch has no established effect");
      fail(StatusCode::attempt_unresolved,
           "an earlier attempt on this branch has no established effect");
      return decision;
    }
    note(decision, PreconditionKind::no_unresolved_attempt, true, StatusCode::ok,
         "no earlier attempt on this branch is unresolved");

    // 6. device generations.
    if (pdu->definition.generation != request.pdu_generation) {
      note(decision, PreconditionKind::pdu_generation, false, StatusCode::generation_mismatch,
           "the request was planned against PDU generation " +
               std::to_string(request.pdu_generation.value()) + " and the current generation is " +
               std::to_string(pdu->definition.generation.value()));
      fail(StatusCode::generation_mismatch,
           "the request was planned against PDU generation " +
               std::to_string(request.pdu_generation.value()) + " and the current generation is " +
               std::to_string(pdu->definition.generation.value()));
      return decision;
    }
    if (branch->definition.generation != request.branch_generation) {
      note(decision, PreconditionKind::branch_generation, false, StatusCode::generation_mismatch,
           "the request was planned against branch generation " +
               std::to_string(request.branch_generation.value()) +
               " and the current generation is " +
               std::to_string(branch->definition.generation.value()));
      fail(StatusCode::generation_mismatch,
           "the request was planned against branch generation " +
               std::to_string(request.branch_generation.value()) +
               " and the current generation is " +
               std::to_string(branch->definition.generation.value()));
      return decision;
    }
    note(decision, PreconditionKind::pdu_generation, true, StatusCode::ok,
         "the stated PDU generation is current");
    note(decision, PreconditionKind::branch_generation, true, StatusCode::ok,
         "the stated branch generation is current");

    // 7. state revision, when the caller stated one.
    decision.revision = branch->state.revision;
    if (request.planned_revision.is_set() && request.planned_revision != branch->state.revision) {
      note(decision, PreconditionKind::state_revision, false, StatusCode::revision_mismatch,
           "the request was planned against revision " +
               std::to_string(request.planned_revision.value()) + " and the branch is at " +
               std::to_string(branch->state.revision.value()));
      fail(StatusCode::revision_mismatch,
           "the request was planned against revision " +
               std::to_string(request.planned_revision.value()) + " and the branch is at " +
               std::to_string(branch->state.revision.value()));
      return decision;
    }
    note(decision, PreconditionKind::state_revision, true, StatusCode::ok,
         request.planned_revision.is_set() ? "the stated revision is current"
                                           : "no revision was stated, so none was checked");

    // 8. authority epoch.
    if (!model.authority_epoch.is_set() || request.epoch != model.authority_epoch) {
      note(decision, PreconditionKind::authority_epoch, false, StatusCode::permission_stale,
           "the request was planned in authority epoch " +
               std::to_string(request.epoch.value()) + " and the adopted epoch is " +
               std::to_string(model.authority_epoch.value()));
      fail(StatusCode::permission_stale,
           "the request was planned in authority epoch " +
               std::to_string(request.epoch.value()) + " and the adopted epoch is " +
               std::to_string(model.authority_epoch.value()));
      return decision;
    }
    note(decision, PreconditionKind::authority_epoch, true, StatusCode::ok,
         "the stated authority epoch is the adopted epoch");

    // 9. permission.
    const PermissionGrant* deciding_grant = nullptr;
    const PermissionVerdict verdict =
        permission_verdict(request.pdu, request.branch, request.pdu_generation,
                           request.branch_generation, required_action(request.intent),
                           request.epoch, model.current_tick, &deciding_grant);
    decision.permission = verdict;
    if (verdict != PermissionVerdict::usable) {
      std::string detail = std::string("permission is ") + std::string(to_token(verdict));
      if (deciding_grant != nullptr) {
        detail.append(" for grant ");
        detail.append(deciding_grant->id.value());
        detail.append(" issued by ");
        detail.append(deciding_grant->issuer.value());
      }
      const StatusCode code = status_for(verdict);
      note(decision, PreconditionKind::permission, false, code, detail);
      fail(code, detail);
      return decision;
    }
    note(decision, PreconditionKind::permission, true, StatusCode::ok,
         deciding_grant != nullptr ? "a current grant covers this action"
                                   : "the required action is covered");

    // 10. interlocks.
    InterlockSummary summary;
    (void)interlock_views(*branch, summary);
    decision.interlocks = summary;
    if (summary.verdict != InterlockVerdict::clear) {
      const StatusCode code = summary.verdict == InterlockVerdict::blocked
                                  ? StatusCode::interlock_open
                                  : StatusCode::interlock_unknown;
      std::string detail = "protected obligation " + summary.deciding.value() + " is " +
                           std::string(to_token(summary.verdict));
      note(decision, PreconditionKind::interlock, false, code, detail);
      fail(code, detail);
      return decision;
    }
    note(decision, PreconditionKind::interlock, true, StatusCode::ok,
         "every protected obligation on this branch is satisfied");

    // 11. limits.
    const Status limits_valid = validate_limits(branch->definition.limits);
    if (!limits_valid.ok()) {
      note(decision, PreconditionKind::limits, false, StatusCode::limit_invalid,
           limits_valid.message());
      fail(StatusCode::limit_invalid, limits_valid.message());
      return decision;
    }
    if (request.projected_current.has_value()) {
      const Result<LimitVerdict> compared =
          compare_to_limit(request.projected_current.value(),
                           branch->definition.limits.continuous_current);
      if (!compared.ok()) {
        note(decision, PreconditionKind::limits, false, compared.code(), compared.status().message());
        fail(compared.code(), compared.status().message());
        return decision;
      }
      decision.limit = compared.value();
      if (compared.value() == LimitVerdict::limit_unknown) {
        note(decision, PreconditionKind::limits, false, StatusCode::limit_invalid,
             "the branch continuous current limit is not established, so a projected load cannot "
             "be checked against it");
        fail(StatusCode::limit_invalid,
             "the branch continuous current limit is not established, so a projected load cannot "
             "be checked against it");
        return decision;
      }
      if (compared.value() == LimitVerdict::exceeds_limit) {
        note(decision, PreconditionKind::limits, false, StatusCode::limit_exceeded,
             "the projected current exceeds the declared continuous limit");
        fail(StatusCode::limit_exceeded,
             "the projected current exceeds the declared continuous limit");
        return decision;
      }
    }
    note(decision, PreconditionKind::limits, true, StatusCode::ok,
         request.projected_current.has_value() ? "the projected load is within the declared limits"
                                               : "no projected load was stated, so no load check ran");

    decision.eligible = true;
    decision.code = StatusCode::ok;
    decision.detail = "the request may be attempted";
    decision.prior_commanded = branch->state.commanded.condition;
    decision.prior_observed = branch->observations.has_current
                                  ? Sample<BranchCondition>::known(branch->observations.current.condition)
                                  : Sample<BranchCondition>::unknown();
    decision.maintenance_override_used = override_used;
    return decision;
  }
};

std::string_view to_token(AttemptResolution resolution) noexcept {
  switch (resolution) {
    case AttemptResolution::cancelled:
      return "cancelled";
    case AttemptResolution::superseded:
      return "superseded";
  }
  return "unknown_resolution";
}

bool parse_attempt_resolution(std::string_view token, AttemptResolution& out) noexcept {
  constexpr AttemptResolution kResolutions[] = {AttemptResolution::cancelled,
                                                AttemptResolution::superseded};
  for (const AttemptResolution resolution : kResolutions) {
    if (to_token(resolution) == token) {
      out = resolution;
      return true;
    }
  }
  return false;
}

PduControlEngine::PduControlEngine() = default;
PduControlEngine::~PduControlEngine() = default;
PduControlEngine::PduControlEngine(PduControlEngine&& other) noexcept = default;
PduControlEngine& PduControlEngine::operator=(PduControlEngine&& other) noexcept = default;

Result<PduControlEngine> PduControlEngine::in_memory(const EngineOptions& options) {
  PduControlEngine engine;
  engine.impl_ = std::make_unique<Impl>();
  Impl& impl = *engine.impl_;
  impl.options = normalize_options(options);
  impl.open = true;
  impl.durable = false;
  impl.read_only = impl.options.read_only;
  impl.audit(AuditKind::engine_opened, StatusCode::ok,
             "opened an in-memory engine with no durable backing");
  return engine;
}

Result<PduControlEngine> PduControlEngine::open(std::string_view path, OpenMode mode,
                                                const EngineOptions& options) {
  const EngineOptions normalized = normalize_options(options);
  Result<std::string> normalized_path = validate_store_path(path, normalized.path_policy);
  if (!normalized_path.ok()) {
    return normalized_path.status();
  }
  Result<detail::StoreFile> store =
      detail::StoreFile::open(normalized_path.value(), mode, normalized.bounds,
                              normalized.read_only || mode == OpenMode::read_only,
                              normalized.min_store_generation);
  if (!store.ok()) {
    return store.status();
  }
  PduControlEngine engine;
  engine.impl_ = std::make_unique<Impl>();
  Impl& impl = *engine.impl_;
  impl.options = normalized;
  impl.path = normalized_path.value();
  impl.store = std::make_unique<detail::StoreFile>(std::move(store.value()));
  impl.model = impl.store->state();
  impl.open = true;
  impl.durable = true;
  impl.read_only = impl.store->is_read_only();
  const bool first_open = impl.model.open_count <= 1;
  impl.recover();
  impl.audit(first_open ? AuditKind::engine_opened : AuditKind::engine_reopened, StatusCode::ok,
             first_open ? "created a new store and adopted its initial state"
                        : "adopted the committed state of an existing store");
  if (!impl.read_only) {
    const Status published = impl.publish();
    if (!published.ok()) {
      return published;
    }
  }
  return engine;
}

Status PduControlEngine::close() {
  if (impl_ == nullptr || !impl_->open) {
    return Status::success();
  }
  Impl& impl = *impl_;
  Status result = Status::success();
  if (impl.durable && !impl.read_only) {
    impl.audit(AuditKind::engine_closed, StatusCode::ok, "closing the engine");
    result = impl.publish();
  }
  impl.open = false;
  if (impl.store != nullptr) {
    const Status closed = impl.store->close();
    if (result.ok()) {
      result = closed;
    }
  }
  return result;
}

bool PduControlEngine::is_open() const noexcept { return impl_ != nullptr && impl_->open; }
bool PduControlEngine::is_durable() const noexcept { return impl_ != nullptr && impl_->durable; }
bool PduControlEngine::is_read_only() const noexcept { return impl_ != nullptr && impl_->read_only; }
const std::string& PduControlEngine::store_path() const noexcept {
  static const std::string kEmpty;
  return impl_ == nullptr ? kEmpty : impl_->path;
}
const EngineOptions& PduControlEngine::options() const noexcept {
  static const EngineOptions kDefault;
  return impl_ == nullptr ? kDefault : impl_->options;
}
Incarnation PduControlEngine::incarnation() const noexcept {
  return impl_ == nullptr || impl_->store == nullptr ? Incarnation{} : impl_->store->incarnation();
}
AuthorityEpoch PduControlEngine::authority_epoch() const noexcept {
  return impl_ == nullptr ? AuthorityEpoch{} : impl_->model.authority_epoch;
}
LogicalTick PduControlEngine::current_tick() const noexcept {
  return impl_ == nullptr ? LogicalTick{} : impl_->model.current_tick;
}
StoreGeneration PduControlEngine::store_generation() const noexcept {
  return impl_ == nullptr ? StoreGeneration{} : impl_->model.generation;
}

Status PduControlEngine::flush() {
  if (impl_ == nullptr) {
    return Status::failure(StatusCode::internal, "the engine is empty");
  }
  const Status writable = impl_->ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  return impl_->publish();
}

StoreAudit PduControlEngine::store_audit() const {
  StoreAudit audit;
  if (impl_ == nullptr) {
    return audit;
  }
  const Impl& impl = *impl_;
  audit.durable = impl.durable;
  audit.open = impl.open;
  audit.read_only = impl.read_only;
  audit.path = impl.path;
  audit.format_version = store_format_version;
  audit.generation = impl.model.generation;
  audit.current_tick = impl.model.current_tick;
  audit.authority_epoch = impl.model.authority_epoch;
  audit.state_digest = state_digest();
  if (impl.store != nullptr) {
    const StoreAudit& inner = impl.store->audit();
    audit.published_generation = inner.published_generation;
    audit.min_accepted_generation = inner.min_accepted_generation;
    audit.incarnation = inner.incarnation;
    audit.stored_incarnation = inner.stored_incarnation;
    audit.open_count = inner.open_count;
    audit.publication_count = inner.publication_count;
    audit.head_writes = inner.head_writes;
    audit.slot_writes = inner.slot_writes;
    audit.bytes_written = inner.bytes_written;
    audit.bytes_read = inner.bytes_read;
    audit.flushes = inner.flushes;
    audit.readback_verifications = inner.readback_verifications;
    audit.crc_mismatches = inner.crc_mismatches;
    audit.rejected_open_attempts = inner.rejected_open_attempts;
    audit.fenced_writes = inner.fenced_writes;
    audit.recovered_publications = inner.recovered_publications;
    audit.exclusively_locked = inner.exclusively_locked;
    audit.rollback_fence_armed = inner.rollback_fence_armed;
    audit.head_records_valid = inner.head_records_valid;
    audit.head_slot_index = inner.head_slot_index;
    audit.last_published_digest = inner.last_published_digest;
  }
  return audit;
}

EngineStatus PduControlEngine::status() const {
  EngineStatus result;
  if (impl_ == nullptr) {
    return result;
  }
  const Impl& impl = *impl_;
  result.open = impl.open;
  result.durable = impl.durable;
  result.read_only = impl.read_only;
  result.store_path = impl.path;
  result.incarnation = incarnation();
  result.authority_epoch = impl.model.authority_epoch;
  result.current_tick = impl.model.current_tick;
  result.store_generation = impl.model.generation;
  result.state_digest = state_digest();
  result.pdu_count = impl.model.pdus.size();
  result.branch_count = impl.model.branches.size();
  result.attempt_count = impl.model.attempts.size();
  for (const AttemptRecord& attempt : impl.model.attempts) {
    if (is_unresolved(attempt.outcome) || attempt.outcome == AttemptOutcome::recovery_required) {
      result.unresolved_attempt_count += 1;
    }
  }
  result.idempotency_entries = impl.model.idempotency.size();
  result.audit_entries = impl.model.audit.size();
  result.audit_dropped = impl.model.audit_dropped;
  result.refusal_count = impl.refusal_count;
  result.dispatch_count = impl.dispatch_count;
  result.verification_count = impl.verification_count;
  result.store = store_audit();
  return result;
}

Status PduControlEngine::adopt_authority_epoch(AuthorityEpoch epoch) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (!epoch.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "an authority epoch must carry a nonzero value");
  }
  if (impl.model.authority_epoch.is_set() && epoch <= impl.model.authority_epoch) {
    return Status::failure(StatusCode::permission_stale,
                           "authority epoch " + std::to_string(epoch.value()) +
                               " is not later than the adopted epoch " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  impl.model.authority_epoch = epoch;
  impl.audit(AuditKind::authority_epoch_adopted, StatusCode::ok,
             "adopted authority epoch " + std::to_string(epoch.value()));
  return impl.publish();
}

Status PduControlEngine::advance_tick(LogicalTick tick) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (!tick.is_set()) {
    return Status::failure(StatusCode::invalid_argument, "a logical tick must carry a nonzero value");
  }
  if (tick <= impl.model.current_tick) {
    return Status::failure(StatusCode::out_of_range,
                           "the logical clock never moves backwards: tick " +
                               std::to_string(tick.value()) + " is not later than " +
                               std::to_string(impl.model.current_tick.value()));
  }
  impl.model.current_tick = tick;
  impl.audit(AuditKind::tick_advanced, StatusCode::ok,
             "advanced to logical tick " + std::to_string(tick.value()));
  return impl.publish();
}

Status PduControlEngine::set_wall_instant(Instant instant) {
  Impl& impl = *impl_;
  if (!impl.open) {
    return Status::failure(StatusCode::store_io, "the engine is not open");
  }
  const Status valid = validate_instant(instant);
  if (!valid.ok()) {
    return valid;
  }
  // Wall-clock content is audit decoration. It is never used for a control
  // decision, and it is excluded from the canonical state text.
  impl.model.wall = instant;
  return Status::success();
}

namespace {

bool instant_is_unset(const Instant& instant) {
  return !instant.tick.is_set() && instant.nanoseconds == 0;
}

}  // namespace

Status PduControlEngine::register_pdu(const PduDefinition& definition) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  const Status valid = validate(definition, impl.options.bounds);
  if (!valid.ok()) {
    return valid;
  }
  if (impl.find_pdu(definition.id) != nullptr) {
    return Status::failure(StatusCode::duplicate_identity,
                           "a PDU with this identity is already registered");
  }
  if (impl.model.pdus.size() >= impl.options.bounds.max_pdus) {
    return Status::failure(StatusCode::capacity_exhausted,
                           "the model holds the maximum number of PDUs");
  }
  detail::PduRecord record;
  record.definition = definition;
  record.state.lifecycle = definition.lifecycle;
  record.state.revision = StateRevision::from(1);
  impl.model.pdus.push_back(std::move(record));
  if (definition.registered_at > impl.model.current_tick) {
    impl.model.current_tick = definition.registered_at;
  }
  impl.audit(AuditKind::pdu_registered, StatusCode::ok,
             "registered PDU generation " + std::to_string(definition.generation.value()),
             definition.id);
  return impl.publish();
}

Status PduControlEngine::register_branch(const BranchDefinition& definition) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  const Status valid = validate(definition, impl.options.bounds);
  if (!valid.ok()) {
    return valid;
  }
  if (impl.find_branch_any(definition.id) != nullptr) {
    return Status::failure(StatusCode::duplicate_identity,
                           "a branch circuit with this identity is already registered");
  }
  detail::PduRecord* pdu = impl.find_pdu(definition.pdu);
  if (pdu == nullptr) {
    return Status::failure(StatusCode::not_found,
                           "the PDU this branch belongs to is not registered");
  }
  std::size_t on_this_pdu = 0;
  for (const detail::BranchRecord& record : impl.model.branches) {
    if (record.definition.pdu == definition.pdu) {
      on_this_pdu += 1;
    }
  }
  if (on_this_pdu >= impl.options.bounds.max_branches_per_pdu) {
    return Status::failure(StatusCode::capacity_exhausted,
                           "this PDU already holds the maximum number of branch circuits");
  }
  detail::BranchRecord record;
  record.definition = definition;
  record.state.lifecycle = definition.lifecycle;
  record.state.revision = StateRevision::from(1);
  impl.model.branches.push_back(std::move(record));
  if (definition.registered_at > impl.model.current_tick) {
    impl.model.current_tick = definition.registered_at;
  }
  impl.audit(AuditKind::branch_registered, StatusCode::ok,
             "registered branch generation " + std::to_string(definition.generation.value()),
             definition.pdu, definition.id);
  return impl.publish();
}

Status PduControlEngine::transition_lifecycle(const LifecycleRequest& request) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (request.pdu.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a lifecycle request must name the PDU it addresses");
  }
  if (!request.epoch.is_set() || !request.pdu_generation.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a lifecycle request must state its authority epoch and PDU generation");
  }
  if (!request.planned_revision.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a lifecycle request must state the state revision it was planned "
                           "against");
  }
  if (!request.requested_at.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a lifecycle request must state the logical instant it was made at");
  }
  if (request.actor.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a lifecycle request must name the actor that asked for it");
  }
  detail::PduRecord* pdu = impl.find_pdu(request.pdu);
  if (pdu == nullptr) {
    return Status::failure(StatusCode::not_found, "no PDU with this identity is registered");
  }
  detail::BranchRecord* branch = nullptr;
  if (!request.branch.empty()) {
    branch = impl.find_branch(request.pdu, request.branch);
    if (branch == nullptr) {
      if (impl.find_branch_any(request.branch) != nullptr) {
        return Status::failure(StatusCode::identity_mismatch,
                               "the named branch belongs to another PDU");
      }
      return Status::failure(StatusCode::not_found,
                             "no branch circuit with this identity is registered on this PDU");
    }
    if (!request.branch_generation.is_set()) {
      return Status::failure(StatusCode::invalid_argument,
                             "a branch lifecycle request must state the branch generation");
    }
    if (branch->definition.generation != request.branch_generation) {
      return Status::failure(StatusCode::generation_mismatch,
                             "the request was planned against branch generation " +
                                 std::to_string(request.branch_generation.value()) +
                                 " and the current generation is " +
                                 std::to_string(branch->definition.generation.value()));
    }
  }
  if (pdu->definition.generation != request.pdu_generation) {
    return Status::failure(StatusCode::generation_mismatch,
                           "the request was planned against PDU generation " +
                               std::to_string(request.pdu_generation.value()) +
                               " and the current generation is " +
                               std::to_string(pdu->definition.generation.value()));
  }
  const StateRevision current_revision =
      branch != nullptr ? branch->state.revision : pdu->state.revision;
  if (request.planned_revision != current_revision) {
    return Status::failure(StatusCode::revision_mismatch,
                           "the request was planned against revision " +
                               std::to_string(request.planned_revision.value()) +
                               " and the entity is at " +
                               std::to_string(current_revision.value()));
  }
  const LifecycleState from =
      branch != nullptr ? branch->state.lifecycle : pdu->state.lifecycle;
  Result<TransitionClass> klass = transition_class(from, request.to);
  if (!klass.ok()) {
    return klass.status();
  }
  const Result<PermissionAction> action = required_action(from, request.to);
  if (!action.ok()) {
    return action.status();
  }
  if (!impl.model.authority_epoch.is_set() || request.epoch != impl.model.authority_epoch) {
    return Status::failure(StatusCode::permission_stale,
                           "the request was planned in authority epoch " +
                               std::to_string(request.epoch.value()) +
                               " and the adopted epoch is " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  const PduGeneration pdu_generation = pdu->definition.generation;
  const BranchGeneration branch_generation =
      branch != nullptr ? branch->definition.generation : BranchGeneration{};
  const BranchId branch_id = branch != nullptr ? branch->definition.id : BranchId{};
  const PermissionGrant* deciding = nullptr;
  const PermissionVerdict verdict =
      branch != nullptr
          ? impl.permission_verdict(request.pdu, branch_id, pdu_generation, branch_generation,
                                    action.value(), request.epoch, impl.model.current_tick,
                                    &deciding)
          : impl.permission_verdict_pdu(request.pdu, pdu_generation, action.value(), request.epoch,
                                        impl.model.current_tick, &deciding);
  if (verdict != PermissionVerdict::usable) {
    std::string detail = std::string("permission for this lifecycle transition is ") +
                         std::string(to_token(verdict));
    if (deciding != nullptr) {
      detail.append(" for grant ");
      detail.append(deciding->id.value());
    }
    return Status::failure(status_for(verdict), detail);
  }
  // A transition that returns an entity to service must not walk past an open
  // protected obligation.
  if (branch != nullptr &&
      (request.to == LifecycleState::active || request.to == LifecycleState::degraded)) {
    InterlockSummary summary;
    (void)impl.interlock_views(*branch, summary);
    if (summary.verdict != InterlockVerdict::clear) {
      return Status::failure(summary.verdict == InterlockVerdict::blocked
                                 ? StatusCode::interlock_open
                                 : StatusCode::interlock_unknown,
                             "protected obligation " + summary.deciding.value() +
                                 " is not satisfied, so the transition to service is refused");
    }
  }
  if (request.to == LifecycleState::active) {
    // A PDU-level transition to service must not leave a branch below it in a
    // state that contradicts it.
    if (branch == nullptr) {
      for (const detail::BranchRecord& record : impl.model.branches) {
        if (record.definition.pdu == request.pdu && record.state.lifecycle == LifecycleState::retired) {
          return Status::failure(StatusCode::transition_invalid,
                                 "a retired branch on this PDU prevents the PDU from returning to "
                                 "service");
        }
      }
    }
  }
  const LifecycleState previous = from;
  if (branch != nullptr) {
    branch->state.lifecycle = request.to;
    const Result<StateRevision> next = branch->state.revision.next();
    if (!next.ok()) {
      return next.status();
    }
    branch->state.revision = next.value();
  } else {
    pdu->state.lifecycle = request.to;
    const Result<StateRevision> next = pdu->state.revision.next();
    if (!next.ok()) {
      return next.status();
    }
    pdu->state.revision = next.value();
  }
  if (request.requested_at > impl.model.current_tick) {
    impl.model.current_tick = request.requested_at;
  }
  impl.audit(AuditKind::lifecycle_transition, StatusCode::ok,
             std::string(to_token(previous)) + " -> " + std::string(to_token(request.to)) + " by " +
                 request.actor.value(),
             request.pdu, branch_id);
  return impl.publish();
}

Status PduControlEngine::update_limits(const LimitUpdateRequest& request) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (request.pdu.empty() || request.branch.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a limit update must name both a PDU and a branch");
  }
  if (!request.epoch.is_set() || !request.pdu_generation.is_set() ||
      !request.branch_generation.is_set() || !request.planned_revision.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a limit update must state its authority epoch, both device "
                           "generations, and the revision it was planned against");
  }
  const Status valid = validate_limits(request.limits);
  if (!valid.ok()) {
    return valid;
  }
  detail::BranchRecord* branch = impl.find_branch(request.pdu, request.branch);
  if (branch == nullptr) {
    return Status::failure(StatusCode::not_found,
                           "no branch circuit with this identity is registered on this PDU");
  }
  if (branch->definition.generation != request.branch_generation) {
    return Status::failure(StatusCode::generation_mismatch,
                           "the request was planned against branch generation " +
                               std::to_string(request.branch_generation.value()) +
                               " and the current generation is " +
                               std::to_string(branch->definition.generation.value()));
  }
  if (branch->state.revision != request.planned_revision) {
    return Status::failure(StatusCode::revision_mismatch,
                           "the request was planned against revision " +
                               std::to_string(request.planned_revision.value()) +
                               " and the branch is at " +
                               std::to_string(branch->state.revision.value()));
  }
  if (!impl.model.authority_epoch.is_set() || request.epoch != impl.model.authority_epoch) {
    return Status::failure(StatusCode::permission_stale,
                           "the request was planned in authority epoch " +
                               std::to_string(request.epoch.value()) +
                               " and the adopted epoch is " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  const PermissionGrant* deciding = nullptr;
  const PermissionVerdict verdict = impl.permission_verdict(
      request.pdu, request.branch, request.pdu_generation, request.branch_generation,
      PermissionAction::lifecycle_service, request.epoch, impl.model.current_tick, &deciding);
  if (verdict != PermissionVerdict::usable) {
    return Status::failure(status_for(verdict),
                           std::string("permission to change branch limits is ") +
                               std::string(to_token(verdict)));
  }
  if (deciding == nullptr) {
    return Status::failure(StatusCode::internal, "a usable permission verdict named no grant");
  }
  if (request.limits.provenance.issuer.empty() ||
      request.limits.provenance.issuer != deciding->issuer) {
    return Status::failure(StatusCode::identity_mismatch,
                           "the limit provenance issuer '" +
                               request.limits.provenance.issuer.value() +
                               "' is not the issuer of the grant that authorizes the update ('" +
                               deciding->issuer.value() + "')");
  }
  BranchLimits limits = request.limits;
  // The engine canonicalizes provenance: the authority reference, the epoch, and
  // the instant are facts this runtime knows, not values a caller asserts.
  limits.provenance.authority = deciding->id;
  limits.provenance.epoch = impl.model.authority_epoch;
  limits.provenance.stated_at =
      request.requested_at.is_set() ? request.requested_at : impl.model.current_tick;
  const Result<StateRevision> next_limits = branch->definition.limits.revision.next();
  if (!next_limits.ok()) {
    return next_limits.status();
  }
  limits.revision = next_limits.value();
  branch->definition.limits = limits;
  const Result<StateRevision> next = branch->state.revision.next();
  if (!next.ok()) {
    return next.status();
  }
  branch->state.revision = next.value();
  if (request.requested_at > impl.model.current_tick) {
    impl.model.current_tick = request.requested_at;
  }
  impl.audit(AuditKind::limits_updated, StatusCode::ok,
             "limits updated from grant " + deciding->id.value(), request.pdu, request.branch);
  return impl.publish();
}

Status PduControlEngine::record_grant(const PermissionGrant& grant) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  const Status valid = validate_grant(grant);
  if (!valid.ok()) {
    return valid;
  }
  if (!impl.model.authority_epoch.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "adopt an authority epoch before recording grants");
  }
  if (grant.epoch > impl.model.authority_epoch) {
    return Status::failure(StatusCode::invalid_argument,
                           "the grant was issued in epoch " + std::to_string(grant.epoch.value()) +
                               ", which is later than the adopted epoch " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  if (impl.find_grant(grant.id) != nullptr) {
    return Status::failure(StatusCode::duplicate_identity,
                           "a grant with this identity is already recorded");
  }
  if (impl.model.grants.size() >= impl.options.bounds.max_grants) {
    return Status::failure(StatusCode::capacity_exhausted,
                           "the model holds the maximum number of grants");
  }
  detail::GrantRecord record;
  record.grant = grant;
  impl.model.grants.push_back(std::move(record));
  impl.audit(AuditKind::grant_recorded, StatusCode::ok,
             "grant records actions " + to_token(grant.actions) + " from " + grant.issuer.value(),
             grant.pdu, grant.branch);
  return impl.publish();
}

Status PduControlEngine::revoke_grant(const AuthorityId& id, AuthorityEpoch epoch,
                                      LogicalTick at) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (!epoch.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a revocation must state the authority epoch it happens in");
  }
  detail::GrantRecord* record = impl.find_grant(id);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no grant with this identity is recorded");
  }
  if (!impl.model.authority_epoch.is_set() || epoch != impl.model.authority_epoch) {
    return Status::failure(StatusCode::permission_stale,
                           "the revocation is stated in epoch " + std::to_string(epoch.value()) +
                               " and the adopted epoch is " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  if (record->grant.revoked) {
    return Status::failure(StatusCode::duplicate_identity, "this grant is already revoked");
  }
  record->grant.revoked = true;
  record->grant.revoked_at = at.is_set() ? at : impl.model.current_tick;
  if (at.is_set() && at > impl.model.current_tick) {
    impl.model.current_tick = at;
  }
  impl.audit(AuditKind::grant_revoked, StatusCode::ok, "grant revoked", record->grant.pdu,
             record->grant.branch);
  return impl.publish();
}

Status PduControlEngine::record_maintenance_override(const MaintenanceOverride& override_value) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (override_value.id.empty() || override_value.issuer.empty() || override_value.pdu.empty() ||
      override_value.branch.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a maintenance override must name itself, its issuer, and its scope");
  }
  if (!override_value.epoch.is_set() || !override_value.pdu_generation.is_set() ||
      !override_value.branch_generation.is_set() || !override_value.issued_at.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a maintenance override must state its epoch, device generations, and "
                           "issue instant");
  }
  if (override_value.not_after.is_set() && override_value.not_after <= override_value.issued_at) {
    return Status::failure(StatusCode::invalid_argument,
                           "a maintenance override must expire after it was issued");
  }
  if (!impl.model.authority_epoch.is_set() ||
      override_value.epoch > impl.model.authority_epoch) {
    return Status::failure(StatusCode::invalid_argument,
                           "the override was issued in epoch " +
                               std::to_string(override_value.epoch.value()) +
                               ", which is later than the adopted epoch " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  if (impl.find_override(override_value.id) != nullptr) {
    return Status::failure(StatusCode::duplicate_identity,
                           "a maintenance override with this identity is already recorded");
  }
  if (impl.model.overrides.size() >= impl.options.bounds.max_overrides) {
    return Status::failure(StatusCode::capacity_exhausted,
                           "the model holds the maximum number of maintenance overrides");
  }
  detail::OverrideRecord record;
  record.value = override_value;
  impl.model.overrides.push_back(std::move(record));
  impl.audit(AuditKind::override_recorded, StatusCode::ok,
             "maintenance override recorded from " + override_value.issuer.value(),
             override_value.pdu, override_value.branch);
  return impl.publish();
}

Status PduControlEngine::revoke_maintenance_override(const AuthorityId& id, AuthorityEpoch epoch,
                                                     LogicalTick at) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  detail::OverrideRecord* record = impl.find_override(id);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found,
                           "no maintenance override with this identity is recorded");
  }
  if (!impl.model.authority_epoch.is_set() || epoch != impl.model.authority_epoch) {
    return Status::failure(StatusCode::permission_stale,
                           "the revocation is stated in epoch " + std::to_string(epoch.value()) +
                               " and the adopted epoch is " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  if (record->value.revoked) {
    return Status::failure(StatusCode::duplicate_identity,
                           "this maintenance override is already revoked");
  }
  record->value.revoked = true;
  if (at.is_set() && at > impl.model.current_tick) {
    impl.model.current_tick = at;
  }
  impl.audit(AuditKind::override_recorded, StatusCode::ok, "maintenance override revoked",
             record->value.pdu, record->value.branch);
  return impl.publish();
}

Status PduControlEngine::declare_interlock(const InterlockDeclaration& declaration) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (declaration.id.empty() || declaration.pdu.empty() || declaration.branch.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "an interlock declaration must name itself and the branch it guards");
  }
  if (!declaration.epoch.is_set() || !declaration.declared_at.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "an interlock declaration must state its epoch and declaration instant");
  }
  if (impl.find_branch(declaration.pdu, declaration.branch) == nullptr) {
    return Status::failure(StatusCode::not_found,
                           "no branch circuit with this identity is registered on this PDU");
  }
  if (impl.find_interlock(declaration.id) != nullptr) {
    return Status::failure(StatusCode::duplicate_identity,
                           "an interlock with this identity is already declared");
  }
  detail::InterlockRecord record;
  record.declaration = declaration;
  if (declaration.declared_at > impl.model.current_tick) {
    impl.model.current_tick = declaration.declared_at;
  }
  impl.model.interlocks.push_back(std::move(record));
  impl.audit(AuditKind::interlock_declared, StatusCode::ok,
             std::string("interlock declared as ") + std::string(to_token(declaration.klass)),
             declaration.pdu, declaration.branch);
  return impl.publish();
}

Status PduControlEngine::report_interlock(const InterlockStatus& status) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (status.id.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an interlock report must name the interlock");
  }
  detail::InterlockRecord* record = impl.find_interlock(status.id);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no interlock with this identity is declared");
  }
  if (!impl.model.authority_epoch.is_set() || status.epoch != impl.model.authority_epoch) {
    return Status::failure(StatusCode::permission_stale,
                           "the report is stated in epoch " + std::to_string(status.epoch.value()) +
                               " and the adopted epoch is " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  if (record->has_status && status.updated_at.is_set() && record->status.updated_at.is_set() &&
      status.updated_at < record->status.updated_at) {
    return Status::failure(StatusCode::evidence_stale,
                           "the report is older than the one already recorded for this interlock");
  }
  record->status = status;
  record->has_status = true;
  if (status.updated_at.is_set() && status.updated_at > impl.model.current_tick) {
    impl.model.current_tick = status.updated_at;
  }
  impl.audit(AuditKind::interlock_reported, StatusCode::ok,
             std::string("interlock reported ") + std::string(to_token(status.state)),
             record->declaration.pdu, record->declaration.branch);
  return impl.publish();
}

Result<ObservationId> PduControlEngine::record_observation(const TelemetryObservation& observation) {
  return record_observation_internal(observation, AuditKind::observation_recorded, false);
}

Result<ObservationId> PduControlEngine::record_observation_internal(
    const TelemetryObservation& observation, AuditKind kind, bool supersede_required) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  const Status shape = validate_observation_shape(observation);
  if (!shape.ok()) {
    return shape;
  }
  detail::BranchRecord* branch = impl.find_branch(observation.pdu, observation.branch);
  if (branch == nullptr) {
    return Status::failure(StatusCode::not_found,
                           "no branch circuit with this identity is registered on this PDU");
  }
  if (branch->definition.generation != observation.branch_generation) {
    return Status::failure(StatusCode::generation_mismatch,
                           "the observation was taken against branch generation " +
                               std::to_string(observation.branch_generation.value()) +
                               " and the current generation is " +
                               std::to_string(branch->definition.generation.value()));
  }
  detail::PduRecord* pdu = impl.find_pdu(observation.pdu);
  if (pdu == nullptr) {
    return Status::failure(StatusCode::not_found, "no PDU with this identity is registered");
  }
  if (pdu->definition.generation != observation.pdu_generation) {
    return Status::failure(StatusCode::generation_mismatch,
                           "the observation was taken against PDU generation " +
                               std::to_string(observation.pdu_generation.value()) +
                               " and the current generation is " +
                               std::to_string(pdu->definition.generation.value()));
  }

  detail::ObservationRing& ring = branch->observations;
  if (supersede_required && ring.has_current && ring.current.source == observation.source) {
    const bool later_sequence = observation.sequence > ring.current.sequence;
    const bool later_instant = observation.taken_at.is_logical() &&
                               ring.current.taken_at.is_logical() &&
                               observation.taken_at.tick > ring.current.taken_at.tick;
    if (!later_sequence && !later_instant) {
      return Status::failure(StatusCode::evidence_stale,
                             "the reading is not later than the evidence it would replace");
    }
  }

  TelemetryObservation stored = observation;
  const Result<ObservationId> id = impl.model.next_observation.next();
  if (!id.ok()) {
    return id.status();
  }
  stored.id = ObservationId::from(impl.model.next_observation.value());
  impl.model.next_observation = id.value();
  stored.accepted_tick = acceptance_tick(stored, impl.model.current_tick);
  if (stored.accepted_tick > impl.model.current_tick) {
    impl.model.current_tick = stored.accepted_tick;
  }
  if (instant_is_unset(stored.received_at)) {
    stored.received_at = impl.model.wall.is_logical() && !impl.model.wall.tick.is_set()
                             ? Instant::logical(stored.accepted_tick)
                             : impl.model.wall;
    if (instant_is_unset(stored.received_at)) {
      stored.received_at = Instant::logical(stored.accepted_tick);
    }
  }
  // Freshness is assigned here, never taken from the caller: a source that
  // claims its reading is fresh has asserted nothing this runtime accepts on
  // faith, and a reading that arrives marked "unknown" is still aged by the
  // instant it was taken at.
  stored.freshness = FreshnessState::fresh;
  stored.freshness = effective_freshness(stored, impl.model.current_tick, impl.options.evidence);

  if (!ring.has_current) {
    ring.current = stored;
    ring.has_current = true;
  } else {
    const bool same_source = ring.current.source == stored.source;
    const bool newer = same_source ? stored.sequence > ring.current.sequence
                                   : stored.accepted_tick >= ring.current.accepted_tick;
    if (newer) {
      TelemetryObservation previous = ring.current;
      previous.freshness = FreshnessState::stale;
      ring.entries.push_back(std::move(previous));
      ring.current = stored;
    } else {
      // A reordered or late arrival is kept for audit but never becomes the
      // current evidence, because a runtime that adopts the last arrival as the
      // newest fact can be walked backwards by a replayed message.
      ring.entries.push_back(stored);
    }
    while (ring.entries.size() > impl.options.bounds.max_observations_per_branch) {
      ring.entries.erase(ring.entries.begin());
    }
  }
  impl.audit(kind, StatusCode::ok,
             std::string("condition ") + std::string(to_token(stored.condition)) + " from " +
                 stored.source.value() + " at logical tick " +
                 std::to_string(stored.taken_at.tick.value()),
             stored.pdu, stored.branch, AttemptId{}, stored.id);
  const Status published = impl.publish();
  if (!published.ok()) {
    return published;
  }
  return stored.id;
}

Result<ObservationId> PduControlEngine::revalidate(const PduId& pdu, const BranchId& branch,
                                                   const TelemetryObservation& observation) {
  Impl& impl = *impl_;
  if (pdu.empty() || branch.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a revalidation must name the branch it revalidates");
  }
  if (observation.pdu != pdu || observation.branch != branch) {
    return Status::failure(StatusCode::identity_mismatch,
                           "the reading does not address the branch it is meant to revalidate");
  }
  (void)impl;
  return record_observation_internal(observation, AuditKind::observation_revalidated, true);
}

Result<ObservationId> PduControlEngine::read_back(const PduId& pdu, const BranchId& branch,
                                                  PowerAdapter& adapter, LogicalTick at) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (pdu.empty() || branch.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a read-back must name a branch");
  }
  if (!at.is_set()) {
    return Status::failure(StatusCode::invalid_argument, "a read-back must state the logical instant");
  }
  if (at < impl.model.current_tick) {
    return Status::failure(StatusCode::out_of_range,
                           "a read-back cannot be stamped earlier than the logical clock");
  }
  detail::BranchRecord* record = impl.find_branch(pdu, branch);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found,
                           "no branch circuit with this identity is registered on this PDU");
  }
  const AdapterDescriptor descriptor = adapter.describe();
  const Status descriptor_status = validate_descriptor(descriptor);
  if (!descriptor_status.ok()) {
    return descriptor_status;
  }
  AdapterReadRequest request;
  request.pdu = pdu;
  request.branch = branch;
  request.pdu_generation = impl.find_pdu(pdu)->definition.generation;
  request.branch_generation = record->definition.generation;
  request.at = at;
  Result<TelemetryObservation> reading = adapter.read(request);
  if (!reading.ok()) {
    return reading.status();
  }
  TelemetryObservation observation = reading.value();
  if (observation.pdu != request.pdu || observation.branch != request.branch) {
    return Status::failure(StatusCode::adapter_fault,
                           "the adapter returned a reading for another branch");
  }
  observation.pdu_generation = request.pdu_generation;
  observation.branch_generation = request.branch_generation;
  if (instant_is_unset(observation.taken_at)) {
    observation.taken_at = Instant::logical(at);
  }
  if (!observation.taken_at.is_logical()) {
    observation.taken_at = Instant::logical(at);
  }
  // The reading belongs to the instant the caller asked for it, so the logical
  // clock moves to that instant before the observation is accepted. That is what
  // lets a read-back taken after a command be ordered after it, and it never
  // moves the clock backwards because `at` was already checked to be at or
  // after the current instant.
  impl.model.current_tick = at;
  return record_observation_internal(observation, AuditKind::observation_recorded, false);
}

Result<Decision> PduControlEngine::evaluate(const BranchControlRequest& request) const {
  const Impl& impl = *impl_;
  if (!impl.open) {
    Decision decision;
    decision.eligible = false;
    decision.code = StatusCode::store_io;
    decision.detail = "the engine is not open";
    return decision;
  }
  Decision decision = impl.evaluate_control(request);
  if (!decision.eligible) {
    return decision;
  }
  // An idempotent replay is reported as eligible with the prior attempt named,
  // so a caller that evaluates before issuing learns that issuing would replay
  // rather than actuate.
  const Digest64 digest = request_digest(request);
  for (const detail::IdempotencyRecord& entry : impl.model.idempotency) {
    if (entry.key != request.key) {
      continue;
    }
    decision.replay = true;
    decision.replay_attempt = entry.attempt;
    if (entry.request_digest != digest) {
      decision.eligible = false;
      decision.code = StatusCode::idempotency_conflict;
      decision.detail =
          "the idempotency key was already used for a different request; a retry must repeat the "
          "same request";
    } else {
      decision.detail = "the request replays an accepted attempt and will not actuate again";
    }
    return decision;
  }
  return decision;
}

Result<AttemptRecord> PduControlEngine::issue(const BranchControlRequest& request,
                                              PowerAdapter& adapter) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (request.key.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a control request must carry an idempotency key");
  }

  // Step 2 of the documented precedence: replay precedes every currency check,
  // so a retry of an accepted attempt returns the prior result instead of being
  // refused because the branch moved on in the meantime.
  const Digest64 digest = request_digest(request);
  for (const detail::IdempotencyRecord& entry : impl.model.idempotency) {
    if (entry.key != request.key) {
      continue;
    }
    if (entry.request_digest != digest) {
      impl.refusal_count += 1;
      return Status::failure(StatusCode::idempotency_conflict,
                             "the idempotency key was already used for a different request");
    }
    const AttemptRecord* prior = impl.find_attempt(entry.attempt);
    if (prior == nullptr) {
      return Status::failure(StatusCode::internal,
                             "an idempotency entry names an attempt that is not in the journal");
    }
    AttemptRecord copy = *prior;
    copy.replayed = true;
    return copy;
  }

  const Decision decision = impl.evaluate_control(request);
  if (!decision.eligible) {
    impl.refusal_count += 1;
    const Result<AttemptId> refused_id = impl.model.next_attempt.next();
    if (refused_id.ok()) {
      AttemptRecord refused;
      refused.id = impl.model.next_attempt;
      impl.model.next_attempt = refused_id.value();
      refused.key = request.key;
      refused.request_digest = digest;
      refused.pdu = request.pdu;
      refused.branch = request.branch;
      refused.planned_pdu_generation = request.pdu_generation;
      refused.planned_branch_generation = request.branch_generation;
      refused.planned_revision = request.planned_revision;
      refused.epoch = request.epoch;
      refused.intent = request.intent;
      refused.requested_at = request.requested_at;
      refused.issued_at = impl.model.current_tick;
      refused.outcome = AttemptOutcome::refused;
      refused.code = decision.code;
      refused.detail = truncate_bytes(decision.detail, max_adapter_detail_bytes);
      refused.effect = EffectState::not_attempted;
      impl.model.attempts.push_back(std::move(refused));
      while (impl.model.attempts.size() > impl.options.bounds.max_attempt_journal) {
        impl.model.attempts.erase(impl.model.attempts.begin());
      }
      impl.audit(AuditKind::attempt_refused, decision.code, decision.detail, request.pdu,
                 request.branch, impl.model.attempts.back().id);
      (void)impl.publish();
    }
    return Status::failure(decision.code, decision.detail);
  }

  const AdapterDescriptor descriptor = adapter.describe();
  const Status descriptor_status = validate_descriptor(descriptor);
  if (!descriptor_status.ok()) {
    return descriptor_status;
  }

  detail::BranchRecord* branch = impl.find_branch(request.pdu, request.branch);
  if (branch == nullptr) {
    return Status::failure(StatusCode::internal, "the evaluated branch disappeared");
  }
  const BranchState saved_state = branch->state;
  const std::size_t saved_attempts = impl.model.attempts.size();
  const std::size_t saved_idempotency = impl.model.idempotency.size();

  const Result<AttemptId> attempt_id = impl.model.next_attempt.next();
  if (!attempt_id.ok()) {
    return attempt_id.status();
  }
  const Result<AdapterSequence> sequence = impl.model.next_adapter_sequence.next();
  if (!sequence.ok()) {
    return sequence.status();
  }

  AttemptRecord attempt;
  attempt.id = impl.model.next_attempt;
  impl.model.next_attempt = attempt_id.value();
  attempt.key = request.key;
  attempt.request_digest = digest;
  attempt.pdu = request.pdu;
  attempt.branch = request.branch;
  attempt.planned_pdu_generation = request.pdu_generation;
  attempt.planned_branch_generation = request.branch_generation;
  attempt.planned_revision = request.planned_revision;
  attempt.epoch = request.epoch;
  attempt.intent = request.intent;
  attempt.requested_at = request.requested_at;
  attempt.issued_at = impl.model.current_tick;
  attempt.outcome = AttemptOutcome::dispatched;
  attempt.code = StatusCode::ok;
  attempt.detail = "dispatched";
  attempt.dispatched = true;
  attempt.applied_command = true;
  attempt.effect = EffectState::pending;
  attempt.adapter_sequence = impl.model.next_adapter_sequence;
  attempt.maintenance_override_used = decision.maintenance_override_used;
  impl.model.next_adapter_sequence = sequence.value();
  detail::ActuationAccess::assign(attempt.authorization, attempt.id, attempt.epoch, request.pdu,
                                  request.branch, request.pdu_generation, request.branch_generation,
                                  branch->state.revision, attempt.issued_at, digest,
                                  required_control_preconditions,
                                  decision.maintenance_override_used);

  // The authoritative desired state is written at the dispatch boundary. That is
  // the conservative direction: after a crash the record says "this branch was
  // asked for this condition and may already be in it".
  branch->state.commanded.condition = Sample<BranchCondition>::known(target_condition(request.intent));
  branch->state.commanded.by_attempt = attempt.id;
  branch->state.commanded.commanded_at = attempt.issued_at;
  branch->state.last_attempt = attempt.id;
  branch->state.unresolved_attempt = true;
  branch->state.unresolved_since = attempt.issued_at;
  const Result<StateRevision> next_revision = branch->state.revision.next();
  if (!next_revision.ok()) {
    return next_revision.status();
  }
  branch->state.revision = next_revision.value();

  const AttemptId issued_id = attempt.id;
  const AdapterSequence issued_sequence = attempt.adapter_sequence;
  impl.model.attempts.push_back(std::move(attempt));
  {
    detail::IdempotencyRecord entry;
    entry.key = request.key;
    entry.request_digest = digest;
    entry.attempt = issued_id;
    impl.model.idempotency.push_back(std::move(entry));
    while (impl.model.idempotency.size() > impl.options.idempotency_window) {
      impl.model.idempotency.erase(impl.model.idempotency.begin());
    }
  }
  while (impl.model.attempts.size() > impl.options.bounds.max_attempt_journal) {
    impl.model.attempts.erase(impl.model.attempts.begin());
  }
  // A retained key must never point at an attempt the journal no longer holds.
  for (std::size_t index = impl.model.idempotency.size(); index > 0; --index) {
    const detail::IdempotencyRecord& entry = impl.model.idempotency[index - 1];
    if (impl.find_attempt(entry.attempt) == nullptr) {
      impl.model.idempotency.erase(impl.model.idempotency.begin() +
                                   static_cast<std::ptrdiff_t>(index - 1));
    }
  }
  impl.audit(AuditKind::attempt_dispatched, StatusCode::ok,
             std::string("dispatched ") + std::string(to_token(request.intent)) +
                 " through adapter " + descriptor.id.value(),
             request.pdu, request.branch, issued_id);

  // The durable command-attempt boundary. If this fails, nothing is sent.
  const Status boundary = impl.publish();
  if (!boundary.ok()) {
    impl.model.attempts.resize(saved_attempts);
    impl.model.idempotency.resize(saved_idempotency);
    branch->state = saved_state;
    impl.audit(AuditKind::attempt_refused, boundary.code(),
               "the accepted attempt could not be committed durably and was not dispatched",
               request.pdu, request.branch);
    return boundary;
  }

  AdapterCommand command;
  command.sequence_ = issued_sequence;
  command.authorization_ = impl.find_attempt(issued_id)->authorization;
  command.intent_ = request.intent;
  command.issued_at_ = impl.model.current_tick;

  AdapterOutcome outcome = adapter.execute(command);
  const Status outcome_status = validate_outcome(outcome, command);
  AdapterDisposition disposition = outcome.disposition;
  std::string detail = outcome.detail;
  StatusCode terminal_code = StatusCode::ok;
  bool fenced = false;
  if (!outcome_status.ok()) {
    fenced = outcome_status.code() == StatusCode::adapter_fenced;
    disposition = AdapterDisposition::fault;
    terminal_code = outcome_status.code();
    detail = outcome_status.message();
  }

  if (outcome.has_reading && outcome_status.ok()) {
    TelemetryObservation reading = outcome.reading;
    reading.pdu = request.pdu;
    reading.branch = request.branch;
    reading.pdu_generation = request.pdu_generation;
    reading.branch_generation = request.branch_generation;
    if (instant_is_unset(reading.taken_at)) {
      reading.taken_at = Instant::logical(impl.model.current_tick);
    }
    const Result<ObservationId> stored =
        record_observation_internal(reading, AuditKind::observation_recorded, false);
    if (!stored.ok()) {
      detail.append("; the reading returned with the acknowledgement was refused: ");
      detail.append(stored.status().token());
    }
  }

  AttemptRecord* record = impl.find_attempt(issued_id);
  if (record == nullptr) {
    return Status::failure(StatusCode::internal, "the dispatched attempt disappeared");
  }
  record->disposition = disposition;
  switch (disposition) {
    case AdapterDisposition::acknowledged:
      record->outcome = AttemptOutcome::acknowledged;
      record->code = StatusCode::ok;
      record->detail = truncate_bytes(detail.empty() ? "acknowledged" : detail,
                                      max_adapter_detail_bytes);
      record->effect = EffectState::pending;
      impl.dispatch_count += 1;
      impl.audit(AuditKind::attempt_acknowledged, StatusCode::ok,
                 "adapter acknowledged the command; the effect is not yet established",
                 request.pdu, request.branch, issued_id);
      break;
    case AdapterDisposition::refused:
    case AdapterDisposition::unavailable:
    case AdapterDisposition::fault: {
      const bool no_effect = disposition == AdapterDisposition::refused ||
                             disposition == AdapterDisposition::unavailable;
      if (disposition == AdapterDisposition::refused) {
        record->outcome = AttemptOutcome::rejected;
      } else if (disposition == AdapterDisposition::unavailable) {
        record->outcome = AttemptOutcome::unavailable;
      } else {
        // A faulted or fenced answer says nothing about whether the command took
        // effect, so the attempt stays unresolved.
        record->outcome = AttemptOutcome::unanswered;
      }
      record->code = terminal_code != StatusCode::ok
                         ? terminal_code
                         : (disposition == AdapterDisposition::refused ? StatusCode::adapter_refused
                                                                       : StatusCode::adapter_unavailable);
      record->detail = truncate_bytes(detail, max_adapter_detail_bytes);
      record->effect = no_effect ? EffectState::not_attempted : EffectState::unknown;
      record->applied_command = false;
      impl.dispatch_count += 1;
      if (no_effect) {
        // The adapter states that the command was not applied, so the desired
        // state written at the dispatch boundary is repaired rather than left
        // claiming an intention that was never carried out.
        record->effect = EffectState::not_attempted;
        branch->state.commanded = saved_state.commanded;
        const Result<StateRevision> repair = branch->state.revision.next();
        if (!repair.ok()) {
          return repair.status();
        }
        branch->state.revision = repair.value();
        impl.settle_branch(*branch, record->id);
      }
      impl.audit(AuditKind::attempt_refused, record->code, record->detail, request.pdu,
                 request.branch, issued_id);
      break;
    }
  }
  if (fenced && record->code == StatusCode::ok) {
    record->code = StatusCode::adapter_fenced;
  }
  const Status published = impl.publish();
  if (!published.ok()) {
    return published;
  }
  return *impl.find_attempt(issued_id);
}

namespace {

/// Why an observation cannot serve as evidence of an attempt's effect.
StatusCode evidence_rejection(const TelemetryObservation& observation, const AttemptRecord& attempt,
                              LogicalTick now, const EvidencePolicy& policy,
                              std::string& detail) {
  if (observation.pdu_generation != attempt.planned_pdu_generation ||
      observation.branch_generation != attempt.planned_branch_generation) {
    detail = "the observation was taken against another device generation";
    return StatusCode::generation_mismatch;
  }
  if (!observation.taken_at.is_logical()) {
    detail =
        "the observation carries no logical instant, so it cannot be ordered against the command";
    return StatusCode::evidence_stale;
  }
  if (observation.taken_at.tick < attempt.issued_at) {
    detail = "the observation was measured before the command was issued";
    return StatusCode::evidence_stale;
  }
  if (observation.accepted_tick <= attempt.issued_at) {
    detail = "the observation was accepted at the same logical instant as the command";
    return StatusCode::evidence_stale;
  }
  const FreshnessState freshness = effective_freshness(observation, now, policy);
  if (freshness != FreshnessState::fresh) {
    detail = std::string("the observation is ") + std::string(to_token(freshness));
    return StatusCode::evidence_stale;
  }
  if (!quality_usable(observation.quality, policy)) {
    detail = std::string("the observation quality is ") +
             std::string(to_token(observation.quality));
    return StatusCode::evidence_quality;
  }
  return StatusCode::ok;
}

}  // namespace

Result<VerificationResult> PduControlEngine::verify(const AttemptId& attempt) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (!attempt.is_set()) {
    return Status::failure(StatusCode::invalid_argument, "a verification must name an attempt");
  }
  AttemptRecord* record = impl.find_attempt(attempt);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no attempt with this identity is recorded");
  }
  if (!verifiable(record->outcome)) {
    return Status::failure(StatusCode::attempt_not_verifiable,
                           std::string("an attempt whose outcome is ") +
                               std::string(to_token(record->outcome)) +
                               " has no effect to establish");
  }
  detail::BranchRecord* branch = impl.find_branch(record->pdu, record->branch);
  detail::PduRecord* pdu = impl.find_pdu(record->pdu);
  if (branch == nullptr || pdu == nullptr) {
    return Status::failure(StatusCode::not_found, "the branch of this attempt is not registered");
  }

  VerificationResult result;
  result.attempt = attempt;
  result.verified_at = impl.model.current_tick;

  if (branch->definition.generation != record->planned_branch_generation ||
      pdu->definition.generation != record->planned_pdu_generation) {
    // The device was replaced while the attempt was outstanding, so evidence
    // from the new device says nothing about the old one.
    result.effect = EffectState::unknown;
    result.code = StatusCode::generation_mismatch;
    result.detail =
        "the device generation changed after this attempt, so its effect cannot be established "
        "from current evidence";
    impl.audit(AuditKind::attempt_verified, result.code, result.detail, record->pdu, record->branch,
               attempt, ObservationId{});
    const Status published = impl.publish();
    if (!published.ok()) {
      return published;
    }
    return result;
  }

  const TelemetryObservation* candidate = nullptr;
  LogicalTick candidate_tick;
  const TelemetryObservation* newest = nullptr;
  LogicalTick newest_tick;
  StatusCode newest_rejection = StatusCode::ok;
  std::string newest_detail;

  const auto consider = [&](const TelemetryObservation& observation) {
    std::string detail;
    const StatusCode rejection = evidence_rejection(observation, *record, impl.model.current_tick,
                                                    impl.options.evidence, detail);
    if (rejection == StatusCode::ok) {
      if (candidate == nullptr || observation.accepted_tick > candidate_tick ||
          (observation.accepted_tick == candidate_tick &&
           observation.sequence > candidate->sequence)) {
        candidate = &observation;
        candidate_tick = observation.accepted_tick;
      }
      return;
    }
    if (newest == nullptr || observation.accepted_tick >= newest_tick) {
      newest = &observation;
      newest_tick = observation.accepted_tick;
      newest_rejection = rejection;
      newest_detail = detail;
    }
  };
  if (branch->observations.has_current) {
    consider(branch->observations.current);
  }
  for (const TelemetryObservation& entry : branch->observations.entries) {
    consider(entry);
  }

  if (candidate == nullptr) {
    result.effect = EffectState::pending;
    if (newest == nullptr) {
      result.code = StatusCode::evidence_missing;
      result.detail = "no observation of this branch has been recorded";
      record->effect = EffectState::unknown;
    } else {
      result.code = newest_rejection;
      result.detail = newest_detail;
      record->effect = EffectState::pending;
    }
    impl.audit(AuditKind::attempt_verified, result.code, result.detail, record->pdu, record->branch,
               attempt, ObservationId{});
    const Status published = impl.publish();
    if (!published.ok()) {
      return published;
    }
    return result;
  }

  result.observation_used = true;
  result.observation = candidate->id;
  result.observed = Sample<BranchCondition>::known(candidate->condition);
  impl.verification_count += 1;

  if (candidate->condition == BranchCondition::unknown ||
      candidate->condition == BranchCondition::transitioning) {
    result.effect = EffectState::contradictory;
    result.code = StatusCode::evidence_contradictory;
    result.detail = std::string("the newest qualifying evidence reports ") +
                    std::string(to_token(candidate->condition)) +
                    ", which establishes neither the requested nor the opposite condition";
    record->effect = EffectState::contradictory;
    record->verifying_observation = candidate->id;
    impl.audit(AuditKind::attempt_verified, result.code, result.detail, record->pdu, record->branch,
               attempt, candidate->id);
    const Status published = impl.publish();
    if (!published.ok()) {
      return published;
    }
    return result;
  }

  const bool effective = candidate->condition == target_condition(record->intent);
  result.effect = effective ? EffectState::effective : EffectState::ineffective;
  result.code = StatusCode::ok;
  result.detail = effective
                      ? "fresh evidence shows the requested condition"
                      : "fresh evidence shows the opposite condition: the acknowledgement did not "
                        "produce the requested effect";
  record->effect = result.effect;
  record->outcome = effective ? AttemptOutcome::verified_effective : AttemptOutcome::observed_ineffective;
  record->code = StatusCode::ok;
  record->verifying_observation = candidate->id;
  record->verified_at = impl.model.current_tick;
  record->detail = truncate_bytes(std::string(to_token(record->outcome)) + " from observation " +
                                      std::to_string(candidate->id.value()),
                                  max_adapter_detail_bytes);

  branch->state.verified.condition = Sample<BranchCondition>::known(candidate->condition);
  branch->state.verified.observation = candidate->id;
  branch->state.verified.verified_at = impl.model.current_tick;
  branch->state.verified.by_attempt = record->id;
  // The branch is unblocked only when no other attempt on it is still open.
  impl.settle_branch(*branch, record->id);
  const Result<StateRevision> next = branch->state.revision.next();
  if (!next.ok()) {
    return next.status();
  }
  branch->state.revision = next.value();
  result.state_updated = true;
  impl.audit(AuditKind::attempt_verified, StatusCode::ok, result.detail, record->pdu, record->branch,
             attempt, candidate->id);
  const Status published = impl.publish();
  if (!published.ok()) {
    return published;
  }
  return result;
}

Result<VerificationResult> PduControlEngine::verify_with_adapter(const AttemptId& attempt,
                                                                PowerAdapter& adapter) {
  Impl& impl = *impl_;
  AttemptRecord* record = impl.find_attempt(attempt);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no attempt with this identity is recorded");
  }
  const Result<LogicalTick> next = impl.model.current_tick.next();
  if (!next.ok()) {
    return next.status();
  }
  // A read-back is a new measurement, so it is taken one logical tick later than
  // the instant the engine is currently at. That is the only ordering authority
  // this runtime has, and it never reads a clock.
  const Result<ObservationId> reading =
      read_back(record->pdu, record->branch, adapter, next.value());
  if (!reading.ok()) {
    return reading.status();
  }
  return verify(attempt);
}

Status PduControlEngine::resolve_attempt(const AttemptId& attempt, AttemptResolution resolution,
                                         const ActorId& actor, AuthorityEpoch epoch,
                                         LogicalTick at) {
  Impl& impl = *impl_;
  const Status writable = impl.ensure_writable();
  if (!writable.ok()) {
    return writable;
  }
  if (actor.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "resolving an attempt requires the actor that resolved it");
  }
  if (!epoch.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "resolving an attempt requires the authority epoch it happens in");
  }
  AttemptRecord* record = impl.find_attempt(attempt);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no attempt with this identity is recorded");
  }
  if (!resolvable(record->outcome)) {
    return Status::failure(StatusCode::attempt_not_verifiable,
                           std::string("an attempt whose outcome is ") +
                               std::string(to_token(record->outcome)) +
                               " is already closed and cannot be resolved again");
  }
  detail::BranchRecord* branch = impl.find_branch(record->pdu, record->branch);
  detail::PduRecord* pdu = impl.find_pdu(record->pdu);
  if (branch == nullptr || pdu == nullptr) {
    return Status::failure(StatusCode::not_found, "the branch of this attempt is not registered");
  }
  if (!impl.model.authority_epoch.is_set() || epoch != impl.model.authority_epoch) {
    return Status::failure(StatusCode::permission_stale,
                           "the resolution is stated in epoch " + std::to_string(epoch.value()) +
                               " and the adopted epoch is " +
                               std::to_string(impl.model.authority_epoch.value()));
  }
  const PermissionGrant* deciding = nullptr;
  const PermissionVerdict verdict = impl.permission_verdict(
      record->pdu, record->branch, pdu->definition.generation, branch->definition.generation,
      PermissionAction::lifecycle_recovery, epoch, impl.model.current_tick, &deciding);
  if (verdict != PermissionVerdict::usable) {
    return Status::failure(status_for(verdict),
                           std::string("resolving an unresolved attempt requires current "
                                       "lifecycle_recovery authority, and permission is ") +
                               std::string(to_token(verdict)));
  }
  record->outcome = resolution == AttemptResolution::cancelled ? AttemptOutcome::cancelled
                                                               : AttemptOutcome::superseded;
  record->code = StatusCode::ok;
  record->detail = truncate_bytes(std::string("resolved as ") + std::string(to_token(resolution)) +
                                      " by " + actor.value(),
                                  max_adapter_detail_bytes);
  // Resolving an attempt does not invent knowledge: the branch's physical
  // condition is unknown until fresh evidence establishes it.
  branch->state.verified.condition = Sample<BranchCondition>::unknown();
  branch->state.verified.observation = ObservationId{};
  branch->state.verified.verified_at = LogicalTick{};
  branch->state.verified.by_attempt = record->id;
  impl.settle_branch(*branch, record->id);
  const Result<StateRevision> next = branch->state.revision.next();
  if (!next.ok()) {
    return next.status();
  }
  branch->state.revision = next.value();
  if (at.is_set() && at > impl.model.current_tick) {
    impl.model.current_tick = at;
  }
  impl.audit(AuditKind::attempt_resolved, StatusCode::ok, record->detail, record->pdu,
             record->branch, record->id);
  return impl.publish();
}

Result<PduSnapshot> PduControlEngine::inspect_pdu(const PduId& pdu) const {
  const Impl& impl = *impl_;
  const detail::PduRecord* record = impl.find_pdu(pdu);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no PDU with this identity is registered");
  }
  PduSnapshot snapshot;
  snapshot.id = record->definition.id;
  snapshot.generation = record->definition.generation;
  snapshot.revision = record->state.revision;
  snapshot.lifecycle = record->state.lifecycle;
  snapshot.label = record->definition.label;
  for (const detail::BranchRecord& branch : impl.model.branches) {
    if (branch.definition.pdu != pdu) {
      continue;
    }
    snapshot.branches.push_back(impl.snapshot_of(branch, *record));
  }
  return snapshot;
}

Result<BranchSnapshot> PduControlEngine::inspect_branch(const PduId& pdu,
                                                        const BranchId& branch) const {
  const Impl& impl = *impl_;
  const detail::BranchRecord* record = impl.find_branch(pdu, branch);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found,
                           "no branch circuit with this identity is registered on this PDU");
  }
  const detail::PduRecord* pdu_record = impl.find_pdu(pdu);
  if (pdu_record == nullptr) {
    return Status::failure(StatusCode::internal, "the branch has no PDU");
  }
  return impl.snapshot_of(*record, *pdu_record);
}

Result<BranchSnapshot> PduControlEngine::inspect_branch(const BranchId& branch) const {
  const Impl& impl = *impl_;
  const detail::BranchRecord* record = impl.find_branch_any(branch);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no branch circuit with this identity is registered");
  }
  const detail::PduRecord* pdu_record = impl.find_pdu(record->definition.pdu);
  if (pdu_record == nullptr) {
    return Status::failure(StatusCode::internal, "the branch has no PDU");
  }
  return impl.snapshot_of(*record, *pdu_record);
}

std::vector<PduSnapshot> PduControlEngine::inspect_all() const {
  std::vector<PduSnapshot> snapshots;
  if (impl_ == nullptr) {
    return snapshots;
  }
  const Impl& impl = *impl_;
  snapshots.reserve(impl.model.pdus.size());
  for (const detail::PduRecord& record : impl.model.pdus) {
    PduSnapshot snapshot;
    snapshot.id = record.definition.id;
    snapshot.generation = record.definition.generation;
    snapshot.revision = record.state.revision;
    snapshot.lifecycle = record.state.lifecycle;
    snapshot.label = record.definition.label;
    for (const detail::BranchRecord& branch : impl.model.branches) {
      if (branch.definition.pdu != record.definition.id) {
        continue;
      }
      snapshot.branches.push_back(impl.snapshot_of(branch, record));
    }
    snapshots.push_back(std::move(snapshot));
  }
  return snapshots;
}

std::vector<AttemptRecord> PduControlEngine::attempts(std::size_t limit) const {
  std::vector<AttemptRecord> result;
  if (impl_ == nullptr) {
    return result;
  }
  const Impl& impl = *impl_;
  if (limit == 0 || limit > impl.options.bounds.max_attempt_journal) {
    limit = impl.options.bounds.max_attempt_journal;
  }
  const std::size_t total = impl.model.attempts.size();
  const std::size_t first = total > limit ? total - limit : 0;
  result.reserve(total - first);
  for (std::size_t index = first; index < total; ++index) {
    result.push_back(impl.model.attempts[index]);
  }
  return result;
}

Result<AttemptRecord> PduControlEngine::attempt(const AttemptId& attempt) const {
  const Impl& impl = *impl_;
  const AttemptRecord* record = impl.find_attempt(attempt);
  if (record == nullptr) {
    return Status::failure(StatusCode::not_found, "no attempt with this identity is recorded");
  }
  return *record;
}

Result<AttemptRecord> PduControlEngine::attempt_by_key(const IdempotencyKey& key) const {
  const Impl& impl = *impl_;
  if (key.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an idempotency key must not be empty");
  }
  for (const detail::IdempotencyRecord& entry : impl.model.idempotency) {
    if (entry.key != key) {
      continue;
    }
    const AttemptRecord* record = impl.find_attempt(entry.attempt);
    if (record == nullptr) {
      return Status::failure(StatusCode::internal,
                             "an idempotency entry names an attempt that is not in the journal");
    }
    AttemptRecord copy = *record;
    copy.replayed = true;
    return copy;
  }
  return Status::failure(StatusCode::not_found,
                         "no retained attempt was accepted under this idempotency key");
}

std::vector<AuditEntry> PduControlEngine::history(const HistoryQuery& query) const {
  std::vector<AuditEntry> result;
  if (impl_ == nullptr) {
    return result;
  }
  const Impl& impl = *impl_;
  std::size_t limit = query.limit;
  if (limit == 0 || limit > impl.options.bounds.max_audit_entries) {
    limit = impl.options.bounds.max_audit_entries;
  }
  for (auto it = impl.model.audit.rbegin(); it != impl.model.audit.rend(); ++it) {
    const AuditEntry& entry = *it;
    if (query.has_pdu && entry.pdu != query.pdu) {
      continue;
    }
    if (query.has_branch && entry.branch != query.branch) {
      continue;
    }
    if (query.has_attempt && entry.attempt != query.attempt) {
      continue;
    }
    if (query.has_kind && entry.kind != query.kind) {
      continue;
    }
    result.push_back(entry);
    if (result.size() >= limit) {
      break;
    }
  }
  return result;
}

std::string PduControlEngine::canonical_state() const {
  if (impl_ == nullptr) {
    return std::string();
  }
  return detail::canonical_text(impl_->model);
}

Digest64 PduControlEngine::state_digest() const {
  if (impl_ == nullptr) {
    return Digest64{};
  }
  return digest_of(detail::canonical_text(impl_->model));
}

}  // namespace pdu_control


