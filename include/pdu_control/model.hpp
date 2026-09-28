#pragma once

// The modeled entities: PDUs, branch circuits, their lifecycle, their commanded
// state, and their verified state.
//
// Three values are deliberately kept apart for every branch:
//   * commanded  - what this runtime last asked the branch to do;
//   * observed   - what a telemetry source last said about the branch;
//   * verified   - what a *fresh* observation established after a command.
// None of the three is derived from another. In particular, an acknowledgement
// from an adapter updates none of them.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pdu_control/authority.hpp"
#include "pdu_control/evidence.hpp"
#include "pdu_control/ids.hpp"
#include "pdu_control/lifecycle.hpp"
#include "pdu_control/status.hpp"
#include "pdu_control/units.hpp"

namespace pdu_control {

/// Bounds applied to every externally influenced collection and string in the
/// model. The store enforces the same numbers when reading, so a durable file
/// can never describe a structure larger than a running engine would accept.
struct ModelBounds {
  std::size_t max_pdus{256};
  std::size_t max_branches_per_pdu{256};
  std::size_t max_label_bytes{160};
  std::size_t max_required_interlocks_per_branch{32};
  std::size_t max_grants{4096};
  std::size_t max_overrides{1024};
  std::size_t max_observations_per_branch{64};
  std::size_t max_attempt_journal{512};
  std::size_t max_idempotency_window{512};
  std::size_t max_audit_entries{16384};
};

/// Validates a free-text label: optional, at most `max_label_bytes` bytes, and
/// printable ASCII only. Non-ASCII bytes are refused rather than sanitized, so
/// malformed or overlong encodings cannot hide inside a label.
[[nodiscard]] Status validate_label(std::string_view label, std::size_t max_bytes);

/// Definition of a PDU.
struct PduDefinition {
  PduId id;
  PduGeneration generation;
  LifecycleState lifecycle{LifecycleState::provisioned};
  std::string label;
  IssuerId owner;            ///< Owning authority layer, for provenance only.
  ProtectionZoneId zone;     ///< Optional upstream protection zone reference.
  LogicalTick registered_at;
};

/// Definition of a branch circuit.
struct BranchDefinition {
  BranchId id;
  PduId pdu;
  BranchGeneration generation;
  LifecycleState lifecycle{LifecycleState::provisioned};
  std::string label;
  BranchLimits limits;
  /// Interlocks that must be satisfied before this branch may be controlled.
  /// An interlock named here but never declared fails closed.
  std::vector<InterlockId> required_interlocks;
  LogicalTick registered_at;
};

/// Definition-shape validation. Independent of current runtime state.
[[nodiscard]] Status validate(const PduDefinition& definition, const ModelBounds& bounds);
[[nodiscard]] Status validate(const BranchDefinition& definition, const ModelBounds& bounds);

/// The condition a branch was last commanded toward, with the proof of *why*
/// this runtime believes it: the attempt that issued the command.
struct CommandedState {
  Sample<BranchCondition> condition; ///< `unknown` until a command is issued.
  AttemptId by_attempt;
  LogicalTick commanded_at;
};

/// The condition established by fresh evidence after a command.
struct VerifiedEffect {
  Sample<BranchCondition> condition; ///< `unknown` until evidence establishes it.
  ObservationId observation;         ///< Evidence that established the condition.
  LogicalTick verified_at;
  AttemptId by_attempt;

  [[nodiscard]] bool established() const noexcept { return condition.has_value(); }
};

/// Authoritative mutable state of one branch circuit.
struct BranchState {
  LifecycleState lifecycle{LifecycleState::provisioned};
  StateRevision revision;
  CommandedState commanded;
  VerifiedEffect verified;
  AttemptId last_attempt;
  /// Set when the last attempt has no terminal outcome, for example because the
  /// process died between dispatching the command and observing the effect.
  /// While set, no new control command is accepted on this branch.
  bool unresolved_attempt{false};
  LogicalTick unresolved_since;
};

/// Authoritative mutable state of one PDU.
struct PduState {
  LifecycleState lifecycle{LifecycleState::provisioned};
  StateRevision revision;
};

/// A branch as presented for inspection. Immutable: the engine builds one under
/// its read path and hands it out; the caller cannot mutate engine state
/// through it.
struct BranchSnapshot {
  BranchId id;
  PduId pdu;
  BranchGeneration generation;
  PduGeneration pdu_generation;
  StateRevision revision;
  LifecycleState lifecycle{LifecycleState::provisioned};
  LifecycleState pdu_lifecycle{LifecycleState::provisioned};
  std::string label;
  ControlScope control_scope{ControlScope::forbidden};
  CommandedState commanded;
  VerifiedEffect verified;
  TelemetryView observation;
  BranchLimits limits;
  std::vector<InterlockView> interlocks;
  InterlockSummary interlocks_summary;
  PermissionView permission;
  AttemptId last_attempt;
  bool unresolved_attempt{false};
};

/// A PDU with its branches.
struct PduSnapshot {
  PduId id;
  PduGeneration generation;
  StateRevision revision;
  LifecycleState lifecycle{LifecycleState::provisioned};
  std::string label;
  std::vector<BranchSnapshot> branches;
};

/// A request to move an entity through the lifecycle.
///
/// An empty `branch` addresses the PDU itself. The request states the authority
/// epoch, the device generations, and the state revision it was planned against;
/// all three are checked and a mismatch is refused rather than merged.
struct LifecycleRequest {
  PduId pdu;
  BranchId branch;              ///< Empty addresses the PDU.
  PduGeneration pdu_generation;
  BranchGeneration branch_generation;
  StateRevision planned_revision;
  AuthorityEpoch epoch;
  LifecycleState to{LifecycleState::provisioned};
  ActorId actor;
  LogicalTick requested_at;
};

/// A request to control a branch circuit.
///
/// `planned_revision` is optional: when set, it must equal the branch's current
/// revision or the request is refused with `revision_mismatch`. `planned_revision`
/// is required (and is always checked) for lifecycle requests.
struct BranchControlRequest {
  IdempotencyKey key;
  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation;
  BranchGeneration branch_generation;
  StateRevision planned_revision;   ///< Unset means "not checked".
  AuthorityEpoch epoch;
  CommandIntent intent{CommandIntent::de_energize};
  ActorId actor;
  LogicalTick requested_at;
  /// Optional projection of the load the command would produce, checked against
  /// the branch limits with checked arithmetic.
  CurrentSample projected_current;
};

/// A request to change the limit metadata of a branch.
struct LimitUpdateRequest {
  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation;
  BranchGeneration branch_generation;
  StateRevision planned_revision;
  AuthorityEpoch epoch;
  BranchLimits limits;
  ActorId actor;
  LogicalTick requested_at;
};

}  // namespace pdu_control
