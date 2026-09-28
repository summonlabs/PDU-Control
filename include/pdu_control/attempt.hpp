#pragma once

// Operation attempts: the durable record of what this runtime tried to do, what
// the adapter said, and what evidence subsequently established.
//
// The attempt is the unit of idempotency and of crash recovery. It is written
// durably *before* a command leaves for the adapter, so a process that dies
// immediately after dispatch leaves behind a record that says "a command may
// have reached this branch". Recovery adopts that record and refuses to issue
// anything new on the branch until the effect is established or the attempt is
// explicitly resolved. A command is never re-sent merely because the process
// that sent it died.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pdu_control/adapter.hpp"
#include "pdu_control/model.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control {

/// What evidence has established about the physical effect of an attempt.
enum class EffectState : std::uint8_t {
  not_attempted, ///< Nothing was dispatched; no effect is possible.
  pending,       ///< Dispatched, but no qualifying fresh evidence exists yet.
  effective,     ///< Fresh evidence shows the requested condition.
  ineffective,   ///< Fresh evidence shows the opposite condition.
  contradictory, ///< Fresh evidence is transitional or self-contradictory.
  unknown,       ///< Evidence cannot be established at all.
};

[[nodiscard]] std::string_view to_token(EffectState state) noexcept;
[[nodiscard]] bool parse_effect_state(std::string_view token, EffectState& out) noexcept;

/// Terminal and non-terminal disposition of an attempt.
enum class AttemptOutcome : std::uint8_t {
  refused,             ///< No command was built. `status` carries the reason.
  dispatched,          ///< A command was built and handed to the adapter.
  acknowledged,        ///< The adapter acknowledged it. Not an effect.
  rejected,            ///< The adapter refused it.
  unavailable,         ///< The adapter could not attempt it.
  unanswered,          ///< The adapter's answer was fenced or malformed.
  verified_effective,  ///< Fresh evidence established the requested condition.
  observed_ineffective,///< Fresh evidence established the opposite condition.
  recovery_required,   ///< The process ended before the effect was established.
  superseded,          ///< A later attempt on the branch replaced it.
  cancelled,           ///< Explicitly abandoned.
};

[[nodiscard]] std::string_view to_token(AttemptOutcome outcome) noexcept;
[[nodiscard]] bool parse_attempt_outcome(std::string_view token, AttemptOutcome& out) noexcept;

/// True when no further transition of this attempt is expected without an
/// explicit recovery or verification step.
[[nodiscard]] constexpr bool is_terminal(AttemptOutcome outcome) noexcept {
  switch (outcome) {
    case AttemptOutcome::refused:
    case AttemptOutcome::rejected:
    case AttemptOutcome::unavailable:
    case AttemptOutcome::unanswered:
    case AttemptOutcome::verified_effective:
    case AttemptOutcome::observed_ineffective:
    case AttemptOutcome::recovery_required:
    case AttemptOutcome::superseded:
    case AttemptOutcome::cancelled:
      return true;
    case AttemptOutcome::dispatched:
    case AttemptOutcome::acknowledged:
      return false;
  }
  return true;
}

/// True when a command was actually built and handed to an adapter. Only these
/// attempts are retained by the idempotency window.
[[nodiscard]] constexpr bool is_accepted(AttemptOutcome outcome) noexcept {
  switch (outcome) {
    case AttemptOutcome::dispatched:
    case AttemptOutcome::acknowledged:
    case AttemptOutcome::rejected:
    case AttemptOutcome::unavailable:
    case AttemptOutcome::unanswered:
    case AttemptOutcome::verified_effective:
    case AttemptOutcome::observed_ineffective:
    case AttemptOutcome::recovery_required:
    case AttemptOutcome::superseded:
      return true;
    case AttemptOutcome::refused:
    case AttemptOutcome::cancelled:
      return false;
  }
  return false;
}

/// True while the attempt still needs a resolution step (verification or an
/// explicit cancel/supersede) before the branch may be controlled again.
[[nodiscard]] constexpr bool is_unresolved(AttemptOutcome outcome) noexcept {
  return outcome == AttemptOutcome::dispatched || outcome == AttemptOutcome::acknowledged;
}

/// The durable record of one attempt.
struct AttemptRecord {
  AttemptId id;
  IdempotencyKey key;
  Digest64 request_digest;   ///< Binds the key to the exact request it served.
  bool replayed{false};      ///< True when this copy was served from the window.

  PduId pdu;
  BranchId branch;
  PduGeneration planned_pdu_generation;
  BranchGeneration planned_branch_generation;
  StateRevision planned_revision;
  AuthorityEpoch epoch;
  CommandIntent intent{CommandIntent::de_energize};
  LogicalTick requested_at;
  LogicalTick issued_at;

  AttemptOutcome outcome{AttemptOutcome::refused};
  StatusCode code{StatusCode::ok};   ///< Primary reason for a refusal or terminal state.
  std::string detail;

  ActuationAuthorization authorization;
  bool dispatched{false};
  AdapterSequence adapter_sequence;
  AdapterDisposition disposition{AdapterDisposition::fault};

  EffectState effect{EffectState::not_attempted};
  ObservationId verifying_observation;
  LogicalTick verified_at;

  /// True only when the accepted command wrote the authoritative commanded
  /// state of the branch. A refused or rejected attempt never sets it.
  bool applied_command{false};
  bool maintenance_override_used{false};
};

/// Result of a verification step.
struct VerificationResult {
  AttemptId attempt;
  EffectState effect{EffectState::unknown};
  StatusCode code{StatusCode::evidence_missing};
  std::string detail;
  bool observation_used{false};
  ObservationId observation;
  Sample<BranchCondition> observed;
  LogicalTick verified_at;
  /// True when the attempt record and the branch's verified state changed.
  bool state_updated{false};
};

/// One precondition check, kept for the explanation trace of an evaluation.
struct PreconditionCheck {
  PreconditionKind kind{PreconditionKind::none};
  bool satisfied{false};
  StatusCode code{StatusCode::ok};
  std::string detail;
};

/// The answer to "may this control request be attempted, and against what?".
///
/// `evaluate` produces one of these without mutating anything. `issue` produces
/// the same decision and then acts on it.
struct Decision {
  bool eligible{false};
  StatusCode code{StatusCode::ok};   ///< `ok` exactly when `eligible`.
  std::string detail;

  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation;
  BranchGeneration branch_generation;
  StateRevision revision;
  AuthorityEpoch epoch;
  CommandIntent intent{CommandIntent::de_energize};

  PermissionVerdict permission{PermissionVerdict::missing};
  OverrideVerdict override_verdict{OverrideVerdict::missing};
  InterlockSummary interlocks;
  LimitVerdict limit{LimitVerdict::limit_unknown};
  Sample<BranchCondition> prior_commanded;
  Sample<BranchCondition> prior_observed;
  bool maintenance_override_used{false};
  bool replay{false};           ///< True when the request replayed a retained attempt.
  AttemptId replay_attempt;

  /// Deterministic, ordered explanation of the checks performed. Bounded by the
  /// number of precondition classes, so it can never grow with input.
  std::vector<PreconditionCheck> trace;
};

}  // namespace pdu_control
