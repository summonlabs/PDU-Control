#include "pdu_control/attempt.hpp"

namespace pdu_control {

std::string_view to_token(EffectState state) noexcept {
  switch (state) {
    case EffectState::not_attempted:
      return "not_attempted";
    case EffectState::pending:
      return "pending";
    case EffectState::effective:
      return "effective";
    case EffectState::ineffective:
      return "ineffective";
    case EffectState::contradictory:
      return "contradictory";
    case EffectState::unknown:
      return "unknown";
  }
  return "unknown_effect";
}

bool parse_effect_state(std::string_view token, EffectState& out) noexcept {
  constexpr EffectState kStates[] = {
      EffectState::not_attempted, EffectState::pending,  EffectState::effective,
      EffectState::ineffective,   EffectState::contradictory, EffectState::unknown};
  for (const EffectState state : kStates) {
    if (to_token(state) == token) {
      out = state;
      return true;
    }
  }
  return false;
}

std::string_view to_token(AttemptOutcome outcome) noexcept {
  switch (outcome) {
    case AttemptOutcome::refused:
      return "refused";
    case AttemptOutcome::dispatched:
      return "dispatched";
    case AttemptOutcome::acknowledged:
      return "acknowledged";
    case AttemptOutcome::rejected:
      return "rejected";
    case AttemptOutcome::unavailable:
      return "unavailable";
    case AttemptOutcome::unanswered:
      return "unanswered";
    case AttemptOutcome::verified_effective:
      return "verified_effective";
    case AttemptOutcome::observed_ineffective:
      return "observed_ineffective";
    case AttemptOutcome::recovery_required:
      return "recovery_required";
    case AttemptOutcome::superseded:
      return "superseded";
    case AttemptOutcome::cancelled:
      return "cancelled";
  }
  return "unknown_outcome";
}

bool parse_attempt_outcome(std::string_view token, AttemptOutcome& out) noexcept {
  constexpr AttemptOutcome kOutcomes[] = {
      AttemptOutcome::refused,       AttemptOutcome::dispatched,
      AttemptOutcome::acknowledged,  AttemptOutcome::rejected,
      AttemptOutcome::unavailable,   AttemptOutcome::unanswered,
      AttemptOutcome::verified_effective, AttemptOutcome::observed_ineffective,
      AttemptOutcome::recovery_required,  AttemptOutcome::superseded,
      AttemptOutcome::cancelled};
  for (const AttemptOutcome outcome : kOutcomes) {
    if (to_token(outcome) == token) {
      out = outcome;
      return true;
    }
  }
  return false;
}

}  // namespace pdu_control
