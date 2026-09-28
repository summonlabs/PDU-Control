#include "pdu_control/authority.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace pdu_control {
namespace {

/// Emitted in this fixed order so that a mask always renders identically.
constexpr std::pair<PermissionAction, std::string_view> kActionTokens[] = {
    {PermissionAction::control_de_energize, "control_de_energize"},
    {PermissionAction::control_energize, "control_energize"},
    {PermissionAction::lifecycle_administrative, "lifecycle_administrative"},
    {PermissionAction::lifecycle_recovery, "lifecycle_recovery"},
    {PermissionAction::lifecycle_service, "lifecycle_service"},
    {PermissionAction::maintenance_override, "maintenance_override"},
};

}  // namespace

std::string to_token(PermissionActions actions) {
  if (actions == 0) {
    return "none";
  }
  std::string text;
  for (const auto& entry : kActionTokens) {
    if ((actions & action_mask(entry.first)) == 0) {
      continue;
    }
    if (!text.empty()) {
      text.push_back('|');
    }
    text.append(entry.second);
  }
  return text;
}

Result<PermissionActions> parse_permission_actions(std::string_view text) {
  if (text.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a permission action list must not be empty");
  }
  if (text == "none") {
    return PermissionActions{0};
  }
  PermissionActions mask = 0;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t separator = text.find('|', start);
    const std::string_view piece =
        separator == std::string_view::npos ? text.substr(start) : text.substr(start, separator - start);
    bool recognized = false;
    for (const auto& entry : kActionTokens) {
      if (entry.second == piece) {
        mask = static_cast<PermissionActions>(mask | action_mask(entry.first));
        recognized = true;
        break;
      }
    }
    if (!recognized) {
      return Status::failure(StatusCode::malformed_input,
                             "unrecognized permission action '" + std::string(piece) + "'");
    }
    if (separator == std::string_view::npos) {
      break;
    }
    start = separator + 1;
  }
  return mask;
}

Result<PermissionAction> required_action(LifecycleState from, LifecycleState to) noexcept {
  const Result<TransitionClass> klass = transition_class(from, to);
  if (!klass.ok()) {
    return klass.status();
  }
  switch (klass.value()) {
    case TransitionClass::commission:
    case TransitionClass::service:
    case TransitionClass::fault:
      return PermissionAction::lifecycle_service;
    case TransitionClass::recovery:
      return PermissionAction::lifecycle_recovery;
    case TransitionClass::administrative:
      return PermissionAction::lifecycle_administrative;
  }
  return Status::failure(StatusCode::internal, "unhandled transition class");
}

Status validate_grant(const PermissionGrant& grant) {
  if (grant.id.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a grant requires an id");
  }
  if (grant.issuer.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a grant requires an issuer");
  }
  if (!grant.epoch.is_set()) {
    return Status::failure(StatusCode::invalid_argument, "a grant requires an authority epoch");
  }
  if (grant.pdu.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a grant requires a PDU scope");
  }
  if (grant.branch.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a grant requires a branch scope");
  }
  if (!grant.pdu_generation.is_set() || !grant.branch_generation.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a grant requires the device generations it was issued against");
  }
  if (grant.actions == 0) {
    return Status::failure(StatusCode::invalid_argument, "a grant must authorize at least one action");
  }
  if (!grant.issued_at.is_set()) {
    return Status::failure(StatusCode::invalid_argument, "a grant requires the instant it was issued");
  }
  if (grant.not_after.is_set() && grant.not_after <= grant.issued_at) {
    return Status::failure(StatusCode::invalid_argument,
                           "a grant must expire after the instant it was issued");
  }
  return Status::success();
}

std::string_view to_token(PermissionVerdict verdict) noexcept {
  switch (verdict) {
    case PermissionVerdict::usable:
      return "usable";
    case PermissionVerdict::missing:
      return "missing";
    case PermissionVerdict::stale_epoch:
      return "stale_epoch";
    case PermissionVerdict::expired:
      return "expired";
    case PermissionVerdict::revoked:
      return "revoked";
    case PermissionVerdict::scope_mismatch:
      return "scope_mismatch";
    case PermissionVerdict::generation_mismatch:
      return "generation_mismatch";
    case PermissionVerdict::action_missing:
      return "action_missing";
    case PermissionVerdict::malformed:
      return "malformed";
  }
  return "unknown_verdict";
}

StatusCode status_for(PermissionVerdict verdict) noexcept {
  switch (verdict) {
    case PermissionVerdict::usable:
      return StatusCode::ok;
    case PermissionVerdict::missing:
      return StatusCode::permission_missing;
    case PermissionVerdict::stale_epoch:
    case PermissionVerdict::expired:
    case PermissionVerdict::revoked:
      return StatusCode::permission_stale;
    case PermissionVerdict::scope_mismatch:
    case PermissionVerdict::generation_mismatch:
      return StatusCode::permission_scope_mismatch;
    case PermissionVerdict::action_missing:
      return StatusCode::permission_denied;
    case PermissionVerdict::malformed:
      return StatusCode::invalid_argument;
  }
  return StatusCode::internal;
}

std::string_view to_token(ObligationClass value) noexcept {
  switch (value) {
    case ObligationClass::protected_obligation:
      return "protected";
    case ObligationClass::advisory:
      return "advisory";
  }
  return "unknown_class";
}

bool parse_obligation_class(std::string_view token, ObligationClass& out) noexcept {
  if (token == "protected" || token == "protected_obligation") {
    out = ObligationClass::protected_obligation;
    return true;
  }
  if (token == "advisory") {
    out = ObligationClass::advisory;
    return true;
  }
  return false;
}

std::string_view to_token(InterlockState state) noexcept {
  switch (state) {
    case InterlockState::satisfied:
      return "satisfied";
    case InterlockState::open:
      return "open";
    case InterlockState::unknown:
      return "unknown";
  }
  return "unknown_state";
}

bool parse_interlock_state(std::string_view token, InterlockState& out) noexcept {
  constexpr InterlockState kStates[] = {InterlockState::satisfied, InterlockState::open,
                                        InterlockState::unknown};
  for (const InterlockState state : kStates) {
    if (to_token(state) == token) {
      out = state;
      return true;
    }
  }
  return false;
}

std::string_view to_token(InterlockVerdict verdict) noexcept {
  switch (verdict) {
    case InterlockVerdict::clear:
      return "clear";
    case InterlockVerdict::blocked:
      return "blocked";
    case InterlockVerdict::unknown:
      return "unknown";
  }
  return "unknown_verdict";
}

std::string_view to_token(OverrideVerdict verdict) noexcept {
  switch (verdict) {
    case OverrideVerdict::usable:
      return "usable";
    case OverrideVerdict::missing:
      return "missing";
    case OverrideVerdict::stale_epoch:
      return "stale_epoch";
    case OverrideVerdict::expired:
      return "expired";
    case OverrideVerdict::revoked:
      return "revoked";
    case OverrideVerdict::scope_mismatch:
      return "scope_mismatch";
    case OverrideVerdict::generation_mismatch:
      return "generation_mismatch";
  }
  return "unknown_verdict";
}

StatusCode status_for(OverrideVerdict verdict) noexcept {
  switch (verdict) {
    case OverrideVerdict::usable:
      return StatusCode::ok;
    case OverrideVerdict::missing:
      return StatusCode::permission_missing;
    case OverrideVerdict::stale_epoch:
    case OverrideVerdict::expired:
    case OverrideVerdict::revoked:
      return StatusCode::permission_stale;
    case OverrideVerdict::scope_mismatch:
    case OverrideVerdict::generation_mismatch:
      return StatusCode::permission_scope_mismatch;
  }
  return StatusCode::internal;
}

}  // namespace pdu_control
