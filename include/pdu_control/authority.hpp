#pragma once

// Permission and interlock references from the layer that owns them.
//
// This runtime adjudicates control; it does not decide who may control. The
// authority layer (a power control plane, a feed authority, a maintenance
// window system) issues grants that name an epoch, a scope, a device
// generation, and an expiry. This runtime checks those references and refuses
// anything it cannot establish as current. It never mints a permission, never
// extends one, and never treats the mere existence of a grant as authority.

#include <cstdint>
#include <string_view>
#include <vector>

#include "pdu_control/evidence.hpp"
#include "pdu_control/ids.hpp"
#include "pdu_control/lifecycle.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control {

/// What a grant authorizes. A bitmask rather than an enumerator because one
/// grant routinely covers several actions on the same scope.
enum class PermissionAction : std::uint16_t {
  none = 0,
  control_energize = 1U << 0,
  control_de_energize = 1U << 1,
  lifecycle_service = 1U << 2,
  lifecycle_recovery = 1U << 3,
  lifecycle_administrative = 1U << 4,
  maintenance_override = 1U << 5,
};

using PermissionActions = std::uint16_t;

[[nodiscard]] constexpr PermissionActions action_mask(PermissionAction action) noexcept {
  return static_cast<PermissionActions>(action);
}
[[nodiscard]] constexpr bool has_action(PermissionActions mask, PermissionAction action) noexcept {
  return (mask & action_mask(action)) != 0;
}
[[nodiscard]] constexpr PermissionActions combine(PermissionAction left,
                                                  PermissionAction right) noexcept {
  return static_cast<PermissionActions>(action_mask(left) | action_mask(right));
}
[[nodiscard]] constexpr PermissionActions operator|(PermissionAction left,
                                                    PermissionAction right) noexcept {
  return combine(left, right);
}
[[nodiscard]] constexpr PermissionActions operator|(PermissionActions left,
                                                    PermissionAction right) noexcept {
  return static_cast<PermissionActions>(left | action_mask(right));
}

/// Stable token list, "|"-separated and sorted, for example "control_energize".
[[nodiscard]] std::string to_token(PermissionActions actions);
/// Parses a "|"-separated token list produced by `to_token`.
[[nodiscard]] Result<PermissionActions> parse_permission_actions(std::string_view text);

/// The action a control command requires.
[[nodiscard]] constexpr PermissionAction required_action(CommandIntent intent) noexcept {
  return intent == CommandIntent::energize ? PermissionAction::control_energize
                                           : PermissionAction::control_de_energize;
}

/// The action a lifecycle transition requires, or `transition_invalid` when the
/// transition is not declared at all.
[[nodiscard]] Result<PermissionAction> required_action(LifecycleState from,
                                                       LifecycleState to) noexcept;

/// A grant issued by the owning authority layer.
struct PermissionGrant {
  AuthorityId id;
  IssuerId issuer;                  ///< For example "power-control-plane".
  AuthorityEpoch epoch;             ///< Epoch the grant was issued in.
  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation;     ///< Device generation the grant was issued against.
  BranchGeneration branch_generation;
  PermissionActions actions{0};
  LogicalTick issued_at;
  LogicalTick not_after;            ///< Exclusive expiry; unset means "no expiry stated".
  bool revoked{false};
  LogicalTick revoked_at;

  [[nodiscard]] bool operator==(const PermissionGrant& other) const noexcept {
    return id == other.id && issuer == other.issuer && epoch == other.epoch &&
           pdu == other.pdu && branch == other.branch &&
           pdu_generation == other.pdu_generation &&
           branch_generation == other.branch_generation && actions == other.actions &&
           issued_at == other.issued_at && not_after == other.not_after &&
           revoked == other.revoked && revoked_at == other.revoked_at;
  }
};

/// Validation of a grant's shape, independent of any current state: bounded
/// identifiers, a stated epoch, a scope, at least one action, and an expiry that
/// is not before the instant it was issued.
[[nodiscard]] Status validate_grant(const PermissionGrant& grant);

/// Why a grant was or was not usable. Reported by `PermissionVerdict`.
enum class PermissionVerdict : std::uint8_t {
  usable,             ///< Current, in epoch, unexpired, in scope, action present.
  missing,            ///< No grant covers the branch.
  stale_epoch,        ///< Issued in an epoch this runtime no longer honors.
  expired,            ///< Past its stated expiry.
  revoked,            ///< Explicitly withdrawn.
  scope_mismatch,     ///< Wrong pdu/branch scope.
  generation_mismatch,///< Issued against another device generation.
  action_missing,     ///< Does not cover the requested action.
  malformed,          ///< Fails `validate_grant`.
};

[[nodiscard]] std::string_view to_token(PermissionVerdict verdict) noexcept;

/// The status code a verdict maps to. `usable` maps to `ok`.
[[nodiscard]] StatusCode status_for(PermissionVerdict verdict) noexcept;

/// The grant as presented for inspection.
struct PermissionView {
  bool present{false};
  AuthorityId id;
  IssuerId issuer;
  AuthorityEpoch epoch;
  PermissionActions actions{0};
  LogicalTick issued_at;
  LogicalTick not_after;
  bool revoked{false};
  PermissionVerdict verdict{PermissionVerdict::missing};
};

/// How an obligation behaves when it cannot be established.
enum class ObligationClass : std::uint8_t {
  protected_obligation, ///< Fails closed: unknown or open blocks control.
  advisory,             ///< Reported, does not block control.
};

[[nodiscard]] std::string_view to_token(ObligationClass value) noexcept;
[[nodiscard]] bool parse_obligation_class(std::string_view token, ObligationClass& out) noexcept;

/// State of an interlock as last reported by its owner.
enum class InterlockState : std::uint8_t {
  satisfied, ///< The obligation is met.
  open,      ///< The obligation is not met.
  unknown,   ///< The owner cannot state the obligation. Blocks protected obligations.
};

[[nodiscard]] std::string_view to_token(InterlockState state) noexcept;
[[nodiscard]] bool parse_interlock_state(std::string_view token, InterlockState& out) noexcept;

/// Declaration that a branch depends on an interlock.
struct InterlockDeclaration {
  InterlockId id;
  PduId pdu;
  BranchId branch;
  ObligationClass klass{ObligationClass::protected_obligation};
  LogicalTick declared_at;
  AuthorityEpoch epoch;

  [[nodiscard]] bool operator==(const InterlockDeclaration& other) const noexcept {
    return id == other.id && pdu == other.pdu && branch == other.branch &&
           klass == other.klass && declared_at == other.declared_at && epoch == other.epoch;
  }
};

/// Last reported state of an interlock.
struct InterlockStatus {
  InterlockId id;
  InterlockState state{InterlockState::unknown};
  AuthorityEpoch epoch;      ///< Epoch the report belongs to.
  LogicalTick updated_at;
  AuthorityId clearance;     ///< Grant that cleared it, when one was required.

  [[nodiscard]] bool operator==(const InterlockStatus& other) const noexcept {
    return id == other.id && state == other.state && epoch == other.epoch &&
           updated_at == other.updated_at && clearance == other.clearance;
  }
};

/// An interlock as presented for inspection. `effective_state` folds in epoch
/// currency: a report from another epoch is `unknown`, never `satisfied`.
struct InterlockView {
  InterlockId id;
  ObligationClass klass{ObligationClass::protected_obligation};
  InterlockState reported_state{InterlockState::unknown};
  InterlockState effective_state{InterlockState::unknown};
  bool report_current{false};
  LogicalTick updated_at;
};

/// Aggregate interlock verdict for a branch.
enum class InterlockVerdict : std::uint8_t {
  clear,     ///< Every protected obligation is satisfied.
  blocked,   ///< At least one protected obligation is open.
  unknown,   ///< At least one protected obligation cannot be established.
};

[[nodiscard]] std::string_view to_token(InterlockVerdict verdict) noexcept;

/// Aggregate verdict plus the interlock that decided it, so a refusal always
/// names a concrete obligation.
struct InterlockSummary {
  InterlockVerdict verdict{InterlockVerdict::unknown};
  InterlockId deciding;      ///< The interlock that produced the verdict.
  bool has_deciding{false};
  std::size_t protected_count{0};
  std::size_t satisfied_count{0};
};

/// A maintenance override: an explicitly granted, scoped, expiring authorization
/// to control a branch whose lifecycle state would otherwise refuse control.
struct MaintenanceOverride {
  AuthorityId id;
  IssuerId issuer;
  AuthorityEpoch epoch;
  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation;
  BranchGeneration branch_generation;
  LogicalTick issued_at;
  LogicalTick not_after;
  bool revoked{false};

  [[nodiscard]] bool operator==(const MaintenanceOverride& other) const noexcept {
    return id == other.id && issuer == other.issuer && epoch == other.epoch &&
           pdu == other.pdu && branch == other.branch &&
           pdu_generation == other.pdu_generation &&
           branch_generation == other.branch_generation && issued_at == other.issued_at &&
           not_after == other.not_after && revoked == other.revoked;
  }
};

/// Why a maintenance override was or was not usable.
enum class OverrideVerdict : std::uint8_t {
  usable,
  missing,
  stale_epoch,
  expired,
  revoked,
  scope_mismatch,
  generation_mismatch,
};

[[nodiscard]] std::string_view to_token(OverrideVerdict verdict) noexcept;
[[nodiscard]] StatusCode status_for(OverrideVerdict verdict) noexcept;

}  // namespace pdu_control
