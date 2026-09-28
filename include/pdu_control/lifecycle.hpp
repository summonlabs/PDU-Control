#pragma once

// Lifecycle of a PDU and of a branch circuit.
//
// The transition table below is the whole of the permitted lifecycle surface.
// Any transition that is not in it is refused with `transition_invalid`; there
// is no implicit "any state to any state" path and no state that can be reached
// without naming the class of transition that reaches it.

#include <cstdint>
#include <string_view>

#include "pdu_control/status.hpp"

namespace pdu_control {

/// Lifecycle state of a PDU or a branch circuit.
enum class LifecycleState : std::uint8_t {
  provisioned,  ///< Known and modeled, never placed in service.
  active,       ///< In service and controllable.
  maintenance,  ///< Withdrawn for work; control requires an explicit override grant.
  degraded,     ///< In service with reduced capability; control permitted.
  isolated,     ///< Deliberately separated from the bus; control refused.
  faulted,      ///< A fault is asserted; control refused.
  retired,      ///< Permanently withdrawn; terminal.
};

/// Why a lifecycle transition happens. The class decides which permission
/// action the caller must hold; it is not inferred from the state names.
enum class TransitionClass : std::uint8_t {
  commission,     ///< provisioned -> in service for the first time.
  service,        ///< Withdraw to, or return from, maintenance.
  recovery,       ///< Bring an isolated or faulted entity back toward service.
  administrative, ///< Retire an entity.
  fault,          ///< Report or clear a fault condition.
};

[[nodiscard]] std::string_view to_token(LifecycleState state) noexcept;
[[nodiscard]] std::string_view to_token(TransitionClass value) noexcept;

[[nodiscard]] bool parse_lifecycle_state(std::string_view token, LifecycleState& out) noexcept;
[[nodiscard]] bool parse_transition_class(std::string_view token, TransitionClass& out) noexcept;

/// One row of the transition table.
struct TransitionRule {
  LifecycleState from;
  LifecycleState to;
  TransitionClass klass;
};

/// The complete transition table. Sorted by (from, to); used by the canonical
/// encoding so that a digest of the policy is stable.
[[nodiscard]] const TransitionRule* transition_table() noexcept;

/// Number of rows in `transition_table()`.
[[nodiscard]] std::size_t transition_table_size() noexcept;

/// The class of the declared transition, or `transition_invalid`.
[[nodiscard]] Result<TransitionClass> transition_class(LifecycleState from, LifecycleState to);

/// True when the transition is declared.
[[nodiscard]] bool is_declared_transition(LifecycleState from, LifecycleState to) noexcept;

/// How control (energize/de-energize of a branch) is gated by a lifecycle state.
enum class ControlScope : std::uint8_t {
  normal,                      ///< Control is permitted.
  maintenance_override,        ///< Control requires an explicit maintenance override grant.
  forbidden,                   ///< Control is refused; only service/recovery transitions remain.
};

/// `active` and `degraded` permit control; `maintenance` requires an explicit
/// override grant; `provisioned`, `isolated`, `faulted`, and `retired` refuse
/// it. This function is the single definition of that rule.
[[nodiscard]] constexpr ControlScope control_scope(LifecycleState state) noexcept {
  switch (state) {
    case LifecycleState::active:
    case LifecycleState::degraded:
      return ControlScope::normal;
    case LifecycleState::maintenance:
      return ControlScope::maintenance_override;
    case LifecycleState::provisioned:
    case LifecycleState::isolated:
    case LifecycleState::faulted:
    case LifecycleState::retired:
      return ControlScope::forbidden;
  }
  return ControlScope::forbidden;
}

/// Stable token for a control scope: "normal", "maintenance_override", "forbidden".
[[nodiscard]] std::string_view to_token(ControlScope scope) noexcept;

/// True when the lifecycle state denotes a terminal condition that can only be
/// left by a recovery or administrative transition.
[[nodiscard]] constexpr bool is_quiescent(LifecycleState state) noexcept {
  return state == LifecycleState::isolated || state == LifecycleState::faulted ||
         state == LifecycleState::retired;
}

}  // namespace pdu_control
