#include "pdu_control/lifecycle.hpp"

#include <cstddef>

namespace pdu_control {
namespace {

/// The complete transition table.
///
/// Two properties are deliberate. First, every state has at least one outgoing
/// transition except `retired`, which is terminal. Second, no transition leaves
/// a quiescent state except a recovery or an administrative one, so an isolated,
/// faulted, or retired entity can never be walked back into service by accident.
constexpr TransitionRule kTransitions[] = {
    {LifecycleState::provisioned, LifecycleState::active, TransitionClass::commission},
    {LifecycleState::provisioned, LifecycleState::maintenance, TransitionClass::service},
    {LifecycleState::provisioned, LifecycleState::retired, TransitionClass::administrative},

    {LifecycleState::active, LifecycleState::maintenance, TransitionClass::service},
    {LifecycleState::active, LifecycleState::degraded, TransitionClass::fault},
    {LifecycleState::active, LifecycleState::isolated, TransitionClass::service},
    {LifecycleState::active, LifecycleState::faulted, TransitionClass::fault},
    {LifecycleState::active, LifecycleState::retired, TransitionClass::administrative},

    {LifecycleState::maintenance, LifecycleState::active, TransitionClass::service},
    {LifecycleState::maintenance, LifecycleState::isolated, TransitionClass::service},
    {LifecycleState::maintenance, LifecycleState::retired, TransitionClass::administrative},

    {LifecycleState::degraded, LifecycleState::active, TransitionClass::recovery},
    {LifecycleState::degraded, LifecycleState::maintenance, TransitionClass::service},
    {LifecycleState::degraded, LifecycleState::isolated, TransitionClass::service},
    {LifecycleState::degraded, LifecycleState::faulted, TransitionClass::fault},
    {LifecycleState::degraded, LifecycleState::retired, TransitionClass::administrative},

    {LifecycleState::isolated, LifecycleState::active, TransitionClass::recovery},
    {LifecycleState::isolated, LifecycleState::maintenance, TransitionClass::recovery},
    {LifecycleState::isolated, LifecycleState::faulted, TransitionClass::fault},
    {LifecycleState::isolated, LifecycleState::retired, TransitionClass::administrative},

    {LifecycleState::faulted, LifecycleState::isolated, TransitionClass::recovery},
    {LifecycleState::faulted, LifecycleState::maintenance, TransitionClass::recovery},
    {LifecycleState::faulted, LifecycleState::retired, TransitionClass::administrative},
};

}  // namespace

std::string_view to_token(LifecycleState state) noexcept {
  switch (state) {
    case LifecycleState::provisioned:
      return "provisioned";
    case LifecycleState::active:
      return "active";
    case LifecycleState::maintenance:
      return "maintenance";
    case LifecycleState::degraded:
      return "degraded";
    case LifecycleState::isolated:
      return "isolated";
    case LifecycleState::faulted:
      return "faulted";
    case LifecycleState::retired:
      return "retired";
  }
  return "unknown_lifecycle";
}

std::string_view to_token(TransitionClass value) noexcept {
  switch (value) {
    case TransitionClass::commission:
      return "commission";
    case TransitionClass::service:
      return "service";
    case TransitionClass::recovery:
      return "recovery";
    case TransitionClass::administrative:
      return "administrative";
    case TransitionClass::fault:
      return "fault";
  }
  return "unknown_transition_class";
}

std::string_view to_token(ControlScope scope) noexcept {
  switch (scope) {
    case ControlScope::normal:
      return "normal";
    case ControlScope::maintenance_override:
      return "maintenance_override";
    case ControlScope::forbidden:
      return "forbidden";
  }
  return "unknown_control_scope";
}

bool parse_lifecycle_state(std::string_view token, LifecycleState& out) noexcept {
  constexpr LifecycleState kStates[] = {
      LifecycleState::provisioned, LifecycleState::active,   LifecycleState::maintenance,
      LifecycleState::degraded,    LifecycleState::isolated, LifecycleState::faulted,
      LifecycleState::retired,
  };
  for (const LifecycleState state : kStates) {
    if (to_token(state) == token) {
      out = state;
      return true;
    }
  }
  return false;
}

bool parse_transition_class(std::string_view token, TransitionClass& out) noexcept {
  constexpr TransitionClass kClasses[] = {
      TransitionClass::commission, TransitionClass::service, TransitionClass::recovery,
      TransitionClass::administrative, TransitionClass::fault,
  };
  for (const TransitionClass value : kClasses) {
    if (to_token(value) == token) {
      out = value;
      return true;
    }
  }
  return false;
}

const TransitionRule* transition_table() noexcept { return kTransitions; }

std::size_t transition_table_size() noexcept { return sizeof(kTransitions) / sizeof(kTransitions[0]); }

bool is_declared_transition(LifecycleState from, LifecycleState to) noexcept {
  for (const TransitionRule& rule : kTransitions) {
    if (rule.from == from && rule.to == to) {
      return true;
    }
  }
  return false;
}

Result<TransitionClass> transition_class(LifecycleState from, LifecycleState to) {
  for (const TransitionRule& rule : kTransitions) {
    if (rule.from == from && rule.to == to) {
      return rule.klass;
    }
  }
  if (from == to) {
    return Status::failure(StatusCode::transition_invalid,
                           std::string("the entity is already ") + std::string(to_token(from)) +
                               "; a same-state transition is not an operation");
  }
  return Status::failure(StatusCode::transition_invalid,
                         std::string("no declared transition from ") + std::string(to_token(from)) +
                             " to " + std::string(to_token(to)));
}

}  // namespace pdu_control
