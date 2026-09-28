#include "pdu_control/audit.hpp"

#include <cstddef>

namespace pdu_control {
namespace {

constexpr AuditKind kKinds[] = {
    AuditKind::engine_opened,        AuditKind::engine_reopened,
    AuditKind::engine_closed,        AuditKind::store_published,
    AuditKind::authority_epoch_adopted, AuditKind::pdu_registered,
    AuditKind::branch_registered,    AuditKind::lifecycle_transition,
    AuditKind::limits_updated,       AuditKind::grant_recorded,
    AuditKind::grant_revoked,        AuditKind::override_recorded,
    AuditKind::interlock_declared,   AuditKind::interlock_reported,
    AuditKind::observation_recorded, AuditKind::observation_revalidated,
    AuditKind::tick_advanced,        AuditKind::attempt_refused,
    AuditKind::attempt_dispatched,   AuditKind::attempt_acknowledged,
    AuditKind::attempt_verified,     AuditKind::attempt_resolved,
    AuditKind::recovery_adopted,
};

}  // namespace

std::string_view to_token(AuditKind kind) noexcept {
  switch (kind) {
    case AuditKind::engine_opened:
      return "engine_opened";
    case AuditKind::engine_reopened:
      return "engine_reopened";
    case AuditKind::engine_closed:
      return "engine_closed";
    case AuditKind::store_published:
      return "store_published";
    case AuditKind::authority_epoch_adopted:
      return "authority_epoch_adopted";
    case AuditKind::pdu_registered:
      return "pdu_registered";
    case AuditKind::branch_registered:
      return "branch_registered";
    case AuditKind::lifecycle_transition:
      return "lifecycle_transition";
    case AuditKind::limits_updated:
      return "limits_updated";
    case AuditKind::grant_recorded:
      return "grant_recorded";
    case AuditKind::grant_revoked:
      return "grant_revoked";
    case AuditKind::override_recorded:
      return "override_recorded";
    case AuditKind::interlock_declared:
      return "interlock_declared";
    case AuditKind::interlock_reported:
      return "interlock_reported";
    case AuditKind::observation_recorded:
      return "observation_recorded";
    case AuditKind::observation_revalidated:
      return "observation_revalidated";
    case AuditKind::tick_advanced:
      return "tick_advanced";
    case AuditKind::attempt_refused:
      return "attempt_refused";
    case AuditKind::attempt_dispatched:
      return "attempt_dispatched";
    case AuditKind::attempt_acknowledged:
      return "attempt_acknowledged";
    case AuditKind::attempt_verified:
      return "attempt_verified";
    case AuditKind::attempt_resolved:
      return "attempt_resolved";
    case AuditKind::recovery_adopted:
      return "recovery_adopted";
  }
  return "unknown_audit_kind";
}

bool parse_audit_kind(std::string_view token, AuditKind& out) noexcept {
  for (const AuditKind kind : kKinds) {
    if (to_token(kind) == token) {
      out = kind;
      return true;
    }
  }
  return false;
}

}  // namespace pdu_control
