#pragma once

// The audit trail.
//
// Audit entries are append-only, ordered by a dedicated sequence, and bounded by
// `ModelBounds::max_audit_entries`; the retention rule is a ring: when the bound
// is reached the oldest entry is dropped and the drop count is recorded, so a
// truncated history is visible rather than silent.
//
// An audit entry carries a wall-clock instant when the caller supplied one. That
// instant is deliberately excluded from the canonical state digest: it is
// intentional audit content, not model state, and including it would make two
// logically identical engines digest differently.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pdu_control/evidence.hpp"
#include "pdu_control/ids.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control {

enum class AuditKind : std::uint8_t {
  engine_opened,
  engine_reopened,
  engine_closed,
  store_published,
  authority_epoch_adopted,
  pdu_registered,
  branch_registered,
  lifecycle_transition,
  limits_updated,
  grant_recorded,
  grant_revoked,
  override_recorded,
  interlock_declared,
  interlock_reported,
  observation_recorded,
  observation_revalidated,
  tick_advanced,
  attempt_refused,
  attempt_dispatched,
  attempt_acknowledged,
  attempt_verified,
  attempt_resolved,
  recovery_adopted,
};

[[nodiscard]] std::string_view to_token(AuditKind kind) noexcept;
[[nodiscard]] bool parse_audit_kind(std::string_view token, AuditKind& out) noexcept;

inline constexpr std::size_t max_audit_detail_bytes = 192;

struct AuditEntry {
  SequenceNumber sequence;
  AuditKind kind{AuditKind::engine_opened};
  LogicalTick tick;
  Instant wall;              ///< Excluded from the canonical state digest.
  PduId pdu;
  BranchId branch;
  AttemptId attempt;
  ObservationId observation;
  StatusCode code{StatusCode::ok};
  std::string detail;
};

/// Query for the audit trail. All fields are optional filters.
struct HistoryQuery {
  std::size_t limit{64};       ///< Clamped to `max_audit_entries`.
  bool has_pdu{false};
  PduId pdu;
  bool has_branch{false};
  BranchId branch;
  bool has_attempt{false};
  AttemptId attempt;
  bool has_kind{false};
  AuditKind kind{AuditKind::engine_opened};
};

}  // namespace pdu_control
