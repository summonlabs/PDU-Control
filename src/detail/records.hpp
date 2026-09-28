#pragma once

// The in-memory model that the engine mutates and that the store persists.
//
// The engine's public snapshots are views built from these records; the records
// themselves stay internal so that the persisted shape and the mutable shape are
// the same thing and cannot drift apart.

#include <cstdint>
#include <deque>
#include <vector>

#include "pdu_control/attempt.hpp"
#include "pdu_control/audit.hpp"
#include "pdu_control/authority.hpp"
#include "pdu_control/evidence.hpp"
#include "pdu_control/model.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control::detail {

struct PduRecord {
  PduDefinition definition;
  PduState state;
};

struct ObservationRing {
  /// Newest last. Bounded by `ModelBounds::max_observations_per_branch`.
  std::vector<TelemetryObservation> entries;
  bool has_current{false};
  TelemetryObservation current;
};

struct BranchRecord {
  BranchDefinition definition;
  BranchState state;
  ObservationRing observations;
};

struct GrantRecord {
  PermissionGrant grant;
};

struct OverrideRecord {
  MaintenanceOverride value;
};

struct InterlockRecord {
  InterlockDeclaration declaration;
  bool has_status{false};
  InterlockStatus status;
};

struct IdempotencyRecord {
  IdempotencyKey key;
  Digest64 request_digest;
  AttemptId attempt;
};

/// Everything that is authoritative and survives a restart.
struct ModelState {
  /// Generation of the durable publication this state was read from or will be
  /// written as. Excluded from the canonical state text: it counts publications,
  /// not logical events.
  StoreGeneration generation{StoreGeneration::from(1)};
  AuthorityEpoch authority_epoch;
  LogicalTick current_tick;
  Instant wall{Instant::logical(LogicalTick::unset())};
  AttemptId next_attempt{AttemptId::from(1)};
  ObservationId next_observation{ObservationId::from(1)};
  AdapterSequence next_adapter_sequence{AdapterSequence::from(1)};
  SequenceNumber next_audit_sequence{SequenceNumber::from(1)};
  std::uint64_t audit_dropped{0};
  std::uint64_t open_count{0};
  Incarnation last_incarnation;

  std::vector<PduRecord> pdus;
  std::vector<BranchRecord> branches;
  std::vector<GrantRecord> grants;
  std::vector<OverrideRecord> overrides;
  std::vector<InterlockRecord> interlocks;
  /// Attempt journal, oldest first. Bounded by `ModelBounds::max_attempt_journal`.
  std::vector<AttemptRecord> attempts;
  /// Idempotency window, oldest first. Bounded by the configured window size.
  std::vector<IdempotencyRecord> idempotency;
  /// Audit ring, oldest first. Bounded by the configured audit capacity.
  std::deque<AuditEntry> audit;
};

}  // namespace pdu_control::detail
