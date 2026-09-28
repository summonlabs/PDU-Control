#pragma once

// The control engine.
//
// # Authority model
//
// Every mutating call states the authority it was planned against: the authority
// epoch, the PDU generation, the branch generation, and (where required) the
// state revision. A call whose stated authority does not match current state is
// refused; nothing is merged and nothing is "upgraded" to current.
//
// # Validation precedence
//
// The primary code returned for an invalid request is a deterministic function
// of the request and the current state. The order below is the whole of it:
//
//   1. request shape            invalid_argument / out_of_range / overflow
//   2. idempotent replay        return the retained result, or idempotency_conflict
//   3. identity resolution      not_found / duplicate_identity
//   4. identity binding         identity_mismatch
//   5. lifecycle gate           lifecycle_forbidden / transition_invalid
//   6. unresolved attempt       attempt_unresolved
//   7. device generations       generation_mismatch
//   8. state revision           revision_mismatch
//   9. authority epoch          permission_stale
//  10. permission               permission_missing / permission_stale / permission_denied
//  11. interlock                interlock_open / interlock_unknown
//  12. limits                   limit_invalid / limit_exceeded
//  13. adapter                  adapter_refused / adapter_unavailable / adapter_fault /
//                               adapter_fenced
//
// The idempotency step deliberately precedes the generation and revision checks:
// a retry of an already accepted attempt must return the prior accepted result,
// not be rejected because the branch moved on in the meantime.
//
// # Concurrency
//
// An engine instance is not internally synchronized: one instance is used by one
// thread at a time. Cross-process write authority over a durable store is a real
// operating-system lock held for the lifetime of the engine. There is no second
// lock, no nested acquisition, and no lock is ever reacquired on any call path.
// The lock is deliberately held across adapter calls, because a second process
// must not interleave commands with this one; no code reachable from an adapter
// can acquire it. The operating system releases the lock when the process dies,
// which is the property the crash and multiprocess tests exercise.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "pdu_control/adapter.hpp"
#include "pdu_control/attempt.hpp"
#include "pdu_control/audit.hpp"
#include "pdu_control/authority.hpp"
#include "pdu_control/evidence.hpp"
#include "pdu_control/ids.hpp"
#include "pdu_control/lifecycle.hpp"
#include "pdu_control/model.hpp"
#include "pdu_control/status.hpp"
#include "pdu_control/store.hpp"

namespace pdu_control {

/// When an observation stops being usable as current evidence.
struct EvidencePolicy {
  /// An observation taken more than this many logical ticks before the current
  /// tick is stale. Zero means "only the current tick is fresh".
  LogicalTick max_age_ticks{1000};
  /// Require `EvidenceQuality::good` for an observation to be usable.
  bool require_good_quality{true};
};

/// Options for opening or constructing an engine. Defaults are the conservative
/// values; every bound is explicit and enforced.
struct EngineOptions {
  ModelBounds bounds;
  EvidencePolicy evidence;
  /// Number of accepted attempts retained for idempotent replay. Clamped to
  /// [1, bounds.max_idempotency_window]. Retention is by recency: the window
  /// keeps the most recently accepted attempts, and an older key evicted from
  /// the window no longer replays -- a retry after eviction is a new request and
  /// is re-evaluated against current state.
  std::size_t idempotency_window{256};
  /// Rollback fence: refuse to open a store whose committed generation is lower
  /// than this. Unset means no floor is applied.
  StoreGeneration min_store_generation;
  /// Refuse every mutation after opening. Implied by `OpenMode::read_only`.
  bool read_only{false};
  PathPolicy path_policy;
  /// Audit ring capacity. Clamped to [16, bounds.max_audit_entries].
  std::size_t audit_capacity{4096};
};

/// A compact description of engine state, used by the CLI `inspect` and
/// `store-audit` verbs.
struct EngineStatus {
  bool open{false};
  bool durable{false};
  bool read_only{false};
  std::string store_path;
  Incarnation incarnation;
  AuthorityEpoch authority_epoch;
  LogicalTick current_tick;
  StoreGeneration store_generation;
  Digest64 state_digest;
  std::size_t pdu_count{0};
  std::size_t branch_count{0};
  std::size_t attempt_count{0};
  std::size_t unresolved_attempt_count{0};
  std::size_t idempotency_entries{0};
  std::size_t audit_entries{0};
  std::uint64_t audit_dropped{0};
  std::uint64_t refusal_count{0};
  std::uint64_t dispatch_count{0};
  std::uint64_t verification_count{0};
  StoreAudit store;
};

/// How an unresolved attempt is closed without a verified effect.
enum class AttemptResolution : std::uint8_t {
  cancelled,   ///< Deliberately abandoned; the effect may or may not have occurred.
  superseded,  ///< Replaced by a later decision taken with better information.
};

[[nodiscard]] std::string_view to_token(AttemptResolution resolution) noexcept;
[[nodiscard]] bool parse_attempt_resolution(std::string_view token, AttemptResolution& out) noexcept;

/// The PDU and branch control engine.
class PduControlEngine {
 public:
  /// Opens or creates a durable store and adopts its committed state.
  ///
  /// The returned engine holds exclusive write authority over the store unless
  /// `OpenMode::read_only` was requested. Recovery is deterministic: every
  /// attempt that was left non-terminal by a previous incarnation is adopted as
  /// `recovery_required`, the branch it targets is blocked from new control,
  /// and no command is re-sent.
  [[nodiscard]] static Result<PduControlEngine> open(std::string_view path, OpenMode mode,
                                                     const EngineOptions& options = {});

  /// An engine with no durable backing. Used by tests and by `--store`-less CLI
  /// invocations; it has no crash semantics because it has no durability.
  [[nodiscard]] static Result<PduControlEngine> in_memory(const EngineOptions& options = {});

  PduControlEngine();
  ~PduControlEngine();
  PduControlEngine(PduControlEngine&& other) noexcept;
  PduControlEngine& operator=(PduControlEngine&& other) noexcept;
  PduControlEngine(const PduControlEngine&) = delete;
  PduControlEngine& operator=(const PduControlEngine&) = delete;

  /// Publishes any pending state, releases write authority, and closes the
  /// store. Idempotent. An engine that was never opened is already closed.
  Status close();

  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] bool is_durable() const noexcept;
  [[nodiscard]] bool is_read_only() const noexcept;
  [[nodiscard]] const std::string& store_path() const noexcept;
  [[nodiscard]] const EngineOptions& options() const noexcept;
  [[nodiscard]] Incarnation incarnation() const noexcept;
  [[nodiscard]] AuthorityEpoch authority_epoch() const noexcept;
  [[nodiscard]] LogicalTick current_tick() const noexcept;
  [[nodiscard]] StoreGeneration store_generation() const noexcept;

  /// Writes the current state durably. Fails with `busy` when another writer has
  /// advanced the store past this engine's incarnation.
  Status flush();

  [[nodiscard]] StoreAudit store_audit() const;
  [[nodiscard]] EngineStatus status() const;

  // -- authority and time ---------------------------------------------------

  /// Adopts a new authority epoch. The epoch must carry a value and must be
  /// strictly greater than the current one; adopting an older epoch would
  /// silently re-authorize grants that were already withdrawn.
  Status adopt_authority_epoch(AuthorityEpoch epoch);

  /// Advances the logical clock. Time never moves backwards.
  Status advance_tick(LogicalTick tick);

  /// Sets the wall-clock instant stamped into subsequent audit entries. This
  /// library never reads a clock itself; a caller that wants wall-clock audit
  /// content supplies it, and doing so does not change the canonical state
  /// digest.
  Status set_wall_instant(Instant instant);

  // -- model ----------------------------------------------------------------

  Status register_pdu(const PduDefinition& definition);
  Status register_branch(const BranchDefinition& definition);

  /// Moves a PDU (empty `branch`) or a branch through the declared lifecycle
  /// transition table. Requires current `lifecycle_service`,
  /// `lifecycle_recovery`, or `lifecycle_administrative` authority as dictated
  /// by the transition class, plus a current state revision.
  Status transition_lifecycle(const LifecycleRequest& request);

  Status update_limits(const LimitUpdateRequest& request);

  // -- authority data -------------------------------------------------------

  Status record_grant(const PermissionGrant& grant);
  Status revoke_grant(const AuthorityId& id, AuthorityEpoch epoch, LogicalTick at);
  Status record_maintenance_override(const MaintenanceOverride& override_value);
  Status revoke_maintenance_override(const AuthorityId& id, AuthorityEpoch epoch, LogicalTick at);
  Status declare_interlock(const InterlockDeclaration& declaration);
  Status report_interlock(const InterlockStatus& status);

  // -- evidence -------------------------------------------------------------

  /// Records a telemetry observation. Freshness, acceptance instant, and
  /// observation identity are assigned by the engine; a caller cannot assert
  /// them. An observation whose generation does not match the branch is refused.
  Result<ObservationId> record_observation(const TelemetryObservation& observation);

  /// Revalidates recovered or stale evidence with a fresh reading. The reading
  /// must be taken later than the evidence it replaces; the replaced evidence is
  /// marked stale, and this runtime never promotes old evidence back to fresh.
  Result<ObservationId> revalidate(const PduId& pdu, const BranchId& branch,
                                   const TelemetryObservation& observation);

  /// Records a fresh reading from an adapter as evidence. The adapter is an
  /// evidence source like any other: its reading is subject to the same quality
  /// and freshness rules and is never treated as verification by itself.
  Result<ObservationId> read_back(const PduId& pdu, const BranchId& branch,
                                  PowerAdapter& adapter, LogicalTick at);

  // -- control --------------------------------------------------------------

  /// Answers whether the request may be attempted. Mutates nothing.
  [[nodiscard]] Result<Decision> evaluate(const BranchControlRequest& request) const;

  /// Evaluates and, when eligible, dispatches exactly one command through the
  /// adapter.
  ///
  /// The accepted attempt is published durably *before* the adapter is called,
  /// so a process that dies immediately after dispatch leaves a record that says
  /// a command may have reached the branch. That record is what stops recovery
  /// from re-sending anything.
  Result<AttemptRecord> issue(const BranchControlRequest& request, PowerAdapter& adapter);

  /// Establishes the effect of an attempt from evidence already recorded.
  Result<VerificationResult> verify(const AttemptId& attempt);

  /// Reads the branch through the adapter, records the reading as evidence, and
  /// then verifies.
  Result<VerificationResult> verify_with_adapter(const AttemptId& attempt, PowerAdapter& adapter);

  /// Closes an unresolved attempt without a verified effect. Requires a current
  /// `lifecycle_recovery` grant on the branch. The branch's verified state
  /// becomes `unknown`: resolving an attempt does not invent knowledge.
  Status resolve_attempt(const AttemptId& attempt, AttemptResolution resolution,
                         const ActorId& actor, AuthorityEpoch epoch, LogicalTick at);

  // -- inspection -----------------------------------------------------------

  [[nodiscard]] Result<PduSnapshot> inspect_pdu(const PduId& pdu) const;
  [[nodiscard]] Result<BranchSnapshot> inspect_branch(const PduId& pdu, const BranchId& branch) const;
  [[nodiscard]] Result<BranchSnapshot> inspect_branch(const BranchId& branch) const;
  [[nodiscard]] std::vector<PduSnapshot> inspect_all() const;

  [[nodiscard]] std::vector<AttemptRecord> attempts(std::size_t limit) const;
  [[nodiscard]] Result<AttemptRecord> attempt(const AttemptId& attempt) const;
  [[nodiscard]] Result<AttemptRecord> attempt_by_key(const IdempotencyKey& key) const;
  [[nodiscard]] std::vector<AuditEntry> history(const HistoryQuery& query) const;

  /// Deterministic canonical text form of the authoritative model state.
  ///
  /// Excluded by construction: wall-clock instants, the process incarnation, the
  /// store path, adapter identities, and audit sequence numbers. Two engines
  /// driven through the same logical event sequence produce byte-identical
  /// canonical text regardless of when they ran or which process ran them.
  [[nodiscard]] std::string canonical_state() const;

  /// Digest of `canonical_state()`.
  [[nodiscard]] Digest64 state_digest() const;

 private:
  struct Impl;

  /// Shared implementation of `record_observation` and `revalidate`. Not part
  /// of the public surface: the audit kind and the supersession rule are the
  /// only differences between the two entry points.
  Result<ObservationId> record_observation_internal(const TelemetryObservation& observation,
                                                    AuditKind kind, bool supersede_required);

  std::unique_ptr<Impl> impl_;
};

}  // namespace pdu_control
