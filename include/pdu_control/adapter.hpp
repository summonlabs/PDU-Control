#pragma once

// The complete vendor boundary.
//
// Everything a vendor integration is allowed to do is expressed by one abstract
// class with three operations. No vendor type, header, error code, or transport
// appears in this library: an adapter receives an already-authorized command and
// returns a disposition plus, optionally, a reading.
//
// Two properties are enforced structurally rather than by convention:
//
//  1. An `AdapterCommand` cannot be constructed outside the engine. Its
//     authorization token carries the preconditions that the engine validated,
//     and the token's constructor is private to the engine. An adapter therefore
//     cannot fabricate a command, and the engine cannot dispatch one that has not
//     passed validation.
//  2. An `AdapterOutcome` must echo the attempt, epoch, and sequence it answers.
//     An outcome that echoes anything else is fenced and discarded with
//     `adapter_fenced`; it can never be attributed to the wrong command.
//
// An acknowledgement is never proof of effect. The engine records the
// disposition for the audit trail and then requires fresh telemetry evidence
// before any effect is reported as verified.

#include <cstdint>
#include <string>
#include <string_view>

#include "pdu_control/evidence.hpp"
#include "pdu_control/ids.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control {

namespace detail {
/// Internal accessor that lets the durable decoder and the engine populate an
/// authorization. Forward-declared only: the definition lives in an internal
/// header, so no public surface can construct or widen an authorization.
struct ActuationAccess;
}  // namespace detail

/// What kind of thing is on the other side of the interface.
enum class AdapterKind : std::uint8_t {
  synthetic, ///< A deterministic simulator. Drives no hardware.
  vendor,    ///< A vendor integration.
  gateway,   ///< An aggregation or protocol gateway.
  unknown,
};

[[nodiscard]] std::string_view to_token(AdapterKind kind) noexcept;
[[nodiscard]] bool parse_adapter_kind(std::string_view token, AdapterKind& out) noexcept;

/// Static description of an adapter. Reported into audit records and inspection
/// output so that an operator can always see what the runtime was talking to.
struct AdapterDescriptor {
  AdapterId id;
  IssuerId vendor;         ///< "synthetic" for the built-in simulator.
  std::string model;
  std::string firmware;
  AdapterKind kind{AdapterKind::unknown};
  bool supports_readback{false};
  /// True when the adapter drives no physical equipment. The CLI, the examples,
  /// and the benchmark surface this so that synthetic evidence is never mistaken
  /// for hardware evidence.
  bool synthetic{false};
};

/// Precondition classes the engine validates before a command may be built.
enum class PreconditionKind : std::uint32_t {
  none = 0,
  identity = 1U << 0,
  branch_binding = 1U << 1,
  lifecycle = 1U << 2,
  no_unresolved_attempt = 1U << 3,
  pdu_generation = 1U << 4,
  branch_generation = 1U << 5,
  state_revision = 1U << 6,
  authority_epoch = 1U << 7,
  permission = 1U << 8,
  interlock = 1U << 9,
  limits = 1U << 10,
};

using PreconditionMask = std::uint32_t;

[[nodiscard]] constexpr PreconditionMask mask_of(PreconditionKind kind) noexcept {
  return static_cast<PreconditionMask>(kind);
}
[[nodiscard]] constexpr bool includes(PreconditionMask mask, PreconditionKind kind) noexcept {
  return (mask & mask_of(kind)) != 0;
}
[[nodiscard]] constexpr PreconditionMask with(PreconditionMask mask,
                                              PreconditionKind kind) noexcept {
  return static_cast<PreconditionMask>(mask | mask_of(kind));
}

/// Name of a single precondition bit, for diagnostics and test output.
[[nodiscard]] std::string_view to_token(PreconditionKind kind) noexcept;

/// Every precondition the engine must validate before an energize or
/// de-energize command is built.
inline constexpr PreconditionMask required_control_preconditions =
    mask_of(PreconditionKind::identity) | mask_of(PreconditionKind::branch_binding) |
    mask_of(PreconditionKind::lifecycle) | mask_of(PreconditionKind::no_unresolved_attempt) |
    mask_of(PreconditionKind::pdu_generation) | mask_of(PreconditionKind::branch_generation) |
    mask_of(PreconditionKind::authority_epoch) | mask_of(PreconditionKind::permission) |
    mask_of(PreconditionKind::interlock) | mask_of(PreconditionKind::limits);

/// Proof, carried with a command, that the engine validated the preconditions
/// above at the stated authority and generations.
///
/// The type is constructible only by `PduControlEngine`. An adapter can read it
/// and can refuse a command whose mask is incomplete, but it cannot create one,
/// and it cannot widen one.
class ActuationAuthorization {
 public:
  ActuationAuthorization() = default;

  [[nodiscard]] AttemptId attempt() const noexcept { return attempt_; }
  [[nodiscard]] AuthorityEpoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] PduId pdu() const noexcept { return pdu_; }
  [[nodiscard]] BranchId branch() const noexcept { return branch_; }
  [[nodiscard]] PduGeneration pdu_generation() const noexcept { return pdu_generation_; }
  [[nodiscard]] BranchGeneration branch_generation() const noexcept {
    return branch_generation_;
  }
  [[nodiscard]] StateRevision revision() const noexcept { return revision_; }
  [[nodiscard]] LogicalTick issued_at() const noexcept { return issued_at_; }
  [[nodiscard]] Digest64 request_digest() const noexcept { return request_digest_; }
  [[nodiscard]] PreconditionMask validated() const noexcept { return validated_; }
  [[nodiscard]] bool maintenance_override() const noexcept { return maintenance_override_; }

  /// True when every precondition required for a control command was validated.
  [[nodiscard]] bool complete_for_control() const noexcept {
    return (validated_ & required_control_preconditions) == required_control_preconditions;
  }

 private:
  friend class PduControlEngine;
  friend struct detail::ActuationAccess;

  AttemptId attempt_;
  AuthorityEpoch epoch_;
  PduId pdu_;
  BranchId branch_;
  PduGeneration pdu_generation_;
  BranchGeneration branch_generation_;
  StateRevision revision_;
  LogicalTick issued_at_;
  Digest64 request_digest_;
  PreconditionMask validated_{0};
  bool maintenance_override_{false};
};

/// A command handed to an adapter. Constructible only by the engine.
class AdapterCommand {
 public:
  AdapterCommand() = default;

  [[nodiscard]] AdapterSequence sequence() const noexcept { return sequence_; }
  [[nodiscard]] const ActuationAuthorization& authorization() const noexcept {
    return authorization_;
  }
  [[nodiscard]] CommandIntent intent() const noexcept { return intent_; }
  [[nodiscard]] LogicalTick issued_at() const noexcept { return issued_at_; }

 private:
  friend class PduControlEngine;

  AdapterSequence sequence_;
  ActuationAuthorization authorization_;
  CommandIntent intent_{CommandIntent::de_energize};
  LogicalTick issued_at_;
};

/// What the adapter did with a command.
enum class AdapterDisposition : std::uint8_t {
  acknowledged, ///< Received. Says nothing about the physical effect.
  refused,      ///< Rejected the command; no effect claimed.
  unavailable,  ///< Could not attempt it now.
  fault,        ///< Reported an internal fault.
};

[[nodiscard]] std::string_view to_token(AdapterDisposition disposition) noexcept;
[[nodiscard]] bool parse_adapter_disposition(std::string_view token,
                                             AdapterDisposition& out) noexcept;

/// Largest accepted adapter detail string.
inline constexpr std::size_t max_adapter_detail_bytes = 256;

/// The adapter's answer. It must echo the command it answers.
struct AdapterOutcome {
  AdapterSequence sequence;     ///< Must equal the command's sequence.
  AttemptId attempt;            ///< Must equal the command's attempt.
  AuthorityEpoch epoch;         ///< Must equal the command's epoch.
  AdapterDisposition disposition{AdapterDisposition::fault};
  std::string detail;
  /// An optional reading returned with the acknowledgement. It is recorded as
  /// evidence with the adapter as its source; it is never verification by
  /// itself, and it is subject to the same freshness and quality rules as any
  /// other observation.
  bool has_reading{false};
  TelemetryObservation reading;
};

/// A request for a fresh reading.
struct AdapterReadRequest {
  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation;
  BranchGeneration branch_generation;
  LogicalTick at;
};

/// The vendor boundary.
///
/// Implementations must be deterministic with respect to the commands they are
/// given if they are to be used in tests, and must not block indefinitely. The
/// engine calls `execute` and `read` from the calling thread only; it holds no
/// internal lock across either call.
class PowerAdapter {
 public:
  PowerAdapter() = default;
  virtual ~PowerAdapter();
  PowerAdapter(const PowerAdapter&) = delete;
  PowerAdapter& operator=(const PowerAdapter&) = delete;
  /// Adapters are movable so that one can be handed back from a factory or held
  /// in a result; they are never copied, because a copy would be a second
  /// adapter driving the same device.
  PowerAdapter(PowerAdapter&&) noexcept = default;
  PowerAdapter& operator=(PowerAdapter&&) noexcept = default;

  /// Static description. Must not throw and must not block.
  [[nodiscard]] virtual AdapterDescriptor describe() const = 0;

  /// Applies or refuses a command. The engine has already validated every
  /// precondition recorded in `command.authorization()`.
  [[nodiscard]] virtual AdapterOutcome execute(const AdapterCommand& command) = 0;

  /// Reads the current condition. Returning `evidence_missing` or
  /// `adapter_unavailable` is a normal outcome and is not an error in the
  /// adapter.
  [[nodiscard]] virtual Result<TelemetryObservation> read(const AdapterReadRequest& request) = 0;
};

/// Validates an outcome reported by an untrusted adapter: bounded detail text,
/// echoed identifiers, and a reading whose shape is valid.
[[nodiscard]] Status validate_outcome(const AdapterOutcome& outcome, const AdapterCommand& command);

/// Validates an adapter descriptor: bounded text and a set adapter identity.
[[nodiscard]] Status validate_descriptor(const AdapterDescriptor& descriptor);

}  // namespace pdu_control
