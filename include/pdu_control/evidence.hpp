#pragma once

// Telemetry: what a source says about a branch circuit, when it said it, and
// how much that statement is worth.
//
// An observation is evidence. It is never authority, it never authorizes an
// action on its own, and an observation that was recovered from durable storage
// is stale until it is revalidated by a fresh reading.

#include <cstdint>
#include <string_view>

#include "pdu_control/ids.hpp"
#include "pdu_control/status.hpp"
#include "pdu_control/units.hpp"

namespace pdu_control {

/// Condition of a branch circuit as *observed*. Distinct from `CommandIntent`,
/// which is what was asked for: the whole point of this runtime is that the two
/// are tracked separately and never conflated.
enum class BranchCondition : std::uint8_t {
  energized,     ///< The branch is conducting.
  de_energized,  ///< The branch is not conducting.
  transitioning, ///< The source reports an in-progress change.
  unknown,       ///< The source cannot state the condition.
};

/// What was asked for. There is no "unknown" intent: a command either asks for
/// energize or de-energize, and the absence of a command is an unset sample.
enum class CommandIntent : std::uint8_t {
  energize,
  de_energize,
};

/// The condition a command intends to produce.
[[nodiscard]] constexpr BranchCondition target_condition(CommandIntent intent) noexcept {
  return intent == CommandIntent::energize ? BranchCondition::energized
                                           : BranchCondition::de_energized;
}

/// The inverse intent.
[[nodiscard]] constexpr CommandIntent invert(CommandIntent intent) noexcept {
  return intent == CommandIntent::energize ? CommandIntent::de_energize
                                           : CommandIntent::energize;
}

[[nodiscard]] std::string_view to_token(BranchCondition condition) noexcept;
[[nodiscard]] std::string_view to_token(CommandIntent intent) noexcept;
[[nodiscard]] bool parse_branch_condition(std::string_view token, BranchCondition& out) noexcept;
[[nodiscard]] bool parse_command_intent(std::string_view token, CommandIntent& out) noexcept;

/// Clock domain of an instant. A logical tick and a wall-clock instant are not
/// comparable, and this runtime never compares them: control decisions use
/// logical ticks only.
enum class ClockDomain : std::uint8_t {
  logical_tick,           ///< Caller-supplied logical instant.
  unix_epoch_nanoseconds, ///< Wall clock, nanoseconds since 1970-01-01T00:00:00Z.
  monotonic_nanoseconds,  ///< A monotonic counter in nanoseconds; not comparable across processes.
  vendor_opaque,          ///< A vendor-internal counter; ordering within one source only.
};

[[nodiscard]] std::string_view to_token(ClockDomain domain) noexcept;
[[nodiscard]] bool parse_clock_domain(std::string_view token, ClockDomain& out) noexcept;

/// The largest wall-clock instant this library accepts: 2100-01-01T00:00:00Z in
/// nanoseconds. Larger values are refused with `out_of_range`, which keeps a
/// corrupt field from becoming an absurd deadline.
inline constexpr std::int64_t max_unix_nanoseconds = 4102444800000000000LL;

/// An instant in a named clock domain.
struct Instant {
  ClockDomain domain{ClockDomain::logical_tick};
  LogicalTick tick;            ///< Read only when `domain == logical_tick`.
  std::int64_t nanoseconds{0}; ///< Read only for the non-logical domains.

  [[nodiscard]] static constexpr Instant logical(LogicalTick value) noexcept {
    Instant instant;
    instant.domain = ClockDomain::logical_tick;
    instant.tick = value;
    return instant;
  }
  [[nodiscard]] static constexpr Instant unix_nanoseconds(std::int64_t value) noexcept {
    Instant instant;
    instant.domain = ClockDomain::unix_epoch_nanoseconds;
    instant.nanoseconds = value;
    return instant;
  }
  [[nodiscard]] static constexpr Instant monotonic_nanoseconds(std::int64_t value) noexcept {
    Instant instant;
    instant.domain = ClockDomain::monotonic_nanoseconds;
    instant.nanoseconds = value;
    return instant;
  }
  [[nodiscard]] constexpr bool is_logical() const noexcept {
    return domain == ClockDomain::logical_tick;
  }
  [[nodiscard]] bool operator==(const Instant& other) const noexcept {
    return domain == other.domain && tick == other.tick &&
           nanoseconds == other.nanoseconds;
  }
  [[nodiscard]] bool operator!=(const Instant& other) const noexcept {
    return !(*this == other);
  }
};

/// Validates an instant. Wall-clock and monotonic instants must be in
/// `[0, max_unix_nanoseconds]`; a logical instant must carry a set tick.
[[nodiscard]] Status validate_instant(const Instant& instant);

/// Quality of an observation as reported by its source.
enum class EvidenceQuality : std::uint8_t {
  good,     ///< The source asserts the reading is trustworthy.
  suspect,  ///< The source asserts reduced confidence; not usable for verification.
  bad,      ///< The source asserts the reading is wrong.
  unknown,  ///< The source does not state quality; treated as unusable.
};

[[nodiscard]] std::string_view to_token(EvidenceQuality quality) noexcept;
[[nodiscard]] bool parse_evidence_quality(std::string_view token, EvidenceQuality& out) noexcept;

/// Freshness assigned by this runtime. Never supplied by a caller.
enum class FreshnessState : std::uint8_t {
  fresh,     ///< Accepted live within the configured freshness window.
  stale,     ///< Older than the freshness window, or superseded by a newer sequence.
  recovered, ///< Loaded from durable storage; stale until revalidated.
  unknown,   ///< Never accepted by this runtime.
};

[[nodiscard]] std::string_view to_token(FreshnessState state) noexcept;

/// One telemetry observation.
struct TelemetryObservation {
  ObservationId id;                 ///< Assigned by the engine on acceptance.
  PduId pdu;
  BranchId branch;
  PduGeneration pdu_generation;     ///< Generation the source was reading.
  BranchGeneration branch_generation;
  SourceId source;                  ///< Vendor-neutral source reference.
  SequenceNumber sequence;          ///< Ordering within a source.
  Instant taken_at;                 ///< When the source believes it measured.
  Instant received_at;              ///< When this runtime accepted it.
  LogicalTick accepted_tick;        ///< Engine-assigned logical instant of acceptance.
  EvidenceQuality quality{EvidenceQuality::unknown};
  BranchCondition condition{BranchCondition::unknown};
  CurrentSample current;
  VoltageSample voltage;
  PowerSample power;
  FreshnessState freshness{FreshnessState::unknown}; ///< Assigned by the engine.

  [[nodiscard]] bool operator==(const TelemetryObservation& other) const noexcept {
    return id == other.id && pdu == other.pdu && branch == other.branch &&
           pdu_generation == other.pdu_generation &&
           branch_generation == other.branch_generation && source == other.source &&
           sequence == other.sequence && taken_at == other.taken_at &&
           received_at == other.received_at && accepted_tick == other.accepted_tick &&
           quality == other.quality &&
           condition == other.condition && current == other.current &&
           voltage == other.voltage && power == other.power &&
           freshness == other.freshness;
  }
};

/// An observation as presented for inspection, with its age already resolved.
struct TelemetryView {
  bool present{false};                              ///< False when nothing was ever recorded.
  ObservationId id;
  SourceId source;
  SequenceNumber sequence;
  Instant taken_at;
  Instant received_at;
  LogicalTick accepted_tick;
  EvidenceQuality quality{EvidenceQuality::unknown};
  FreshnessState freshness{FreshnessState::unknown};
  BranchCondition condition{BranchCondition::unknown};
  CurrentSample current;
  VoltageSample voltage;
  PowerSample power;
  LogicalTick age_ticks;                            ///< Current tick minus `taken_at`, when both are logical.
  bool age_known{false};                            ///< False when the age cannot be established.
};

}  // namespace pdu_control
