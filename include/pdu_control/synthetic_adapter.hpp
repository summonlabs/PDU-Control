#pragma once

// A deterministic synthetic adapter.
//
// This adapter drives no hardware. It exists so that the control semantics of
// this runtime can be exercised end to end, deterministically, without a
// physical PDU: the same command sequence always produces the same outcome, no
// clock is read, no randomness is used, and no timing assumption is made.
//
// Every result produced through this adapter is SYNTHETIC evidence. It is never
// hardware proof, and the CLI and examples label it as such. A real integration
// implements `PowerAdapter` the same way and is then subject to exactly the same
// engine-side validation.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pdu_control/adapter.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control {

/// What a synthetic adapter does with the commands it receives.
enum class SyntheticMode : std::uint8_t {
  /// Applies the command: the reported condition follows the command.
  honor,
  /// Acknowledges every command and changes nothing. Models the case the whole
  /// runtime exists to catch: an acknowledgement that produces no effect.
  ack_without_effect,
  /// Refuses every command.
  refuse,
  /// Reports that it cannot serve the request.
  unavailable,
  /// Reports an internal fault.
  fault,
  /// Applies the command but refuses every read-back.
  no_readback,
  /// Applies the command but reports readings whose instant never advances, so
  /// they can never be ordered after a command and are therefore stale.
  frozen_readings,
  /// Applies the command but answers with a mismatched echo, which the engine
  /// fences.
  mismatched_echo,
};

[[nodiscard]] std::string_view to_token(SyntheticMode mode) noexcept;
[[nodiscard]] bool parse_synthetic_mode(std::string_view token, SyntheticMode& out) noexcept;

/// One command as the adapter saw it. Bounded, so an adapter can never grow
/// without limit because a caller kept issuing.
struct AdapterCommandTrace {
  AdapterSequence sequence;
  AttemptId attempt;
  AuthorityEpoch epoch;
  CommandIntent intent{CommandIntent::de_energize};
  PreconditionMask validated{0};
  bool complete_preconditions{false};
  PduGeneration pdu_generation;
  BranchGeneration branch_generation;
};

/// Largest number of commands a synthetic adapter remembers.
inline constexpr std::size_t synthetic_command_trace_capacity = 256;

/// Largest number of readings a synthetic adapter remembers.
inline constexpr std::size_t synthetic_read_trace_capacity = 256;

class SyntheticPduAdapter final : public PowerAdapter {
 public:
  struct Config {
    AdapterId id;
    IssuerId vendor;
    std::string model;
    std::string firmware;
    PduId pdu;
    BranchId branch;
    PduGeneration pdu_generation;
    BranchGeneration branch_generation;
    SyntheticMode mode{SyntheticMode::honor};
    BranchCondition initial_condition{BranchCondition::de_energized};
    Instant reading_taken_at{Instant::logical(LogicalTick::from(1))};
    /// Added to `reading_taken_at` before each read. Zero keeps readings at a
    /// fixed instant.
    LogicalTick reading_tick_step;
    /// When set, a reading is reported at the instant the caller asked for it,
    /// which is what a synchronous read-back device does. The
    /// `frozen_readings` mode ignores this, because reporting a reading from
    /// before the command is the whole point of that mode.
    bool read_at_request_instant{false};
    EvidenceQuality reading_quality{EvidenceQuality::good};
    CurrentSample current;
    VoltageSample voltage;
    PowerSample power;
    /// When false the adapter reports itself as a vendor adapter that drives no
    /// hardware; used by tests that check SYNTHETIC labeling.
    bool synthetic{true};
  };

  explicit SyntheticPduAdapter(Config config);

  [[nodiscard]] AdapterDescriptor describe() const override;
  [[nodiscard]] AdapterOutcome execute(const AdapterCommand& command) override;
  [[nodiscard]] Result<TelemetryObservation> read(const AdapterReadRequest& request) override;

  // -- deterministic introspection -----------------------------------------

  [[nodiscard]] std::size_t execute_count() const noexcept { return execute_count_; }
  [[nodiscard]] std::size_t read_count() const noexcept { return read_count_; }
  [[nodiscard]] BranchCondition reported_condition() const noexcept { return condition_; }
  [[nodiscard]] const std::vector<AdapterCommandTrace>& commands() const noexcept {
    return traces_;
  }
  [[nodiscard]] AttemptId last_attempt() const noexcept { return last_attempt_; }

  /// Simulates the physical world changing outside the adapter.
  void set_condition(BranchCondition condition) noexcept;
  void set_current(CurrentSample sample) noexcept;
  void set_voltage(VoltageSample sample) noexcept;
  void set_power(PowerSample sample) noexcept;
  void set_reading_quality(EvidenceQuality quality) noexcept;
  void set_reading_taken_at(Instant instant) noexcept;
  void set_mode(SyntheticMode mode) noexcept;

 private:
  Config config_;
  BranchCondition condition_{BranchCondition::de_energized};
  std::vector<AdapterCommandTrace> traces_;
  std::size_t execute_count_{0};
  std::size_t read_count_{0};
  AttemptId last_attempt_;
  LogicalTick next_reading_tick_;
};

}  // namespace pdu_control
