#pragma once

// Exact integer quantities.
//
// No authoritative value in this library is a floating-point number. Current,
// voltage, power, and ratios are exact integers in fixed units, and every
// arithmetic operation on them is checked: a result that would wrap is refused
// with `overflow` rather than silently becoming a different physical value.
//
// Fixed units:
//   Current  milliampere (mA)
//   Voltage  millivolt   (mV)
//   Power    milliwatt   (mW)
//   Ratio    basis point (1/100 of a percent; 10000 bp == 100 %)

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "pdu_control/ids.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control {

/// Unit of a quantity. Carried as a value so that diagnostics and canonical
/// encodings can state the unit without guessing from the type.
enum class Unit : std::uint8_t {
  milliampere,
  millivolt,
  milliwatt,
  basis_point,
};

/// Stable lowercase token: "mA", "mV", "mW", "bp".
[[nodiscard]] std::string_view to_token(Unit unit) noexcept;

/// Narrow helpers with defined overflow behaviour. Exposed for the quantity
/// templates below; they are part of the public contract because callers with
/// their own exact accounting use the same rules.
namespace detail {
[[nodiscard]] Result<std::int64_t> checked_add(std::int64_t left, std::int64_t right);
[[nodiscard]] Result<std::int64_t> checked_sub(std::int64_t left, std::int64_t right);
[[nodiscard]] Result<std::int64_t> checked_mul(std::int64_t left, std::int64_t right);
[[nodiscard]] Result<std::int64_t> checked_negate(std::int64_t value);
}  // namespace detail

/// An exact integer quantity of a named unit.
///
/// The raw value may be negative only for types whose domain permits it; use
/// `magnitude` for physical quantities such as current or power, which refuse
/// negative input at construction. Negation is available for differences.
template <typename Tag, Unit U>
class Quantity {
 public:
  using value_type = std::int64_t;
  static constexpr Unit unit = U;

  constexpr Quantity() noexcept = default;

  /// Any value, including negative. Used for signed differences.
  [[nodiscard]] static constexpr Quantity from_raw(value_type raw) noexcept {
    return Quantity{raw};
  }

  /// A physical magnitude. Negative input is refused with `out_of_range`.
  [[nodiscard]] static Result<Quantity> magnitude(value_type raw);

  [[nodiscard]] constexpr value_type raw() const noexcept { return raw_; }
  [[nodiscard]] constexpr bool is_negative() const noexcept { return raw_ < 0; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return raw_ == 0; }

  [[nodiscard]] Result<Quantity> checked_add(const Quantity& other) const;
  [[nodiscard]] Result<Quantity> checked_sub(const Quantity& other) const;
  [[nodiscard]] Result<Quantity> checked_mul(value_type factor) const;
  [[nodiscard]] Result<Quantity> checked_negate() const;

  /// Sum of a sequence, refusing overflow and refusing an empty sequence (an
  /// empty sum has no established value here and is not reported as zero).
  [[nodiscard]] static Result<Quantity> checked_sum(const std::vector<Quantity>& parts);

  [[nodiscard]] constexpr bool operator==(const Quantity& other) const noexcept {
    return raw_ == other.raw_;
  }
  [[nodiscard]] constexpr bool operator!=(const Quantity& other) const noexcept {
    return raw_ != other.raw_;
  }
  [[nodiscard]] constexpr bool operator<(const Quantity& other) const noexcept {
    return raw_ < other.raw_;
  }
  [[nodiscard]] constexpr bool operator<=(const Quantity& other) const noexcept {
    return raw_ <= other.raw_;
  }
  [[nodiscard]] constexpr bool operator>(const Quantity& other) const noexcept {
    return raw_ > other.raw_;
  }
  [[nodiscard]] constexpr bool operator>=(const Quantity& other) const noexcept {
    return raw_ >= other.raw_;
  }

 private:
  constexpr explicit Quantity(value_type raw) noexcept : raw_(raw) {}

  value_type raw_{0};
};

using Current = Quantity<struct CurrentTag, Unit::milliampere>;
using Voltage = Quantity<struct VoltageTag, Unit::millivolt>;
using Power = Quantity<struct PowerTag, Unit::milliwatt>;
using Ratio = Quantity<struct RatioTag, Unit::basis_point>;

/// 100 % as a ratio.
[[nodiscard]] constexpr Ratio full_ratio() noexcept { return Ratio::from_raw(10000); }

/// How a measurement relates to the world. "Zero" is a known value of zero and
/// is never a stand-in for any of the states below.
enum class SampleState : std::uint8_t {
  known,        ///< A value was established from evidence.
  unknown,      ///< No evidence establishes the value.
  unavailable,  ///< A source exists but could not supply the value now.
  unsupported,  ///< The quantity is not modeled by the source at all.
};

[[nodiscard]] std::string_view to_token(SampleState state) noexcept;

/// A quantity with an explicit state. Accessing the value of a sample that is
/// not `known` is a programming error and is reported as such.
template <typename Q>
class Sample {
 public:
  constexpr Sample() noexcept = default;

  [[nodiscard]] static constexpr Sample known(Q value) noexcept {
    Sample sample;
    sample.state_ = SampleState::known;
    sample.value_ = value;
    return sample;
  }
  [[nodiscard]] static constexpr Sample unknown() noexcept { return Sample{}; }
  [[nodiscard]] static constexpr Sample unavailable() noexcept {
    Sample sample;
    sample.state_ = SampleState::unavailable;
    return sample;
  }
  [[nodiscard]] static constexpr Sample unsupported() noexcept {
    Sample sample;
    sample.state_ = SampleState::unsupported;
    return sample;
  }

  [[nodiscard]] constexpr SampleState state() const noexcept { return state_; }
  [[nodiscard]] constexpr bool has_value() const noexcept {
    return state_ == SampleState::known;
  }

  /// The value. Only valid when `has_value()`; otherwise the returned value is
  /// zero and the caller has already ignored `state()`.
  [[nodiscard]] constexpr const Q& value() const noexcept { return value_; }

  /// The value when known, otherwise `fallback`.
  [[nodiscard]] constexpr Q value_or(Q fallback) const noexcept {
    return has_value() ? value_ : fallback;
  }

  [[nodiscard]] constexpr bool operator==(const Sample& other) const noexcept {
    if (state_ != other.state_) {
      return false;
    }
    return state_ != SampleState::known || value_ == other.value_;
  }
  [[nodiscard]] constexpr bool operator!=(const Sample& other) const noexcept {
    return !(*this == other);
  }

 private:
  SampleState state_{SampleState::unknown};
  Q value_{};
};

using CurrentSample = Sample<Current>;
using VoltageSample = Sample<Voltage>;
using PowerSample = Sample<Power>;
using RatioSample = Sample<Ratio>;

/// Provenance of limit metadata: where the numbers came from and how long they
/// are to be believed. This runtime consumes limits; it never derives them.
struct LimitProvenance {
  IssuerId issuer;                 ///< Owning layer (for example "power-capacity").
  AuthorityId authority;           ///< Reference to the grant that carried the limits.
  AuthorityEpoch epoch;            ///< Epoch the limits were stated in.
  LogicalTick stated_at;           ///< Logical instant the limits were stated.
  LogicalTick not_after;           ///< Exclusive expiry instant; unset means "no stated expiry".

  [[nodiscard]] bool operator==(const LimitProvenance& other) const noexcept {
    return issuer == other.issuer && authority == other.authority &&
           epoch == other.epoch && stated_at == other.stated_at &&
           not_after == other.not_after;
  }
};

/// Limit metadata for one branch circuit.
///
/// These numbers arrive from the authority that owns power capacity. They are
/// carried, arithmetically checked, and enforced here; they are never computed
/// here. A limit that is absent is `unknown` and fails closed when a check
/// needs it, and an inverted or negative limit is `limit_invalid`.
struct BranchLimits {
  CurrentSample continuous_current;  ///< Steady-state current the branch may carry.
  CurrentSample peak_current;        ///< Short-duration current the branch may carry.
  PowerSample power;                 ///< Apparent/real power ceiling for the branch.
  LimitProvenance provenance;
  StateRevision revision;            ///< Bumped on every accepted limit update.

  [[nodiscard]] bool operator==(const BranchLimits& other) const noexcept {
    return continuous_current == other.continuous_current &&
           peak_current == other.peak_current && power == other.power &&
           provenance == other.provenance && revision == other.revision;
  }
};

/// Validates limit metadata without reference to any observed load.
///
/// Refusals: a known value that is negative (`limit_invalid`); a peak below the
/// continuous limit (`limit_invalid`); a stated expiry that is not later than
/// the instant it was stated (`limit_invalid`). An unset expiry is allowed and
/// means "no expiry stated", which is distinct from "expired".
[[nodiscard]] Status validate_limits(const BranchLimits& limits);

/// Outcome of comparing a projected load against a declared limit. The verdict
/// is explicit so that "no limit is declared" is never reported as "within
/// limits".
enum class LimitVerdict : std::uint8_t {
  within_limit,      ///< The projection is known and does not exceed the limit.
  exceeds_limit,     ///< The projection is known and exceeds the limit.
  limit_unknown,     ///< The limit itself is not established.
  projection_unknown ///< The projection is not established.
};

[[nodiscard]] std::string_view to_token(LimitVerdict verdict) noexcept;

/// Compares `projected` against `limit` with checked arithmetic.
///
/// A negative projection is refused with `out_of_range` by the caller, not
/// clamped here. An empty limit sample yields `limit_unknown`, never
/// `within_limit`.
[[nodiscard]] Result<LimitVerdict> compare_to_limit(Current projected, CurrentSample limit);

}  // namespace pdu_control
