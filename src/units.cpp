#include "pdu_control/units.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace pdu_control {

namespace detail {

Result<std::int64_t> checked_add(std::int64_t left, std::int64_t right) {
  constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
  constexpr std::int64_t kMin = std::numeric_limits<std::int64_t>::min();
  if (right > 0 && left > kMax - right) {
    return Status::failure(StatusCode::overflow, "integer addition would overflow");
  }
  if (right < 0 && left < kMin - right) {
    return Status::failure(StatusCode::overflow, "integer addition would underflow");
  }
  return left + right;
}

Result<std::int64_t> checked_sub(std::int64_t left, std::int64_t right) {
  constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
  constexpr std::int64_t kMin = std::numeric_limits<std::int64_t>::min();
  if (right < 0 && left > kMax + right) {
    return Status::failure(StatusCode::overflow, "integer subtraction would overflow");
  }
  if (right > 0 && left < kMin + right) {
    return Status::failure(StatusCode::overflow, "integer subtraction would underflow");
  }
  return left - right;
}

Result<std::int64_t> checked_mul(std::int64_t left, std::int64_t right) {
  constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
  constexpr std::int64_t kMin = std::numeric_limits<std::int64_t>::min();
  if (left == 0 || right == 0) {
    return std::int64_t{0};
  }
  if (left == -1) {
    if (right == kMin) {
      return Status::failure(StatusCode::overflow, "integer multiplication would overflow");
    }
    return -right;
  }
  if (right == -1) {
    if (left == kMin) {
      return Status::failure(StatusCode::overflow, "integer multiplication would overflow");
    }
    return -left;
  }
  if (left > 0) {
    if (right > 0) {
      if (left > kMax / right) {
        return Status::failure(StatusCode::overflow, "integer multiplication would overflow");
      }
    } else if (right < kMin / left) {
      return Status::failure(StatusCode::overflow, "integer multiplication would underflow");
    }
  } else {
    if (right > 0) {
      if (left < kMin / right) {
        return Status::failure(StatusCode::overflow, "integer multiplication would underflow");
      }
    } else if (left != 0 && right < kMax / left) {
      return Status::failure(StatusCode::overflow, "integer multiplication would overflow");
    }
  }
  return left * right;
}

Result<std::int64_t> checked_negate(std::int64_t value) {
  if (value == std::numeric_limits<std::int64_t>::min()) {
    return Status::failure(StatusCode::overflow, "negating this value would overflow");
  }
  return -value;
}

}  // namespace detail

std::string_view to_token(Unit unit) noexcept {
  switch (unit) {
    case Unit::milliampere:
      return "mA";
    case Unit::millivolt:
      return "mV";
    case Unit::milliwatt:
      return "mW";
    case Unit::basis_point:
      return "bp";
  }
  return "unknown_unit";
}

std::string_view to_token(SampleState state) noexcept {
  switch (state) {
    case SampleState::known:
      return "known";
    case SampleState::unknown:
      return "unknown";
    case SampleState::unavailable:
      return "unavailable";
    case SampleState::unsupported:
      return "unsupported";
  }
  return "unknown_state";
}

std::string_view to_token(LimitVerdict verdict) noexcept {
  switch (verdict) {
    case LimitVerdict::within_limit:
      return "within_limit";
    case LimitVerdict::exceeds_limit:
      return "exceeds_limit";
    case LimitVerdict::limit_unknown:
      return "limit_unknown";
    case LimitVerdict::projection_unknown:
      return "projection_unknown";
  }
  return "unknown_verdict";
}

template <typename Tag, Unit U>
Result<Quantity<Tag, U>> Quantity<Tag, U>::magnitude(value_type raw) {
  if (raw < 0) {
    return Status::failure(StatusCode::out_of_range,
                           "a physical magnitude must not be negative; this one is " +
                               std::to_string(raw) + " " + std::string(to_token(U)));
  }
  return Quantity{raw};
}

template <typename Tag, Unit U>
Result<Quantity<Tag, U>> Quantity<Tag, U>::checked_add(const Quantity& other) const {
  auto sum = detail::checked_add(raw_, other.raw_);
  if (!sum.ok()) {
    return sum.status();
  }
  return Quantity{sum.value()};
}

template <typename Tag, Unit U>
Result<Quantity<Tag, U>> Quantity<Tag, U>::checked_sub(const Quantity& other) const {
  auto difference = detail::checked_sub(raw_, other.raw_);
  if (!difference.ok()) {
    return difference.status();
  }
  return Quantity{difference.value()};
}

template <typename Tag, Unit U>
Result<Quantity<Tag, U>> Quantity<Tag, U>::checked_mul(value_type factor) const {
  auto product = detail::checked_mul(raw_, factor);
  if (!product.ok()) {
    return product.status();
  }
  return Quantity{product.value()};
}

template <typename Tag, Unit U>
Result<Quantity<Tag, U>> Quantity<Tag, U>::checked_negate() const {
  auto negated = detail::checked_negate(raw_);
  if (!negated.ok()) {
    return negated.status();
  }
  return Quantity{negated.value()};
}

template <typename Tag, Unit U>
Result<Quantity<Tag, U>> Quantity<Tag, U>::checked_sum(const std::vector<Quantity>& parts) {
  if (parts.empty()) {
    // An empty sum has no established value. Reporting zero would claim that an
    // empty set of loads draws no current, which is an assertion, not a fact.
    return Status::failure(StatusCode::invalid_argument,
                           "an empty sequence has no established sum");
  }
  std::int64_t total = 0;
  for (const Quantity& part : parts) {
    auto next = detail::checked_add(total, part.raw_);
    if (!next.ok()) {
      return next.status();
    }
    total = next.value();
  }
  return Quantity{total};
}

Status validate_limits(const BranchLimits& limits) {
  if (limits.continuous_current.has_value() && limits.continuous_current.value().is_negative()) {
    return Status::failure(StatusCode::limit_invalid,
                           "the continuous current limit is negative");
  }
  if (limits.peak_current.has_value() && limits.peak_current.value().is_negative()) {
    return Status::failure(StatusCode::limit_invalid, "the peak current limit is negative");
  }
  if (limits.power.has_value() && limits.power.value().is_negative()) {
    return Status::failure(StatusCode::limit_invalid, "the power limit is negative");
  }
  if (limits.continuous_current.has_value() && limits.peak_current.has_value() &&
      limits.peak_current.value() < limits.continuous_current.value()) {
    return Status::failure(StatusCode::limit_invalid,
                           "the peak current limit is below the continuous current limit");
  }
  const bool any_value = limits.continuous_current.has_value() ||
                         limits.peak_current.has_value() || limits.power.has_value();
  if (any_value && limits.provenance.issuer.empty()) {
    return Status::failure(StatusCode::limit_invalid,
                           "limit values were supplied without a provenance issuer");
  }
  if (limits.provenance.not_after.is_set() && limits.provenance.stated_at.is_set() &&
      limits.provenance.not_after <= limits.provenance.stated_at) {
    return Status::failure(StatusCode::limit_invalid,
                           "limit provenance expires at or before the instant it was stated");
  }
  return Status::success();
}

Result<LimitVerdict> compare_to_limit(Current projected, CurrentSample limit) {
  if (!limit.has_value()) {
    // A limit that is not established cannot be satisfied. Reporting
    // "within limits" here would turn missing evidence into permission.
    return LimitVerdict::limit_unknown;
  }
  if (projected > limit.value()) {
    return LimitVerdict::exceeds_limit;
  }
  return LimitVerdict::within_limit;
}

template class Quantity<CurrentTag, Unit::milliampere>;
template class Quantity<VoltageTag, Unit::millivolt>;
template class Quantity<PowerTag, Unit::milliwatt>;
template class Quantity<RatioTag, Unit::basis_point>;

}  // namespace pdu_control
