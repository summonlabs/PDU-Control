#include "pdu_control/evidence.hpp"

namespace pdu_control {

std::string_view to_token(BranchCondition condition) noexcept {
  switch (condition) {
    case BranchCondition::energized:
      return "energized";
    case BranchCondition::de_energized:
      return "de_energized";
    case BranchCondition::transitioning:
      return "transitioning";
    case BranchCondition::unknown:
      return "unknown";
  }
  return "unknown_condition";
}

std::string_view to_token(CommandIntent intent) noexcept {
  switch (intent) {
    case CommandIntent::energize:
      return "energize";
    case CommandIntent::de_energize:
      return "de_energize";
  }
  return "unknown_intent";
}

bool parse_branch_condition(std::string_view token, BranchCondition& out) noexcept {
  constexpr BranchCondition kConditions[] = {BranchCondition::energized,
                                             BranchCondition::de_energized,
                                             BranchCondition::transitioning,
                                             BranchCondition::unknown};
  for (const BranchCondition condition : kConditions) {
    if (to_token(condition) == token) {
      out = condition;
      return true;
    }
  }
  return false;
}

bool parse_command_intent(std::string_view token, CommandIntent& out) noexcept {
  constexpr CommandIntent kIntents[] = {CommandIntent::energize, CommandIntent::de_energize};
  for (const CommandIntent intent : kIntents) {
    if (to_token(intent) == token) {
      out = intent;
      return true;
    }
  }
  return false;
}

std::string_view to_token(ClockDomain domain) noexcept {
  switch (domain) {
    case ClockDomain::logical_tick:
      return "logical_tick";
    case ClockDomain::unix_epoch_nanoseconds:
      return "unix_epoch_nanoseconds";
    case ClockDomain::monotonic_nanoseconds:
      return "monotonic_nanoseconds";
    case ClockDomain::vendor_opaque:
      return "vendor_opaque";
  }
  return "unknown_clock_domain";
}

bool parse_clock_domain(std::string_view token, ClockDomain& out) noexcept {
  constexpr ClockDomain kDomains[] = {ClockDomain::logical_tick,
                                      ClockDomain::unix_epoch_nanoseconds,
                                      ClockDomain::monotonic_nanoseconds,
                                      ClockDomain::vendor_opaque};
  for (const ClockDomain domain : kDomains) {
    if (to_token(domain) == token) {
      out = domain;
      return true;
    }
  }
  return false;
}

Status validate_instant(const Instant& instant) {
  if (instant.is_logical()) {
    if (!instant.tick.is_set()) {
      return Status::failure(StatusCode::invalid_argument,
                             "a logical instant must carry a set tick");
    }
    return Status::success();
  }
  if (instant.nanoseconds < 0) {
    return Status::failure(StatusCode::out_of_range,
                           "a clock instant must not be negative");
  }
  if (instant.nanoseconds > max_unix_nanoseconds) {
    return Status::failure(StatusCode::out_of_range,
                           "a clock instant beyond 2100-01-01T00:00:00Z is refused");
  }
  return Status::success();
}

std::string_view to_token(EvidenceQuality quality) noexcept {
  switch (quality) {
    case EvidenceQuality::good:
      return "good";
    case EvidenceQuality::suspect:
      return "suspect";
    case EvidenceQuality::bad:
      return "bad";
    case EvidenceQuality::unknown:
      return "unknown";
  }
  return "unknown_quality";
}

bool parse_evidence_quality(std::string_view token, EvidenceQuality& out) noexcept {
  constexpr EvidenceQuality kQualities[] = {EvidenceQuality::good, EvidenceQuality::suspect,
                                            EvidenceQuality::bad, EvidenceQuality::unknown};
  for (const EvidenceQuality quality : kQualities) {
    if (to_token(quality) == token) {
      out = quality;
      return true;
    }
  }
  return false;
}

std::string_view to_token(FreshnessState state) noexcept {
  switch (state) {
    case FreshnessState::fresh:
      return "fresh";
    case FreshnessState::stale:
      return "stale";
    case FreshnessState::recovered:
      return "recovered";
    case FreshnessState::unknown:
      return "unknown";
  }
  return "unknown_freshness";
}

}  // namespace pdu_control
