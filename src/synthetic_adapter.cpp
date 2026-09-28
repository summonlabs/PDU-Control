#include "pdu_control/synthetic_adapter.hpp"

#include <string>
#include <utility>

namespace pdu_control {

std::string_view to_token(SyntheticMode mode) noexcept {
  switch (mode) {
    case SyntheticMode::honor:
      return "honor";
    case SyntheticMode::ack_without_effect:
      return "ack_without_effect";
    case SyntheticMode::refuse:
      return "refuse";
    case SyntheticMode::unavailable:
      return "unavailable";
    case SyntheticMode::fault:
      return "fault";
    case SyntheticMode::no_readback:
      return "no_readback";
    case SyntheticMode::frozen_readings:
      return "frozen_readings";
    case SyntheticMode::mismatched_echo:
      return "mismatched_echo";
  }
  return "unknown_mode";
}

bool parse_synthetic_mode(std::string_view token, SyntheticMode& out) noexcept {
  constexpr SyntheticMode kModes[] = {
      SyntheticMode::honor,         SyntheticMode::ack_without_effect,
      SyntheticMode::refuse,        SyntheticMode::unavailable,
      SyntheticMode::fault,         SyntheticMode::no_readback,
      SyntheticMode::frozen_readings, SyntheticMode::mismatched_echo};
  for (const SyntheticMode mode : kModes) {
    if (to_token(mode) == token) {
      out = mode;
      return true;
    }
  }
  return false;
}

SyntheticPduAdapter::SyntheticPduAdapter(Config config)
    : config_(std::move(config)), condition_(config_.initial_condition) {
  // Deterministic defaults, so a minimally configured adapter is still fully
  // described. These literals satisfy the identity policy by construction.
  if (config_.id.empty()) {
    config_.id = AdapterId::parse("synthetic-adapter").value();
  }
  if (config_.vendor.empty()) {
    config_.vendor = IssuerId::parse("synthetic").value();
  }
  if (config_.model.empty()) {
    config_.model = "synthetic-pdu";
  }
  if (config_.firmware.empty()) {
    config_.firmware = "0";
  }
  if (config_.reading_taken_at.is_logical()) {
    next_reading_tick_ = config_.reading_taken_at.tick;
  } else {
    next_reading_tick_ = LogicalTick::from(1);
  }
}

AdapterDescriptor SyntheticPduAdapter::describe() const {
  AdapterDescriptor descriptor;
  descriptor.id = config_.id;
  descriptor.vendor = config_.vendor;
  descriptor.model = config_.model;
  descriptor.firmware = config_.firmware;
  descriptor.kind = AdapterKind::synthetic;
  descriptor.supports_readback = config_.mode != SyntheticMode::no_readback;
  descriptor.synthetic = true;
  return descriptor;
}

AdapterOutcome SyntheticPduAdapter::execute(const AdapterCommand& command) {
  ++execute_count_;
  last_attempt_ = command.authorization().attempt();

  AdapterCommandTrace trace;
  trace.sequence = command.sequence();
  trace.attempt = command.authorization().attempt();
  trace.epoch = command.authorization().epoch();
  trace.intent = command.intent();
  trace.validated = command.authorization().validated();
  trace.complete_preconditions = command.authorization().complete_for_control();
  trace.pdu_generation = command.authorization().pdu_generation();
  trace.branch_generation = command.authorization().branch_generation();
  traces_.push_back(trace);
  if (traces_.size() > synthetic_command_trace_capacity) {
    traces_.erase(traces_.begin());
  }

  AdapterOutcome outcome;
  outcome.sequence = command.sequence();
  outcome.attempt = command.authorization().attempt();
  outcome.epoch = command.authorization().epoch();

  switch (config_.mode) {
    case SyntheticMode::honor:
    case SyntheticMode::no_readback:
      condition_ = target_condition(command.intent());
      outcome.disposition = AdapterDisposition::acknowledged;
      outcome.detail = "applied";
      break;
    case SyntheticMode::frozen_readings:
      condition_ = target_condition(command.intent());
      outcome.disposition = AdapterDisposition::acknowledged;
      outcome.detail = "applied; readings are not refreshed by this adapter";
      break;
    case SyntheticMode::ack_without_effect:
      outcome.disposition = AdapterDisposition::acknowledged;
      outcome.detail = "acknowledged without applying";
      break;
    case SyntheticMode::mismatched_echo: {
      // A deliberately wrong echo. The engine must fence it rather than
      // attribute the answer to the command it was given.
      const auto next = command.authorization().attempt().next();
      outcome.attempt = next.ok() ? next.value() : command.authorization().attempt();
      outcome.disposition = AdapterDisposition::acknowledged;
      outcome.detail = "acknowledged with a mismatched echo";
      break;
    }
    case SyntheticMode::refuse:
      outcome.disposition = AdapterDisposition::refused;
      outcome.detail = "refused by synthetic policy";
      break;
    case SyntheticMode::unavailable:
      outcome.disposition = AdapterDisposition::unavailable;
      outcome.detail = "synthetic adapter is not available";
      break;
    case SyntheticMode::fault:
      outcome.disposition = AdapterDisposition::fault;
      outcome.detail = "synthetic adapter fault";
      break;
  }
  return outcome;
}

Result<TelemetryObservation> SyntheticPduAdapter::read(const AdapterReadRequest& request) {
  ++read_count_;
  switch (config_.mode) {
    case SyntheticMode::no_readback:
      return Status::failure(StatusCode::adapter_unavailable,
                             "this synthetic adapter does not support read-back");
    case SyntheticMode::refuse:
      return Status::failure(StatusCode::adapter_unavailable,
                             "this synthetic adapter refuses to read");
    case SyntheticMode::unavailable:
      return Status::failure(StatusCode::adapter_unavailable,
                             "this synthetic adapter is not available");
    case SyntheticMode::fault:
      return Status::failure(StatusCode::adapter_fault, "this synthetic adapter reports a fault");
    case SyntheticMode::honor:
    case SyntheticMode::ack_without_effect:
    case SyntheticMode::mismatched_echo:
    case SyntheticMode::frozen_readings:
      break;
  }

  TelemetryObservation observation;
  observation.pdu = request.pdu;
  observation.branch = request.branch;
  observation.pdu_generation = request.pdu_generation;
  observation.branch_generation = request.branch_generation;
  // The adapter identity doubles as the telemetry source identity; both follow
  // the same validation policy, so the conversion cannot fail for a configured
  // adapter.
  const Result<SourceId> source = SourceId::parse(config_.id.value());
  observation.source = source.ok() ? source.value() : SourceId::parse("synthetic-source").value();
  observation.sequence = SequenceNumber::from(read_count_);
  if (config_.mode == SyntheticMode::frozen_readings) {
    // The reading instant never advances. A reading taken before a command can
    // never be evidence of that command's effect, which is exactly the case the
    // engine must refuse.
    observation.taken_at = config_.reading_taken_at;
  } else if (config_.read_at_request_instant && request.at.is_set()) {
    observation.taken_at = Instant::logical(request.at);
  } else {
    observation.taken_at = Instant::logical(next_reading_tick_);
    if (config_.reading_tick_step.is_set()) {
      const auto advanced = next_reading_tick_.advanced_by(config_.reading_tick_step.value());
      if (advanced.ok()) {
        next_reading_tick_ = advanced.value();
      }
    }
  }
  observation.quality = config_.reading_quality;
  observation.condition = condition_;
  observation.current = config_.current;
  observation.voltage = config_.voltage;
  observation.power = config_.power;
  return observation;
}

void SyntheticPduAdapter::set_condition(BranchCondition condition) noexcept { condition_ = condition; }

void SyntheticPduAdapter::set_current(CurrentSample sample) noexcept { config_.current = sample; }

void SyntheticPduAdapter::set_voltage(VoltageSample sample) noexcept { config_.voltage = sample; }

void SyntheticPduAdapter::set_power(PowerSample sample) noexcept { config_.power = sample; }

void SyntheticPduAdapter::set_reading_quality(EvidenceQuality quality) noexcept {
  config_.reading_quality = quality;
}

void SyntheticPduAdapter::set_reading_taken_at(Instant instant) noexcept {
  config_.reading_taken_at = instant;
  if (instant.is_logical()) {
    next_reading_tick_ = instant.tick;
  }
}

void SyntheticPduAdapter::set_mode(SyntheticMode mode) noexcept { config_.mode = mode; }

}  // namespace pdu_control
