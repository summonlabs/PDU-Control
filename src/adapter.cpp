#include "pdu_control/adapter.hpp"

#include <cstddef>
#include <string>

#include "pdu_control/model.hpp"

namespace pdu_control {

std::string_view to_token(AdapterKind kind) noexcept {
  switch (kind) {
    case AdapterKind::synthetic:
      return "synthetic";
    case AdapterKind::vendor:
      return "vendor";
    case AdapterKind::gateway:
      return "gateway";
    case AdapterKind::unknown:
      return "unknown";
  }
  return "unknown_kind";
}

bool parse_adapter_kind(std::string_view token, AdapterKind& out) noexcept {
  constexpr AdapterKind kKinds[] = {AdapterKind::synthetic, AdapterKind::vendor,
                                    AdapterKind::gateway, AdapterKind::unknown};
  for (const AdapterKind kind : kKinds) {
    if (to_token(kind) == token) {
      out = kind;
      return true;
    }
  }
  return false;
}

std::string_view to_token(PreconditionKind kind) noexcept {
  switch (kind) {
    case PreconditionKind::none:
      return "none";
    case PreconditionKind::identity:
      return "identity";
    case PreconditionKind::branch_binding:
      return "branch_binding";
    case PreconditionKind::lifecycle:
      return "lifecycle";
    case PreconditionKind::no_unresolved_attempt:
      return "no_unresolved_attempt";
    case PreconditionKind::pdu_generation:
      return "pdu_generation";
    case PreconditionKind::branch_generation:
      return "branch_generation";
    case PreconditionKind::state_revision:
      return "state_revision";
    case PreconditionKind::authority_epoch:
      return "authority_epoch";
    case PreconditionKind::permission:
      return "permission";
    case PreconditionKind::interlock:
      return "interlock";
    case PreconditionKind::limits:
      return "limits";
  }
  return "unknown_precondition";
}

std::string_view to_token(AdapterDisposition disposition) noexcept {
  switch (disposition) {
    case AdapterDisposition::acknowledged:
      return "acknowledged";
    case AdapterDisposition::refused:
      return "refused";
    case AdapterDisposition::unavailable:
      return "unavailable";
    case AdapterDisposition::fault:
      return "fault";
  }
  return "unknown_disposition";
}

bool parse_adapter_disposition(std::string_view token, AdapterDisposition& out) noexcept {
  constexpr AdapterDisposition kDispositions[] = {
      AdapterDisposition::acknowledged, AdapterDisposition::refused,
      AdapterDisposition::unavailable, AdapterDisposition::fault};
  for (const AdapterDisposition disposition : kDispositions) {
    if (to_token(disposition) == token) {
      out = disposition;
      return true;
    }
  }
  return false;
}

PowerAdapter::~PowerAdapter() = default;

Status validate_descriptor(const AdapterDescriptor& descriptor) {
  if (descriptor.id.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an adapter descriptor requires an id");
  }
  if (descriptor.vendor.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an adapter descriptor requires a vendor");
  }
  constexpr std::size_t kMaxText = 64;
  Status status = validate_label(descriptor.model, kMaxText);
  if (!status.ok()) {
    return status;
  }
  return validate_label(descriptor.firmware, kMaxText);
}

Status validate_outcome(const AdapterOutcome& outcome, const AdapterCommand& command) {
  const ActuationAuthorization& authorization = command.authorization();
  if (outcome.detail.size() > max_adapter_detail_bytes) {
    return Status::failure(StatusCode::adapter_fault,
                           "the adapter returned " + std::to_string(outcome.detail.size()) +
                               " bytes of detail; the maximum is " +
                               std::to_string(max_adapter_detail_bytes));
  }
  if (outcome.sequence != command.sequence()) {
    return Status::failure(StatusCode::adapter_fenced,
                           "the adapter answered command sequence " +
                               std::to_string(outcome.sequence.value()) +
                               " but was given " + std::to_string(command.sequence().value()));
  }
  if (outcome.attempt != authorization.attempt()) {
    return Status::failure(StatusCode::adapter_fenced,
                           "the adapter answered attempt " +
                               std::to_string(outcome.attempt.value()) + " but was given " +
                               std::to_string(authorization.attempt().value()));
  }
  if (outcome.epoch != authorization.epoch()) {
    return Status::failure(StatusCode::adapter_fenced,
                           "the adapter answered in authority epoch " +
                               std::to_string(outcome.epoch.value()) + " but was given " +
                               std::to_string(authorization.epoch().value()));
  }
  if (!outcome.has_reading) {
    return Status::success();
  }
  const TelemetryObservation& reading = outcome.reading;
  if (reading.pdu.empty() || reading.branch.empty() || reading.source.empty()) {
    return Status::failure(StatusCode::adapter_fault,
                           "the reading returned with the acknowledgement does not name its "
                           "pdu, branch, and source");
  }
  if (reading.pdu != authorization.pdu() || reading.branch != authorization.branch()) {
    return Status::failure(StatusCode::adapter_fault,
                           "the reading returned with the acknowledgement is for another branch");
  }
  if (reading.pdu_generation != authorization.pdu_generation() ||
      reading.branch_generation != authorization.branch_generation()) {
    return Status::failure(StatusCode::adapter_fault,
                           "the reading returned with the acknowledgement is for another device "
                           "generation");
  }
  if (!reading.sequence.is_set()) {
    return Status::failure(StatusCode::adapter_fault,
                           "the reading returned with the acknowledgement has no sequence");
  }
  return validate_instant(reading.taken_at);
}

}  // namespace pdu_control
