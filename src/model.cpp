#include "pdu_control/model.hpp"

namespace pdu_control {

Status validate_label(std::string_view label, std::size_t max_bytes) {
  if (label.size() > max_bytes) {
    return Status::failure(StatusCode::out_of_range,
                           "a label is at most " + std::to_string(max_bytes) +
                               " bytes and this one is " + std::to_string(label.size()) +
                               " bytes");
  }
  for (const char value : label) {
    const auto code = static_cast<unsigned char>(value);
    if (code < 0x20 || code > 0x7E) {
      // Non-ASCII bytes are refused rather than replaced, so a malformed or
      // overlong encoding cannot hide inside a label and be re-emitted later.
      return Status::failure(StatusCode::malformed_input,
                             "a label may contain only printable ASCII characters");
    }
  }
  return Status::success();
}

Status validate(const PduDefinition& definition, const ModelBounds& bounds) {
  if (definition.id.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a PDU definition requires an id");
  }
  if (!definition.generation.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a PDU definition requires a nonzero generation");
  }
  if (definition.registered_at.is_set() == false) {
    return Status::failure(StatusCode::invalid_argument,
                           "a PDU definition requires the logical instant it was registered at");
  }
  return validate_label(definition.label, bounds.max_label_bytes);
}

Status validate(const BranchDefinition& definition, const ModelBounds& bounds) {
  if (definition.id.empty()) {
    return Status::failure(StatusCode::invalid_argument, "a branch definition requires an id");
  }
  if (definition.pdu.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a branch definition requires the PDU it belongs to");
  }
  if (!definition.generation.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a branch definition requires a nonzero generation");
  }
  if (!definition.registered_at.is_set()) {
    return Status::failure(StatusCode::invalid_argument,
                           "a branch definition requires the logical instant it was registered at");
  }
  if (definition.required_interlocks.size() > bounds.max_required_interlocks_per_branch) {
    return Status::failure(StatusCode::capacity_exhausted,
                           "a branch may require at most " +
                               std::to_string(bounds.max_required_interlocks_per_branch) +
                               " interlocks");
  }
  for (std::size_t index = 0; index < definition.required_interlocks.size(); ++index) {
    if (definition.required_interlocks[index].empty()) {
      return Status::failure(StatusCode::invalid_argument,
                             "a required interlock entry must name an interlock");
    }
    for (std::size_t other = index + 1; other < definition.required_interlocks.size(); ++other) {
      if (definition.required_interlocks[index] == definition.required_interlocks[other]) {
        return Status::failure(StatusCode::duplicate_identity,
                               "a branch may not declare the same required interlock twice");
      }
    }
  }
  const Status limit_status = validate_limits(definition.limits);
  if (!limit_status.ok()) {
    return limit_status;
  }
  return validate_label(definition.label, bounds.max_label_bytes);
}

}  // namespace pdu_control
