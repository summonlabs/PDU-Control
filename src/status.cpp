#include "pdu_control/status.hpp"

#include <utility>

namespace pdu_control {
namespace {

/// One row per enumerator. Keeping the table in declaration order makes it easy
/// to see that every code has a token, and `parse_status_code` searches the same
/// table, so the two directions cannot drift apart.
constexpr std::pair<StatusCode, std::string_view> kTokens[] = {
    {StatusCode::ok, "ok"},
    {StatusCode::invalid_argument, "invalid_argument"},
    {StatusCode::out_of_range, "out_of_range"},
    {StatusCode::overflow, "overflow"},
    {StatusCode::malformed_input, "malformed_input"},
    {StatusCode::unsupported, "unsupported"},
    {StatusCode::capacity_exhausted, "capacity_exhausted"},
    {StatusCode::not_found, "not_found"},
    {StatusCode::duplicate_identity, "duplicate_identity"},
    {StatusCode::identity_mismatch, "identity_mismatch"},
    {StatusCode::generation_mismatch, "generation_mismatch"},
    {StatusCode::revision_mismatch, "revision_mismatch"},
    {StatusCode::lifecycle_forbidden, "lifecycle_forbidden"},
    {StatusCode::transition_invalid, "transition_invalid"},
    {StatusCode::permission_missing, "permission_missing"},
    {StatusCode::permission_stale, "permission_stale"},
    {StatusCode::permission_denied, "permission_denied"},
    {StatusCode::permission_scope_mismatch, "permission_scope_mismatch"},
    {StatusCode::interlock_open, "interlock_open"},
    {StatusCode::interlock_unknown, "interlock_unknown"},
    {StatusCode::evidence_missing, "evidence_missing"},
    {StatusCode::evidence_stale, "evidence_stale"},
    {StatusCode::evidence_quality, "evidence_quality"},
    {StatusCode::evidence_contradictory, "evidence_contradictory"},
    {StatusCode::limit_invalid, "limit_invalid"},
    {StatusCode::limit_exceeded, "limit_exceeded"},
    {StatusCode::adapter_unavailable, "adapter_unavailable"},
    {StatusCode::adapter_refused, "adapter_refused"},
    {StatusCode::adapter_fault, "adapter_fault"},
    {StatusCode::adapter_fenced, "adapter_fenced"},
    {StatusCode::idempotency_conflict, "idempotency_conflict"},
    {StatusCode::attempt_unresolved, "attempt_unresolved"},
    {StatusCode::attempt_not_verifiable, "attempt_not_verifiable"},
    {StatusCode::busy, "busy"},
    {StatusCode::path_invalid, "path_invalid"},
    {StatusCode::store_io, "store_io"},
    {StatusCode::store_malformed, "store_malformed"},
    {StatusCode::store_version_unsupported, "store_version_unsupported"},
    {StatusCode::store_truncated, "store_truncated"},
    {StatusCode::store_oversized, "store_oversized"},
    {StatusCode::rollback_detected, "rollback_detected"},
    {StatusCode::store_locked, "store_locked"},
    {StatusCode::internal, "internal"},
};

constexpr std::string_view kUnknownToken = "unknown_code";

}  // namespace

std::string_view to_token(StatusCode code) noexcept {
  for (const auto& entry : kTokens) {
    if (entry.first == code) {
      return entry.second;
    }
  }
  return kUnknownToken;
}

std::string_view describe(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::ok:
      return "the operation completed";
    case StatusCode::invalid_argument:
      return "a required field is absent or structurally wrong";
    case StatusCode::out_of_range:
      return "a value is outside its declared domain";
    case StatusCode::overflow:
      return "checked arithmetic refused to wrap";
    case StatusCode::malformed_input:
      return "text or bytes failed structural validation";
    case StatusCode::unsupported:
      return "the request is well formed but not modeled here";
    case StatusCode::capacity_exhausted:
      return "a bounded collection is full; the request was refused";
    case StatusCode::not_found:
      return "the referenced entity is not registered";
    case StatusCode::duplicate_identity:
      return "the identity is already registered";
    case StatusCode::identity_mismatch:
      return "entities do not belong together";
    case StatusCode::generation_mismatch:
      return "the request was planned against a stale device generation";
    case StatusCode::revision_mismatch:
      return "the request was planned against a stale state revision";
    case StatusCode::lifecycle_forbidden:
      return "the lifecycle state forbids control";
    case StatusCode::transition_invalid:
      return "the requested lifecycle transition is not declared";
    case StatusCode::permission_missing:
      return "no permission covering this branch and action exists";
    case StatusCode::permission_stale:
      return "permission is expired, revoked, or from another epoch";
    case StatusCode::permission_denied:
      return "the owning authority denied the action";
    case StatusCode::permission_scope_mismatch:
      return "permission does not cover this branch, action, or generation";
    case StatusCode::interlock_open:
      return "a protected obligation is not satisfied";
    case StatusCode::interlock_unknown:
      return "a protected obligation cannot be established";
    case StatusCode::evidence_missing:
      return "no observation of the required kind exists";
    case StatusCode::evidence_stale:
      return "an observation exists but is stale or recovered";
    case StatusCode::evidence_quality:
      return "an observation exists but its quality is insufficient";
    case StatusCode::evidence_contradictory:
      return "observations disagree and the newest cannot be trusted";
    case StatusCode::limit_invalid:
      return "limit metadata is impossible";
    case StatusCode::limit_exceeded:
      return "a checked projection exceeds a declared branch limit";
    case StatusCode::adapter_unavailable:
      return "the adapter reported that it cannot serve the request";
    case StatusCode::adapter_refused:
      return "the adapter rejected the command";
    case StatusCode::adapter_fault:
      return "the adapter returned a malformed or inconsistent outcome";
    case StatusCode::adapter_fenced:
      return "the adapter outcome belongs to another attempt or epoch";
    case StatusCode::idempotency_conflict:
      return "the idempotency key was already used for a different request";
    case StatusCode::attempt_unresolved:
      return "a previous attempt on this branch has no verified effect";
    case StatusCode::attempt_not_verifiable:
      return "the attempt is in a state that cannot be verified";
    case StatusCode::busy:
      return "another process holds write authority over the store";
    case StatusCode::path_invalid:
      return "a path failed the documented trust model checks";
    case StatusCode::store_io:
      return "an operating-system I/O operation failed";
    case StatusCode::store_malformed:
      return "durable content failed structural validation";
    case StatusCode::store_version_unsupported:
      return "the durable format version is not supported";
    case StatusCode::store_truncated:
      return "durable content ends before its declared length";
    case StatusCode::store_oversized:
      return "durable content exceeds a declared bound";
    case StatusCode::rollback_detected:
      return "the store is older than the monotonic fence requires";
    case StatusCode::store_locked:
      return "the store is locked by this process already";
    case StatusCode::internal:
      return "an invariant that should hold did not";
  }
  return "unrecognized status code";
}

bool parse_status_code(std::string_view token, StatusCode& out) noexcept {
  for (const auto& entry : kTokens) {
    if (entry.second == token) {
      out = entry.first;
      return true;
    }
  }
  return false;
}

Status Status::failure(StatusCode code, std::string message) {
  if (code == StatusCode::ok) {
    // A failure status must not claim success; that would make `ok()` lie.
    return Status{StatusCode::internal, std::move(message)};
  }
  return Status{code, std::move(message)};
}

Status Status::failure(StatusCode code) {
  return failure(code, std::string(describe(code)));
}

std::string Status::to_string() const {
  std::string text(to_token(code_));
  if (!message_.empty()) {
    text.append(": ");
    text.append(message_);
  }
  return text;
}

}  // namespace pdu_control
