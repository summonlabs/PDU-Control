#pragma once

// Explicit, deterministic outcomes. Every fallible operation in this library
// returns either a `Status` or a `Result<T>`; nothing signals failure by
// returning a sentinel value, and no failure is expressed by throwing.
//
// A code identifies one *class* of outcome. The code that a request produces is
// a function of the request and the current state only: the validation
// precedence documented on PduControlEngine guarantees that the same invalid
// request always produces the same primary code.

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace pdu_control {

/// Outcome class for every library operation.
///
/// The enumerators are grouped by the layer that produces them. Names are part
/// of the public contract: `to_token` renders them into stable lowercase
/// tokens used by the CLI, the audit trail, and the tests.
enum class StatusCode : std::uint16_t {
  ok = 0,

  // --- request shape -------------------------------------------------------
  invalid_argument,        ///< A required field is absent or structurally wrong.
  out_of_range,            ///< A value is outside its declared domain.
  overflow,                ///< Checked arithmetic refused to wrap.
  malformed_input,         ///< Text or bytes failed structural validation.
  unsupported,             ///< The request is well formed but not modeled here.
  capacity_exhausted,      ///< A bounded collection is full; the request was refused.

  // --- identity, generation, revision -------------------------------------
  not_found,               ///< The referenced entity is not registered.
  duplicate_identity,      ///< The identity is already registered.
  identity_mismatch,       ///< Entities do not belong together (branch/pdu, scope).
  generation_mismatch,     ///< Stale device generation; refused, never merged.
  revision_mismatch,       ///< Stale state revision; refused, never merged.

  // --- lifecycle -----------------------------------------------------------
  lifecycle_forbidden,     ///< The lifecycle state forbids control.
  transition_invalid,      ///< The requested lifecycle transition is not declared.

  // --- authority -----------------------------------------------------------
  permission_missing,      ///< No permission covering this branch and action exists.
  permission_stale,        ///< Permission is expired, revoked, or from another epoch.
  permission_denied,       ///< The owning authority explicitly denied the action.
  permission_scope_mismatch, ///< Permission does not cover this branch/action/generation.
  interlock_open,          ///< A protected obligation is not satisfied.
  interlock_unknown,       ///< A protected obligation cannot be established; fails closed.

  // --- evidence ------------------------------------------------------------
  evidence_missing,        ///< No observation of the required kind exists.
  evidence_stale,          ///< An observation exists but is stale or recovered.
  evidence_quality,        ///< An observation exists but its quality is insufficient.
  evidence_contradictory,  ///< Observations disagree and the newest cannot be trusted.

  // --- limits --------------------------------------------------------------
  limit_invalid,           ///< Limit metadata is impossible (negative, inverted, absent).
  limit_exceeded,          ///< A checked projection exceeds a declared branch limit.

  // --- adapter -------------------------------------------------------------
  adapter_unavailable,     ///< The adapter reported that it cannot serve the request.
  adapter_refused,         ///< The adapter rejected the command.
  adapter_fault,           ///< The adapter returned a malformed or inconsistent outcome.
  adapter_fenced,          ///< The adapter outcome belongs to another attempt or epoch.

  // --- attempts ------------------------------------------------------------
  idempotency_conflict,    ///< The key was used for a different request.
  attempt_unresolved,      ///< A previous attempt on this branch has no verified effect.
  attempt_not_verifiable,  ///< The attempt is in a state that cannot be verified.

  // --- store ---------------------------------------------------------------
  busy,                    ///< Another process holds write authority over the store.
  path_invalid,            ///< A path failed the documented trust model checks.
  store_io,                ///< An operating-system I/O operation failed.
  store_malformed,         ///< Durable content failed structural validation.
  store_version_unsupported, ///< The durable format version is not supported.
  store_truncated,         ///< Durable content ends before its declared length.
  store_oversized,         ///< Durable content exceeds a declared bound.
  rollback_detected,       ///< The store is older than the monotonic fence requires.
  store_locked,            ///< The store is locked by this process already.

  // --- internal ------------------------------------------------------------
  internal                 ///< An invariant that should hold did not; report it.
};

/// True when the code denotes success. `ok` is the only success code.
[[nodiscard]] constexpr bool is_success(StatusCode code) noexcept {
  return code == StatusCode::ok;
}

/// Stable lowercase token for a code, used by the CLI, JSON output, and audit
/// records. The mapping is total and never changes for an existing enumerator.
[[nodiscard]] std::string_view to_token(StatusCode code) noexcept;

/// Human-readable description of a code. Intended for diagnostics; `to_token`
/// is the stable machine form.
[[nodiscard]] std::string_view describe(StatusCode code) noexcept;

/// Parses a token produced by `to_token`. Returns `internal` handling through
/// an optional-free API: the caller learns whether the token was recognized.
[[nodiscard]] bool parse_status_code(std::string_view token, StatusCode& out) noexcept;

/// A code plus a bounded, library-generated explanation.
class Status {
 public:
  Status() = default;

  Status(StatusCode code, std::string message)
      : code_(code), message_(std::move(message)) {}

  /// Success. The message is empty.
  [[nodiscard]] static Status success() { return Status{}; }

  /// Failure with a generated message. `code` must not be `ok`.
  [[nodiscard]] static Status failure(StatusCode code, std::string message);

  /// Failure whose message is the standard description of `code`.
  [[nodiscard]] static Status failure(StatusCode code);

  [[nodiscard]] StatusCode code() const noexcept { return code_; }
  [[nodiscard]] bool ok() const noexcept { return code_ == StatusCode::ok; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }
  [[nodiscard]] std::string_view token() const noexcept { return to_token(code_); }

  /// Renders "token: message" (or just the token when the message is empty).
  [[nodiscard]] std::string to_string() const;

 private:
  StatusCode code_{StatusCode::ok};
  std::string message_;
};

[[nodiscard]] inline bool operator==(const Status& left, const Status& right) noexcept {
  return left.code() == right.code();
}
[[nodiscard]] inline bool operator!=(const Status& left, const Status& right) noexcept {
  return !(left == right);
}

/// Either a value or a `Status`. Constructed implicitly from either, so that a
/// function can `return value;` or `return Status::failure(...);`.
template <typename T>
class Result {
 public:
  Result(T value) : storage_(std::move(value)) {}                    // NOLINT(google-explicit-constructor)
  Result(Status status) : storage_(std::move(status)) {}             // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool ok() const noexcept { return storage_.index() == 0; }
  [[nodiscard]] StatusCode code() const noexcept {
    return ok() ? StatusCode::ok : std::get<1>(storage_).code();
  }

  /// The failure status. Returns a success status when the result holds a value.
  [[nodiscard]] const Status& status() const noexcept {
    static const Status kOk = Status::success();
    return ok() ? kOk : std::get<1>(storage_);
  }

  /// The held value. Calling this on a failed result is a programming error and
  /// is reported as such rather than silently returning a default value.
  [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
  [[nodiscard]] T& value() & { return std::get<0>(storage_); }
  [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

  [[nodiscard]] const T* operator->() const { return &std::get<0>(storage_); }
  [[nodiscard]] T* operator->() { return &std::get<0>(storage_); }
  [[nodiscard]] const T& operator*() const& { return std::get<0>(storage_); }
  [[nodiscard]] T& operator*() & { return std::get<0>(storage_); }

  /// Returns the value when present, otherwise `fallback`.
  template <typename U>
  [[nodiscard]] T value_or(U&& fallback) const {
    return ok() ? std::get<0>(storage_) : static_cast<T>(std::forward<U>(fallback));
  }

 private:
  std::variant<T, Status> storage_;
};

}  // namespace pdu_control
