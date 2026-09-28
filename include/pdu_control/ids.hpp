#pragma once

// Strongly typed identities, generations, epochs, and revisions.
//
// The types in this header are deliberately not interchangeable. A device
// generation is not a state revision, a state revision is not an authority
// epoch, an authority epoch is not a process incarnation, and none of them is a
// generic integer. Every place that consumes one of these values names exactly
// which kind of currency it requires.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "pdu_control/status.hpp"

namespace pdu_control {

/// Tag types. Each appears exactly once as the parameter of an `Identifier` or
/// `Counter` alias, so the aliases below are distinct types.
struct PduIdTag;
struct BranchIdTag;
struct AuthorityIdTag;
struct IssuerIdTag;
struct InterlockIdTag;
struct SourceIdTag;
struct ActorIdTag;
struct AdapterIdTag;
struct ProtectionZoneIdTag;

struct PduGenerationTag;
struct BranchGenerationTag;
struct StateRevisionTag;
struct AuthorityEpochTag;
struct IncarnationTag;
struct StoreGenerationTag;
struct LogicalTickTag;
struct SequenceNumberTag;
struct AttemptIdTag;
struct ObservationIdTag;
struct AdapterSequenceTag;
struct IdempotencyKeyTag;

/// Bounded, validated textual identity.
///
/// Validation policy (part of the public contract, exercised by the tests):
///  - length is 1..96 bytes inclusive;
///  - the first byte is `[A-Za-z0-9]`;
///  - remaining bytes are `[A-Za-z0-9._-]`;
///  - bytes with the high bit set are rejected, so malformed, overlong, and
///    non-ASCII encodings cannot enter an identity;
///  - the name may not be a reserved device name (`CON`, `NUL`, `COM1`, ...)
///    because generated file names derive from identities;
///  - the empty string is not an identity: it is the "unset" representation and
///    is only produced by the default constructor.
template <typename Tag>
class Identifier {
 public:
  static constexpr std::size_t max_length = 96;

  Identifier() = default;

  /// Validates `text` and returns the identity, or the reason it was refused.
  [[nodiscard]] static Result<Identifier> parse(std::string_view text);

  /// The unset identity. `empty()` is true.
  [[nodiscard]] static Identifier unset() { return Identifier{}; }

  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }
  [[nodiscard]] const std::string& value() const noexcept { return value_; }

  [[nodiscard]] bool operator==(const Identifier& other) const noexcept {
    return value_ == other.value_;
  }
  [[nodiscard]] bool operator!=(const Identifier& other) const noexcept {
    return !(*this == other);
  }
  [[nodiscard]] bool operator<(const Identifier& other) const noexcept {
    return value_ < other.value_;
  }

 private:
  std::string value_;
};

/// Hash support for the identifier types, so they can key an unordered map.
template <typename Tag>
struct IdentifierHash {
  [[nodiscard]] std::size_t operator()(const Identifier<Tag>& value) const noexcept {
    return std::hash<std::string>{}(value.value());
  }
};

/// Monotonic counter with an explicit "unset" value of zero.
///
/// Zero means *not established*, never "the first one". Increment is checked:
/// a counter that would wrap is refused rather than reused, because reusing a
/// generation or an epoch would silently re-authorize stale work.
template <typename Tag>
class Counter {
 public:
  using value_type = std::uint64_t;

  constexpr Counter() noexcept = default;
  constexpr explicit Counter(value_type value) noexcept : value_(value) {}

  [[nodiscard]] static constexpr Counter unset() noexcept { return Counter{}; }
  [[nodiscard]] static constexpr Counter from(value_type value) noexcept {
    return Counter{value};
  }

  [[nodiscard]] constexpr value_type value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_set() const noexcept { return value_ != 0; }

  /// The next counter value; fails with `overflow` at the maximum.
  [[nodiscard]] Result<Counter> next() const;

  /// Checked addition of a delta; fails with `overflow` rather than wrapping.
  [[nodiscard]] Result<Counter> advanced_by(value_type delta) const;

  [[nodiscard]] constexpr bool operator==(const Counter& other) const noexcept {
    return value_ == other.value_;
  }
  [[nodiscard]] constexpr bool operator!=(const Counter& other) const noexcept {
    return value_ != other.value_;
  }
  [[nodiscard]] constexpr bool operator<(const Counter& other) const noexcept {
    return value_ < other.value_;
  }
  [[nodiscard]] constexpr bool operator<=(const Counter& other) const noexcept {
    return value_ <= other.value_;
  }
  [[nodiscard]] constexpr bool operator>(const Counter& other) const noexcept {
    return value_ > other.value_;
  }
  [[nodiscard]] constexpr bool operator>=(const Counter& other) const noexcept {
    return value_ >= other.value_;
  }

 private:
  value_type value_{0};
};

template <typename Tag>
struct CounterHash {
  [[nodiscard]] std::size_t operator()(const Counter<Tag>& value) const noexcept {
    return std::hash<std::uint64_t>{}(value.value());
  }
};

using PduId = Identifier<PduIdTag>;
using BranchId = Identifier<BranchIdTag>;
using AuthorityId = Identifier<AuthorityIdTag>;
using IssuerId = Identifier<IssuerIdTag>;
using InterlockId = Identifier<InterlockIdTag>;
using SourceId = Identifier<SourceIdTag>;
using ActorId = Identifier<ActorIdTag>;
using AdapterId = Identifier<AdapterIdTag>;
using ProtectionZoneId = Identifier<ProtectionZoneIdTag>;

/// Caller-supplied idempotency key.
///
/// A retry that presents the same key and the same request digest receives the
/// previously accepted result instead of a new command. Bounded and validated
/// exactly like any other identity, so a key cannot smuggle text into the store.
using IdempotencyKey = Identifier<IdempotencyKeyTag>;

/// Device generation of a PDU. Bumped when the physical unit is replaced or
/// recommissioned; a request planned against an older generation is stale.
using PduGeneration = Counter<PduGenerationTag>;

/// Device generation of a branch circuit. Independent of the PDU generation: a
/// branch can be re-terminated without the PDU being replaced.
using BranchGeneration = Counter<BranchGenerationTag>;

/// Revision of an entity's mutable state. Bumped by every accepted mutation.
using StateRevision = Counter<StateRevisionTag>;

/// Epoch of the authority layer that issued permissions and interlocks. Adopted
/// explicitly; grants from any other epoch are stale by construction.
using AuthorityEpoch = Counter<AuthorityEpochTag>;

/// Incarnation of the process that owns write authority over a store. Every
/// successful open allocates a new incarnation, so a writer that was thought to
/// be dead can be fenced.
using Incarnation = Counter<IncarnationTag>;

/// Generation of the durably published store state. Strictly increases with each
/// publication and is the monotonic fence for rollback detection.
using StoreGeneration = Counter<StoreGenerationTag>;

/// Logical instant. All control decisions are taken against an explicit logical
/// tick, never against the wall clock, so decisions are reproducible.
using LogicalTick = Counter<LogicalTickTag>;

/// Telemetry sequence number within a source. Ordering evidence, not authority.
using SequenceNumber = Counter<SequenceNumberTag>;

/// Ordinal of an operation attempt. Assigned by the engine, never by a caller.
using AttemptId = Counter<AttemptIdTag>;

/// Ordinal of a recorded telemetry observation.
using ObservationId = Counter<ObservationIdTag>;

/// Sequence of a command as seen by an adapter.
using AdapterSequence = Counter<AdapterSequenceTag>;

/// 64-bit change-detection digest.
///
/// This is a non-cryptographic digest (FNV-1a with a final avalanche mix). It is
/// used to detect state change, to bind an idempotency key to the exact request
/// it was used for, and to compare canonical encodings. It is not a signature
/// and must not be treated as one; durable integrity uses CRC-32C, which is
/// documented as corruption detection rather than authentication.
class Digest64 {
 public:
  constexpr Digest64() noexcept = default;
  constexpr explicit Digest64(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] static constexpr Digest64 from(std::uint64_t value) noexcept {
    return Digest64{value};
  }

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_set() const noexcept { return value_ != 0; }

  /// Renders 16 lowercase hexadecimal digits.
  [[nodiscard]] std::string to_hex() const;

  /// Parses exactly 16 hexadecimal digits. Rejects any other length or
  /// character, so a truncated digest is never silently accepted.
  [[nodiscard]] static Result<Digest64> from_hex(std::string_view text);

  [[nodiscard]] constexpr bool operator==(const Digest64& other) const noexcept {
    return value_ == other.value_;
  }
  [[nodiscard]] constexpr bool operator!=(const Digest64& other) const noexcept {
    return value_ != other.value_;
  }

 private:
  std::uint64_t value_{0};
};

/// Streaming FNV-1a-64 with a final avalanche mix. Deterministic: the same byte
/// sequence always produces the same digest on every platform.
class DigestBuilder {
 public:
  DigestBuilder() = default;

  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept;
  void update_byte(std::uint8_t value) noexcept;
  void update_u64(std::uint64_t value) noexcept;
  void update_i64(std::int64_t value) noexcept;
  void update_u32(std::uint32_t value) noexcept;

  [[nodiscard]] Digest64 finish() const noexcept;

 private:
  std::uint64_t state_{14695981039346656037ULL};
};

/// Convenience: the digest of one byte string.
[[nodiscard]] Digest64 digest_of(std::string_view text) noexcept;

/// True when `name` is a reserved Windows device name. Exposed because callers
/// that derive file names from identities must apply the same rule.
[[nodiscard]] bool is_reserved_device_name(std::string_view name) noexcept;

/// Validates an identifier's text under the documented policy.
[[nodiscard]] Status validate_identifier_text(std::string_view text);

}  // namespace pdu_control
