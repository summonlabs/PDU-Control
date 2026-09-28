#include "pdu_control/ids.hpp"

#include <cstddef>
#include <string>

namespace pdu_control {
namespace {

constexpr bool is_ascii_digit(char value) noexcept {
  return value >= '0' && value <= '9';
}

constexpr bool is_ascii_alpha(char value) noexcept {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
}

constexpr bool is_leading_character(char value) noexcept {
  return is_ascii_digit(value) || is_ascii_alpha(value);
}

constexpr bool is_body_character(char value) noexcept {
  return is_leading_character(value) || value == '.' || value == '_' || value == '-';
}

constexpr char to_upper(char value) noexcept {
  return (value >= 'a' && value <= 'z') ? static_cast<char>(value - 'a' + 'A') : value;
}

}  // namespace

bool is_reserved_device_name(std::string_view name) noexcept {
  // The reserved set is matched on the stem before the first dot, because
  // "NUL.backup" addresses the same device as "NUL" on Windows.
  std::string_view stem = name;
  const std::size_t dot = name.find('.');
  if (dot != std::string_view::npos) {
    stem = name.substr(0, dot);
  }
  if (stem.empty() || stem.size() > 4) {
    return false;
  }
  char upper[4] = {'\0', '\0', '\0', '\0'};
  for (std::size_t index = 0; index < stem.size(); ++index) {
    upper[index] = to_upper(stem[index]);
  }
  const std::string_view text(upper, stem.size());
  if (text == "CON" || text == "PRN" || text == "AUX" || text == "NUL") {
    return true;
  }
  if (text.size() == 4 && text[3] >= '1' && text[3] <= '9') {
    const std::string_view prefix = text.substr(0, 3);
    if (prefix == "COM" || prefix == "LPT") {
      return true;
    }
  }
  return false;
}

Status validate_identifier_text(std::string_view text) {
  if (text.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "an identity must not be empty; the empty string is the unset value");
  }
  if (text.size() > Identifier<PduIdTag>::max_length) {
    return Status::failure(StatusCode::out_of_range,
                           "an identity is at most 96 bytes and this one is " +
                               std::to_string(text.size()) + " bytes");
  }
  if (!is_leading_character(text.front())) {
    return Status::failure(StatusCode::malformed_input,
                           "an identity must start with an ASCII letter or digit");
  }
  for (const char value : text) {
    if (!is_body_character(value)) {
      // Any byte with the high bit set lands here as well, so malformed,
      // overlong, and non-ASCII encodings cannot enter an identity.
      return Status::failure(StatusCode::malformed_input,
                             "an identity may contain only ASCII letters, digits, '.', '_' and '-'");
    }
  }
  if (text.back() == '.' || text.back() == ' ') {
    return Status::failure(StatusCode::malformed_input,
                           "an identity must not end with a dot or a space");
  }
  if (is_reserved_device_name(text)) {
    return Status::failure(StatusCode::malformed_input,
                           "an identity must not be a reserved device name");
  }
  return Status::success();
}

template <typename Tag>
Result<Identifier<Tag>> Identifier<Tag>::parse(std::string_view text) {
  const Status status = validate_identifier_text(text);
  if (!status.ok()) {
    return status;
  }
  Identifier result;
  result.value_.assign(text.data(), text.size());
  return result;
}

template <typename Tag>
Result<Counter<Tag>> Counter<Tag>::next() const {
  if (value_ == static_cast<value_type>(-1)) {
    return Status::failure(StatusCode::overflow,
                           "the counter is at its maximum value and must not wrap");
  }
  return Counter{value_ + 1};
}

template <typename Tag>
Result<Counter<Tag>> Counter<Tag>::advanced_by(value_type delta) const {
  if (delta > static_cast<value_type>(-1) - value_) {
    return Status::failure(StatusCode::overflow,
                           "advancing the counter by " + std::to_string(delta) +
                               " from " + std::to_string(value_) + " would wrap");
  }
  return Counter{value_ + delta};
}

std::string Digest64::to_hex() const {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string text(16, '0');
  for (std::size_t index = 0; index < 16; ++index) {
    const std::size_t shift = (15 - index) * 4;
    text[index] = kDigits[(value_ >> shift) & 0xFULL];
  }
  return text;
}

Result<Digest64> Digest64::from_hex(std::string_view text) {
  if (text.size() != 16) {
    return Status::failure(StatusCode::malformed_input,
                           "a digest is exactly 16 hexadecimal digits and this one has " +
                               std::to_string(text.size()));
  }
  std::uint64_t value = 0;
  for (const char digit : text) {
    std::uint64_t nibble = 0;
    if (digit >= '0' && digit <= '9') {
      nibble = static_cast<std::uint64_t>(digit - '0');
    } else if (digit >= 'a' && digit <= 'f') {
      nibble = static_cast<std::uint64_t>(digit - 'a' + 10);
    } else if (digit >= 'A' && digit <= 'F') {
      nibble = static_cast<std::uint64_t>(digit - 'A' + 10);
    } else {
      return Status::failure(StatusCode::malformed_input,
                             "a digest may contain only hexadecimal digits");
    }
    value = (value << 4) | nibble;
  }
  return Digest64::from(value);
}

void DigestBuilder::update(const void* data, std::size_t size) noexcept {
  const auto* bytes = static_cast<const unsigned char*>(data);
  std::uint64_t state = state_;
  for (std::size_t index = 0; index < size; ++index) {
    state ^= static_cast<std::uint64_t>(bytes[index]);
    state *= 1099511628211ULL;  // FNV-1a 64-bit prime
  }
  state_ = state;
}

void DigestBuilder::update(std::string_view text) noexcept {
  update(text.data(), text.size());
}

void DigestBuilder::update_byte(std::uint8_t value) noexcept {
  update(&value, 1);
}

void DigestBuilder::update_u64(std::uint64_t value) noexcept {
  unsigned char bytes[8];
  for (std::size_t index = 0; index < 8; ++index) {
    bytes[index] = static_cast<unsigned char>((value >> (index * 8)) & 0xFFULL);
  }
  update(bytes, sizeof(bytes));
}

void DigestBuilder::update_i64(std::int64_t value) noexcept {
  update_u64(static_cast<std::uint64_t>(value));
}

void DigestBuilder::update_u32(std::uint32_t value) noexcept {
  unsigned char bytes[4];
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[index] = static_cast<unsigned char>((value >> (index * 8)) & 0xFFU);
  }
  update(bytes, sizeof(bytes));
}

Digest64 DigestBuilder::finish() const noexcept {
  // FNV-1a alone has poor avalanche in the low bits. The final mix is the
  // standard 64-bit splitmix finalizer; it is deterministic and platform
  // independent, which is the property this digest needs.
  std::uint64_t value = state_;
  value ^= value >> 30;
  value *= 0xBF58476D1CE4E5B9ULL;
  value ^= value >> 27;
  value *= 0x94D049BB133111EBULL;
  value ^= value >> 31;
  return Digest64::from(value);
}

Digest64 digest_of(std::string_view text) noexcept {
  DigestBuilder builder;
  builder.update(text);
  return builder.finish();
}

template class Identifier<PduIdTag>;
template class Identifier<BranchIdTag>;
template class Identifier<AuthorityIdTag>;
template class Identifier<IssuerIdTag>;
template class Identifier<InterlockIdTag>;
template class Identifier<SourceIdTag>;
template class Identifier<ActorIdTag>;
template class Identifier<AdapterIdTag>;
template class Identifier<ProtectionZoneIdTag>;
template class Identifier<IdempotencyKeyTag>;

template class Counter<PduGenerationTag>;
template class Counter<BranchGenerationTag>;
template class Counter<StateRevisionTag>;
template class Counter<AuthorityEpochTag>;
template class Counter<IncarnationTag>;
template class Counter<StoreGenerationTag>;
template class Counter<LogicalTickTag>;
template class Counter<SequenceNumberTag>;
template class Counter<AttemptIdTag>;
template class Counter<ObservationIdTag>;
template class Counter<AdapterSequenceTag>;

}  // namespace pdu_control
