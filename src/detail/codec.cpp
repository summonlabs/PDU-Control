#include "detail/codec.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace pdu_control::detail {
namespace {

/// The largest value a 32-bit length or count prefix can carry.
constexpr std::uint64_t kU32Limit = 0xFFFFFFFFULL;

std::string oversized_message(std::string_view what, std::uint64_t value, std::uint64_t bound) {
  return std::string(what) + " of " + std::to_string(value) + " exceeds the " +
         std::to_string(bound) + " byte bound";
}

std::string truncated_message(std::string_view what, std::size_t needed, std::size_t available) {
  return std::string("the buffer ends before the declared ") + std::string(what) + ": " +
         std::to_string(needed) + " byte(s) declared, " + std::to_string(available) +
         " byte(s) remaining";
}

/// Little-endian assembly, one byte at a time: the layout is defined here and
/// never by the host's byte order or by a struct's padding.
std::uint16_t load_le16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint32_t>(p[0]) |
                                    (static_cast<std::uint32_t>(p[1]) << 8U));
}

std::uint32_t load_le32(const std::uint8_t* p) noexcept {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8U) |
         (static_cast<std::uint32_t>(p[2]) << 16U) | (static_cast<std::uint32_t>(p[3]) << 24U);
}

std::uint64_t load_le64(const std::uint8_t* p) noexcept {
  return static_cast<std::uint64_t>(load_le32(p)) |
         (static_cast<std::uint64_t>(load_le32(p + 4)) << 32U);
}

void store_le16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((static_cast<std::uint32_t>(value) >> 8U) & 0xFFU));
}

void store_le32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
}

void store_le64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  store_le32(out, static_cast<std::uint32_t>(value & kU32Limit));
  store_le32(out, static_cast<std::uint32_t>((value >> 32U) & kU32Limit));
}

}  // namespace

// --- Writer -----------------------------------------------------------------

void Writer::u8(std::uint8_t value) { bytes_.push_back(value); }

void Writer::u16(std::uint16_t value) { store_le16(bytes_, value); }

void Writer::u32(std::uint32_t value) { store_le32(bytes_, value); }

void Writer::u64(std::uint64_t value) { store_le64(bytes_, value); }

void Writer::i64(std::int64_t value) {
  store_le64(bytes_, std::bit_cast<std::uint64_t>(value));
}

void Writer::boolean(bool value) { bytes_.push_back(value ? std::uint8_t{1} : std::uint8_t{0}); }

void Writer::raw(const void* data, std::size_t size) {
  if (size == 0) {
    return;
  }
  const auto* first = static_cast<const std::uint8_t*>(data);
  bytes_.insert(bytes_.end(), first, first + size);
}

Status Writer::text(std::string_view value, std::size_t max_bytes) {
  if (value.size() > max_bytes) {
    return Status::failure(StatusCode::store_oversized,
                           oversized_message("text length", value.size(), max_bytes));
  }
  if (value.size() > kU32Limit) {
    return Status::failure(
        StatusCode::store_oversized,
        oversized_message("text length", value.size(), kU32Limit));
  }
  // The bound held, so nothing is written until the framing is known to fit.
  u32(static_cast<std::uint32_t>(value.size()));
  raw(value.data(), value.size());
  return Status::success();
}

Status Writer::count(std::size_t value, std::size_t max_value) {
  if (value > max_value) {
    return Status::failure(StatusCode::store_oversized,
                           oversized_message("collection count", value, max_value));
  }
  if (value > kU32Limit) {
    return Status::failure(StatusCode::overflow,
                           oversized_message("collection count", value, kU32Limit));
  }
  u32(static_cast<std::uint32_t>(value));
  return Status::success();
}

// --- Reader -----------------------------------------------------------------

Result<const std::uint8_t*> Reader::take(std::size_t size) {
  if (size > size_ - offset_) {
    return Status::failure(StatusCode::store_truncated,
                           truncated_message("field", size, size_ - offset_));
  }
  const std::uint8_t* position = data_ == nullptr ? nullptr : data_ + offset_;
  offset_ += size;
  return position;
}

Result<std::uint8_t> Reader::u8() {
  const Result<const std::uint8_t*> taken = take(1);
  if (!taken.ok()) {
    return taken.status();
  }
  return *taken.value();
}

Result<std::uint16_t> Reader::u16() {
  const Result<const std::uint8_t*> taken = take(2);
  if (!taken.ok()) {
    return taken.status();
  }
  return load_le16(taken.value());
}

Result<std::uint32_t> Reader::u32() {
  const Result<const std::uint8_t*> taken = take(4);
  if (!taken.ok()) {
    return taken.status();
  }
  return load_le32(taken.value());
}

Result<std::uint64_t> Reader::u64() {
  const Result<const std::uint8_t*> taken = take(8);
  if (!taken.ok()) {
    return taken.status();
  }
  return load_le64(taken.value());
}

Result<std::int64_t> Reader::i64() {
  const Result<std::uint64_t> value = u64();
  if (!value.ok()) {
    return value.status();
  }
  return std::bit_cast<std::int64_t>(value.value());
}

Result<bool> Reader::boolean() {
  const Result<std::uint8_t> value = u8();
  if (!value.ok()) {
    return value.status();
  }
  if (value.value() > 1U) {
    return Status::failure(StatusCode::store_malformed,
                           "a boolean field holds " + std::to_string(value.value()) +
                               ", which is neither 0 nor 1");
  }
  return value.value() == 1U;
}

Result<std::string_view> Reader::raw(std::size_t size) {
  if (size == 0) {
    return std::string_view{};
  }
  const Result<const std::uint8_t*> taken = take(size);
  if (!taken.ok()) {
    return taken.status();
  }
  return std::string_view(reinterpret_cast<const char*>(taken.value()), size);
}

Result<std::string> Reader::text(std::size_t max_bytes) {
  const Result<std::uint32_t> length = u32();
  if (!length.ok()) {
    return length.status();
  }
  const std::size_t declared = static_cast<std::size_t>(length.value());
  if (declared > max_bytes) {
    // Refused before anything is allocated for it.
    return Status::failure(StatusCode::store_oversized,
                           oversized_message("declared text length", declared, max_bytes));
  }
  if (declared > remaining()) {
    return Status::failure(StatusCode::store_truncated,
                           truncated_message("text", declared, remaining()));
  }
  if (declared == 0) {
    return std::string{};
  }
  const Result<const std::uint8_t*> taken = take(declared);
  if (!taken.ok()) {
    return taken.status();
  }
  return std::string(reinterpret_cast<const char*>(taken.value()), declared);
}

Result<std::size_t> Reader::count(std::size_t max_value) {
  const Result<std::uint32_t> value = u32();
  if (!value.ok()) {
    return value.status();
  }
  const std::size_t declared = static_cast<std::size_t>(value.value());
  if (declared > max_value) {
    // Refused before the caller allocates anything for the collection.
    return Status::failure(StatusCode::store_oversized,
                           oversized_message("declared collection count", declared, max_value));
  }
  return declared;
}

Status Reader::expect_end() const {
  if (offset_ != size_) {
    return Status::failure(StatusCode::store_malformed,
                           std::to_string(size_ - offset_) +
                               " unread byte(s) remain after the last declared field");
  }
  return Status::success();
}

}  // namespace pdu_control::detail
