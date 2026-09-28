#pragma once

// Bounded, explicit, little-endian encoding primitives.
//
// Nothing in this library writes a struct's bytes directly. Every field is
// written and read through these primitives, so the on-disk and canonical forms
// are defined by code rather than by the compiler's layout, padding, or
// endianness. Every read is bounds-checked, and every length is checked against
// the bound that applies to it before anything is allocated.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pdu_control/status.hpp"

namespace pdu_control::detail {

class Writer {
 public:
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);
  void boolean(bool value);
  void raw(const void* data, std::size_t size);

  /// Length-prefixed text. Refuses text longer than `max_bytes` with
  /// `store_oversized` rather than truncating it.
  Status text(std::string_view value, std::size_t max_bytes);

  /// A collection count. Refuses a count above `max_value` with
  /// `store_oversized`.
  Status count(std::size_t value, std::size_t max_value);

  [[nodiscard]] const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
  void clear() noexcept { bytes_.clear(); }

 private:
  std::vector<std::uint8_t> bytes_;
};

class Reader {
 public:
  Reader(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

  [[nodiscard]] bool at_end() const noexcept { return offset_ == size_; }
  [[nodiscard]] std::size_t remaining() const noexcept { return size_ - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

  [[nodiscard]] Result<std::uint8_t> u8();
  [[nodiscard]] Result<std::uint16_t> u16();
  [[nodiscard]] Result<std::uint32_t> u32();
  [[nodiscard]] Result<std::uint64_t> u64();
  [[nodiscard]] Result<std::int64_t> i64();
  [[nodiscard]] Result<bool> boolean();

  /// A view of `size` raw bytes. Fails with `store_truncated` when fewer remain.
  [[nodiscard]] Result<std::string_view> raw(std::size_t size);

  /// Length-prefixed text. Fails with `store_oversized` when the declared
  /// length exceeds `max_bytes` (before allocating) and with `store_truncated`
  /// when the declared length is not present.
  [[nodiscard]] Result<std::string> text(std::size_t max_bytes);

  /// A collection count. Fails with `store_oversized` when the count exceeds
  /// `max_value`, before the caller allocates anything for it.
  [[nodiscard]] Result<std::size_t> count(std::size_t max_value);

  /// Fails with `store_malformed` when unread bytes remain.
  [[nodiscard]] Status expect_end() const;

 private:
  [[nodiscard]] Result<const std::uint8_t*> take(std::size_t size);

  const std::uint8_t* data_;
  std::size_t size_;
  std::size_t offset_{0};
};

}  // namespace pdu_control::detail
