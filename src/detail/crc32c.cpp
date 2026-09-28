#include "detail/crc32c.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace pdu_control::detail {
namespace {

/// Reflected Castagnoli polynomial: 0x1EDC6F41 reversed is 0x82F63B78.
constexpr std::uint32_t kReflectedPolynomial = 0x82F63B78U;
constexpr std::uint32_t kInitial = 0xFFFFFFFFU;
constexpr std::uint32_t kFinalXor = 0xFFFFFFFFU;

/// Built once, at compile time, so the table is read-only shared data and there
/// is no lazy initialization to race on.
constexpr std::array<std::uint32_t, 256> make_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t index = 0; index < 256U; ++index) {
    std::uint32_t remainder = index;
    for (int bit = 0; bit < 8; ++bit) {
      if ((remainder & 1U) != 0U) {
        remainder = (remainder >> 1U) ^ kReflectedPolynomial;
      } else {
        remainder = remainder >> 1U;
      }
    }
    table[index] = remainder;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kTable = make_table();

}  // namespace

std::uint32_t crc32c(const void* data, std::size_t size, std::uint32_t seed) noexcept {
  // Continuation: the caller's running value is un-finalized on entry and
  // re-finalized on exit, so crc32c(b, n, crc32c(a, m)) equals the CRC of the
  // concatenation.
  std::uint32_t crc = seed ^ kInitial;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  for (std::size_t index = 0; index < size; ++index) {
    crc = kTable[(crc ^ bytes[index]) & 0xFFU] ^ (crc >> 8U);
  }
  return crc ^ kFinalXor;
}

}  // namespace pdu_control::detail
