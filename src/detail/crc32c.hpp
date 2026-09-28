#pragma once

// CRC-32C (Castagnoli polynomial 0x1EDC6F41, reflected, init 0xFFFFFFFF, final
// xor 0xFFFFFFFF). Used as a corruption check over durable records.
//
// This is integrity detection, not authentication: it detects accidental
// corruption and truncation. It is not a signature and cannot defend against an
// adversary who can rewrite the file and its checksum.

#include <cstddef>
#include <cstdint>

namespace pdu_control::detail {

[[nodiscard]] std::uint32_t crc32c(const void* data, std::size_t size,
                                   std::uint32_t seed = 0) noexcept;

}  // namespace pdu_control::detail
