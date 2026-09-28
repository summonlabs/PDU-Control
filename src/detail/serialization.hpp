#pragma once

// Encoding of the durable payload and of the canonical state text.
//
// Both directions are total: every field is written, every field is read, and a
// decode that does not consume exactly the payload fails. The encoder is
// deterministic -- the same logical state always produces the same bytes -- and
// the decoder never allocates for a count before checking that count against the
// bound that applies to it.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "pdu_control/model.hpp"
#include "pdu_control/status.hpp"
#include "pdu_control/store.hpp"
#include "detail/records.hpp"

namespace pdu_control::detail {

/// The envelope that precedes the encoded body. Carried inside the payload as
/// well as in the slot header, so a slot cannot be spliced from another
/// generation without the mismatch being visible.
struct PayloadHeader {
  StoreGeneration generation;
  Incarnation incarnation;
  std::uint32_t body_bytes{0};
};

/// Deterministic binary encoding of the whole authoritative state.
[[nodiscard]] Result<std::vector<std::uint8_t>> encode_state(const ModelState& state,
                                                             const ModelBounds& bounds);

/// Reads only the envelope. Used by the store to check the payload header
/// against the slot header before committing to a full decode.
[[nodiscard]] Result<PayloadHeader> decode_payload_header(const std::uint8_t* data,
                                                          std::size_t size);

/// Strict decode. Fails with `store_version_unsupported`, `store_malformed`,
/// `store_truncated`, or `store_oversized`; never returns a partial state.
[[nodiscard]] Result<ModelState> decode_state(const std::uint8_t* data, std::size_t size,
                                              const ModelBounds& bounds);

/// Deterministic canonical text of the model state, excluding every volatile
/// field: wall-clock instants, incarnation, audit sequence numbers, and audit
/// detail that carries a wall instant. Two engines driven through the same
/// logical event sequence produce byte-identical text.
[[nodiscard]] std::string canonical_text(const ModelState& state);

}  // namespace pdu_control::detail
