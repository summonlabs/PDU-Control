#pragma once

// The dual-slot, head-committed durable container.
//
// Layout, all offsets in bytes:
//
//   0                    head record A (256 bytes)
//   256                  head record B (256 bytes)
//   512                  payload slot 0 (64-byte slot header, then the payload)
//   512 + stride         payload slot 1
//   stride = 4096 + store_max_payload_bytes
//
// Both head records are always written; a publication alternates between them so
// that a crash while one head record is being written leaves the other one
// intact and valid. The commit point of a publication is the head write that
// follows the verified payload, flushed to the device.

#include <cstdint>
#include <string>

#include "detail/file_io.hpp"
#include "detail/records.hpp"
#include "detail/serialization.hpp"
#include "pdu_control/model.hpp"
#include "pdu_control/store.hpp"

namespace pdu_control::detail {

/// A decoded head record.
struct StoreHead {
  bool valid{false};
  std::uint64_t serial{0};
  StoreGeneration generation;
  Incarnation incarnation;
  AuthorityEpoch epoch;
  std::uint32_t slot{0};
  std::uint32_t payload_bytes{0};
  std::uint32_t payload_crc{0};
  Digest64 payload_digest;
  std::uint64_t open_count{0};
  /// Which of the two head records this head was read from.
  std::uint32_t record_index{0};
};

class StoreFile {
 public:
  StoreFile() = default;
  ~StoreFile();
  StoreFile(StoreFile&& other) noexcept;
  StoreFile& operator=(StoreFile&& other) noexcept;
  StoreFile(const StoreFile&) = delete;
  StoreFile& operator=(const StoreFile&) = delete;

  /// Opens or creates a store at an already-normalized absolute path and takes
  /// exclusive cross-process write authority over it.
  [[nodiscard]] static Result<StoreFile> open(const std::string& path, OpenMode mode,
                                              const ModelBounds& bounds, bool read_only,
                                              StoreGeneration min_generation);

  [[nodiscard]] bool is_open() const noexcept { return data_.is_open(); }
  [[nodiscard]] bool is_read_only() const noexcept { return read_only_; }
  [[nodiscard]] const ModelState& state() const noexcept { return state_; }
  [[nodiscard]] ModelState& state() noexcept { return state_; }
  [[nodiscard]] Incarnation incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] const StoreHead& head() const noexcept { return head_; }
  [[nodiscard]] const ModelBounds& bounds() const noexcept { return bounds_; }
  [[nodiscard]] StoreAudit& audit() noexcept { return audit_; }
  [[nodiscard]] const StoreAudit& audit() const noexcept { return audit_; }

  /// Publishes `state` as the next whole generation and commits it.
  Status publish(const ModelState& state);

  /// Flushes and releases write authority. Idempotent.
  Status close();

  /// Re-reads the head records without publishing. Used by the fence check.
  [[nodiscard]] Result<StoreHead> read_head() const;

 private:
  Status write_head(const StoreHead& head, std::uint32_t head_slot);
  [[nodiscard]] Result<StoreHead> read_head_slot(std::uint32_t head_slot) const;
  [[nodiscard]] Result<ModelState> load_slot(const StoreHead& head) const;

  File data_;
  File lock_;
  ModelState state_;
  StoreHead head_;
  Incarnation incarnation_;
  StoreGeneration min_generation_;
  ModelBounds bounds_;
  StoreAudit audit_;
  bool read_only_{false};
  std::uint32_t next_head_slot_{0};
};

}  // namespace pdu_control::detail
