#pragma once

// Durable store: format constants, open modes, and the audit surface.
//
// The store is a dual-slot, head-committed container with a per-record CRC-32C
// and an explicit format version. The complete byte layout, the publication
// protocol, and the recovery rules are documented in docs/artifact-format.md;
// the constants here are the ones that document and the CLI report.
//
// Publication protocol (the commit point is the head write that follows the
// verified payload):
//
//   plan      build the canonical payload for the next generation
//   reserve   allocate the next store generation and incarnation
//   stage     write the payload into the slot the head does not reference
//   flush     flush the staged bytes to the device
//   verify    read the staged slot back and verify magic, version, length, and CRC
//   publish   write the head record that references the verified slot, and flush
//   retire    the previous slot becomes residue; it is overwritten by the next
//             publication and is never read unless its head is the committed one
//
// Recovery adopts the payload referenced by the newest *valid* head record whose
// payload verifies in full. If no head record is valid, or the referenced
// payload does not verify, the store refuses to open. Generations are never
// stitched together, and a quieter but older head is never preferred over a
// newer one.

#include <cstdint>
#include <string>
#include <string_view>

#include "pdu_control/ids.hpp"
#include "pdu_control/status.hpp"

namespace pdu_control {

/// Magic of the head record: "PDUCHD01".
inline constexpr std::string_view store_head_magic = "PDUCHD01";
/// Magic of a payload slot: "PDUCSL01".
inline constexpr std::string_view store_slot_magic = "PDUCSL01";
/// Magic of the payload envelope: "PDUCTLP1".
inline constexpr std::string_view store_payload_magic = "PDUCTLP1";

/// Format version written by this build. A store with a different version is
/// refused with `store_version_unsupported`; it is never reinterpreted.
inline constexpr std::uint32_t store_format_version = 1;

/// Bytes reserved for each of the two head records.
inline constexpr std::size_t store_head_record_bytes = 256;
/// Bytes at the start of the file reserved for the head records.
inline constexpr std::size_t store_head_bytes = 2 * store_head_record_bytes;
/// Bytes of slot header in front of each payload slot.
inline constexpr std::size_t store_slot_header_bytes = 64;
/// Largest payload this build accepts or writes.
///
/// This is the bound on the encoded model, not on any single field: the model
/// bounds in `ModelBounds` are what keep a well-formed engine's state inside it,
/// and a payload that exceeds it is refused with `store_oversized` rather than
/// truncated.
inline constexpr std::size_t store_max_payload_bytes = 4U * 1024U * 1024U;
/// Distance between the starts of the two payload slots.
inline constexpr std::size_t store_slot_stride = 4096 + store_max_payload_bytes;
/// Total file size of a well-formed store.
inline constexpr std::size_t store_file_bytes = store_head_bytes + 2 * store_slot_stride;
/// Largest accepted path length, in bytes.
inline constexpr std::size_t store_max_path_bytes = 4096;
/// Suffix of the sidecar lock file that carries cross-process write authority.
inline constexpr std::string_view store_lock_suffix = ".lock";

/// How a store is opened.
enum class OpenMode : std::uint8_t {
  create_new,      ///< Fail if anything exists at the path.
  open_existing,   ///< Fail if no store exists at the path.
  open_or_create,  ///< Adopt an existing store or create one.
  read_only,       ///< Take no write authority; refuse every mutation.
};

[[nodiscard]] std::string_view to_token(OpenMode mode) noexcept;
[[nodiscard]] bool parse_open_mode(std::string_view token, OpenMode& out) noexcept;

/// Path trust model.
struct PathPolicy {
  /// Refuse a final component that is a symlink, junction, or other reparse
  /// point. Default: refuse. Link substitution between validation and use is
  /// the classic way to make a checked path and a used path differ.
  bool refuse_reparse_points{true};
  /// Refuse a path whose final component is a directory.
  bool require_regular_file{true};
  std::size_t max_path_bytes{store_max_path_bytes};
};

/// Validates a store path against the documented trust model: bounded length,
/// no embedded NUL, relative paths and traversal are resolved and then checked
/// for escape, the final component must not be a device name, and (by default)
/// reparse points and directories are refused.
///
/// The returned string is the normalized absolute path to use for every
/// subsequent operation on that store.
[[nodiscard]] Result<std::string> validate_store_path(std::string_view path,
                                                      const PathPolicy& policy);

/// Counters and observations about the durable store. Reported by the CLI
/// `store-audit` verb and by `PduControlEngine::store_audit`.
struct StoreAudit {
  bool durable{false};
  bool open{false};
  bool read_only{false};
  std::string path;
  std::uint32_t format_version{0};
  StoreGeneration generation;              ///< Generation currently held in memory.
  StoreGeneration published_generation;    ///< Generation durably committed.
  StoreGeneration min_accepted_generation; ///< Rollback fence in force.
  Incarnation incarnation;
  Incarnation stored_incarnation;          ///< Incarnation recorded by the last publication.
  std::uint64_t open_count{0};
  std::uint64_t publication_count{0};
  std::uint64_t head_writes{0};
  std::uint64_t slot_writes{0};
  std::uint64_t bytes_written{0};
  std::uint64_t bytes_read{0};
  std::uint64_t flushes{0};
  std::uint64_t readback_verifications{0};
  std::uint64_t crc_mismatches{0};
  std::uint64_t rejected_open_attempts{0};
  std::uint64_t fenced_writes{0};          ///< Publications refused because another writer advanced the head.
  std::uint64_t recovered_publications{0}; ///< Openings that had to adopt an earlier whole generation.
  bool exclusively_locked{false};
  bool rollback_fence_armed{false};
  std::uint32_t head_records_valid{0};
  std::uint32_t head_slot_index{0};
  Digest64 last_published_digest;
  Digest64 state_digest;                   ///< Digest of the state currently in memory.
  LogicalTick current_tick;
  AuthorityEpoch authority_epoch;
};

}  // namespace pdu_control
