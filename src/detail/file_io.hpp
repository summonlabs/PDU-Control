#pragma once

// Narrow native file abstraction.
//
// Only what the store needs: open with an explicit sharing policy, positional
// read and write, size, resize, flush-to-device, and close. Handles are closed
// on every path, including after a failed operation, so a refusal never leaves a
// descriptor behind.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "pdu_control/status.hpp"

namespace pdu_control::detail {

enum class FileAccess : std::uint8_t {
  read_only,
  read_write,
};

struct FileOpenOptions {
  /// Refuse when the file already exists.
  bool create_new{false};
  /// Create the file when it does not exist.
  bool create_if_missing{false};
  /// Refuse to open when the file does not exist.
  bool must_exist{false};
  /// Deny every other opener, including readers, for as long as this handle is
  /// open. This is the cross-process write-authority primitive.
  bool exclusive{false};
  /// Truncate to zero length after opening.
  bool truncate{false};
};

class File {
 public:
  File() = default;
  ~File();
  File(File&& other) noexcept;
  File& operator=(File&& other) noexcept;
  File(const File&) = delete;
  File& operator=(const File&) = delete;

  [[nodiscard]] static Result<File> open(const std::string& path, FileAccess access,
                                         const FileOpenOptions& options);

  [[nodiscard]] bool is_open() const noexcept { return handle_ >= 0; }
  [[nodiscard]] Result<std::uint64_t> size() const;
  [[nodiscard]] Status resize(std::uint64_t size);
  [[nodiscard]] Status read_at(std::uint64_t offset, void* buffer, std::size_t size) const;
  [[nodiscard]] Status write_at(std::uint64_t offset, const void* buffer, std::size_t size);
  /// Flushes the file's contents to the device.
  [[nodiscard]] Status flush();
  [[nodiscard]] Status close();

 private:
  std::intptr_t handle_{-1};
};

/// Creates every missing parent directory of `path`.
[[nodiscard]] Status ensure_parent_directory(const std::string& path);

/// Reads at most `max_bytes` from `path`. Refuses a larger file with
/// `store_oversized` instead of allocating for it.
[[nodiscard]] Result<std::vector<std::uint8_t>> read_file_bounded(const std::string& path,
                                                                  std::size_t max_bytes);

/// Writes `data` to `path`, creating or replacing it, flushing to the device.
[[nodiscard]] Status write_file_flushed(const std::string& path, const void* data,
                                        std::size_t size);

[[nodiscard]] bool path_exists(const std::string& path);
[[nodiscard]] bool path_is_directory(const std::string& path);
[[nodiscard]] bool path_is_reparse_point(const std::string& path);
[[nodiscard]] Status remove_file(const std::string& path);

}  // namespace pdu_control::detail
