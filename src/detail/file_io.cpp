#include "detail/file_io.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace pdu_control::detail {
namespace {

/// Transfer size per syscall: bounded so a huge request cannot overflow the
/// DWORD or ssize_t count argument.
constexpr std::size_t kMaxTransferChunk = static_cast<std::size_t>(1) << 30;

#ifdef _WIN32

/// The largest offset a LARGE_INTEGER can name.
constexpr std::uint64_t kMaxFileOffset = 0x7FFFFFFFFFFFFFFFULL;

HANDLE native_handle(std::intptr_t handle) noexcept {
  return reinterpret_cast<HANDLE>(handle);
}

Status describe_error(StatusCode code, std::string_view action, const std::string& path,
                      DWORD error) {
  return Status::failure(code, std::string(action) + " " + path +
                                   " failed with Windows error " + std::to_string(error));
}

/// Maps a CreateFileW-class outcome onto the library's outcome classes. A
/// sharing violation is the documented cross-process exclusion result, so it is
/// reported as busy rather than as an I/O failure.
Status classify_error(std::string_view action, const std::string& path, DWORD error) {
  switch (error) {
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
      return Status::failure(StatusCode::busy,
                             "another opener already holds " + path +
                                 " with an incompatible sharing mode (Windows error " +
                                 std::to_string(error) + ")");
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
      return describe_error(StatusCode::duplicate_identity, action, path, error);
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
      return describe_error(StatusCode::not_found, action, path, error);
    default:
      return describe_error(StatusCode::store_io, action, path, error);
  }
}

/// UTF-8 to UTF-16. Malformed UTF-8 is refused with path_invalid; it is never
/// replaced or reinterpreted.
Result<std::wstring> to_wide_path(const std::string& path) {
  if (path.empty()) {
    return Status::failure(StatusCode::path_invalid, "the path is empty");
  }
  if (path.find('\0') != std::string::npos) {
    return Status::failure(StatusCode::path_invalid, "the path contains an embedded NUL byte");
  }
  if (path.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return Status::failure(StatusCode::path_invalid, "the path is too long to convert to UTF-16");
  }
  const int length = static_cast<int>(path.size());
  const int wide_length =
      ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), length, nullptr, 0);
  if (wide_length <= 0) {
    return Status::failure(StatusCode::path_invalid, "the path is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
  const int written = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), length,
                                            wide.data(), wide_length);
  if (written != wide_length) {
    return Status::failure(StatusCode::path_invalid,
                           "the path could not be converted to UTF-16");
  }
  return wide;
}

/// Length of the root prefix that must not be created: a drive root such as
/// C: followed by a separator, or a UNC share.
std::size_t root_prefix_length(const std::wstring& path) noexcept {
  if (path.size() >= 2 && (path[0] == L'\\' || path[0] == L'/') &&
      (path[1] == L'\\' || path[1] == L'/')) {
    std::size_t index = 2;
    int separators = 0;
    while (index < path.size() && separators < 2) {
      if (path[index] == L'\\' || path[index] == L'/') {
        ++separators;
      }
      ++index;
    }
    return index;
  }
  if (path.size() >= 2 && path[1] == L':') {
    if (path.size() >= 3 && (path[2] == L'\\' || path[2] == L'/')) {
      return 3;
    }
    return 2;
  }
  return 0;
}

#else  // POSIX

/// The largest offset an off_t can name on this build.
constexpr std::uint64_t kMaxFileOffset = 0x7FFFFFFFFFFFFFFFULL;

int native_handle(std::intptr_t handle) noexcept { return static_cast<int>(handle); }

Status describe_errno(StatusCode code, std::string_view action, const std::string& path,
                      int error) {
  return Status::failure(code, std::string(action) + " " + path + " failed with errno " +
                                   std::to_string(error));
}

/// Maps an open()/flock() outcome onto the library's outcome classes. A lock
/// conflict is the documented cross-process exclusion result.
Status classify_errno(std::string_view action, const std::string& path, int error) {
  switch (error) {
    case EWOULDBLOCK:
    case EAGAIN:
      return Status::failure(StatusCode::busy,
                             "another opener already holds " + path +
                                 " with an incompatible lock or sharing mode (errno " +
                                 std::to_string(error) + ")");
    case EEXIST:
      return describe_errno(StatusCode::duplicate_identity, action, path, error);
    case ENOENT:
      return describe_errno(StatusCode::not_found, action, path, error);
    default:
      return describe_errno(StatusCode::store_io, action, path, error);
  }
}

/// Refuses a path that cannot be handed to the C library as a NUL-terminated
/// string without changing meaning.
Status check_path_text(const std::string& path) {
  if (path.empty()) {
    return Status::failure(StatusCode::path_invalid, "the path is empty");
  }
  if (path.find('\0') != std::string::npos) {
    return Status::failure(StatusCode::path_invalid, "the path contains an embedded NUL byte");
  }
  return Status::success();
}

#endif

}  // namespace

// --- File -------------------------------------------------------------------

File::~File() {
  if (handle_ >= 0) {
    const auto handle = handle_;
    handle_ = -1;
#ifdef _WIN32
    ::CloseHandle(native_handle(handle));
#else
    ::close(native_handle(handle));
#endif
  }
}

File::File(File&& other) noexcept : handle_(other.handle_) { other.handle_ = -1; }

File& File::operator=(File&& other) noexcept {
  if (this != &other) {
    if (handle_ >= 0) {
      const auto handle = handle_;
      handle_ = -1;
#ifdef _WIN32
      ::CloseHandle(native_handle(handle));
#else
      ::close(native_handle(handle));
#endif
    }
    handle_ = other.handle_;
    other.handle_ = -1;
  }
  return *this;
}

Result<File> File::open(const std::string& path, FileAccess access,
                        const FileOpenOptions& options) {
#ifdef _WIN32
  const Result<std::wstring> wide = to_wide_path(path);
  if (!wide.ok()) {
    return wide.status();
  }
  const DWORD desired_access =
      access == FileAccess::read_only ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
  // Exclusive means every other opener is denied, readers included.
  const DWORD share_mode =
      options.exclusive ? 0U : (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
  DWORD creation = OPEN_EXISTING;
  if (options.create_new) {
    creation = CREATE_NEW;
  } else if (options.must_exist) {
    creation = OPEN_EXISTING;
  } else if (options.create_if_missing || options.truncate) {
    creation = OPEN_ALWAYS;
  }
  const HANDLE handle = ::CreateFileW(wide.value().c_str(), desired_access, share_mode, nullptr,
                                      creation, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return classify_error("opening", path, ::GetLastError());
  }
  File file;
  file.handle_ = reinterpret_cast<std::intptr_t>(handle);
  if (options.truncate) {
    // OPEN_ALWAYS does not shorten an existing file; do it explicitly.
    const Status truncated = file.resize(0);
    if (!truncated.ok()) {
      return truncated;  // the destructor closes the handle
    }
  }
  return file;
#else
  const Status text = check_path_text(path);
  if (!text.ok()) {
    return text;
  }
  int flags = access == FileAccess::read_only ? O_RDONLY : O_RDWR;
  if (options.create_new) {
    flags |= O_CREAT | O_EXCL;
  } else if (options.must_exist) {
    // No O_CREAT: a missing file is an error.
  } else if (options.create_if_missing || options.truncate) {
    flags |= O_CREAT;
  }
  if (options.truncate) {
    flags |= O_TRUNC;
  }
  const int descriptor = ::open(path.c_str(), flags, 0644);
  if (descriptor < 0) {
    return classify_errno("opening", path, errno);
  }
  File file;
  file.handle_ = static_cast<std::intptr_t>(descriptor);
  if (options.exclusive) {
    if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
      return classify_errno("locking", path, errno);  // the destructor closes the descriptor
    }
  }
  return file;
#endif
}

Result<std::uint64_t> File::size() const {
  if (handle_ < 0) {
    return Status::failure(StatusCode::internal, "the file handle is not open");
  }
#ifdef _WIN32
  LARGE_INTEGER size{};
  if (::GetFileSizeEx(native_handle(handle_), &size) == 0) {
    return Status::failure(StatusCode::store_io, "GetFileSizeEx failed with Windows error " +
                                                     std::to_string(::GetLastError()));
  }
  if (size.QuadPart < 0) {
    return Status::failure(StatusCode::store_io, "the reported file size is negative");
  }
  return static_cast<std::uint64_t>(size.QuadPart);
#else
  struct stat info {};
  if (::fstat(native_handle(handle_), &info) != 0) {
    return Status::failure(StatusCode::store_io,
                           "fstat failed with errno " + std::to_string(errno));
  }
  if (info.st_size < 0) {
    return Status::failure(StatusCode::store_io, "the reported file size is negative");
  }
  return static_cast<std::uint64_t>(info.st_size);
#endif
}

Status File::resize(std::uint64_t size) {
  if (handle_ < 0) {
    return Status::failure(StatusCode::internal, "the file handle is not open");
  }
  if (size > kMaxFileOffset) {
    return Status::failure(StatusCode::overflow, "the requested size " + std::to_string(size) +
                                                     " is beyond the addressable file range");
  }
#ifdef _WIN32
  LARGE_INTEGER distance{};
  distance.QuadPart = static_cast<LONGLONG>(size);
  if (::SetFilePointerEx(native_handle(handle_), distance, nullptr, FILE_BEGIN) == 0) {
    return Status::failure(StatusCode::store_io, "SetFilePointerEx failed with Windows error " +
                                                     std::to_string(::GetLastError()));
  }
  if (::SetEndOfFile(native_handle(handle_)) == 0) {
    return Status::failure(StatusCode::store_io, "SetEndOfFile failed with Windows error " +
                                                     std::to_string(::GetLastError()));
  }
  return Status::success();
#else
  if (::ftruncate(native_handle(handle_), static_cast<off_t>(size)) != 0) {
    return Status::failure(StatusCode::store_io,
                           "ftruncate failed with errno " + std::to_string(errno));
  }
  return Status::success();
#endif
}

Status File::read_at(std::uint64_t offset, void* buffer, std::size_t size) const {
  if (handle_ < 0) {
    return Status::failure(StatusCode::internal, "the file handle is not open");
  }
  if (size == 0) {
    return Status::success();  // a zero-length read is a no-op
  }
  if (buffer == nullptr) {
    return Status::failure(StatusCode::invalid_argument, "the read buffer is null");
  }
  if (offset > kMaxFileOffset || size > kMaxFileOffset - offset) {
    return Status::failure(StatusCode::overflow,
                           "the read range at offset " + std::to_string(offset) + " for " +
                               std::to_string(size) + " byte(s) is beyond the addressable range");
  }
  auto* out = static_cast<std::uint8_t*>(buffer);
  std::size_t done = 0;
#ifdef _WIN32
  LARGE_INTEGER distance{};
  distance.QuadPart = static_cast<LONGLONG>(offset);
  if (::SetFilePointerEx(native_handle(handle_), distance, nullptr, FILE_BEGIN) == 0) {
    return Status::failure(StatusCode::store_io, "SetFilePointerEx failed with Windows error " +
                                                     std::to_string(::GetLastError()));
  }
  while (done < size) {
    const std::size_t chunk = std::min(size - done, kMaxTransferChunk);
    DWORD transferred = 0;
    if (::ReadFile(native_handle(handle_), out + done, static_cast<DWORD>(chunk), &transferred,
                   nullptr) == 0) {
      return Status::failure(StatusCode::store_io, "ReadFile failed with Windows error " +
                                                       std::to_string(::GetLastError()));
    }
    if (transferred == 0) {
      return Status::failure(StatusCode::store_truncated,
                             "the file ended after " + std::to_string(done) + " of " +
                                 std::to_string(size) + " requested byte(s)");
    }
    done += static_cast<std::size_t>(transferred);
  }
#else
  while (done < size) {
    const std::size_t chunk = std::min(size - done, kMaxTransferChunk);
    const ssize_t transferred =
        ::pread(native_handle(handle_), out + done, chunk, static_cast<off_t>(offset + done));
    if (transferred < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Status::failure(StatusCode::store_io,
                             "pread failed with errno " + std::to_string(errno));
    }
    if (transferred == 0) {
      return Status::failure(StatusCode::store_truncated,
                             "the file ended after " + std::to_string(done) + " of " +
                                 std::to_string(size) + " requested byte(s)");
    }
    done += static_cast<std::size_t>(transferred);
  }
#endif
  return Status::success();
}

Status File::write_at(std::uint64_t offset, const void* buffer, std::size_t size) {
  if (handle_ < 0) {
    return Status::failure(StatusCode::internal, "the file handle is not open");
  }
  if (size == 0) {
    return Status::success();  // a zero-length write is a no-op
  }
  if (buffer == nullptr) {
    return Status::failure(StatusCode::invalid_argument, "the write buffer is null");
  }
  if (offset > kMaxFileOffset || size > kMaxFileOffset - offset) {
    return Status::failure(StatusCode::overflow,
                           "the write range at offset " + std::to_string(offset) + " for " +
                               std::to_string(size) + " byte(s) is beyond the addressable range");
  }
  const auto* in = static_cast<const std::uint8_t*>(buffer);
  std::size_t done = 0;
#ifdef _WIN32
  LARGE_INTEGER distance{};
  distance.QuadPart = static_cast<LONGLONG>(offset);
  if (::SetFilePointerEx(native_handle(handle_), distance, nullptr, FILE_BEGIN) == 0) {
    return Status::failure(StatusCode::store_io, "SetFilePointerEx failed with Windows error " +
                                                     std::to_string(::GetLastError()));
  }
  while (done < size) {
    const std::size_t chunk = std::min(size - done, kMaxTransferChunk);
    DWORD transferred = 0;
    if (::WriteFile(native_handle(handle_), in + done, static_cast<DWORD>(chunk), &transferred,
                    nullptr) == 0) {
      return Status::failure(StatusCode::store_io, "WriteFile failed with Windows error " +
                                                       std::to_string(::GetLastError()));
    }
    if (transferred == 0) {
      return Status::failure(StatusCode::store_io,
                             "WriteFile accepted 0 of " + std::to_string(chunk) + " byte(s)");
    }
    done += static_cast<std::size_t>(transferred);
  }
#else
  while (done < size) {
    const std::size_t chunk = std::min(size - done, kMaxTransferChunk);
    const ssize_t transferred =
        ::pwrite(native_handle(handle_), in + done, chunk, static_cast<off_t>(offset + done));
    if (transferred < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Status::failure(StatusCode::store_io,
                             "pwrite failed with errno " + std::to_string(errno));
    }
    if (transferred == 0) {
      return Status::failure(StatusCode::store_io,
                             "pwrite accepted 0 of " + std::to_string(chunk) + " byte(s)");
    }
    done += static_cast<std::size_t>(transferred);
  }
#endif
  return Status::success();
}

Status File::flush() {
  if (handle_ < 0) {
    return Status::failure(StatusCode::internal, "the file handle is not open");
  }
#ifdef _WIN32
  if (::FlushFileBuffers(native_handle(handle_)) == 0) {
    return Status::failure(StatusCode::store_io, "FlushFileBuffers failed with Windows error " +
                                                     std::to_string(::GetLastError()));
  }
  return Status::success();
#else
  if (::fsync(native_handle(handle_)) != 0) {
    return Status::failure(StatusCode::store_io,
                           "fsync failed with errno " + std::to_string(errno));
  }
  return Status::success();
#endif
}

Status File::close() {
  if (handle_ < 0) {
    return Status::success();
  }
  const auto handle = handle_;
  handle_ = -1;  // the handle is gone either way; it is never closed twice
#ifdef _WIN32
  if (::CloseHandle(native_handle(handle)) == 0) {
    return Status::failure(StatusCode::store_io, "CloseHandle failed with Windows error " +
                                                     std::to_string(::GetLastError()));
  }
  return Status::success();
#else
  if (::close(native_handle(handle)) != 0) {
    return Status::failure(StatusCode::store_io,
                           "close failed with errno " + std::to_string(errno));
  }
  return Status::success();
#endif
}

// --- Free functions ---------------------------------------------------------

bool path_exists(const std::string& path) {
#ifdef _WIN32
  const Result<std::wstring> wide = to_wide_path(path);
  if (!wide.ok()) {
    return false;
  }
  return ::GetFileAttributesW(wide.value().c_str()) != INVALID_FILE_ATTRIBUTES;
#else
  if (!check_path_text(path).ok()) {
    return false;
  }
  struct stat info {};
  return ::stat(path.c_str(), &info) == 0;
#endif
}

bool path_is_directory(const std::string& path) {
#ifdef _WIN32
  const Result<std::wstring> wide = to_wide_path(path);
  if (!wide.ok()) {
    return false;
  }
  const DWORD attributes = ::GetFileAttributesW(wide.value().c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
  if (!check_path_text(path).ok()) {
    return false;
  }
  struct stat info {};
  return ::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
#endif
}

bool path_is_reparse_point(const std::string& path) {
#ifdef _WIN32
  const Result<std::wstring> wide = to_wide_path(path);
  if (!wide.ok()) {
    return false;
  }
  const DWORD attributes = ::GetFileAttributesW(wide.value().c_str());
  return attributes != INVALID_FILE_ATTRIBUTES &&
         (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
  if (!check_path_text(path).ok()) {
    return false;
  }
  struct stat info {};
  return ::lstat(path.c_str(), &info) == 0 && S_ISLNK(info.st_mode);
#endif
}

Status remove_file(const std::string& path) {
#ifdef _WIN32
  const Result<std::wstring> wide = to_wide_path(path);
  if (!wide.ok()) {
    return wide.status();
  }
  if (::DeleteFileW(wide.value().c_str()) != 0) {
    return Status::success();
  }
  const DWORD error = ::GetLastError();
  if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
    return Status::success();  // removing something that is not there is the goal state
  }
  return describe_error(StatusCode::store_io, "deleting", path, error);
#else
  const Status text = check_path_text(path);
  if (!text.ok()) {
    return text;
  }
  if (::unlink(path.c_str()) == 0) {
    return Status::success();
  }
  if (errno == ENOENT) {
    return Status::success();
  }
  return describe_errno(StatusCode::store_io, "deleting", path, errno);
#endif
}

Status ensure_parent_directory(const std::string& path) {
#ifdef _WIN32
  const Result<std::wstring> wide = to_wide_path(path);
  if (!wide.ok()) {
    return wide.status();
  }
  const std::wstring& full = wide.value();
  const std::size_t separator = full.find_last_of(L"\\/");
  if (separator == std::wstring::npos || separator == 0) {
    return Status::success();  // nothing in the path is a parent
  }
  const std::wstring parent = full.substr(0, separator);
  const std::size_t root = root_prefix_length(parent);
  for (std::size_t index = root; index <= parent.size(); ++index) {
    const bool boundary =
        index == parent.size() || parent[index] == L'\\' || parent[index] == L'/';
    if (!boundary) {
      continue;
    }
    const std::wstring prefix = parent.substr(0, index);
    if (prefix.empty()) {
      continue;
    }
    if (::CreateDirectoryW(prefix.c_str(), nullptr) != 0) {
      continue;
    }
    const DWORD error = ::GetLastError();
    if (error == ERROR_ALREADY_EXISTS) {
      const DWORD attributes = ::GetFileAttributesW(prefix.c_str());
      if (attributes == INVALID_FILE_ATTRIBUTES ||
          (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return Status::failure(StatusCode::store_io,
                               "a component of " + path + " exists and is not a directory");
      }
      continue;
    }
    return describe_error(StatusCode::store_io, "creating the parent directory of", path, error);
  }
  return Status::success();
#else
  const Status text = check_path_text(path);
  if (!text.ok()) {
    return text;
  }
  const std::size_t separator = path.find_last_of('/');
  if (separator == std::string::npos || separator == 0) {
    return Status::success();
  }
  const std::string parent = path.substr(0, separator);
  for (std::size_t index = 1; index <= parent.size(); ++index) {
    if (index != parent.size() && parent[index] != '/') {
      continue;
    }
    const std::string prefix = parent.substr(0, index);
    if (prefix.empty()) {
      continue;
    }
    if (::mkdir(prefix.c_str(), 0755) == 0) {
      continue;
    }
    const int error = errno;
    if (error == EEXIST) {
      struct stat info {};
      if (::stat(prefix.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        return Status::failure(StatusCode::store_io,
                               "a component of " + path + " exists and is not a directory");
      }
      continue;
    }
    return describe_errno(StatusCode::store_io, "creating the parent directory of", path, error);
  }
  return Status::success();
#endif
}

Result<std::vector<std::uint8_t>> read_file_bounded(const std::string& path,
                                                    std::size_t max_bytes) {
  FileOpenOptions options;
  options.must_exist = true;
  Result<File> file = File::open(path, FileAccess::read_only, options);
  if (!file.ok()) {
    return file.status();
  }
  const Result<std::uint64_t> size = file.value().size();
  if (!size.ok()) {
    return size.status();
  }
  if (size.value() > max_bytes) {
    // Refused from the reported size, before any allocation for the contents.
    return Status::failure(StatusCode::store_oversized,
                           "the file " + path + " holds " + std::to_string(size.value()) +
                               " byte(s), which exceeds the " + std::to_string(max_bytes) +
                               " byte bound");
  }
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size.value()));
  if (!data.empty()) {
    const Status read = file.value().read_at(0, data.data(), data.size());
    if (!read.ok()) {
      return read;
    }
  }
  return data;
}

Status write_file_flushed(const std::string& path, const void* data, std::size_t size) {
  if (size != 0 && data == nullptr) {
    return Status::failure(StatusCode::invalid_argument, "the write buffer is null");
  }
  FileOpenOptions options;
  options.create_if_missing = true;
  options.truncate = true;
  Result<File> file = File::open(path, FileAccess::read_write, options);
  if (!file.ok()) {
    return file.status();
  }
  const Status written = file.value().write_at(0, data, size);
  if (!written.ok()) {
    return written;
  }
  return file.value().flush();
}

}  // namespace pdu_control::detail
