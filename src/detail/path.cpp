#include "detail/path.hpp"

#include <cstddef>
#include <limits>
#include <string>
#include <string_view>

#include "detail/file_io.hpp"
#include "pdu_control/ids.hpp"
#include "pdu_control/status.hpp"
#include "pdu_control/store.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <cstdlib>
#include <unistd.h>
#endif

namespace pdu_control::detail {
namespace {

/// Longest run of a path echoed back inside a refusal message.
constexpr std::size_t kMaxQuotedPathBytes = 200;

std::string quote(std::string_view text) {
  std::string clipped(text.substr(0, kMaxQuotedPathBytes));
  if (text.size() > kMaxQuotedPathBytes) {
    clipped += "...";
  }
  return "\"" + clipped + "\"";
}

/// The last component of the raw text, which is the one a device name or a
/// reparse point would have to occupy to matter.
std::string_view final_component(std::string_view path) noexcept {
  const std::size_t separator = path.find_last_of("/\\");
  if (separator == std::string_view::npos) {
    return path;
  }
  return path.substr(separator + 1);
}

/// The first component of the raw text that is exactly "." or "..", or an empty
/// view when there is none. A component such as "a..b" is not traversal.
std::string_view traversal_component(std::string_view path) noexcept {
  std::size_t index = 0;
  while (index <= path.size()) {
    std::size_t next = path.find_first_of("/\\", index);
    if (next == std::string_view::npos) {
      next = path.size();
    }
    const std::string_view component = path.substr(index, next - index);
    if (component == "." || component == "..") {
      return component;
    }
    if (next == path.size()) {
      break;
    }
    index = next + 1;
  }
  return std::string_view{};
}

bool is_absolute_path(std::string_view path) noexcept {
#ifdef _WIN32
  if (path.size() >= 2 && (path[0] == '\\' || path[0] == '/') &&
      (path[1] == '\\' || path[1] == '/')) {
    return true;  // UNC or device path
  }
  return path.size() >= 2 && path[1] == ':';
#else
  return !path.empty() && path[0] == '/';
#endif
}

/// (a) Lexical checks, applied to the original text before anything normalizes
/// it, so a traversal attempt is refused as an attempt rather than erased.
Status lexical_check(std::string_view path, const PathPolicy& policy) {
  if (path.empty()) {
    return Status::failure(StatusCode::path_invalid, "the path is empty");
  }
  if (path.find('\0') != std::string_view::npos) {
    return Status::failure(StatusCode::path_invalid,
                           "the path contains an embedded NUL byte "
                           "(embedded NUL check)");
  }
  if (path.size() > policy.max_path_bytes) {
    return Status::failure(StatusCode::path_invalid,
                           "the path is " + std::to_string(path.size()) +
                               " byte(s), which exceeds the " +
                               std::to_string(policy.max_path_bytes) +
                               " byte bound (length check)");
  }
  const std::string_view traversal = traversal_component(path);
  if (!traversal.empty()) {
    return Status::failure(StatusCode::path_invalid,
                           "the path " + quote(path) + " contains the component \"" +
                               std::string(traversal) +
                               "\" (traversal component check, applied before normalization)");
  }
  const std::string_view leaf = final_component(path);
  if (!leaf.empty() && is_reserved_device_name(leaf)) {
    return Status::failure(StatusCode::path_invalid,
                           "the final component " + quote(leaf) +
                               " is a reserved device name (device name check)");
  }
  return Status::success();
}

#ifdef _WIN32

/// (b) An absolute, lexically normalized path. Nothing here touches the file
/// system, so normalization cannot destroy the evidence a lexical check needs.
Result<std::string> normalize_absolute(std::string_view path) {
  if (path.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return Status::failure(StatusCode::path_invalid, "the path is too long to normalize");
  }
  const int length = static_cast<int>(path.size());
  const int wide_length =
      ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), length, nullptr, 0);
  if (wide_length <= 0) {
    return Status::failure(StatusCode::path_invalid, "the path is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
  if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), length, wide.data(),
                            wide_length) != wide_length) {
    return Status::failure(StatusCode::path_invalid, "the path could not be converted to UTF-16");
  }
  const DWORD needed = ::GetFullPathNameW(wide.c_str(), 0, nullptr, nullptr);
  if (needed == 0) {
    return Status::failure(StatusCode::path_invalid,
                           "the path could not be normalized (GetFullPathNameW failed with "
                           "Windows error " +
                               std::to_string(::GetLastError()) + ")");
  }
  std::wstring buffer(static_cast<std::size_t>(needed), L'\0');
  const DWORD written = ::GetFullPathNameW(wide.c_str(), needed, buffer.data(), nullptr);
  if (written == 0 || written >= needed) {
    return Status::failure(StatusCode::path_invalid,
                           "the path could not be normalized (GetFullPathNameW failed with "
                           "Windows error " +
                               std::to_string(::GetLastError()) + ")");
  }
  buffer.resize(static_cast<std::size_t>(written));
  const int narrow_length =
      ::WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(buffer.size()), nullptr, 0,
                            nullptr, nullptr);
  if (narrow_length <= 0) {
    return Status::failure(StatusCode::path_invalid,
                           "the normalized path could not be encoded as UTF-8");
  }
  std::string narrow(static_cast<std::size_t>(narrow_length), '\0');
  if (::WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(buffer.size()),
                            narrow.data(), narrow_length, nullptr, nullptr) != narrow_length) {
    return Status::failure(StatusCode::path_invalid,
                           "the normalized path could not be encoded as UTF-8");
  }
  return narrow;
}

#else  // POSIX

/// Removes the last component of an absolute path, keeping the leading slash.
void pop_last_component(std::string& value) {
  if (value.size() <= 1) {
    return;
  }
  const std::size_t separator = value.find_last_of('/');
  if (separator == std::string::npos) {
    value.clear();
    return;
  }
  if (separator == 0) {
    value.resize(1);
    return;
  }
  value.resize(separator);
}

/// Lexical join of a relative path onto an absolute base, used when the parent
/// directory does not exist yet and realpath therefore cannot resolve it.
std::string join_lexical(std::string_view base, std::string_view relative) {
  std::string result(base);
  if (result.empty()) {
    result = "/";
  }
  std::size_t index = 0;
  while (index <= relative.size()) {
    std::size_t next = relative.find('/', index);
    if (next == std::string_view::npos) {
      next = relative.size();
    }
    const std::string_view component = relative.substr(index, next - index);
    if (!component.empty() && component != ".") {
      if (component == "..") {
        pop_last_component(result);
      } else {
        if (result.empty() || result.back() != '/') {
          result.push_back('/');
        }
        result += component;
      }
    }
    if (next == relative.size()) {
      break;
    }
    index = next + 1;
  }
  return result;
}

/// (b) An absolute path with every existing symlink in the parent resolved. The
/// final component is deliberately not resolved: the policy checks it as named.
Result<std::string> normalize_absolute(std::string_view path) {
  const std::string text(path);
  const std::size_t separator = text.find_last_of('/');
  std::string parent;
  std::string leaf;
  if (separator == std::string::npos) {
    parent = ".";
    leaf = text;
  } else {
    parent = text.substr(0, separator == 0 ? 1 : separator);
    leaf = text.substr(separator + 1);
  }
  std::string base;
  char* resolved = ::realpath(parent.c_str(), nullptr);
  if (resolved != nullptr) {
    base.assign(resolved);
    std::free(resolved);
  } else {
    std::string start;
    if (!parent.empty() && parent.front() == '/') {
      start = "/";
    } else {
      char cwd[4096];
      if (::getcwd(cwd, sizeof(cwd)) == nullptr) {
        return Status::failure(StatusCode::path_invalid,
                               "the current directory could not be determined while normalizing "
                               "the path");
      }
      start = cwd;
    }
    base = join_lexical(start, parent);
  }
  if (leaf.empty()) {
    return base.empty() ? std::string("/") : base;
  }
  if (base.empty() || base.back() != '/') {
    base.push_back('/');
  }
  base += leaf;
  return base;
}

#endif

}  // namespace

bool has_traversal_component(std::string_view path) noexcept {
  return !traversal_component(path).empty();
}

Result<std::string> normalize_and_check_path(std::string_view path, const PathPolicy& policy) {
  const Status lexical = lexical_check(path, policy);
  if (!lexical.ok()) {
    return lexical;
  }
  const Result<std::string> normalized = normalize_absolute(path);
  if (!normalized.ok()) {
    return normalized.status();
  }
  const std::string absolute = normalized.value();
  if (!is_absolute_path(absolute)) {
    return Status::failure(StatusCode::path_invalid,
                           "the path " + quote(absolute) +
                               " could not be resolved to an absolute path (normalization check)");
  }
  // (c) Filesystem checks, on the normalized path only, and only for the
  // component that will actually be opened.
  if (path_exists(absolute)) {
    if (policy.require_regular_file && path_is_directory(absolute)) {
      return Status::failure(StatusCode::path_invalid,
                             "the final component of " + quote(absolute) +
                                 " is a directory (require_regular_file check)");
    }
  }
  if (policy.refuse_reparse_points && path_is_reparse_point(absolute)) {
    return Status::failure(StatusCode::path_invalid,
                           "the final component of " + quote(absolute) +
                               " is a reparse point (refuse_reparse_points check)");
  }
  return absolute;
}

}  // namespace pdu_control::detail

namespace pdu_control {

Result<std::string> validate_store_path(std::string_view path, const PathPolicy& policy) {
  return detail::normalize_and_check_path(path, policy);
}

}  // namespace pdu_control
