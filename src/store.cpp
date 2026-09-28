#include "pdu_control/store.hpp"

#include "detail/path.hpp"

namespace pdu_control {

std::string_view to_token(OpenMode mode) noexcept {
  switch (mode) {
    case OpenMode::create_new:
      return "create_new";
    case OpenMode::open_existing:
      return "open_existing";
    case OpenMode::open_or_create:
      return "open_or_create";
    case OpenMode::read_only:
      return "read_only";
  }
  return "unknown_mode";
}

bool parse_open_mode(std::string_view token, OpenMode& out) noexcept {
  constexpr OpenMode kModes[] = {OpenMode::create_new, OpenMode::open_existing,
                                 OpenMode::open_or_create, OpenMode::read_only};
  for (const OpenMode mode : kModes) {
    if (to_token(mode) == token) {
      out = mode;
      return true;
    }
  }
  return false;
}

// `validate_store_path` is implemented in src/detail/path.cpp, next to the
// lexical, normalization, and filesystem checks it applies.

}  // namespace pdu_control
