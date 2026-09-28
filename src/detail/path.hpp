#pragma once

// Path normalization and trust-model checks.
//
// The policy is applied in this order, deliberately: lexical checks on the
// original text first (embedded NUL, length, traversal components, device
// names), then normalization, then filesystem checks on the normalized path
// (directory, reparse point). Normalizing first would erase the evidence that a
// traversal was attempted.

#include <string>
#include <string_view>

#include "pdu_control/status.hpp"
#include "pdu_control/store.hpp"

namespace pdu_control::detail {

/// The absolute, normalized path for `path`, or the reason it was refused.
[[nodiscard]] Result<std::string> normalize_and_check_path(std::string_view path,
                                                           const PathPolicy& policy);

/// The same checks applied to a file the caller names under a directory the
/// caller already validated, used by the tests for adversarial path cases.
[[nodiscard]] bool has_traversal_component(std::string_view path) noexcept;

}  // namespace pdu_control::detail
