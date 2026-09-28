#pragma once

// Process-level primitives used by the runtime and by the crash tests.
//
// `terminate_now` ends the current process immediately, without running
// destructors, without flushing standard streams, and without invoking any
// interactive crash handler. It exists so that durability can be tested against
// a process that really dies at a chosen point.

#include <cstdint>

namespace pdu_control::detail {

[[nodiscard]] std::uint64_t current_process_id() noexcept;

/// Terminates this process with `code`. Never returns.
[[noreturn]] void terminate_now(int code) noexcept;

}  // namespace pdu_control::detail
