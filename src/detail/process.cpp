#include "detail/process.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <cstdlib>

namespace pdu_control::detail {

std::uint64_t current_process_id() noexcept {
#ifdef _WIN32
  return static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

void terminate_now(int code) noexcept {
#ifdef _WIN32
  // The process object is the only handle needed, and the pseudo-handle is
  // always valid for it. No DLL detach notifications, no atexit handlers, and
  // no interactive crash handling run before the process is gone.
  ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(code));
  std::_Exit(code);
#else
  ::_exit(code);
#endif
}

}  // namespace pdu_control::detail
