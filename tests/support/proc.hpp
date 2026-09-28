#pragma once

// Real independent operating-system processes.
//
// The crash and multiprocess proofs need processes that really exist, really die,
// and really hold operating-system locks. Child output is redirected to files
// rather than pipes: file redirection cannot deadlock on a full pipe buffer, and
// the parent reads the files after the child has settled.

#include <cstdint>
#include <string>
#include <vector>

#include "pdu_control/status.hpp"

namespace pdu_test {

class Process {
 public:
  Process() = default;
  ~Process();
  Process(Process&& other) noexcept;
  Process& operator=(Process&& other) noexcept;
  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;

  /// Starts \`executable\` with \`arguments\`. The child inherits the parent's
  /// environment and working directory.
  static ::pdu_control::Result<Process> spawn(const std::string& executable,
                                              const std::vector<std::string>& arguments);

  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }
  [[nodiscard]] bool running() const noexcept { return running_; }

  /// Waits for the child to settle and returns its exit code. Safe to call more
  /// than once; the second call returns the recorded code.
  int wait();

  /// True once the child has settled, without blocking. This asks the operating
  /// system rather than trusting a local flag, so a test can wait for a real
  /// process to finish.
  [[nodiscard]] bool exited();
  /// Terminates the child immediately. Safe after the child already settled.
  void terminate();

  [[nodiscard]] std::string standard_output() const;
  [[nodiscard]] std::string standard_error() const;

 private:
  void release();

  std::intptr_t process_{0};
  std::uint64_t id_{0};
  std::string out_path_;
  std::string err_path_;
  bool running_{false};
  bool waited_{false};
  int exit_code_{0};
};

/// Path of the probe executable, injected by the build.
[[nodiscard]] std::string probe_executable();

/// Path of the command line tool, injected by the build. Empty when the tool was
/// not built.
[[nodiscard]] std::string cli_executable();

}  // namespace pdu_test
