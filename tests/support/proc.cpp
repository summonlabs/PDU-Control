#include "proc.hpp"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "detail/process.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace pdu_test {

// The support layer names library values by their library names.
using namespace ::pdu_control;  // NOLINT(google-build-using-namespace)

namespace {

std::uint64_t next_serial() {
  static std::uint64_t serial = 0;
  serial += 1;
  return serial;
}

std::string scratch_prefix() {
  return "proc-" + std::to_string(::pdu_control::detail::current_process_id()) + "-" +
         std::to_string(next_serial());
}

std::string read_text(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return std::string();
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

#if defined(_WIN32)
std::wstring widen(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
                                       static_cast<int>(text.size()), nullptr, 0);
  if (size <= 0) {
    return std::wstring();
  }
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()),
                      wide.data(), size);
  return wide;
}

std::string quote_argument(const std::string& argument) {
  std::string quoted = "\"";
  for (const char value : argument) {
    if (value == '"') {
      quoted.append("\\\"");
    } else {
      quoted.push_back(value);
    }
  }
  quoted.push_back('"');
  return quoted;
}
#endif

}  // namespace

Process::~Process() {
  release();
  // The capture files are this object's own residue: they are read through
  // standard_output() and standard_error(), and they are removed when the object
  // goes away so that a test never leaves files behind in its working directory.
  if (!out_path_.empty()) {
    std::remove(out_path_.c_str());
  }
  if (!err_path_.empty()) {
    std::remove(err_path_.c_str());
  }
}

Process::Process(Process&& other) noexcept
    : process_(other.process_),
      id_(other.id_),
      out_path_(std::move(other.out_path_)),
      err_path_(std::move(other.err_path_)),
      running_(other.running_),
      waited_(other.waited_),
      exit_code_(other.exit_code_) {
  other.process_ = 0;
  other.id_ = 0;
  other.running_ = false;
}

Process& Process::operator=(Process&& other) noexcept {
  if (this != &other) {
    release();
    process_ = other.process_;
    id_ = other.id_;
    out_path_ = std::move(other.out_path_);
    err_path_ = std::move(other.err_path_);
    running_ = other.running_;
    waited_ = other.waited_;
    exit_code_ = other.exit_code_;
    other.process_ = 0;
    other.id_ = 0;
    other.running_ = false;
  }
  return *this;
}

void Process::release() {
  if (running_) {
    terminate();
  }
  // The capture files stay in place until the object is destroyed, because a
  // caller reads them after the child has settled.
#ifdef _WIN32
  if (process_ != 0) {
    CloseHandle(reinterpret_cast<HANDLE>(process_));
  }
#endif
  process_ = 0;
  id_ = 0;
}

Result<Process> Process::spawn(const std::string& executable,
                               const std::vector<std::string>& arguments) {
  if (executable.empty()) {
    return Status::failure(StatusCode::invalid_argument,
                           "no child executable path was supplied; the build must define the "
                           "probe and tool paths");
  }
  Process process;
  const std::string prefix = scratch_prefix();
  process.out_path_ = prefix + ".out";
  process.err_path_ = prefix + ".err";

#ifdef _WIN32
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  const std::wstring out_wide = widen(process.out_path_);
  const std::wstring err_wide = widen(process.err_path_);
  HANDLE out_handle = CreateFileW(out_wide.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (out_handle == INVALID_HANDLE_VALUE) {
    return Status::failure(StatusCode::store_io, "could not create the child output file");
  }
  HANDLE err_handle = CreateFileW(err_wide.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (err_handle == INVALID_HANDLE_VALUE) {
    CloseHandle(out_handle);
    return Status::failure(StatusCode::store_io, "could not create the child error file");
  }

  std::string command = quote_argument(executable);
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command.append(quote_argument(argument));
  }
  std::wstring command_wide = widen(command);
  if (command_wide.empty()) {
    CloseHandle(out_handle);
    CloseHandle(err_handle);
    return Status::failure(StatusCode::invalid_argument, "the child command line is not valid UTF-8");
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = out_handle;
  startup.hStdError = err_handle;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION info{};
  const std::wstring executable_wide = widen(executable);
  const BOOL started =
      CreateProcessW(executable_wide.c_str(), command_wide.data(), nullptr, nullptr, TRUE, 0,
                     nullptr, nullptr, &startup, &info);
  CloseHandle(out_handle);
  CloseHandle(err_handle);
  if (started == FALSE) {
    return Status::failure(StatusCode::store_io,
                           "CreateProcess failed with error " + std::to_string(GetLastError()));
  }
  CloseHandle(info.hThread);
  process.process_ = reinterpret_cast<std::intptr_t>(info.hProcess);
  process.id_ = static_cast<std::uint64_t>(info.dwProcessId);
  process.running_ = true;
  return process;
#else
  // POSIX: fork, redirect the standard descriptors to the capture files, and
  // exec. The child never returns to the test process.
  std::vector<std::string> storage;
  storage.push_back(executable);
  for (const std::string& argument : arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  for (std::string& value : storage) {
    argv.push_back(value.data());
  }
  argv.push_back(nullptr);
  const pid_t pid = fork();
  if (pid < 0) {
    return Status::failure(StatusCode::store_io, "fork failed");
  }
  if (pid == 0) {
    const int out_fd = ::open(process.out_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    const int err_fd = ::open(process.err_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd >= 0) {
      dup2(out_fd, STDOUT_FILENO);
    }
    if (err_fd >= 0) {
      dup2(err_fd, STDERR_FILENO);
    }
    execv(executable.c_str(), argv.data());
    _exit(127);
  }
  process.process_ = static_cast<std::intptr_t>(pid);
  process.id_ = static_cast<std::uint64_t>(pid);
  process.running_ = true;
  return process;
#endif
}

bool Process::exited() {
  if (waited_) {
    return true;
  }
  if (process_ == 0) {
    return true;
  }
#ifdef _WIN32
  return WaitForSingleObject(reinterpret_cast<HANDLE>(process_), 0) == WAIT_OBJECT_0;
#else
  int status = 0;
  const pid_t result = waitpid(static_cast<pid_t>(process_), &status, WNOHANG);
  if (result == static_cast<pid_t>(process_)) {
    exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    running_ = false;
    waited_ = true;
    return true;
  }
  return false;
#endif
}

int Process::wait() {
  if (waited_) {
    return exit_code_;
  }
#ifdef _WIN32
  if (process_ == 0) {
    return 0;
  }
  WaitForSingleObject(reinterpret_cast<HANDLE>(process_), INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(reinterpret_cast<HANDLE>(process_), &code);
  exit_code_ = static_cast<int>(code);
#else
  if (process_ == 0) {
    return 0;
  }
  int status = 0;
  waitpid(static_cast<pid_t>(process_), &status, 0);
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
#endif
  running_ = false;
  waited_ = true;
  return exit_code_;
}

void Process::terminate() {
  if (!running_ || process_ == 0) {
    return;
  }
#ifdef _WIN32
  TerminateProcess(reinterpret_cast<HANDLE>(process_), 1);
  WaitForSingleObject(reinterpret_cast<HANDLE>(process_), INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(reinterpret_cast<HANDLE>(process_), &code);
  exit_code_ = static_cast<int>(code);
#else
  kill(static_cast<pid_t>(process_), SIGKILL);
  int status = 0;
  waitpid(static_cast<pid_t>(process_), &status, 0);
  exit_code_ = 137;
#endif
  running_ = false;
  waited_ = true;
}

std::string Process::standard_output() const { return read_text(out_path_); }
std::string Process::standard_error() const { return read_text(err_path_); }

std::string probe_executable() {
#ifdef PDU_PROBE_EXECUTABLE
  return std::string(PDU_PROBE_EXECUTABLE);
#else
  return std::string();
#endif
}

std::string cli_executable() {
#ifdef PDU_CLI_EXECUTABLE
  return std::string(PDU_CLI_EXECUTABLE);
#else
  return std::string();
#endif
}

}  // namespace pdu_test
