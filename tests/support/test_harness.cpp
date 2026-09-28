#include "test_harness.hpp"

#include <cstddef>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace pdu_test {
namespace {

int g_checks = 0;
int g_failures = 0;
std::string g_current_suite;
std::string g_current_name;
std::vector<std::string> g_failed_tests;

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

Registrar::Registrar(const char* suite, const char* name, Body body) {
  registry().push_back(TestCase{suite, name, std::move(body)});
}

void count_check() { g_checks += 1; }

void report_failure(const char* file, int line, const std::string& expression,
                    const std::string& detail) {
  g_failures += 1;
  if (g_failed_tests.empty() || g_failed_tests.back() != g_current_suite + "." + g_current_name) {
    g_failed_tests.push_back(g_current_suite + "." + g_current_name);
  }
  std::cout << "FAIL " << g_current_suite << "." << g_current_name << " " << file << ":" << line
            << ": " << expression;
  if (!detail.empty()) {
    std::cout << " [" << detail << "]";
  }
  std::cout << "\n";
  std::cout.flush();
}

std::string display(const std::string& value) { return "\"" + value + "\""; }
std::string display(const char* value) { return value == nullptr ? "<null>" : display(std::string(value)); }
std::string display(bool value) { return value ? "true" : "false"; }
std::string display(std::nullptr_t) { return "<null>"; }

int run_all(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--list") {
      list_only = true;
    } else if (argument == "--filter" && index + 1 < argc) {
      filter = argv[++index];
    }
  }

  int tests_run = 0;
  for (const TestCase& test : registry()) {
    const std::string full = test.suite + "." + test.name;
    if (list_only) {
      std::cout << full << "\n";
      continue;
    }
    if (!filter.empty() && full.find(filter) == std::string::npos) {
      continue;
    }
    g_current_suite = test.suite;
    g_current_name = test.name;
    tests_run += 1;
    const int before = g_checks;
    test.body();
    // Every test must actually exercise something. A test that asserts nothing
    // cannot distinguish a working runtime from a broken one, so it fails.
    if (g_checks == before) {
      report_failure(__FILE__, __LINE__, "the test performed at least one check",
                     "a test with no checks proves nothing");
    }
    g_current_suite.clear();
    g_current_name.clear();
  }
  if (list_only) {
    return 0;
  }
  std::cout << (g_failures == 0 ? "PASS " : "FAIL ") << (g_checks - g_failures) << "/" << g_checks
            << " checks in " << tests_run << " tests";
  if (!g_failed_tests.empty()) {
    std::cout << " (failing:";
    for (const std::string& name : g_failed_tests) {
      std::cout << " " << name;
    }
    std::cout << ")";
  }
  std::cout << "\n";
  return g_failures == 0 ? 0 : 1;
}

}  // namespace pdu_test

int main(int argc, char** argv) { return ::pdu_test::run_all(argc, argv); }
