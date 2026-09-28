// End-to-end tests for the command line tool.
//
// The tool is exercised as a real process: each verb is a separate invocation, so
// the store is opened, recovered, mutated, published, and closed for real. The
// tests assert on the reported tokens rather than on prose, and every failure
// path asserts a non-zero exit code.

#include "fixture.hpp"
#include "proc.hpp"
#include "test_harness.hpp"

#include <string>
#include <vector>

using namespace pdu_control;

namespace {

struct Invocation {
  int exit_code{0};
  std::string output;
  std::string error;
};

Invocation run(const std::vector<std::string>& arguments) {
  Invocation result;
  const std::string executable = pdu_test::cli_executable();
  if (executable.empty()) {
    result.exit_code = -1;
    return result;
  }
  auto process = pdu_test::Process::spawn(executable, arguments);
  if (!process.ok()) {
    result.exit_code = -1;
    return result;
  }
  result.exit_code = process.value().wait();
  result.output = process.value().standard_output();
  result.error = process.value().standard_error();
  return result;
}

bool has(const std::string& text, const std::string& needle) {
  return text.find(needle) != std::string::npos;
}

}  // namespace

PDU_TEST(cli, the_required_verbs_work_end_to_end) {
  pdu_test::TempDir directory("cli-walkthrough");
  const std::string store = directory.store_path();
  PDU_CHECK(!pdu_test::cli_executable().empty());

  PDU_CHECK_EQ(run({"init", "--store", store, "--pdu", "pdu-1", "--generation", "1",
                    "--lifecycle", "active"})
                   .exit_code,
               0);
  PDU_CHECK_EQ(run({"epoch", "adopt", "--store", store, "--epoch", "1"}).exit_code, 0);
  PDU_CHECK_EQ(run({"branch", "add", "--store", store, "--pdu", "pdu-1", "--branch", "br-1",
                    "--generation", "1", "--lifecycle", "active", "--continuous-mA", "16000",
                    "--limit-issuer", "power-capacity", "--limit-authority", "cap-1",
                    "--limit-epoch", "1", "--interlock", "site-safe"})
                   .exit_code,
               0);
  PDU_CHECK_EQ(run({"interlock", "declare", "--store", store, "--interlock", "site-safe",
                    "--pdu", "pdu-1", "--branch", "br-1", "--class", "protected", "--epoch", "1",
                    "--tick", "1"})
                   .exit_code,
               0);
  PDU_CHECK_EQ(run({"interlock", "report", "--store", store, "--interlock", "site-safe", "--state",
                    "satisfied", "--epoch", "1", "--tick", "1"})
                   .exit_code,
               0);
  PDU_CHECK_EQ(run({"grant", "add", "--store", store, "--grant", "g1", "--issuer",
                    "power-control-plane", "--epoch", "1", "--pdu", "pdu-1", "--branch", "br-1",
                    "--pdu-generation", "1", "--branch-generation", "1", "--actions",
                    "control_energize,control_de_energize,lifecycle_service,lifecycle_recovery",
                    "--issued", "1"})
                   .exit_code,
               0);
  PDU_CHECK_EQ(run({"observe", "--store", store, "--pdu", "pdu-1", "--branch", "br-1",
                    "--pdu-generation", "1", "--branch-generation", "1", "--source", "field",
                    "--sequence", "1", "--tick", "1", "--condition", "de_energized"})
                   .exit_code,
               0);
  PDU_CHECK_EQ(run({"tick", "advance", "--store", store, "--tick", "5"}).exit_code, 0);

  const Invocation decision =
      run({"evaluate", "--store", store, "--pdu", "pdu-1", "--branch", "br-1", "--intent",
           "energize", "--epoch", "1", "--pdu-generation", "1", "--branch-generation", "1",
           "--key", "k1", "--tick", "5"});
  PDU_CHECK_EQ(decision.exit_code, 0);
  PDU_CHECK(has(decision.output, "eligible=true"));
  PDU_CHECK(has(decision.output, "trace-9-precondition=interlock"));

  const Invocation issued =
      run({"issue", "--store", store, "--pdu", "pdu-1", "--branch", "br-1", "--intent",
           "energize", "--epoch", "1", "--pdu-generation", "1", "--branch-generation", "1",
           "--key", "k1", "--tick", "5", "--verify"});
  PDU_CHECK_EQ(issued.exit_code, 0);
  PDU_CHECK(has(issued.output, "outcome=acknowledged"));
  PDU_CHECK(has(issued.output, "verify-effect=effective"));
  PDU_CHECK(has(issued.output, "SYNTHETIC"));

  const Invocation snapshot = run({"inspect", "--store", store, "--pdu", "pdu-1", "--branch",
                                   "br-1"});
  PDU_CHECK_EQ(snapshot.exit_code, 0);
  PDU_CHECK(has(snapshot.output, "commanded=energized"));
  PDU_CHECK(has(snapshot.output, "verified=energized"));
  PDU_CHECK(has(snapshot.output, "unresolved-attempt=false"));

  const Invocation attempts = run({"attempts", "--store", store});
  PDU_CHECK_EQ(attempts.exit_code, 0);
  PDU_CHECK(has(attempts.output, "count=1"));
  PDU_CHECK(has(attempts.output, "attempt-0-outcome=verified_effective"));

  const Invocation history = run({"history", "--store", store, "--limit", "5"});
  PDU_CHECK_EQ(history.exit_code, 0);
  PDU_CHECK(has(history.output, "count="));

  const Invocation audit = run({"store-audit", "--store", store});
  PDU_CHECK_EQ(audit.exit_code, 0);
  PDU_CHECK(has(audit.output, "durable=true"));
  PDU_CHECK(has(audit.output, "crc-mismatches=0"));
  PDU_CHECK(has(audit.output, "fenced-writes=0"));
  PDU_CHECK(has(audit.output, "format-version=1"));
  PDU_CHECK(has(audit.output, "SYNTHETIC"));

  const Invocation verified = run({"verify", "--store", store, "--attempt", "1", "--read-back"});
  PDU_CHECK_EQ(verified.exit_code, 0);
  PDU_CHECK(has(verified.output, "effect=effective"));
}

PDU_TEST(cli, refusals_exit_non_zero_and_never_print_success) {
  pdu_test::TempDir directory("cli-refusals");
  const std::string store = directory.store_path();
  PDU_CHECK_EQ(run({"init", "--store", store, "--pdu", "pdu-1", "--generation", "1",
                    "--lifecycle", "active"})
                   .exit_code,
               0);
  PDU_CHECK_EQ(run({"epoch", "adopt", "--store", store, "--epoch", "1"}).exit_code, 0);
  PDU_CHECK_EQ(run({"branch", "add", "--store", store, "--pdu", "pdu-1", "--branch", "br-1",
                    "--generation", "1", "--lifecycle", "active", "--continuous-mA", "16000",
                    "--limit-issuer", "power-capacity", "--limit-authority", "cap-1",
                    "--limit-epoch", "1"})
                   .exit_code,
               0);

  // No grant at all: permission is missing, and the adapter must not be reached.
  const Invocation refused =
      run({"issue", "--store", store, "--pdu", "pdu-1", "--branch", "br-1", "--intent",
           "energize", "--epoch", "1", "--pdu-generation", "1", "--branch-generation", "1",
           "--key", "k1", "--tick", "3"});
  PDU_CHECK_EQ(refused.exit_code, 1);
  PDU_CHECK(has(refused.output, "error: permission_missing"));
  PDU_CHECK(!has(refused.output, "outcome=acknowledged"));

  // A stale device generation is refused with its own code.
  const Invocation stale =
      run({"issue", "--store", store, "--pdu", "pdu-1", "--branch", "br-1", "--intent",
           "energize", "--epoch", "1", "--pdu-generation", "9", "--branch-generation", "1",
           "--key", "k2", "--tick", "3"});
  PDU_CHECK_EQ(stale.exit_code, 1);
  PDU_CHECK(has(stale.output, "error: generation_mismatch"));

  // Usage errors are distinct from refusals.
  PDU_CHECK_EQ(run({"issue", "--store", store, "--pdu", "pdu-1"}).exit_code, 2);
  PDU_CHECK_EQ(run({"not-a-verb", "--store", store}).exit_code, 2);
  PDU_CHECK_EQ(run({"inspect", "--store", store, "--pdu", "pdu-1", "--branch", "ghost"}).exit_code,
               1);
  PDU_CHECK_EQ(run({"attempts", "--store", store, "--limit", "100000"}).exit_code, 2);
  PDU_CHECK_EQ(run({"--version"}).exit_code, 0);
}
