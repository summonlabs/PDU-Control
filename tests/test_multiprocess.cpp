#include "fixture.hpp"
#include "proc.hpp"
#include "test_harness.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "detail/crc32c.hpp"
#include "detail/file_io.hpp"
#include "detail/store_file.hpp"

using namespace pdu_control;

namespace {

bool wait_for_file(const std::string& path) {
  for (int attempt = 0; attempt < 2000; ++attempt) {
    if (::pdu_control::detail::path_exists(path)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return ::pdu_control::detail::path_exists(path);
}

bool wait_for_exit(pdu_test::Process& process, int attempts = 2000) {
  for (int attempt = 0; attempt < attempts; ++attempt) {
    if (process.exited()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return process.exited();
}

}  // namespace

PDU_TEST(multiprocess, a_second_process_cannot_take_write_authority) {
  pdu_test::TempDir directory("multiprocess-exclusion");
  const std::string store = directory.store_path();
  std::string ready;
  std::string release;
  PDU_REQUIRE_STATUS(directory.file("ready.flag", ready), StatusCode::ok);
  PDU_REQUIRE_STATUS(directory.file("release.flag", release), StatusCode::ok);

  auto holder = pdu_test::Process::spawn(pdu_test::probe_executable(),
                                         {"hold", store, ready, release});
  PDU_REQUIRE_STATUS(holder, StatusCode::ok);
  PDU_CHECK(wait_for_file(ready));
  PDU_CHECK(holder.value().running());

  // The holder owns write authority, so this process is refused.
  PDU_REQUIRE_STATUS(PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options()),
                     StatusCode::busy);
  // And so is the probe started from this process.
  auto second = pdu_test::Process::spawn(pdu_test::probe_executable(), {"report", store});
  PDU_REQUIRE_STATUS(second, StatusCode::ok);
  PDU_CHECK_EQ(second.value().wait(), 1);
  PDU_CHECK(second.value().standard_output().find("error=busy") != std::string::npos);

  // Releasing explicitly hands authority over without any process dying.
  PDU_REQUIRE_STATUS(::pdu_control::detail::write_file_flushed(release, "go", 2), StatusCode::ok);
  PDU_CHECK(wait_for_exit(holder.value()));
  PDU_CHECK_EQ(holder.value().wait(), 0);
  auto opened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  const Incarnation first = opened.value().incarnation();
  PDU_CHECK(first.is_set());
  PDU_REQUIRE_STATUS(opened.value().close(), StatusCode::ok);

  // A second open allocates a new incarnation, so a writer that was thought to
  // be alive can be told apart from its successor.
  auto reopened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(reopened, StatusCode::ok);
  PDU_CHECK_EQ(reopened.value().incarnation().value(), first.value() + 1);
  PDU_REQUIRE_STATUS(reopened.value().close(), StatusCode::ok);
}

PDU_TEST(multiprocess, process_death_releases_write_authority_and_leaves_a_valid_store) {
  pdu_test::TempDir directory("multiprocess-death");
  const std::string store = directory.store_path();
  std::string ready;
  std::string release;
  PDU_REQUIRE_STATUS(directory.file("ready.flag", ready), StatusCode::ok);
  PDU_REQUIRE_STATUS(directory.file("release.flag", release), StatusCode::ok);

  auto holder = pdu_test::Process::spawn(pdu_test::probe_executable(),
                                         {"hold", store, ready, release});
  PDU_REQUIRE_STATUS(holder, StatusCode::ok);
  PDU_CHECK(wait_for_file(ready));
  PDU_REQUIRE_STATUS(PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options()),
                     StatusCode::busy);

  // Abrupt termination, not a cooperative exit.
  holder.value().terminate();
  PDU_CHECK(!holder.value().running());

  auto opened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PDU_CHECK(opened.value().store_audit().head_records_valid >= 1);
  PDU_CHECK_EQ(opened.value().store_audit().crc_mismatches, std::uint64_t{0});
  PDU_REQUIRE_STATUS(opened.value().close(), StatusCode::ok);

  // A killed writer leaves no residue that blocks the next one, and the report
  // from a fresh process agrees.
  auto reporter = pdu_test::Process::spawn(pdu_test::probe_executable(), {"report", store});
  PDU_REQUIRE_STATUS(reporter, StatusCode::ok);
  PDU_CHECK_EQ(reporter.value().wait(), 0);
  PDU_CHECK(reporter.value().standard_output().find("generation=") != std::string::npos);
}

PDU_TEST(multiprocess, a_writer_whose_head_was_advanced_out_of_band_is_fenced) {
  pdu_test::TempDir directory("multiprocess-fencing");
  const std::string store = directory.store_path();
  const pdu_test::Scenario scenario = pdu_test::make_scenario("fence", 1);

  auto created = PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options());
  PDU_REQUIRE_STATUS(created, StatusCode::ok);
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(created.value(), scenario), StatusCode::ok);
  PDU_REQUIRE_STATUS(created.value().close(), StatusCode::ok);

  // Two store objects on the same path, both taken without the sidecar lock, so
  // the fence itself is what is exercised rather than the file lock.
  auto first = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(first, StatusCode::ok);
  PduControlEngine& engine = first.value();

  // Forge a head record that claims another writer advanced the store. The
  // format is documented and public, so an out-of-band writer really can do
  // this; the fence is what makes it harmless.
  // The data file is opened with sharing enabled, so an out-of-band writer can
  // reach it while this engine holds the sidecar lock. That is exactly the
  // situation the head fence exists for.
  std::vector<std::uint8_t> head(store_head_record_bytes, 0);
  {
    ::pdu_control::detail::FileOpenOptions options;
    options.must_exist = true;
    auto file = ::pdu_control::detail::File::open(store, ::pdu_control::detail::FileAccess::read_write,
                                                  options);
    PDU_REQUIRE_STATUS(file, StatusCode::ok);
    PDU_REQUIRE_STATUS(file.value().read_at(0, head.data(), head.size()), StatusCode::ok);
    // Bump the stored serial and rewrite the CRC over the covered prefix.
    std::uint64_t serial = 0;
    for (std::size_t index = 0; index < 8; ++index) {
      serial |= static_cast<std::uint64_t>(head[16 + index]) << (index * 8);
    }
    serial += 1000;
    for (std::size_t index = 0; index < 8; ++index) {
      head[16 + index] = static_cast<std::uint8_t>((serial >> (index * 8)) & 0xFFULL);
    }
    const std::uint32_t crc = ::pdu_control::detail::crc32c(head.data(), 80);
    for (std::size_t index = 0; index < 4; ++index) {
      head[80 + index] = static_cast<std::uint8_t>((crc >> (index * 8)) & 0xFFU);
    }
    PDU_REQUIRE_STATUS(file.value().write_at(0, head.data(), head.size()), StatusCode::ok);
    PDU_REQUIRE_STATUS(file.value().flush(), StatusCode::ok);
    PDU_REQUIRE_STATUS(file.value().close(), StatusCode::ok);
  }

  // This engine still believes it owns the head, so its next publication is
  // refused instead of overwriting a generation it never saw.
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(99)), StatusCode::busy);
  PDU_CHECK(engine.store_audit().fenced_writes >= 1);

  // Closing publishes, and a fenced writer is refused, so the refusal is what
  // close() reports. It still releases write authority and leaves the store
  // whole; reopening adopts the advanced head.
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::busy);
  auto reopened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  if (reopened.ok()) {
    PDU_CHECK_EQ(reopened.value().status().branch_count, std::size_t{1});
    PDU_REQUIRE_STATUS(reopened.value().close(), StatusCode::ok);
  } else {
    // A forged head that no longer describes the committed payload is refused
    // outright, which is the other acceptable outcome and never a silent merge.
    PDU_CHECK_EQ(reopened.status().code(), StatusCode::store_malformed);
  }
}

PDU_TEST(multiprocess, a_store_written_by_one_process_is_adopted_by_another) {
  pdu_test::TempDir directory("multiprocess-handoff");
  const std::string store = directory.store_path();
  auto writer = pdu_test::Process::spawn(pdu_test::probe_executable(),
                                         {"setup", store, "pdu-mp", "branch-mp"});
  PDU_REQUIRE_STATUS(writer, StatusCode::ok);
  PDU_CHECK_EQ(writer.value().wait(), 0);
  const std::string output = writer.value().standard_output();
  PDU_CHECK(output.find("pdu-generation=1") != std::string::npos);
  PDU_CHECK(output.find("branch-generation=1") != std::string::npos);

  auto reader = pdu_test::Process::spawn(pdu_test::probe_executable(), {"reopen-report", store});
  PDU_REQUIRE_STATUS(reader, StatusCode::ok);
  PDU_CHECK_EQ(reader.value().wait(), 0);
  const std::string report = reader.value().standard_output();
  PDU_CHECK(report.find("branches=1") != std::string::npos);
  PDU_CHECK(report.find("reopened=1") != std::string::npos);
  // Nothing has been verified yet, so the verified condition is unknown; the
  // observed condition is what the recorded telemetry reported.
  PDU_CHECK(report.find("branch-state=active/unknown/unknown") != std::string::npos);
}
