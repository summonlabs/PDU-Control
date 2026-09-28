#include "fixture.hpp"
#include "test_harness.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include "detail/crc32c.hpp"
#include "detail/file_io.hpp"

using namespace pdu_control;

namespace {

std::vector<std::uint8_t> read_all(const std::string& path) {
  std::vector<std::uint8_t> bytes;
  std::ifstream stream(path, std::ios::binary);
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  stream.seekg(0, std::ios::beg);
  if (size <= 0) {
    return bytes;
  }
  bytes.resize(static_cast<std::size_t>(size));
  stream.read(reinterpret_cast<char*>(bytes.data()), size);
  return bytes;
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(bytes[offset + index]) << (index * 8);
  }
  return value;
}

std::uint64_t get_u64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8);
  }
  return value;
}

void put_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (index * 8)) & 0xFFU);
  }
}

/// The head record the store will actually adopt: the valid one with the larger
/// serial. An attack on the other record attacks residue.
std::uint64_t head_serial(const std::vector<std::uint8_t>& bytes, std::size_t base) {
  return get_u64(bytes, base + 16);
}

std::uint64_t head_generation(const std::vector<std::uint8_t>& bytes, std::size_t base) {
  return get_u64(bytes, base + 24);
}

/// The head record whose serial is the largest. The store must agree with this:
/// a publication always writes a serial one greater than the head it replaces.
std::size_t committed_head_base(const std::vector<std::uint8_t>& bytes) {
  std::size_t best = 0;
  std::uint64_t best_serial = 0;
  bool found = false;
  for (std::size_t index = 0; index < 2; ++index) {
    const std::size_t base = index * store_head_record_bytes;
    if (std::memcmp(bytes.data() + base, store_head_magic.data(), store_head_magic.size()) != 0) {
      continue;
    }
    if (get_u32(bytes, base + 80) != ::pdu_control::detail::crc32c(bytes.data() + base, 80)) {
      continue;
    }
    const std::uint64_t serial = head_serial(bytes, base);
    if (!found || serial > best_serial) {
      found = true;
      best_serial = serial;
      best = base;
    }
  }
  return best;
}

std::size_t committed_slot_base(const std::vector<std::uint8_t>& bytes) {
  const std::size_t head = committed_head_base(bytes);
  const std::uint32_t slot = get_u32(bytes, head + 48);
  return store_head_bytes + static_cast<std::size_t>(slot) * store_slot_stride;
}

Status write_all(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return Status::failure(StatusCode::store_io, "cannot open the scratch file for writing");
  }
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return stream ? Status::success()
                : Status::failure(StatusCode::store_io, "cannot write the scratch file");
}

}  // namespace

PDU_TEST(persistence, a_store_round_trips_every_authoritative_value) {
  pdu_test::TempDir directory("persistence-roundtrip");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("roundtrip", 1);
  Digest64 before;
  const std::string store = directory.store_path();
  {
    auto opened = PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(5)), StatusCode::ok);
    before = engine.state_digest();
    const auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
    PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
    PDU_CHECK(PDU_REQUIRE_OK(snapshot).revision.is_set());
    PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  }
  {
    auto reopened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
    PDU_REQUIRE_STATUS(reopened, StatusCode::ok);
    PduControlEngine& engine = reopened.value();
    PDU_CHECK_EQ(engine.authority_epoch(), scenario.epoch);
    PDU_CHECK_EQ(engine.current_tick(), LogicalTick::from(5));
    // The canonical digest is a function of logical state only, so it must be
    // identical after a full round trip through the durable format.
    PDU_CHECK_EQ(engine.state_digest(), before);
    const auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
    PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).generation, scenario.branch_generation);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).pdu_generation, scenario.pdu_generation);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).lifecycle, LifecycleState::active);
    PDU_CHECK(PDU_REQUIRE_OK(snapshot).limits.continuous_current.has_value());
    PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).limits.continuous_current.value().raw(), std::int64_t{16000});
    PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).permission.verdict, PermissionVerdict::usable);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).interlocks_summary.verdict, InterlockVerdict::clear);
    PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  }
}

PDU_TEST(persistence, recovered_evidence_is_stale_until_revalidated) {
  pdu_test::TempDir directory("persistence-recovered");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("recovered", 1);
  const std::string store = directory.store_path();
  AttemptId attempt_id;
  {
    auto opened = PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
    SyntheticPduAdapter::Config config;
    config.id = AdapterId::parse("recovery-adapter").value();
    config.vendor = IssuerId::parse("test").value();
    config.model = "synthetic";
    config.firmware = "0";
    config.pdu = scenario.pdu;
    config.branch = scenario.branch;
    config.pdu_generation = scenario.pdu_generation;
    config.branch_generation = scenario.branch_generation;
    config.mode = SyntheticMode::honor;
    config.initial_condition = BranchCondition::de_energized;
    config.reading_taken_at = Instant::logical(LogicalTick::from(1));
    config.reading_tick_step = LogicalTick::from(1);
  config.read_at_request_instant = true;
    SyntheticPduAdapter adapter(config);
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(4)), StatusCode::ok);
    BranchControlRequest request;
    request.key = IdempotencyKey::parse("k").value();
    request.pdu = scenario.pdu;
    request.branch = scenario.branch;
    request.pdu_generation = scenario.pdu_generation;
    request.branch_generation = scenario.branch_generation;
    request.epoch = scenario.epoch;
    request.intent = CommandIntent::energize;
    request.actor = ActorId::parse("tester").value();
    request.requested_at = LogicalTick::from(4);
    const auto issued = engine.issue(request, adapter);
    PDU_REQUIRE_STATUS(issued, StatusCode::ok);
    attempt_id = PDU_REQUIRE_OK(issued).id;
    PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  }
  {
    auto reopened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
    PDU_REQUIRE_STATUS(reopened, StatusCode::ok);
    PduControlEngine& engine = reopened.value();
    // The process did not die, so the attempt was not turned into recovery work;
    // but the evidence it would be verified against came off disk and is
    // recovered, which is not fresh evidence.
    const auto snapshot = engine.inspect_branch(scenario.pdu, scenario.branch);
    PDU_REQUIRE_STATUS(snapshot, StatusCode::ok);
    PDU_CHECK(PDU_REQUIRE_OK(snapshot).observation.present);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(snapshot).observation.freshness, FreshnessState::recovered);
    const auto verified = engine.verify(attempt_id);
    PDU_REQUIRE_STATUS(verified, StatusCode::ok);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(verified).code, StatusCode::evidence_stale);
    PDU_CHECK(!PDU_REQUIRE_OK(verified).state_updated);
    PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  }
}

PDU_TEST(persistence, open_modes_are_enforced) {
  pdu_test::TempDir directory("persistence-modes");
  const std::string store = directory.store_path();
  PDU_REQUIRE_STATUS(PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options()),
                     StatusCode::not_found);
  PDU_REQUIRE_STATUS(PduControlEngine::open(store, OpenMode::read_only, pdu_test::base_options()),
                     StatusCode::not_found);
  auto created = PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options());
  PDU_REQUIRE_STATUS(created, StatusCode::ok);
  PDU_REQUIRE_STATUS(created.value().close(), StatusCode::ok);
  PDU_REQUIRE_STATUS(PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options()),
                     StatusCode::duplicate_identity);
  auto adopted = PduControlEngine::open(store, OpenMode::open_or_create, pdu_test::base_options());
  PDU_REQUIRE_STATUS(adopted, StatusCode::ok);
  // A second engine on the same store cannot take write authority.
  auto second = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(second, StatusCode::busy);
  auto reader = PduControlEngine::open(store, OpenMode::read_only, pdu_test::base_options());
  PDU_REQUIRE_STATUS(reader, StatusCode::busy);
  PDU_REQUIRE_STATUS(adopted.value().close(), StatusCode::ok);
  auto read_only = PduControlEngine::open(store, OpenMode::read_only, pdu_test::base_options());
  PDU_REQUIRE_STATUS(read_only, StatusCode::ok);
  PDU_CHECK(read_only.value().is_read_only());
  PDU_REQUIRE_STATUS(read_only.value().advance_tick(LogicalTick::from(2)), StatusCode::store_locked);
  PDU_REQUIRE_STATUS(read_only.value().flush(), StatusCode::store_locked);
  PDU_REQUIRE_STATUS(read_only.value().close(), StatusCode::ok);
}

PDU_TEST(persistence, corrupted_stores_are_refused_rather_than_repaired) {
  const std::string store_leaf = "site.pdustore";
  const auto open_case = [&](const std::string& name,
                             const std::function<void(std::vector<std::uint8_t>&)>& corrupt,
                             StatusCode expected) {
    pdu_test::TempDir directory(name);
    const pdu_test::Scenario scenario = pdu_test::make_scenario(name, 1);
    const std::string store = directory.store_path();
    {
      auto opened = PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options());
      PDU_REQUIRE_STATUS(opened, StatusCode::ok);
      PDU_REQUIRE_STATUS(pdu_test::apply_scenario(opened.value(), scenario), StatusCode::ok);
      PDU_REQUIRE_STATUS(opened.value().close(), StatusCode::ok);
    }
    std::vector<std::uint8_t> bytes = read_all(store);
    PDU_CHECK(!bytes.empty());
    corrupt(bytes);
    PDU_REQUIRE_STATUS(write_all(store, bytes), StatusCode::ok);
    const auto reopened =
        PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
    PDU_CHECK_MSG(!reopened.ok(),
                  std::string("expected refusal with ") + std::string(to_token(expected)) +
                      " but the store opened");
    if (!reopened.ok()) {
      PDU_CHECK_EQ(reopened.status().code(), expected);
    }
  };

  open_case("corrupt-payload",
            [](std::vector<std::uint8_t>& bytes) {
              bytes[committed_slot_base(bytes) + store_slot_header_bytes + 40] ^= 0xFF;
            },
            StatusCode::store_malformed);
  open_case("corrupt-slot-magic",
            [](std::vector<std::uint8_t>& bytes) {
              bytes[committed_slot_base(bytes)] = static_cast<std::uint8_t>('X');
            },
            StatusCode::store_malformed);
  open_case("truncate",
            [](std::vector<std::uint8_t>& bytes) { bytes.resize(bytes.size() / 2); },
            StatusCode::store_truncated);
  open_case("oversize",
            [](std::vector<std::uint8_t>& bytes) { bytes.resize(bytes.size() + 4096); },
            StatusCode::store_oversized);
  open_case("future-version",
            [&](std::vector<std::uint8_t>& bytes) {
              const std::size_t head = committed_head_base(bytes);
              bytes[head + 8] = 9;
              put_u32(bytes, head + 80, ::pdu_control::detail::crc32c(bytes.data() + head, 80));
            },
            StatusCode::store_version_unsupported);
  open_case("both-heads-invalid",
            [&](std::vector<std::uint8_t>& bytes) {
              bytes[0] = static_cast<std::uint8_t>('X');
              bytes[store_head_record_bytes] = static_cast<std::uint8_t>('X');
            },
            StatusCode::store_malformed);
}

PDU_TEST(persistence, destroying_the_newest_head_rolls_back_and_the_fence_catches_it) {
  // A head record that is present but unreadable is indistinguishable from a
  // head write that was torn by a crash, so the store adopts the other whole
  // generation rather than refusing. That is a rollback, and it is exactly what
  // the monotonic generation fence exists to catch: a caller that requires
  // monotonic authority arms the fence and gets rollback_detected instead.
  pdu_test::TempDir directory("persistence-rollback");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("rollback", 1);
  const std::string store = directory.store_path();
  StoreGeneration published;
  {
    auto opened = PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(opened.value(), scenario), StatusCode::ok);
    PDU_REQUIRE_STATUS(opened.value().advance_tick(LogicalTick::from(9)), StatusCode::ok);
    PDU_REQUIRE_STATUS(opened.value().close(), StatusCode::ok);
    // The generation after the close, because closing publishes as well.
    published = opened.value().store_generation();
  }
  std::vector<std::uint8_t> bytes = read_all(store);
  const std::size_t committed = committed_head_base(bytes);
  const std::uint64_t newest_generation = head_generation(bytes, committed);
  const std::uint64_t older_generation = head_generation(bytes, committed == 0
                                                                    ? store_head_record_bytes
                                                                    : 0);
  PDU_CHECK_EQ(newest_generation, published.value());
  PDU_CHECK(older_generation < newest_generation);
  bytes[committed] = static_cast<std::uint8_t>('X');
  PDU_REQUIRE_STATUS(write_all(store, bytes), StatusCode::ok);

  // A caller that requires monotonic authority arms the fence and is refused,
  // rather than silently continuing from an older generation.
  EngineOptions fenced = pdu_test::base_options();
  fenced.min_store_generation = StoreGeneration::from(newest_generation);
  PDU_REQUIRE_STATUS(PduControlEngine::open(store, OpenMode::open_existing, fenced),
                     StatusCode::rollback_detected);

  auto rolled_back = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(rolled_back, StatusCode::ok);
  // Opening publishes once, so the generation the engine reports is the adopted
  // one plus that publication.
  PDU_CHECK_EQ(rolled_back.value().store_generation().value(), older_generation + 1);
  PDU_CHECK_EQ(rolled_back.value().status().branch_count, std::size_t{1});
  PDU_CHECK(rolled_back.value().store_audit().head_records_valid == 1);
  PDU_REQUIRE_STATUS(rolled_back.value().close(), StatusCode::ok);
}

PDU_TEST(persistence, an_empty_file_is_not_a_store) {
  pdu_test::TempDir directory("persistence-empty");
  const std::string store = directory.store_path();
  PDU_REQUIRE_STATUS(write_all(store, std::vector<std::uint8_t>{}), StatusCode::ok);
  auto opened = PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PDU_CHECK_EQ(opened.value().status().pdu_count, std::size_t{0});
  PDU_REQUIRE_STATUS(opened.value().close(), StatusCode::ok);
}

PDU_TEST(persistence, the_rollback_fence_refuses_an_older_store) {
  pdu_test::TempDir directory("persistence-fence");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("fence", 1);
  const std::string store = directory.store_path();
  auto opened = PduControlEngine::open(store, OpenMode::create_new, pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  const StoreGeneration high = engine.store_generation();
  PDU_CHECK(high.value() > 3);
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);

  EngineOptions fenced = pdu_test::base_options();
  fenced.min_store_generation = StoreGeneration::from(high.value() + 10);
  PDU_REQUIRE_STATUS(PduControlEngine::open(store, OpenMode::open_existing, fenced),
                     StatusCode::rollback_detected);
  fenced.min_store_generation = high;
  auto accepted = PduControlEngine::open(store, OpenMode::open_existing, fenced);
  PDU_REQUIRE_STATUS(accepted, StatusCode::ok);
  PDU_CHECK(accepted.value().store_audit().rollback_fence_armed);
  PDU_REQUIRE_STATUS(accepted.value().close(), StatusCode::ok);
}

PDU_TEST(persistence, the_store_audit_describes_what_happened) {
  pdu_test::TempDir directory("persistence-audit");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("audit", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  const StoreAudit audit = engine.store_audit();
  PDU_CHECK(audit.durable);
  PDU_CHECK(audit.open);
  PDU_CHECK(audit.exclusively_locked);
  PDU_CHECK_EQ(audit.format_version, store_format_version);
  PDU_CHECK(audit.publication_count > 5);
  PDU_CHECK_EQ(audit.publication_count, audit.readback_verifications);
  PDU_CHECK_EQ(audit.fenced_writes, std::uint64_t{0});
  PDU_CHECK_EQ(audit.crc_mismatches, std::uint64_t{0});
  PDU_CHECK(audit.bytes_written > 0);
  PDU_CHECK(audit.head_records_valid <= 2);
  PDU_CHECK(audit.last_published_digest.is_set());
  PDU_CHECK_EQ(audit.incarnation, engine.incarnation());
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
}

PDU_TEST(persistence, repeated_open_and_close_is_stable) {
  pdu_test::TempDir directory("persistence-reopen-loop");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("loop", 1);
  const std::string store = directory.store_path();
  Digest64 digest;
  for (int round = 0; round < 5; ++round) {
    auto opened = PduControlEngine::open(
        store, round == 0 ? OpenMode::create_new : OpenMode::open_existing, pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    if (round == 0) {
      PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
      digest = engine.state_digest();
    } else {
      PDU_CHECK_EQ(engine.state_digest(), digest);
    }
    PDU_CHECK_EQ(engine.status().branch_count, std::size_t{1});
    PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  }
  const auto bytes = read_all(store);
  PDU_CHECK_EQ(bytes.size(), store_file_bytes);
}
