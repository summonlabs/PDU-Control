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

Status write_all(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return Status::failure(StatusCode::store_io, "cannot open the scratch file");
  }
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return stream ? Status::success() : Status::failure(StatusCode::store_io, "cannot write");
}

void put_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (index * 8)) & 0xFFU);
  }
}

/// Recomputes the head CRC of one head record after a field was edited, so the
/// test attacks the layer above the checksum rather than the checksum itself.
void fix_head_crc(std::vector<std::uint8_t>& bytes, std::size_t base) {
  const std::uint32_t crc = ::pdu_control::detail::crc32c(bytes.data() + base, 80);
  put_u32(bytes, base + 80, crc);
}

void fix_slot_header_crc(std::vector<std::uint8_t>& bytes, std::size_t base) {
  const std::uint32_t crc = ::pdu_control::detail::crc32c(bytes.data() + base, 48);
  put_u32(bytes, base + 48, crc);
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

/// The offset of the payload slot the committed head record actually names. An
/// attack that edits the other slot attacks residue the store will never read,
/// so it would prove nothing.
std::size_t committed_slot_base(const std::vector<std::uint8_t>& bytes) {
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
    const std::uint64_t serial = get_u64(bytes, base + 16);
    if (!found || serial > best_serial) {
      found = true;
      best_serial = serial;
      best = base;
    }
  }
  const std::uint32_t slot = get_u32(bytes, best + 48);
  return store_head_bytes + static_cast<std::size_t>(slot) * store_slot_stride;
}

}  // namespace

PDU_TEST(adversarial, store_paths_are_validated_before_normalization) {
  PathPolicy policy;
  // Traversal, in several spellings.
  PDU_REQUIRE_STATUS(validate_store_path("../escape.pdustore", policy), StatusCode::path_invalid);
  PDU_REQUIRE_STATUS(validate_store_path("a/../../escape.pdustore", policy), StatusCode::path_invalid);
  PDU_REQUIRE_STATUS(validate_store_path("..\\escape.pdustore", policy), StatusCode::path_invalid);
  // An embedded NUL would truncate the path at the operating-system boundary.
  const std::string with_nul = std::string("store") + '\0' + ".pdustore";
  PDU_REQUIRE_STATUS(validate_store_path(with_nul, policy), StatusCode::path_invalid);
  // Reserved device names address devices rather than files.
  PDU_REQUIRE_STATUS(validate_store_path("NUL", policy), StatusCode::path_invalid);
  PDU_REQUIRE_STATUS(validate_store_path("com1.pdustore", policy), StatusCode::path_invalid);
  // Length, emptiness, and malformed UTF-8.
  PDU_REQUIRE_STATUS(validate_store_path("", policy), StatusCode::path_invalid);
  PDU_REQUIRE_STATUS(validate_store_path(std::string(5000, 'a'), policy), StatusCode::path_invalid);
  PDU_REQUIRE_STATUS(validate_store_path("bad\xC3.pdustore", policy), StatusCode::path_invalid);
  PDU_REQUIRE_STATUS(validate_store_path("ok\x80.pdustore", policy), StatusCode::path_invalid);
  // A directory is not a store file.
  pdu_test::TempDir directory("adversarial-path");
  PDU_REQUIRE_STATUS(validate_store_path(directory.path(), policy), StatusCode::path_invalid);
  // A well-formed path is accepted and returned normalized.
  const auto good = validate_store_path(directory.store_path(), policy);
  PDU_REQUIRE_STATUS(good, StatusCode::ok);
  PDU_CHECK(!good.value().empty());
}

PDU_TEST(adversarial, duplicate_identities_and_capacity_bounds_are_refused) {
  EngineOptions options = pdu_test::base_options();
  options.bounds.max_pdus = 2;
  options.bounds.max_branches_per_pdu = 2;
  PduControlEngine engine = PDU_REQUIRE_OK(PduControlEngine::in_memory(options));
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(1)), StatusCode::ok);
  for (int index = 0; index < 2; ++index) {
    PduDefinition pdu;
    pdu.id = PduId::parse("pdu-" + std::to_string(index)).value();
    pdu.generation = PduGeneration::from(1);
    pdu.lifecycle = LifecycleState::active;
    pdu.registered_at = LogicalTick::from(1);
    PDU_REQUIRE_STATUS(engine.register_pdu(pdu), StatusCode::ok);
    PDU_REQUIRE_STATUS(engine.register_pdu(pdu), StatusCode::duplicate_identity);
  }
  PduDefinition extra;
  extra.id = PduId::parse("pdu-overflow").value();
  extra.generation = PduGeneration::from(1);
  extra.lifecycle = LifecycleState::active;
  extra.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_pdu(extra), StatusCode::capacity_exhausted);

  for (int index = 0; index < 2; ++index) {
    BranchDefinition branch;
    branch.id = BranchId::parse("branch-" + std::to_string(index)).value();
    branch.pdu = PduId::parse("pdu-0").value();
    branch.generation = BranchGeneration::from(1);
    branch.lifecycle = LifecycleState::active;
    branch.registered_at = LogicalTick::from(1);
    PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::ok);
    PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::duplicate_identity);
  }
  BranchDefinition overflow;
  overflow.id = BranchId::parse("branch-overflow").value();
  overflow.pdu = PduId::parse("pdu-0").value();
  overflow.generation = BranchGeneration::from(1);
  overflow.lifecycle = LifecycleState::active;
  overflow.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_branch(overflow), StatusCode::capacity_exhausted);

  // A branch identity is unique across the whole model, not per PDU.
  BranchDefinition shared;
  shared.id = BranchId::parse("branch-0").value();
  shared.pdu = PduId::parse("pdu-1").value();
  shared.generation = BranchGeneration::from(1);
  shared.lifecycle = LifecycleState::active;
  shared.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_branch(shared), StatusCode::duplicate_identity);

  // A branch whose PDU does not exist is refused.
  BranchDefinition orphan;
  orphan.id = BranchId::parse("branch-orphan").value();
  orphan.pdu = PduId::parse("no-such-pdu").value();
  orphan.generation = BranchGeneration::from(1);
  orphan.lifecycle = LifecycleState::active;
  orphan.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_branch(orphan), StatusCode::not_found);

  // Definitions are validated: no identifier, no generation, no instant.
  PduDefinition shapeless;
  PDU_REQUIRE_STATUS(engine.register_pdu(shapeless), StatusCode::invalid_argument);
  shapeless.id = PduId::parse("pdu-shapeless").value();
  PDU_REQUIRE_STATUS(engine.register_pdu(shapeless), StatusCode::invalid_argument);
  shapeless.generation = PduGeneration::from(1);
  PDU_REQUIRE_STATUS(engine.register_pdu(shapeless), StatusCode::invalid_argument);
  shapeless.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_pdu(shapeless), StatusCode::capacity_exhausted);
}

PDU_TEST(adversarial, interlock_declarations_are_bounded_and_validated) {
  EngineOptions options = pdu_test::base_options();
  options.bounds.max_required_interlocks_per_branch = 2;
  PduControlEngine engine = PDU_REQUIRE_OK(PduControlEngine::in_memory(options));
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(1)), StatusCode::ok);
  PduDefinition pdu;
  pdu.id = PduId::parse("pdu-i").value();
  pdu.generation = PduGeneration::from(1);
  pdu.lifecycle = LifecycleState::active;
  pdu.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_pdu(pdu), StatusCode::ok);
  BranchDefinition branch;
  branch.id = BranchId::parse("branch-i").value();
  branch.pdu = pdu.id;
  branch.generation = BranchGeneration::from(1);
  branch.lifecycle = LifecycleState::active;
  branch.registered_at = LogicalTick::from(1);
  branch.required_interlocks = {InterlockId::parse("i1").value(), InterlockId::parse("i2").value(),
                                InterlockId::parse("i3").value()};
  PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::capacity_exhausted);
  branch.required_interlocks = {InterlockId::parse("i1").value(), InterlockId::parse("i1").value()};
  PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::duplicate_identity);
  branch.required_interlocks = {InterlockId::unset()};
  PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::invalid_argument);
  branch.required_interlocks.clear();
  PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::ok);

  InterlockDeclaration declaration;
  PDU_REQUIRE_STATUS(engine.declare_interlock(declaration), StatusCode::invalid_argument);
  declaration.id = InterlockId::parse("i1").value();
  declaration.pdu = pdu.id;
  declaration.branch = branch.id;
  declaration.epoch = AuthorityEpoch::from(1);
  declaration.declared_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.declare_interlock(declaration), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.declare_interlock(declaration), StatusCode::duplicate_identity);
  declaration.id = InterlockId::parse("i2").value();
  declaration.branch = BranchId::parse("branch-missing").value();
  PDU_REQUIRE_STATUS(engine.declare_interlock(declaration), StatusCode::not_found);

  InterlockStatus report;
  report.id = InterlockId::parse("i1").value();
  report.state = InterlockState::satisfied;
  report.epoch = AuthorityEpoch::from(1);
  report.updated_at = LogicalTick::from(5);
  PDU_REQUIRE_STATUS(engine.report_interlock(report), StatusCode::ok);
  // An out-of-order report is refused rather than allowed to walk the obligation
  // backwards.
  report.updated_at = LogicalTick::from(4);
  PDU_REQUIRE_STATUS(engine.report_interlock(report), StatusCode::evidence_stale);
  // A report from another epoch cannot make an obligation current.
  report.epoch = AuthorityEpoch::from(2);
  report.updated_at = LogicalTick::from(6);
  PDU_REQUIRE_STATUS(engine.report_interlock(report), StatusCode::permission_stale);
}

PDU_TEST(adversarial, store_field_attacks_are_refused) {
  const auto attack = [](const std::string& name,
                         const std::function<void(std::vector<std::uint8_t>&)>& mutate,
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
    PDU_CHECK_EQ(bytes.size(), store_file_bytes);
    mutate(bytes);
    PDU_REQUIRE_STATUS(write_all(store, bytes), StatusCode::ok);
    const auto reopened =
        PduControlEngine::open(store, OpenMode::open_existing, pdu_test::base_options());
    PDU_CHECK_MSG(!reopened.ok(), std::string("attack ") + name + " was not refused");
    if (!reopened.ok()) {
      PDU_CHECK_EQ(reopened.status().code(), expected);
    }
  };

  // A payload length field that disagrees with the head record.
  attack("slot-length",
         [](std::vector<std::uint8_t>& bytes) {
           const std::size_t slot = committed_slot_base(bytes);
           put_u32(bytes, slot + 40, 4096);
           fix_slot_header_crc(bytes, slot);
         },
         StatusCode::store_malformed);
  // A slot that names another generation.
  attack("slot-generation",
         [](std::vector<std::uint8_t>& bytes) {
           const std::size_t slot = committed_slot_base(bytes);
           for (std::size_t index = 0; index < 8; ++index) {
             bytes[slot + 16 + index] = static_cast<std::uint8_t>(index == 0 ? 9 : 0);
           }
           fix_slot_header_crc(bytes, slot);
         },
         StatusCode::store_malformed);
  // A head record that names a slot which does not exist.
  attack("head-slot-index",
         [](std::vector<std::uint8_t>& bytes) {
           put_u32(bytes, 48, 7);
           fix_head_crc(bytes, 0);
         },
         StatusCode::store_malformed);
  // A head record whose payload length is absurd.
  attack("head-payload-length",
         [](std::vector<std::uint8_t>& bytes) {
           put_u32(bytes, 52, 0xFFFFFFFFU);
           fix_head_crc(bytes, 0);
         },
         StatusCode::store_oversized);
  // A payload envelope that declares a body longer than the record.
  attack("envelope-length",
         [](std::vector<std::uint8_t>& bytes) {
           const std::size_t payload = committed_slot_base(bytes) + store_slot_header_bytes;
           put_u32(bytes, payload + 8 + 4 + 8 + 8, 0x00FFFFFFU);
         },
         StatusCode::store_malformed);
  // A payload envelope whose magic is wrong.
  attack("envelope-magic",
         [](std::vector<std::uint8_t>& bytes) {
           const std::size_t payload = committed_slot_base(bytes) + store_slot_header_bytes;
           bytes[payload] = static_cast<std::uint8_t>('Z');
         },
         StatusCode::store_malformed);
  // A payload whose declared generation disagrees with the slot header.
  attack("envelope-generation",
         [](std::vector<std::uint8_t>& bytes) {
           const std::size_t payload = committed_slot_base(bytes) + store_slot_header_bytes;
           for (std::size_t index = 0; index < 8; ++index) {
             bytes[payload + 12 + index] = static_cast<std::uint8_t>(index == 0 ? 42 : 0);
           }
         },
         StatusCode::store_malformed);
  // A body byte that the encoder never produced.
  attack("body-truncated",
         [](std::vector<std::uint8_t>& bytes) {
           const std::size_t payload = committed_slot_base(bytes) + store_slot_header_bytes;
           bytes[payload + 8 + 4 + 8 + 8 + 4] = 0x7F;
         },
         StatusCode::store_malformed);
}

PDU_TEST(adversarial, a_grant_and_an_override_cannot_be_widened_after_the_fact) {
  pdu_test::TempDir directory("adversarial-widen");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("widen", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  // A second grant for a scope that does not exist cannot be recorded.
  PermissionGrant stray;
  stray.id = AuthorityId::parse("grant-stray").value();
  stray.issuer = scenario.issuer;
  stray.epoch = scenario.epoch;
  stray.pdu = scenario.pdu;
  stray.branch = BranchId::parse("not-a-branch").value();
  stray.pdu_generation = scenario.pdu_generation;
  stray.branch_generation = scenario.branch_generation;
  stray.actions = action_mask(PermissionAction::control_energize);
  stray.issued_at = LogicalTick::from(1);
  // The grant is syntactically valid; it simply never matches any branch, so it
  // grants nothing.
  PDU_REQUIRE_STATUS(engine.record_grant(stray), StatusCode::ok);
  // A grant issued in the future cannot exist.
  PermissionGrant future = stray;
  future.id = AuthorityId::parse("grant-future").value();
  future.branch = scenario.branch;
  future.epoch = AuthorityEpoch::from(50);
  PDU_REQUIRE_STATUS(engine.record_grant(future), StatusCode::invalid_argument);
  // Revoking in another epoch is refused.
  PDU_REQUIRE_STATUS(engine.revoke_grant(scenario.grant, AuthorityEpoch::from(9), LogicalTick::from(2)),
                     StatusCode::permission_stale);
  PDU_REQUIRE_STATUS(engine.revoke_grant(AuthorityId::parse("ghost").value(), scenario.epoch,
                                         LogicalTick::from(2)),
                     StatusCode::not_found);
  // An override for the wrong generation is recorded but never usable.
  MaintenanceOverride override_value;
  override_value.id = AuthorityId::parse("override-stale").value();
  override_value.issuer = scenario.issuer;
  override_value.epoch = scenario.epoch;
  override_value.pdu = scenario.pdu;
  override_value.branch = scenario.branch;
  override_value.pdu_generation = PduGeneration::from(9);
  override_value.branch_generation = scenario.branch_generation;
  override_value.issued_at = LogicalTick::from(1);
  override_value.not_after = LogicalTick::from(99);
  PDU_REQUIRE_STATUS(engine.record_maintenance_override(override_value), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.record_maintenance_override(override_value), StatusCode::duplicate_identity);
  MaintenanceOverride malformed = override_value;
  malformed.id = AuthorityId::parse("override-malformed").value();
  malformed.not_after = malformed.issued_at;
  PDU_REQUIRE_STATUS(engine.record_maintenance_override(malformed), StatusCode::invalid_argument);
  PDU_REQUIRE_STATUS(engine.revoke_maintenance_override(override_value.id, scenario.epoch,
                                                        LogicalTick::from(2)),
                     StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.revoke_maintenance_override(override_value.id, scenario.epoch,
                                                        LogicalTick::from(3)),
                     StatusCode::duplicate_identity);
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
}

PDU_TEST(adversarial, an_in_memory_engine_refuses_every_operation_after_close) {
  PduControlEngine engine = PDU_REQUIRE_OK(PduControlEngine::in_memory(pdu_test::base_options()));
  PDU_CHECK(engine.is_open());
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(1)), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  PDU_CHECK(!engine.is_open());
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(5)), StatusCode::store_io);
  PDU_REQUIRE_STATUS(engine.flush(), StatusCode::store_io);
  PduDefinition pdu;
  pdu.id = PduId::parse("pdu-closed").value();
  pdu.generation = PduGeneration::from(1);
  pdu.lifecycle = LifecycleState::active;
  pdu.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_pdu(pdu), StatusCode::store_io);
}
