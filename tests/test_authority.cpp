#include "fixture.hpp"
#include "test_harness.hpp"

using namespace pdu_control;

namespace {

BranchControlRequest make_request(const pdu_test::Scenario& scenario, CommandIntent intent,
                                  const std::string& key, LogicalTick tick) {
  BranchControlRequest request;
  request.key = IdempotencyKey::parse(key).value();
  request.pdu = scenario.pdu;
  request.branch = scenario.branch;
  request.pdu_generation = scenario.pdu_generation;
  request.branch_generation = scenario.branch_generation;
  request.epoch = scenario.epoch;
  request.intent = intent;
  request.actor = ActorId::parse("tester").value();
  request.requested_at = tick;
  return request;
}

}  // namespace

PDU_TEST(authority, grant_shape_is_validated) {
  PermissionGrant grant;
  PDU_REQUIRE_STATUS(validate_grant(grant), StatusCode::invalid_argument);
  grant.id = AuthorityId::parse("grant-1").value();
  grant.issuer = IssuerId::parse("issuer").value();
  grant.epoch = AuthorityEpoch::from(1);
  grant.pdu = PduId::parse("pdu").value();
  grant.branch = BranchId::parse("branch").value();
  grant.pdu_generation = PduGeneration::from(1);
  grant.branch_generation = BranchGeneration::from(1);
  grant.actions = action_mask(PermissionAction::control_energize);
  grant.issued_at = LogicalTick::from(5);
  PDU_CHECK(validate_grant(grant).ok());
  grant.not_after = LogicalTick::from(5);
  PDU_REQUIRE_STATUS(validate_grant(grant), StatusCode::invalid_argument);
  grant.not_after = LogicalTick::from(6);
  PDU_CHECK(validate_grant(grant).ok());
  grant.actions = 0;
  PDU_REQUIRE_STATUS(validate_grant(grant), StatusCode::invalid_argument);
}

PDU_TEST(authority, verdicts_map_to_distinct_status_codes) {
  PDU_CHECK_EQ(status_for(PermissionVerdict::usable), StatusCode::ok);
  PDU_CHECK_EQ(status_for(PermissionVerdict::missing), StatusCode::permission_missing);
  PDU_CHECK_EQ(status_for(PermissionVerdict::expired), StatusCode::permission_stale);
  PDU_CHECK_EQ(status_for(PermissionVerdict::revoked), StatusCode::permission_stale);
  PDU_CHECK_EQ(status_for(PermissionVerdict::stale_epoch), StatusCode::permission_stale);
  PDU_CHECK_EQ(status_for(PermissionVerdict::scope_mismatch), StatusCode::permission_scope_mismatch);
  PDU_CHECK_EQ(status_for(PermissionVerdict::generation_mismatch), StatusCode::permission_scope_mismatch);
  PDU_CHECK_EQ(status_for(PermissionVerdict::action_missing), StatusCode::permission_denied);
  PDU_CHECK_EQ(status_for(OverrideVerdict::usable), StatusCode::ok);
  PDU_CHECK_EQ(status_for(OverrideVerdict::missing), StatusCode::permission_missing);
}

PDU_TEST(authority, an_existing_grant_is_not_permission_by_itself) {
  pdu_test::TempDir directory("authority-verdicts");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("verdicts", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);

  const LogicalTick tick = LogicalTick::from(4);
  PDU_REQUIRE_STATUS(engine.advance_tick(tick), StatusCode::ok);
  const auto eligible = engine.evaluate(make_request(scenario, CommandIntent::energize, "k1", tick));
  PDU_CHECK(PDU_REQUIRE_OK(eligible).eligible);

  // An epoch advance makes the existing grant stale without removing it.
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(2)), StatusCode::ok);
  const auto stale_epoch = engine.evaluate(make_request(scenario, CommandIntent::energize, "k2", tick));
  PDU_CHECK(!PDU_REQUIRE_OK(stale_epoch).eligible);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(stale_epoch).code, StatusCode::permission_stale);
  // The documented precedence checks the authority epoch before the grants, so
  // the primary reason is the epoch and the trace says so.
  PDU_CHECK_EQ(PDU_REQUIRE_OK(stale_epoch).trace.back().kind, PreconditionKind::authority_epoch);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(stale_epoch).trace.back().code, StatusCode::permission_stale);
}

PDU_TEST(authority, revoked_and_expired_grants_are_refused) {
  {
    pdu_test::TempDir directory("authority-revoked");
    const pdu_test::Scenario scenario = pdu_test::make_scenario("revoked", 1);
    auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                         pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(3)), StatusCode::ok);
    PDU_REQUIRE_STATUS(engine.revoke_grant(scenario.grant, scenario.epoch, LogicalTick::from(3)),
                       StatusCode::ok);
    const LogicalTick tick = LogicalTick::from(4);
    PDU_REQUIRE_STATUS(engine.advance_tick(tick), StatusCode::ok);
    const auto decision = engine.evaluate(make_request(scenario, CommandIntent::energize, "k", tick));
    PDU_CHECK(!PDU_REQUIRE_OK(decision).eligible);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::permission_stale);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).permission, PermissionVerdict::revoked);
  }
  {
    pdu_test::TempDir directory("authority-expired");
    const pdu_test::Scenario scenario = pdu_test::make_scenario("expired", 1);
    auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                         pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
    PermissionGrant expiring;
    expiring.id = AuthorityId::parse("grant-expiring").value();
    expiring.issuer = scenario.issuer;
    expiring.epoch = scenario.epoch;
    expiring.pdu = scenario.pdu;
    expiring.branch = scenario.branch;
    expiring.pdu_generation = scenario.pdu_generation;
    expiring.branch_generation = scenario.branch_generation;
    expiring.actions = action_mask(PermissionAction::control_energize);
    expiring.issued_at = LogicalTick::from(1);
    expiring.not_after = LogicalTick::from(5);
    PDU_REQUIRE_STATUS(engine.record_grant(expiring), StatusCode::ok);
    // The grant that never expires is revoked so that the expiring one is the
    // only candidate left.
    PDU_REQUIRE_STATUS(engine.revoke_grant(scenario.grant, scenario.epoch, LogicalTick::from(2)),
                       StatusCode::ok);
    const LogicalTick tick = LogicalTick::from(5);
    PDU_REQUIRE_STATUS(engine.advance_tick(tick), StatusCode::ok);
    const auto decision = engine.evaluate(make_request(scenario, CommandIntent::energize, "k", tick));
    PDU_CHECK(!PDU_REQUIRE_OK(decision).eligible);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::permission_stale);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).permission, PermissionVerdict::expired);
  }
}

PDU_TEST(authority, interlocks_fail_closed) {
  pdu_test::TempDir directory("authority-interlocks");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("interlocks", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  const LogicalTick tick = LogicalTick::from(4);
  PDU_REQUIRE_STATUS(engine.advance_tick(tick), StatusCode::ok);

  // An interlock reported open blocks control.
  InterlockStatus open;
  open.id = scenario.interlock;
  open.state = InterlockState::open;
  open.epoch = scenario.epoch;
  open.updated_at = LogicalTick::from(4);
  PDU_REQUIRE_STATUS(engine.report_interlock(open), StatusCode::ok);
  auto decision = engine.evaluate(make_request(scenario, CommandIntent::energize, "k1", tick));
  PDU_CHECK(!PDU_REQUIRE_OK(decision).eligible);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::interlock_open);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).interlocks.verdict, InterlockVerdict::blocked);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).interlocks.deciding, scenario.interlock);

  // An interlock reported unknown fails closed as unknown, not as satisfied.
  InterlockStatus unknown;
  unknown.id = scenario.interlock;
  unknown.state = InterlockState::unknown;
  unknown.epoch = scenario.epoch;
  unknown.updated_at = LogicalTick::from(5);
  PDU_REQUIRE_STATUS(engine.report_interlock(unknown), StatusCode::ok);
  decision = engine.evaluate(make_request(scenario, CommandIntent::energize, "k2", tick));
  PDU_CHECK(!PDU_REQUIRE_OK(decision).eligible);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::interlock_unknown);

  // A report from another epoch does not count as current.
  InterlockStatus satisfied;
  satisfied.id = scenario.interlock;
  satisfied.state = InterlockState::satisfied;
  satisfied.epoch = scenario.epoch;
  satisfied.updated_at = LogicalTick::from(6);
  PDU_REQUIRE_STATUS(engine.report_interlock(satisfied), StatusCode::ok);
  // Moving the epoch makes the interlock report stale. A grant is issued in the
  // new epoch so that the interlock is what the decision turns on rather than
  // the epoch itself.
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(2)), StatusCode::ok);
  PermissionGrant renewed = PermissionGrant{};
  renewed.id = AuthorityId::parse("grant-renewed").value();
  renewed.issuer = scenario.issuer;
  renewed.epoch = AuthorityEpoch::from(2);
  renewed.pdu = scenario.pdu;
  renewed.branch = scenario.branch;
  renewed.pdu_generation = scenario.pdu_generation;
  renewed.branch_generation = scenario.branch_generation;
  renewed.actions = action_mask(PermissionAction::control_energize);
  renewed.issued_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.record_grant(renewed), StatusCode::ok);
  BranchControlRequest current = make_request(scenario, CommandIntent::energize, "k3", tick);
  current.epoch = AuthorityEpoch::from(2);
  decision = engine.evaluate(current);
  PDU_CHECK(!PDU_REQUIRE_OK(decision).eligible);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::interlock_unknown);
  PDU_CHECK(PDU_REQUIRE_OK(decision).interlocks.has_deciding);
}

PDU_TEST(authority, an_undeclared_required_interlock_fails_closed) {
  // A branch that requires an interlock nobody ever declared cannot be
  // controlled, and the refusal names the obligation.
  pdu_test::TempDir directory("authority-undeclared");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("undeclared", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(scenario.epoch), StatusCode::ok);
  PduDefinition pdu;
  pdu.id = scenario.pdu;
  pdu.generation = scenario.pdu_generation;
  pdu.lifecycle = LifecycleState::active;
  pdu.registered_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.register_pdu(pdu), StatusCode::ok);
  BranchDefinition branch;
  branch.id = scenario.branch;
  branch.pdu = scenario.pdu;
  branch.generation = scenario.branch_generation;
  branch.lifecycle = LifecycleState::active;
  branch.registered_at = LogicalTick::from(1);
  branch.required_interlocks.push_back(InterlockId::parse("never-declared").value());
  PDU_REQUIRE_STATUS(engine.register_branch(branch), StatusCode::ok);
  PermissionGrant grant;
  grant.id = AuthorityId::parse("g").value();
  grant.issuer = IssuerId::parse("issuer").value();
  grant.epoch = scenario.epoch;
  grant.pdu = scenario.pdu;
  grant.branch = scenario.branch;
  grant.pdu_generation = scenario.pdu_generation;
  grant.branch_generation = scenario.branch_generation;
  grant.actions = action_mask(PermissionAction::control_energize);
  grant.issued_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(engine.record_grant(grant), StatusCode::ok);
  const auto decision =
      engine.evaluate(make_request(scenario, CommandIntent::energize, "k", LogicalTick::from(1)));
  PDU_CHECK(!PDU_REQUIRE_OK(decision).eligible);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).code, StatusCode::interlock_unknown);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).interlocks.deciding,
               InterlockId::parse("never-declared").value());
}

PDU_TEST(authority, epoch_can_only_move_forward) {
  auto engine = PDU_REQUIRE_OK(PduControlEngine::in_memory(pdu_test::base_options()));
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::unset()), StatusCode::invalid_argument);
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(2)), StatusCode::ok);
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(2)), StatusCode::permission_stale);
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(1)), StatusCode::permission_stale);
  PDU_REQUIRE_STATUS(engine.adopt_authority_epoch(AuthorityEpoch::from(3)), StatusCode::ok);
  // Without an adopted epoch, a grant cannot be recorded at all.
  auto empty = PDU_REQUIRE_OK(PduControlEngine::in_memory(pdu_test::base_options()));
  PermissionGrant grant;
  grant.id = AuthorityId::parse("g").value();
  grant.issuer = IssuerId::parse("i").value();
  grant.epoch = AuthorityEpoch::from(1);
  grant.pdu = PduId::parse("p").value();
  grant.branch = BranchId::parse("b").value();
  grant.pdu_generation = PduGeneration::from(1);
  grant.branch_generation = BranchGeneration::from(1);
  grant.actions = action_mask(PermissionAction::control_energize);
  grant.issued_at = LogicalTick::from(1);
  PDU_REQUIRE_STATUS(empty.record_grant(grant), StatusCode::invalid_argument);
}
