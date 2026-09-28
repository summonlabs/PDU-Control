#include "fixture.hpp"
#include "test_harness.hpp"

#include <cstdint>
#include <random>
#include <string>
#include <vector>

using namespace pdu_control;

namespace {

BranchControlRequest request_for(const pdu_test::Scenario& scenario, CommandIntent intent,
                                 const std::string& key, LogicalTick tick) {
  BranchControlRequest request;
  request.key = IdempotencyKey::parse(key).value();
  request.pdu = scenario.pdu;
  request.branch = scenario.branch;
  request.pdu_generation = scenario.pdu_generation;
  request.branch_generation = scenario.branch_generation;
  request.epoch = scenario.epoch;
  request.intent = intent;
  request.actor = ActorId::parse("prover").value();
  request.requested_at = tick;
  return request;
}

SyntheticPduAdapter adapter_for(const pdu_test::Scenario& scenario, SyntheticMode mode) {
  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("property-adapter").value();
  config.vendor = IssuerId::parse("test").value();
  config.model = "synthetic";
  config.firmware = "0";
  config.pdu = scenario.pdu;
  config.branch = scenario.branch;
  config.pdu_generation = scenario.pdu_generation;
  config.branch_generation = scenario.branch_generation;
  config.mode = mode;
  config.initial_condition = BranchCondition::de_energized;
  config.reading_taken_at = Instant::logical(LogicalTick::from(1));
  config.reading_tick_step = LogicalTick::from(1);
  config.read_at_request_instant = true;
  return SyntheticPduAdapter(config);
}

/// An independent reference model of the control gate.
///
/// It is written from the documented rules rather than from the engine's code,
/// so a disagreement means one of the two is wrong.
enum class Gate { allowed, forbidden_lifecycle, unresolved, stale_generation, stale_epoch, no_permission, interlock };

Gate reference_gate(LifecycleState pdu_lifecycle, LifecycleState branch_lifecycle,
                    bool has_override, bool unresolved, bool generation_current,
                    bool epoch_current, bool permission_current, InterlockState interlock) {
  if (control_scope(pdu_lifecycle) == ControlScope::forbidden ||
      control_scope(branch_lifecycle) == ControlScope::forbidden) {
    return Gate::forbidden_lifecycle;
  }
  if ((control_scope(pdu_lifecycle) == ControlScope::maintenance_override ||
       control_scope(branch_lifecycle) == ControlScope::maintenance_override) &&
      !has_override) {
    return Gate::no_permission;
  }
  if (unresolved) {
    return Gate::unresolved;
  }
  if (!generation_current) {
    return Gate::stale_generation;
  }
  if (!epoch_current) {
    return Gate::stale_epoch;
  }
  if (!permission_current) {
    return Gate::no_permission;
  }
  if (interlock == InterlockState::open) {
    return Gate::interlock;
  }
  if (interlock == InterlockState::unknown) {
    return Gate::interlock;
  }
  return Gate::allowed;
}

std::string invariant_failure;

void require_invariant(bool condition, const std::string& description) {
  if (!condition && invariant_failure.empty()) {
    invariant_failure = description;
  }
}

std::uint64_t run_script(std::uint64_t seed, std::string& canonical) {
  pdu_test::TempDir directory("property-" + std::to_string(seed));
  const pdu_test::Scenario scenario = pdu_test::make_scenario("prop", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                       pdu_test::base_options());
  if (!opened.ok()) {
    return 0;
  }
  PduControlEngine& engine = opened.value();
  if (!pdu_test::apply_scenario(engine, scenario).ok()) {
    return 0;
  }
  SyntheticPduAdapter adapter = adapter_for(scenario, SyntheticMode::honor);
  std::mt19937_64 random(seed);
  std::uint64_t dispatched = 0;
  std::uint64_t refusals = 0;
  LogicalTick tick = LogicalTick::from(2);
  std::size_t unresolved_seen = 0;
  for (int step = 0; step < 400; ++step) {
    const std::uint64_t choice = random() % 6;
    switch (choice) {
      case 0: {
        const LogicalTick next = LogicalTick::from(tick.value() + 1 + random() % 3);
        if (engine.advance_tick(next).ok()) {
          tick = next;
        }
        break;
      }
      case 1: {
        TelemetryObservation observation = pdu_test::make_observation(
            scenario, tick, 2 + (random() % 1000),
            (random() % 2) == 0 ? BranchCondition::energized : BranchCondition::de_energized,
            (random() % 4) == 0 ? EvidenceQuality::suspect : EvidenceQuality::good);
        (void)engine.record_observation(observation);
        break;
      }
      case 2:
      case 3: {
        const CommandIntent intent =
            (random() % 2) == 0 ? CommandIntent::energize : CommandIntent::de_energize;
        const std::string key = "key-" + std::to_string(step % 5);
        const auto issued =
            engine.issue(request_for(scenario, intent, key, tick), adapter);
        if (issued.ok()) {
          if (!PDU_REQUIRE_OK(issued).replayed) {
            dispatched += 1;
          }
          if (random() % 2 == 0) {
            (void)engine.verify_with_adapter(PDU_REQUIRE_OK(issued).id, adapter);
          }
        } else {
          refusals += 1;
        }
        break;
      }
      case 4: {
        InterlockStatus status;
        status.id = scenario.interlock;
        status.epoch = scenario.epoch;
        status.updated_at = tick;
        const std::uint64_t pick = random() % 3;
        status.state = pick == 0 ? InterlockState::satisfied
                                 : (pick == 1 ? InterlockState::open : InterlockState::unknown);
        (void)engine.report_interlock(status);
        break;
      }
      default: {
        const auto attempts = engine.attempts(0);
        for (const AttemptRecord& record : attempts) {
          require_invariant(!record.dispatched || record.authorization.complete_for_control(),
                            "a dispatched attempt carried an incomplete precondition mask");
        }
        // An engine may only hold state the durable decoder would accept.
        require_invariant(engine.flush().ok(),
                          "the engine could not publish state the decoder would accept");
        break;
      }
    }
    const EngineStatus status = engine.status();
    {
      // The two views of the same fact must agree after every single step: an
      // attempt whose effect is not established blocks its branch, and a branch
      // that is blocked has such an attempt.
      const auto consistency = engine.inspect_branch(scenario.pdu, scenario.branch);
      require_invariant(
          status.unresolved_attempt_count == 0 ||
              (consistency.ok() && consistency.value().unresolved_attempt),
          "step " + std::to_string(step) + " choice " + std::to_string(choice) +
              " left an unresolved attempt with a clear branch flag");
    }
    if (status.unresolved_attempt_count > 0) {
      unresolved_seen += 1;
      // While an attempt is unresolved, no new attempt may be accepted with a
      // different key.
      const std::size_t before = adapter.execute_count();
      const auto blocked = engine.issue(
          request_for(scenario, CommandIntent::energize, "probe-key", tick), adapter);
      const auto pre_state = engine.inspect_branch(scenario.pdu, scenario.branch);
      const bool pre_flag = pre_state.ok() && pre_state.value().unresolved_attempt;
      const auto pre_journal = engine.attempts(0);
      std::string pre_open;
      for (const AttemptRecord& entry : pre_journal) {
        if (!is_unresolved(entry.outcome)) {
          continue;
        }
        pre_open.append(std::to_string(entry.id.value()));
        pre_open.push_back('(');
        pre_open.append(to_token(entry.outcome));
        pre_open.append(entry.applied_command ? ",applied" : ",no-apply");
        pre_open.push_back(')');
        pre_open.push_back(' ');
      }
      require_invariant(status.unresolved_attempt_count == 0 || pre_flag,
                        "the branch flag disagreed with the unresolved attempt count: count=" +
                            std::to_string(status.unresolved_attempt_count) + " flag=" +
                            (pre_flag ? "set" : "clear") + " state-ok=" +
                            (pre_state.ok() ? "yes" : "no") + " open=" + pre_open);
      const bool answered_with_a_replay = blocked.ok() && blocked.value().replayed;
      require_invariant(!blocked.ok() || answered_with_a_replay,
                        "a new command was accepted while an attempt had no established effect: "
                        "the unresolved count was " +
                            std::to_string(status.unresolved_attempt_count) +
                            ", the command answered " + std::string(to_token(blocked.code())) +
                            ", adapter calls " +
                            std::to_string(adapter.execute_count() - before));
      require_invariant(adapter.execute_count() == before,
                        "a refused command reached the adapter");
    }
    require_invariant(status.idempotency_entries <= engine.options().idempotency_window,
                      "the idempotency window grew past its bound");
  }
  require_invariant(adapter.execute_count() == dispatched,
                    "the number of adapter invocations did not match the number of dispatches");
  require_invariant(refusals > 0, "the script produced no refusals at all");
  require_invariant(unresolved_seen > 0, "the script never left an attempt unresolved");
  canonical = engine.canonical_state();
  const std::uint64_t digest = engine.state_digest().value();
  (void)engine.close();
  return digest;
}

}  // namespace

PDU_TEST(property, the_randomized_state_machine_holds_its_invariants) {
  for (std::uint64_t seed : {std::uint64_t{1}, std::uint64_t{7}, std::uint64_t{1234},
                             std::uint64_t{987654321}}) {
    std::string text;
    invariant_failure.clear();
    (void)run_script(seed, text);
    PDU_CHECK_MSG(invariant_failure.empty(),
                  "seed " + std::to_string(seed) + " violated an invariant: " + invariant_failure);
    PDU_CHECK(!text.empty());
  }
}

PDU_TEST(property, the_same_logical_script_produces_the_same_canonical_state) {
  std::string first_text;
  std::string second_text;
  invariant_failure.clear();
  const std::uint64_t first = run_script(4242, first_text);
  const std::string first_failure = invariant_failure;
  invariant_failure.clear();
  const std::uint64_t second = run_script(4242, second_text);
  PDU_CHECK_MSG(first_failure.empty(), "first run violated an invariant: " + first_failure);
  PDU_CHECK_MSG(invariant_failure.empty(), "second run violated an invariant: " + invariant_failure);
  PDU_CHECK_EQ(first, second);
  PDU_CHECK_EQ(first_text, second_text);
}

PDU_TEST(property, the_engine_agrees_with_the_reference_gate) {
  const LifecycleState lifecycles[] = {
      LifecycleState::provisioned, LifecycleState::active, LifecycleState::maintenance,
      LifecycleState::degraded,    LifecycleState::isolated, LifecycleState::faulted,
      LifecycleState::retired};
  for (const LifecycleState branch_lifecycle : lifecycles) {
    for (const LifecycleState pdu_lifecycle : lifecycles) {
      pdu_test::TempDir directory(std::string("gate-") + std::string(to_token(branch_lifecycle)) +
                                  "-" + std::string(to_token(pdu_lifecycle)));
      const pdu_test::Scenario scenario = pdu_test::make_scenario("gate", 1);
      auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                           pdu_test::base_options());
      PDU_REQUIRE_STATUS(opened, StatusCode::ok);
      PduControlEngine& engine = opened.value();
      PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario, branch_lifecycle),
                         StatusCode::ok);
      // The PDU lifecycle is moved by a direct transition where the table allows
      // it; where it does not, the scenario is skipped rather than forced.
      if (pdu_lifecycle != LifecycleState::active) {
        const auto pdu_snapshot = engine.inspect_pdu(scenario.pdu);
        PDU_REQUIRE_STATUS(pdu_snapshot, StatusCode::ok);
        LifecycleRequest move;
        move.pdu = scenario.pdu;
        move.pdu_generation = scenario.pdu_generation;
        move.planned_revision = PDU_REQUIRE_OK(pdu_snapshot).revision;
        move.epoch = scenario.epoch;
        move.to = pdu_lifecycle;
        move.actor = ActorId::parse("prover").value();
        move.requested_at = LogicalTick::from(2);
        if (!engine.transition_lifecycle(move).ok()) {
          continue;
        }
      }
      const auto decision =
          engine.evaluate(request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(2)));
      const Gate expected = reference_gate(pdu_lifecycle, branch_lifecycle, false, false, true, true,
                                           true, InterlockState::satisfied);
      if (expected == Gate::allowed) {
        PDU_CHECK_MSG(PDU_REQUIRE_OK(decision).eligible,
                      std::string("engine refused a state the reference model allows: ") +
                          std::string(to_token(branch_lifecycle)) + "/" +
                          std::string(to_token(pdu_lifecycle)));
      } else {
        PDU_CHECK_MSG(!PDU_REQUIRE_OK(decision).eligible,
                      std::string("engine allowed a state the reference model refuses: ") +
                          std::string(to_token(branch_lifecycle)) + "/" +
                          std::string(to_token(pdu_lifecycle)));
      }
      PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
    }
  }
}

PDU_TEST(property, interlock_states_map_to_the_documented_verdicts) {
  const InterlockState states[] = {InterlockState::satisfied, InterlockState::open,
                                   InterlockState::unknown};
  for (const InterlockState interlock : states) {
    pdu_test::TempDir directory(std::string("interlock-") + std::string(to_token(interlock)));
    const pdu_test::Scenario scenario = pdu_test::make_scenario("interlock", 1);
    auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new,
                                         pdu_test::base_options());
    PDU_REQUIRE_STATUS(opened, StatusCode::ok);
    PduControlEngine& engine = opened.value();
    PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
    InterlockStatus status;
    status.id = scenario.interlock;
    status.state = interlock;
    status.epoch = scenario.epoch;
    status.updated_at = LogicalTick::from(2);
    PDU_REQUIRE_STATUS(engine.report_interlock(status), StatusCode::ok);
    const auto decision =
        engine.evaluate(request_for(scenario, CommandIntent::energize, "k", LogicalTick::from(2)));
    const Gate expected = reference_gate(LifecycleState::active, LifecycleState::active, false, false,
                                         true, true, true, interlock);
    PDU_CHECK_EQ(PDU_REQUIRE_OK(decision).eligible, expected == Gate::allowed);
    PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
  }
}

PDU_TEST(property, the_audit_trail_is_bounded_and_reports_what_it_dropped) {
  EngineOptions options = pdu_test::base_options();
  options.audit_capacity = 16;
  pdu_test::TempDir directory("property-audit-bound");
  const pdu_test::Scenario scenario = pdu_test::make_scenario("auditbound", 1);
  auto opened = PduControlEngine::open(directory.store_path(), OpenMode::create_new, options);
  PDU_REQUIRE_STATUS(opened, StatusCode::ok);
  PduControlEngine& engine = opened.value();
  PDU_REQUIRE_STATUS(pdu_test::apply_scenario(engine, scenario), StatusCode::ok);
  for (std::uint64_t index = 0; index < 40; ++index) {
    PDU_REQUIRE_STATUS(engine.advance_tick(LogicalTick::from(10 + index)), StatusCode::ok);
  }
  const EngineStatus status = engine.status();
  PDU_CHECK(status.audit_entries <= std::size_t{16});
  PDU_CHECK(status.audit_dropped > 0);
  HistoryQuery query;
  query.limit = 1000;
  const auto history = engine.history(query);
  PDU_CHECK(history.size() <= std::size_t{16});
  // Newest first, so the sequence numbers strictly decrease.
  for (std::size_t index = 1; index < history.size(); ++index) {
    PDU_CHECK(history[index - 1].sequence > history[index].sequence);
  }
  query.has_kind = true;
  query.kind = AuditKind::tick_advanced;
  const auto filtered = engine.history(query);
  PDU_CHECK(!filtered.empty());
  for (const AuditEntry& entry : filtered) {
    PDU_CHECK_EQ(entry.kind, AuditKind::tick_advanced);
  }
  PDU_REQUIRE_STATUS(engine.close(), StatusCode::ok);
}
