#include "test_harness.hpp"

using namespace pdu_control;

PDU_TEST(lifecycle, table_is_the_whole_surface) {
  PDU_CHECK(transition_table_size() == 23);
  PDU_CHECK(is_declared_transition(LifecycleState::provisioned, LifecycleState::active));
  PDU_CHECK(is_declared_transition(LifecycleState::isolated, LifecycleState::active));
  PDU_CHECK(is_declared_transition(LifecycleState::faulted, LifecycleState::maintenance));
  PDU_CHECK(!is_declared_transition(LifecycleState::retired, LifecycleState::active));
  PDU_CHECK(!is_declared_transition(LifecycleState::provisioned, LifecycleState::isolated));
  PDU_CHECK(!is_declared_transition(LifecycleState::active, LifecycleState::active));
  // Every state except retired has at least one outgoing transition.
  for (const LifecycleState state : {LifecycleState::provisioned, LifecycleState::active,
                                     LifecycleState::maintenance, LifecycleState::degraded,
                                     LifecycleState::isolated, LifecycleState::faulted}) {
    bool found = false;
    for (std::size_t index = 0; index < transition_table_size(); ++index) {
      if (transition_table()[index].from == state) {
        found = true;
        break;
      }
    }
    PDU_CHECK_MSG(found, std::string("no transition leaves ") + std::string(to_token(state)));
  }
}

PDU_TEST(lifecycle, transition_class_is_never_inferred_from_names) {
  PDU_CHECK_EQ(PDU_REQUIRE_OK(transition_class(LifecycleState::provisioned, LifecycleState::active)),
               TransitionClass::commission);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(transition_class(LifecycleState::isolated, LifecycleState::active)),
               TransitionClass::recovery);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(transition_class(LifecycleState::faulted, LifecycleState::retired)),
               TransitionClass::administrative);
  PDU_REQUIRE_STATUS(transition_class(LifecycleState::active, LifecycleState::active),
                     StatusCode::transition_invalid);
  PDU_REQUIRE_STATUS(transition_class(LifecycleState::retired, LifecycleState::active),
                     StatusCode::transition_invalid);
  PDU_REQUIRE_STATUS(transition_class(LifecycleState::provisioned, LifecycleState::faulted),
                     StatusCode::transition_invalid);
}

PDU_TEST(lifecycle, control_scope_matches_the_safety_rule) {
  PDU_CHECK(control_scope(LifecycleState::active) == ControlScope::normal);
  PDU_CHECK(control_scope(LifecycleState::degraded) == ControlScope::normal);
  PDU_CHECK(control_scope(LifecycleState::maintenance) == ControlScope::maintenance_override);
  for (const LifecycleState state : {LifecycleState::provisioned, LifecycleState::isolated,
                                     LifecycleState::faulted, LifecycleState::retired}) {
    PDU_CHECK_MSG(control_scope(state) == ControlScope::forbidden,
                  std::string("control must be refused in ") + std::string(to_token(state)));
  }
  PDU_CHECK(is_quiescent(LifecycleState::isolated));
  PDU_CHECK(is_quiescent(LifecycleState::faulted));
  PDU_CHECK(is_quiescent(LifecycleState::retired));
  PDU_CHECK(!is_quiescent(LifecycleState::active));
}

PDU_TEST(lifecycle, tokens_round_trip) {
  for (const LifecycleState state : {LifecycleState::provisioned, LifecycleState::active,
                                     LifecycleState::maintenance, LifecycleState::degraded,
                                     LifecycleState::isolated, LifecycleState::faulted,
                                     LifecycleState::retired}) {
    LifecycleState parsed = LifecycleState::provisioned;
    PDU_CHECK(parse_lifecycle_state(to_token(state), parsed));
    PDU_CHECK(parsed == state);
  }
  LifecycleState unused = LifecycleState::active;
  PDU_CHECK(!parse_lifecycle_state("nonsense", unused));
  TransitionClass klass = TransitionClass::service;
  PDU_CHECK(parse_transition_class("recovery", klass));
  PDU_CHECK(klass == TransitionClass::recovery);
}

PDU_TEST(lifecycle, required_action_follows_the_transition_class) {
  PDU_CHECK_EQ(PDU_REQUIRE_OK(required_action(LifecycleState::provisioned, LifecycleState::active)),
               PermissionAction::lifecycle_service);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(required_action(LifecycleState::isolated, LifecycleState::active)),
               PermissionAction::lifecycle_recovery);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(required_action(LifecycleState::active, LifecycleState::retired)),
               PermissionAction::lifecycle_administrative);
  PDU_REQUIRE_STATUS(required_action(LifecycleState::retired, LifecycleState::active),
                     StatusCode::transition_invalid);
}

PDU_TEST(lifecycle, permission_action_masks_round_trip) {
  const PermissionActions mask = action_mask(PermissionAction::control_energize) |
                                 action_mask(PermissionAction::lifecycle_recovery);
  PDU_CHECK(has_action(mask, PermissionAction::control_energize));
  PDU_CHECK(!has_action(mask, PermissionAction::control_de_energize));
  const std::string token = to_token(mask);
  PDU_CHECK_EQ(token, std::string("control_energize|lifecycle_recovery"));
  PDU_CHECK_EQ(PDU_REQUIRE_OK(parse_permission_actions(token)), mask);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(parse_permission_actions("none")), PermissionActions{0});
  PDU_REQUIRE_STATUS(parse_permission_actions(""), StatusCode::invalid_argument);
  PDU_REQUIRE_STATUS(parse_permission_actions("control_explode"), StatusCode::malformed_input);
  PDU_CHECK_EQ(to_token(PermissionActions{0}), std::string("none"));
}
