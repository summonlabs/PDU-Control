#include "test_harness.hpp"

using namespace pdu_control;

PDU_TEST(identity, identifier_accepts_and_refuses) {
  PDU_CHECK(PDU_REQUIRE_OK(PduId::parse("pdu-1")).value() == "pdu-1");
  PDU_CHECK(PDU_REQUIRE_OK(PduId::parse("A.b_c-9")).value() == "A.b_c-9");
  PDU_REQUIRE_STATUS(PduId::parse(""), StatusCode::invalid_argument);
  PDU_REQUIRE_STATUS(PduId::parse("-leading"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse("has space"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse("has/slash"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse("has\\backslash"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse("trailing."), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse("nul"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse("COM1"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse("com9.log"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(PduId::parse(std::string(97, 'a')), StatusCode::out_of_range);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(PduId::parse(std::string(96, 'a'))).value().size(), std::size_t{96});
  // A non-ASCII byte is refused rather than replaced, so a malformed or
  // overlong encoding cannot enter an identity.
  const std::string utf8 = "caf\xC3\xA9";
  PDU_REQUIRE_STATUS(PduId::parse(utf8), StatusCode::malformed_input);
  // A lone continuation byte is malformed UTF-8 and must be refused too.
  const std::string broken = "a\x80z";
  PDU_REQUIRE_STATUS(PduId::parse(broken), StatusCode::malformed_input);
  PDU_CHECK(PduId{}.empty());
  PDU_CHECK(!PDU_REQUIRE_OK(PduId::parse("x")).value().empty());
}

PDU_TEST(identity, reserved_device_names) {
  PDU_CHECK(is_reserved_device_name("CON"));
  PDU_CHECK(is_reserved_device_name("con"));
  PDU_CHECK(is_reserved_device_name("NUL.txt"));
  PDU_CHECK(is_reserved_device_name("LPT1"));
  PDU_CHECK(!is_reserved_device_name("CONS"));
  PDU_CHECK(!is_reserved_device_name("COM0"));
  PDU_CHECK(!is_reserved_device_name(""));
}

PDU_TEST(identity, counter_arithmetic_is_checked) {
  const PduGeneration one = PduGeneration::from(1);
  PDU_CHECK(PDU_REQUIRE_OK(one.next()) == PduGeneration::from(2));
  PduGeneration unset_value;
  PDU_CHECK(!unset_value.is_set());
  const PduGeneration maximum = PduGeneration::from(0xFFFFFFFFFFFFFFFFULL);
  PDU_REQUIRE_STATUS(maximum.next(), StatusCode::overflow);
  PDU_CHECK(PDU_REQUIRE_OK(one.advanced_by(41)) == PduGeneration::from(42));
  PDU_REQUIRE_STATUS(maximum.advanced_by(1), StatusCode::overflow);
  PDU_REQUIRE_STATUS(PduGeneration::from(0xFFFFFFFFFFFFFFFEULL).advanced_by(2), StatusCode::overflow);
}

PDU_TEST(identity, digest_hex_round_trip) {
  const Digest64 value = digest_of("pdu-control");
  const std::string hex = value.to_hex();
  PDU_CHECK_EQ(hex.size(), std::size_t{16});
  PDU_CHECK(PDU_REQUIRE_OK(Digest64::from_hex(hex)) == value);
  PDU_CHECK_EQ(digest_of("pdu-control"), value);
  PDU_CHECK_NE(digest_of("pdu-control"), digest_of("pdu-contro1"));
  PDU_REQUIRE_STATUS(Digest64::from_hex("abc"), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(Digest64::from_hex("zzzzzzzzzzzzzzzz"), StatusCode::malformed_input);
  DigestBuilder builder;
  builder.update("pdu-");
  builder.update("control");
  PDU_CHECK_EQ(builder.finish(), value);
}

PDU_TEST(units, magnitudes_refuse_negative_input) {
  PDU_CHECK(PDU_REQUIRE_OK(Current::magnitude(0)).is_zero());
  PDU_REQUIRE_STATUS(Current::magnitude(-1), StatusCode::out_of_range);
  PDU_CHECK(Current::from_raw(-5).is_negative());
  Current measured = Current::from_raw(1500);
  std::int64_t expected = 1500;
  PDU_CHECK_EQ(measured.raw(), expected);
}

PDU_TEST(units, checked_arithmetic_refuses_overflow) {
  const Current big = Current::from_raw(9223372036854775807LL);
  PDU_REQUIRE_STATUS(big.checked_add(Current::from_raw(1)), StatusCode::overflow);
  PDU_REQUIRE_STATUS(Current::from_raw(-9223372036854775807LL - 1).checked_sub(Current::from_raw(1)),
                     StatusCode::overflow);
  PDU_REQUIRE_STATUS(Current::from_raw(1).checked_negate(), StatusCode::ok);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(Current::from_raw(3).checked_mul(4)).raw(), std::int64_t{12});
  PDU_REQUIRE_STATUS(big.checked_mul(2), StatusCode::overflow);
  PDU_REQUIRE_STATUS(Current::checked_sum({}), StatusCode::invalid_argument);
  const auto sum = Current::checked_sum({Current::from_raw(1), Current::from_raw(2)});
  PDU_CHECK_EQ(PDU_REQUIRE_OK(sum).raw(), std::int64_t{3});
  PDU_REQUIRE_STATUS(Current::checked_sum({big, Current::from_raw(1)}), StatusCode::overflow);
}

PDU_TEST(units, samples_keep_unknown_distinct_from_zero) {
  const CurrentSample known_zero = CurrentSample::known(Current::from_raw(0));
  const CurrentSample unknown = CurrentSample::unknown();
  PDU_CHECK(known_zero.has_value());
  PDU_CHECK(!unknown.has_value());
  PDU_CHECK_NE(known_zero.state(), unknown.state());
  PDU_CHECK_EQ(unknown.value_or(Current::from_raw(7)).raw(), std::int64_t{7});
  PDU_CHECK_EQ(to_token(CurrentSample::unavailable().state()), std::string_view("unavailable"));
  PDU_CHECK_EQ(to_token(CurrentSample::unsupported().state()), std::string_view("unsupported"));
}

PDU_TEST(units, limits_are_validated_without_a_load) {
  BranchLimits limits;
  PDU_CHECK(validate_limits(limits).ok());
  limits.continuous_current = CurrentSample::known(Current::from_raw(-1));
  PDU_REQUIRE_STATUS(validate_limits(limits), StatusCode::limit_invalid);

  BranchLimits inverted;
  inverted.continuous_current = CurrentSample::known(Current::from_raw(100));
  inverted.peak_current = CurrentSample::known(Current::from_raw(99));
  inverted.provenance.issuer = IssuerId::parse("authority").value();
  PDU_REQUIRE_STATUS(validate_limits(inverted), StatusCode::limit_invalid);

  BranchLimits no_provenance;
  no_provenance.continuous_current = CurrentSample::known(Current::from_raw(100));
  PDU_REQUIRE_STATUS(validate_limits(no_provenance), StatusCode::limit_invalid);

  BranchLimits bad_expiry;
  bad_expiry.provenance.issuer = IssuerId::parse("authority").value();
  bad_expiry.provenance.stated_at = LogicalTick::from(10);
  bad_expiry.provenance.not_after = LogicalTick::from(10);
  PDU_REQUIRE_STATUS(validate_limits(bad_expiry), StatusCode::limit_invalid);
}

PDU_TEST(units, comparing_a_projection_never_invents_a_limit) {
  const Current projected = Current::from_raw(100);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(compare_to_limit(projected, CurrentSample::unknown())),
               LimitVerdict::limit_unknown);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(compare_to_limit(projected, CurrentSample::known(Current::from_raw(100)))),
               LimitVerdict::within_limit);
  PDU_CHECK_EQ(PDU_REQUIRE_OK(compare_to_limit(projected, CurrentSample::known(Current::from_raw(99)))),
               LimitVerdict::exceeds_limit);
}

PDU_TEST(identity, labels_refuse_non_ascii) {
  ModelBounds bounds;
  PDU_CHECK(validate_label("rack pdu 1", bounds.max_label_bytes).ok());
  PDU_CHECK(validate_label("", bounds.max_label_bytes).ok());
  PDU_REQUIRE_STATUS(validate_label("line\nbreak", bounds.max_label_bytes), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(validate_label("caf\xC3\xA9", bounds.max_label_bytes), StatusCode::malformed_input);
  PDU_REQUIRE_STATUS(validate_label(std::string(161, 'x'), bounds.max_label_bytes), StatusCode::out_of_range);
}
