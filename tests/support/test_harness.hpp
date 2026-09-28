#pragma once

// Minimal deterministic test harness. No third-party dependency, no timeouts,
// no watchdog logic: a check either passes, fails, or the program does not
// finish, and an unfinished program is a defect to diagnose rather than to
// bound.

#include <cstdint>
#include <functional>
#include <ostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include "pdu_control/adapter.hpp"
#include "pdu_control/attempt.hpp"
#include "pdu_control/audit.hpp"
#include "pdu_control/authority.hpp"
#include "pdu_control/engine.hpp"
#include "pdu_control/evidence.hpp"
#include "pdu_control/ids.hpp"
#include "pdu_control/lifecycle.hpp"
#include "pdu_control/model.hpp"
#include "pdu_control/status.hpp"
#include "pdu_control/store.hpp"
#include "pdu_control/synthetic_adapter.hpp"
#include "pdu_control/units.hpp"

namespace pdu_control {

#define PDU_CONTROL_TOKEN_OPERATOR(type)                        \
  inline std::ostream& operator<<(std::ostream& stream, type value) { \
    return stream << to_token(value);                           \
  }

PDU_CONTROL_TOKEN_OPERATOR(StatusCode)
PDU_CONTROL_TOKEN_OPERATOR(LifecycleState)
PDU_CONTROL_TOKEN_OPERATOR(TransitionClass)
PDU_CONTROL_TOKEN_OPERATOR(ObligationClass)
PDU_CONTROL_TOKEN_OPERATOR(InterlockState)
PDU_CONTROL_TOKEN_OPERATOR(InterlockVerdict)
PDU_CONTROL_TOKEN_OPERATOR(PermissionVerdict)
PDU_CONTROL_TOKEN_OPERATOR(OverrideVerdict)
PDU_CONTROL_TOKEN_OPERATOR(BranchCondition)
PDU_CONTROL_TOKEN_OPERATOR(CommandIntent)
PDU_CONTROL_TOKEN_OPERATOR(ClockDomain)
PDU_CONTROL_TOKEN_OPERATOR(EvidenceQuality)
PDU_CONTROL_TOKEN_OPERATOR(FreshnessState)
PDU_CONTROL_TOKEN_OPERATOR(SampleState)
PDU_CONTROL_TOKEN_OPERATOR(Unit)
PDU_CONTROL_TOKEN_OPERATOR(LimitVerdict)
PDU_CONTROL_TOKEN_OPERATOR(AdapterKind)
PDU_CONTROL_TOKEN_OPERATOR(AdapterDisposition)
PDU_CONTROL_TOKEN_OPERATOR(PreconditionKind)
PDU_CONTROL_TOKEN_OPERATOR(EffectState)
PDU_CONTROL_TOKEN_OPERATOR(AttemptOutcome)
PDU_CONTROL_TOKEN_OPERATOR(AttemptResolution)
PDU_CONTROL_TOKEN_OPERATOR(AuditKind)
PDU_CONTROL_TOKEN_OPERATOR(OpenMode)
PDU_CONTROL_TOKEN_OPERATOR(SyntheticMode)

#undef PDU_CONTROL_TOKEN_OPERATOR

inline std::ostream& operator<<(std::ostream& stream, const Status& value) {
  return stream << value.to_string();
}
inline std::ostream& operator<<(std::ostream& stream, const Digest64& value) {
  return stream << value.to_hex();
}
inline std::ostream& operator<<(std::ostream& stream, const Instant& value) {
  if (value.is_logical()) {
    return stream << "logical:" << value.tick.value();
  }
  return stream << to_token(value.domain) << ":" << value.nanoseconds;
}
inline std::ostream& operator<<(std::ostream& stream, const InterlockSummary& value) {
  return stream << to_token(value.verdict) << "(" << value.deciding.value() << ")";
}
inline std::ostream& operator<<(std::ostream& stream, const Decision& value) {
  return stream << (value.eligible ? "eligible" : "refused") << ":" << value.code << ":"
                << value.detail;
}

template <typename Tag>
std::ostream& operator<<(std::ostream& stream, const Identifier<Tag>& value) {
  return stream << (value.empty() ? std::string("-") : value.value());
}
template <typename Tag>
std::ostream& operator<<(std::ostream& stream, const Counter<Tag>& value) {
  return stream << value.value();
}
template <typename Tag, Unit U>
std::ostream& operator<<(std::ostream& stream, const Quantity<Tag, U>& value) {
  return stream << value.raw() << to_token(U);
}
template <typename Q>
std::ostream& operator<<(std::ostream& stream, const Sample<Q>& value) {
  stream << to_token(value.state());
  if (value.has_value()) {
    stream << "(" << value.value() << ")";
  }
  return stream;
}

}  // namespace pdu_control

namespace pdu_test {

using Body = std::function<void()>;

struct TestCase {
  std::string suite;
  std::string name;
  Body body;
};

std::vector<TestCase>& registry();

class Registrar {
 public:
  Registrar(const char* suite, const char* name, Body body);
};

/// Records a failure for the currently running test.
void report_failure(const char* file, int line, const std::string& expression,
                    const std::string& detail);

/// Counts one assertion. A test that performs no assertions fails, because it
/// cannot distinguish a working runtime from a broken one.
void count_check();

/// Renders a value for a failure message. Types without a stream operator are
/// named by their RTTI name rather than silently omitted.
template <typename T>
std::string display(const T& value) {
  if constexpr (requires(std::ostream& stream, const T& item) { stream << item; }) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else {
    return std::string("<value of type ") + typeid(T).name() + ">";
  }
}

std::string display(const std::string& value);
std::string display(const char* value);
std::string display(bool value);
std::string display(std::nullptr_t value);

/// Extracts the status of either a Status or a Result<T>, so a check can be
/// written the same way for both. Returned by value so that a temporary
/// Result<T> in the caller's full expression cannot dangle.
inline ::pdu_control::Status status_of(const ::pdu_control::Status& value) { return value; }

template <typename T>
::pdu_control::Status status_of(const ::pdu_control::Result<T>& value) {
  return value.status();
}

int run_all(int argc, char** argv);

}  // namespace pdu_test

#define PDU_TEST(suite, name)                                                        \
  static void pdu_test_body_##suite##_##name();                                      \
  static const ::pdu_test::Registrar pdu_test_registrar_##suite##_##name(            \
      #suite, #name, pdu_test_body_##suite##_##name);                                \
  static void pdu_test_body_##suite##_##name()

#define PDU_CHECK(expression)                                     \
  do {                                                            \
    ::pdu_test::count_check();                                    \
    if (!(expression)) {                                          \
      ::pdu_test::report_failure(__FILE__, __LINE__, #expression, ""); \
    }                                                             \
  } while (false)

#define PDU_CHECK_MSG(expression, detail)                                    \
  do {                                                                       \
    ::pdu_test::count_check();                                               \
    if (!(expression)) {                                                     \
      ::pdu_test::report_failure(__FILE__, __LINE__, #expression, (detail)); \
    }                                                                        \
  } while (false)

#define PDU_CHECK_EQ(left, right)                                                     \
  do {                                                                                \
    ::pdu_test::count_check();                                                          \
    /* Copied, not bound by reference: an expression such as                          \
       \"InterlockId::parse(\"x\").value()\" yields a reference into a temporary that     \
       would already be destroyed by the time the comparison runs. */                 \
    const auto pdu_left_value = (left);                                               \
    const auto pdu_right_value = (right);                                             \
    if (!(pdu_left_value == pdu_right_value)) {                                       \
      ::pdu_test::report_failure(__FILE__, __LINE__, #left " == " #right,             \
                                 "left=" + ::pdu_test::display(pdu_left_value) +      \
                                     " right=" + ::pdu_test::display(pdu_right_value)); \
    }                                                                                 \
  } while (false)

#define PDU_CHECK_NE(left, right)                                                 \
  do {                                                                            \
    ::pdu_test::count_check();                                                      \
    const auto pdu_left_value = (left);                                           \
    const auto pdu_right_value = (right);                                         \
    if (pdu_left_value == pdu_right_value) {                                      \
      ::pdu_test::report_failure(__FILE__, __LINE__, #left " != " #right,         \
                                 "both=" + ::pdu_test::display(pdu_left_value));  \
    }                                                                             \
  } while (false)

/// Requires the result to hold and yields its value.
#define PDU_REQUIRE_OK(expression)                                                       \
  ([&]() {                                                                               \
    ::pdu_test::count_check();                                                             \
    auto pdu_result_value = (expression);                                                \
    using pdu_required_type = std::remove_cvref_t<decltype(pdu_result_value.value())>;    \
    if (!pdu_result_value.ok()) {                                                        \
      ::pdu_test::report_failure(__FILE__, __LINE__, #expression " is ok",               \
                                 "status=" + ::pdu_test::display(pdu_result_value.status())); \
      /* The failure is already recorded, so the test will not pass. Returning a      \
         default value keeps the remaining checks running and reports every problem     \
         in one run instead of dying inside the variant. */                           \
      return pdu_required_type{};                                                        \
    }                                                                                    \
    return std::move(pdu_result_value).value();                                         \
  }())

/// Requires the status to fail with exactly the given code. Accepts either a
/// Status or a Result<T>.
#define PDU_REQUIRE_STATUS(expression, expected_code)                                     \
  do {                                                                                     \
    ::pdu_test::count_check();                                                               \
    const ::pdu_control::Status pdu_status_value = ::pdu_test::status_of(expression);       \
    if (pdu_status_value.code() != (expected_code)) {                                       \
      ::pdu_test::report_failure(__FILE__, __LINE__,                                        \
                                 #expression " fails with " #expected_code,                 \
                                 "actual=" + ::pdu_test::display(pdu_status_value));        \
    }                                                                                       \
  } while (false)
