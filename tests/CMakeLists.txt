# Test suite.
#
# No test is given a timeout. CTest timeouts, timeout wrappers, and watchdog
# processes are prohibited in this repository: a test that does not finish is a
# defect to diagnose, not to bound.

# The probe is a real program that the crash and multiprocess tests start as an
# independent operating-system process, and that terminates itself at chosen
# durable stages.
add_executable(pdu_probe support/pdu_probe.cpp)
target_link_libraries(pdu_probe PRIVATE pdu_control)
target_include_directories(pdu_probe PRIVATE "${CMAKE_SOURCE_DIR}/src")
pdu_control_apply_strict_options(pdu_probe)

add_library(pdu_test_support STATIC
  support/test_harness.cpp
  support/fixture.cpp
  support/proc.cpp)
target_include_directories(pdu_test_support PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/support")
target_link_libraries(pdu_test_support PUBLIC pdu_control)
target_include_directories(pdu_test_support PUBLIC "${CMAKE_SOURCE_DIR}/src")
target_compile_definitions(pdu_test_support PUBLIC
  "PDU_PROBE_EXECUTABLE=\"$<TARGET_FILE:pdu_probe>\"")
add_dependencies(pdu_test_support pdu_probe)
pdu_control_apply_strict_options(pdu_test_support)

if(TARGET pdu_control_cli)
  target_compile_definitions(pdu_test_support PUBLIC
    "PDU_CLI_EXECUTABLE=\"$<TARGET_FILE:pdu_control_cli>\"")
  add_dependencies(pdu_test_support pdu_control_cli)
endif()

function(pdu_control_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE pdu_test_support)
  pdu_control_apply_strict_options(${name})
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

pdu_control_add_test(pdu_test_identity test_identity.cpp)
pdu_control_add_test(pdu_test_lifecycle test_lifecycle.cpp)
pdu_control_add_test(pdu_test_authority test_authority.cpp)
pdu_control_add_test(pdu_test_evidence test_evidence.cpp)
pdu_control_add_test(pdu_test_control test_control.cpp)
pdu_control_add_test(pdu_test_idempotency test_idempotency.cpp)
pdu_control_add_test(pdu_test_adapter test_adapter.cpp)
pdu_control_add_test(pdu_test_persistence test_persistence.cpp)
pdu_control_add_test(pdu_test_recovery test_recovery.cpp)
pdu_control_add_test(pdu_test_multiprocess test_multiprocess.cpp)
pdu_control_add_test(pdu_test_property test_property.cpp)
pdu_control_add_test(pdu_test_adversarial test_adversarial.cpp)

if(TARGET pdu_control_cli)
  pdu_control_add_test(pdu_test_cli test_cli.cpp)
endif()

# The downstream consumer is configured, built, and run out of tree against an
# installed package. It is enabled by pointing PDU_CONTROL_DOWNSTREAM_PREFIX at
# an install prefix produced by this project.
if(PDU_CONTROL_DOWNSTREAM_PREFIX)
  add_test(NAME pdu_test_downstream_install
    COMMAND "${CMAKE_COMMAND}"
      -DPDU_SOURCE_DIR=${CMAKE_SOURCE_DIR}
      -DPDU_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/downstream
      -DPDU_PREFIX=${PDU_CONTROL_DOWNSTREAM_PREFIX}
      -DPDU_GENERATOR=${CMAKE_GENERATOR}
      -DPDU_CXX_COMPILER=${CMAKE_CXX_COMPILER}
      -DPDU_CONFIG=$<CONFIG>
      -P "${CMAKE_SOURCE_DIR}/cmake/RunDownstreamCheck.cmake")
  set_tests_properties(pdu_test_downstream_install PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endif()
