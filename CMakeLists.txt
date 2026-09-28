cmake_minimum_required(VERSION 3.21)

project(PDUControl
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral lifecycle and safe control semantics for power distribution units and branch circuits"
  HOMEPAGE_URL "https://github.com/summonlabs/PDU-Control"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(PDU_CONTROL_IS_TOP_LEVEL ON)
else()
  set(PDU_CONTROL_IS_TOP_LEVEL OFF)
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(PDU_CONTROL_IS_TOP_LEVEL)
  option(PDU_CONTROL_BUILD_TESTS "Build the PDU Control test suite" ON)
  option(PDU_CONTROL_BUILD_EXAMPLES "Build the PDU Control examples" ON)
  option(PDU_CONTROL_BUILD_BENCHMARKS "Build the PDU Control benchmarks" ON)
  option(PDU_CONTROL_BUILD_TOOLS "Build the PDU Control command line tool" ON)
else()
  option(PDU_CONTROL_BUILD_TESTS "Build the PDU Control test suite" OFF)
  option(PDU_CONTROL_BUILD_EXAMPLES "Build the PDU Control examples" OFF)
  option(PDU_CONTROL_BUILD_BENCHMARKS "Build the PDU Control benchmarks" OFF)
  option(PDU_CONTROL_BUILD_TOOLS "Build the PDU Control command line tool" OFF)
endif()

option(PDU_CONTROL_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(PDU_CONTROL_ENABLE_ADDRESS_SANITIZER
  "Build first-party targets with AddressSanitizer where the toolchain supports it" OFF)

set(PDU_CONTROL_DOWNSTREAM_PREFIX "" CACHE PATH
  "Install prefix of a previous PDU Control installation; enables the downstream consumer test")

# ---------------------------------------------------------------------------
# First-party compile options
# ---------------------------------------------------------------------------
function(pdu_control_apply_strict_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    if(PDU_CONTROL_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wshadow
      -Wconversion
      -Wsign-conversion
      -Wnon-virtual-dtor
      -Wcast-qual
      -Wdouble-promotion)
    if(PDU_CONTROL_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
  if(PDU_CONTROL_ENABLE_ADDRESS_SANITIZER)
    if(MSVC)
      # Debug information is emitted because the sanitizer needs it for a usable
      # report; building with the sanitizer and no debug info is itself a
      # diagnostic warning, and the honest fix is to emit the information rather
      # than to silence the warning.
      # The sanitizer flag is a compiler option: the compiler records the runtime
      # libraries it needs, and link.exe does not accept the flag itself.
      target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
      target_link_options(${target} PRIVATE /DEBUG /INCREMENTAL:NO)
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer -g)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Generated version header
# ---------------------------------------------------------------------------
set(PDU_CONTROL_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(PDU_CONTROL_STORE_FORMAT_VERSION 1)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/pdu_control/version.hpp.in"
  "${PDU_CONTROL_GENERATED_INCLUDE_DIR}/pdu_control/version.hpp"
  @ONLY)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(pdu_control
  src/status.cpp
  src/ids.cpp
  src/units.cpp
  src/lifecycle.cpp
  src/evidence.cpp
  src/model.cpp
  src/authority.cpp
  src/adapter.cpp
  src/attempt.cpp
  src/audit.cpp
  src/synthetic_adapter.cpp
  src/store.cpp
  src/engine.cpp
  src/detail/codec.cpp
  src/detail/crc32c.cpp
  src/detail/file_io.cpp
  src/detail/path.cpp
  src/detail/process.cpp
  src/detail/store_file.cpp
  src/detail/serialization.cpp)
add_library(PDUControl::pdu_control ALIAS pdu_control)

target_include_directories(pdu_control
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${PDU_CONTROL_GENERATED_INCLUDE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_features(pdu_control PUBLIC cxx_std_20)
pdu_control_apply_strict_options(pdu_control)

set_target_properties(pdu_control PROPERTIES
  OUTPUT_NAME "pdu_control"
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}"
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON)

if(BUILD_SHARED_LIBS AND WIN32)
  set_target_properties(pdu_control PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ---------------------------------------------------------------------------
# CLI tool
# ---------------------------------------------------------------------------
if(PDU_CONTROL_BUILD_TOOLS)
  add_executable(pdu_control_cli tools/pdu_cli.cpp tools/cli_json.cpp)
  set_target_properties(pdu_control_cli PROPERTIES OUTPUT_NAME "pdu-control")
  target_link_libraries(pdu_control_cli PRIVATE pdu_control)
  target_include_directories(pdu_control_cli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")
  pdu_control_apply_strict_options(pdu_control_cli)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS pdu_control
  EXPORT PDUControlTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

if(PDU_CONTROL_BUILD_TOOLS)
  install(TARGETS pdu_control_cli
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/pdu_control"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")
install(FILES "${PDU_CONTROL_GENERATED_INCLUDE_DIR}/pdu_control/version.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/pdu_control")

set(PDU_CONTROL_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/PDUControl")

install(EXPORT PDUControlTargets
  NAMESPACE PDUControl::
  FILE PDUControlTargets.cmake
  DESTINATION "${PDU_CONTROL_INSTALL_CMAKEDIR}")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PDUControlConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/PDUControlConfig.cmake"
  INSTALL_DESTINATION "${PDU_CONTROL_INSTALL_CMAKEDIR}")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/PDUControlConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/PDUControlConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/PDUControlConfigVersion.cmake"
  DESTINATION "${PDU_CONTROL_INSTALL_CMAKEDIR}")

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/PDUControl")

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------
if(PDU_CONTROL_IS_TOP_LEVEL AND (PDU_CONTROL_BUILD_TESTS OR PDU_CONTROL_BUILD_EXAMPLES))
  enable_testing()
endif()

if(PDU_CONTROL_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(PDU_CONTROL_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()

if(PDU_CONTROL_BUILD_TESTS)
  add_subdirectory(tests)
endif()
