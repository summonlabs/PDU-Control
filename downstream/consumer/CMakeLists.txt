cmake_minimum_required(VERSION 3.21)

# Independent out-of-tree consumer of the installed PDU Control package.
# This project is not part of the PDU Control build tree: it is configured
# separately with CMAKE_PREFIX_PATH pointing at an install prefix.

project(PDUControlConsumer
  VERSION 1.0.0
  DESCRIPTION "Out-of-tree consumer of the installed PDU Control package"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PDUControl 1.0 REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE PDUControl::pdu_control)

if(MSVC)
  target_compile_options(consumer PRIVATE /W4 /permissive- /utf-8 /WX)
else()
  target_compile_options(consumer PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Runs the consumer through a real minimal lifecycle: create a durable store,
# register a PDU and a branch, record authority and telemetry, evaluate and issue
# a control command through a synthetic adapter, verify the effect, close,
# reopen, and confirm that the verified state and the attempt journal survived.
add_custom_target(run_consumer
  COMMAND consumer "${CMAKE_CURRENT_BINARY_DIR}/consumer-store/site.pdustore"
  DEPENDS consumer
  COMMENT "Running the installed-package consumer lifecycle"
  VERBATIM)
