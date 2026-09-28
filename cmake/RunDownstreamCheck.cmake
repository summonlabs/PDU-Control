# Configures, builds, and runs the out-of-tree downstream consumer against an
# installed PDU Control package. Invoked by CTest when PDU_CONTROL_DOWNSTREAM_PREFIX
# is set, and by the release verification steps.
#
# A nested CMake project needs a usable C++ toolchain in this process's
# environment. On Windows with MSVC that environment is produced by vcvars64.bat,
# so this script locates it through vswhere (never through a hard-coded path) and
# runs the nested commands through it. When no toolchain can be reached the check
# fails with the exact reason rather than reporting a pass it did not earn.

foreach(required PDU_SOURCE_DIR PDU_BINARY_DIR PDU_PREFIX)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "RunDownstreamCheck.cmake requires -D${required}=...")
  endif()
endforeach()

set(pdu_vcvars "")
if(WIN32 AND DEFINED PDU_VCVARS AND NOT PDU_VCVARS STREQUAL "")
  set(pdu_vcvars "${PDU_VCVARS}")
elseif(WIN32)
  set(pdu_program_files_x86 "$ENV{ProgramFiles\(x86\)}")
  set(pdu_vswhere "${pdu_program_files_x86}/Microsoft Visual Studio/Installer/vswhere.exe")
  if(EXISTS "${pdu_vswhere}")
    execute_process(COMMAND "${pdu_vswhere}" -latest -products * -requires
                            Microsoft.VisualStudio.Component.VC.Tools.x86.x64
                            -property installationPath
                    OUTPUT_VARIABLE pdu_vs_path
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    if(NOT pdu_vs_path STREQUAL "")
      set(pdu_vcvars "${pdu_vs_path}/VC/Auxiliary/Build/vcvars64.bat")
    endif()
  endif()
endif()

# Runs one nested command, entering the MSVC developer environment first when one
# was found. The environment is entered through a generated batch file rather than
# through `cmd /c "call ... && ..."`, because nesting quotes inside an outer quoted
# command line is not reliable.
set(pdu_run_serial 0)
function(pdu_run description)
  math(EXPR pdu_run_serial "${pdu_run_serial} + 1")
  if(WIN32 AND NOT pdu_vcvars STREQUAL "" AND EXISTS "${pdu_vcvars}")
    set(pdu_batch "${PDU_BINARY_DIR}/pdu-run-${pdu_run_serial}.bat")
    set(pdu_script "@echo off\r\ncall \"${pdu_vcvars}\" >nul 2>&1\r\n")
    foreach(argument IN LISTS ARGN)
      set(pdu_script "${pdu_script}\"${argument}\" ")
    endforeach()
    set(pdu_script "${pdu_script}\r\nexit /b %ERRORLEVEL%\r\n")
    file(WRITE "${pdu_batch}" "${pdu_script}")
    execute_process(COMMAND cmd /c "${pdu_batch}"
      RESULT_VARIABLE pdu_result
      OUTPUT_VARIABLE pdu_output
      ERROR_VARIABLE pdu_output)
  else()
    execute_process(COMMAND ${ARGN}
      RESULT_VARIABLE pdu_result
      OUTPUT_VARIABLE pdu_output
      ERROR_VARIABLE pdu_output)
  endif()

  if(NOT pdu_result EQUAL 0)
    if(pdu_output MATCHES "No CMAKE_CXX_COMPILER could be found" OR
       pdu_output MATCHES "CMAKE_CXX_COMPILER not set")
      message(FATAL_ERROR
              "${description} could not run because no C++ compiler is reachable from this "
              "environment. Run the suite from a developer environment (for MSVC, after "
              "vcvars64.bat) to execute the installed-package check for real.\n${pdu_output}")
    endif()
    if(pdu_output MATCHES "Could not find a package configuration file provided by \"PDUControl\"")
      message(FATAL_ERROR
              "${description} failed because no PDU Control package was found under "
              "'${PDU_PREFIX}'. Install the project into that prefix first, for example "
              "'cmake --install <build-dir> --prefix ${PDU_PREFIX}'.\n${pdu_output}")
    endif()
    message(FATAL_ERROR "${description} failed with exit ${pdu_result}:\n${pdu_output}")
  endif()
  set(pdu_last_output "${pdu_output}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${PDU_BINARY_DIR}")
file(MAKE_DIRECTORY "${PDU_BINARY_DIR}")

set(configure_command "${CMAKE_COMMAND}"
  -S "${PDU_SOURCE_DIR}/downstream/consumer"
  -B "${PDU_BINARY_DIR}"
  "-DCMAKE_PREFIX_PATH=${PDU_PREFIX}")
if(DEFINED PDU_GENERATOR AND NOT PDU_GENERATOR STREQUAL "")
  list(APPEND configure_command -G "${PDU_GENERATOR}")
endif()
if(DEFINED PDU_CONFIG AND NOT PDU_CONFIG STREQUAL "")
  list(APPEND configure_command "-DCMAKE_BUILD_TYPE=${PDU_CONFIG}")
endif()

pdu_run("downstream configure" ${configure_command})

# A multi-configuration generator ignores CMAKE_BUILD_TYPE, so the configuration
# is named explicitly here. Building the "Debug" configuration of a project that
# links a release-installed library produces a PDB mismatch rather than a compile
# error, which is exactly the kind of failure this check exists to catch.
set(build_command "${CMAKE_COMMAND}" --build "${PDU_BINARY_DIR}")
if(DEFINED PDU_CONFIG AND NOT PDU_CONFIG STREQUAL "")
  list(APPEND build_command --config "${PDU_CONFIG}")
endif()

pdu_run("downstream build" ${build_command})
pdu_run("downstream run" ${build_command} --target run_consumer)

message(STATUS "downstream consumer output:\n${pdu_last_output}")
