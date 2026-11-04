cmake_minimum_required(VERSION 3.24)

project(openrecover VERSION 1.4.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(OPENRECOVER_BUILD_TESTS "Build unit tests" ON)
option(OPENRECOVER_BUILD_FUZZ "Build libFuzzer targets (Linux clang only)" OFF)
option(OPENRECOVER_BUILD_EXAMPLES "Build the library usage examples" ON)
option(OPENRECOVER_NIGHTLY_TESTS "Register long-running nightly tests (64 GiB stress)" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(OpenRecoverWarnings)
include(OpenRecoverDeps)

find_package(Python3 COMPONENTS Interpreter)

add_subdirectory(libopenrecover)

# The Python sidecar consumes policy.json generated from the C++ policy. Generating it
# during the build keeps both implementations on the same constants and deny list.
add_executable(adb_policy_dump tools/adb_sidecar/policy_dump.cpp)
target_link_libraries(adb_policy_dump PRIVATE openrecover_core)
openrecover_set_warnings(adb_policy_dump)
set(OPENRECOVER_SIDECAR_POLICY_JSON "${CMAKE_BINARY_DIR}/tools/adb_sidecar/policy.json")
add_custom_command(
  OUTPUT "${OPENRECOVER_SIDECAR_POLICY_JSON}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/tools/adb_sidecar"
  COMMAND $<TARGET_FILE:adb_policy_dump> "${OPENRECOVER_SIDECAR_POLICY_JSON}"
  DEPENDS adb_policy_dump
  COMMENT "Generating the shared adb sidecar policy.json")
add_custom_target(adb_sidecar_policy ALL DEPENDS "${OPENRECOVER_SIDECAR_POLICY_JSON}")

add_subdirectory(cli)

if(OPENRECOVER_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(OPENRECOVER_BUILD_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "OPENRECOVER_BUILD_FUZZ requires clang with libFuzzer")
  endif()
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "OPENRECOVER_BUILD_FUZZ requires Linux (libFuzzer runtime support)")
  endif()
  add_subdirectory(fuzz)
endif()

if(OPENRECOVER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

install(FILES
  README.md
  RELEASE_NOTES.md
  docs/DECISIONS.md
  docs/READONLY_POLICY.md
  DESTINATION share/doc/openrecover)

# ---- library package (find_package(OpenRecover)) -------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# openrecover_core links miniz privately, and a static archive cannot hide that: the
# consumer's final link needs miniz's objects, so the archive ships in the same export set.
install(TARGETS openrecover_miniz
  EXPORT OpenRecoverTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(EXPORT OpenRecoverTargets
  NAMESPACE OpenRecover::
  FILE OpenRecoverTargets.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenRecover)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/OpenRecoverConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cmake/OpenRecoverConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenRecover)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/cmake/OpenRecoverConfigVersion.cmake
  COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cmake/OpenRecoverConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/cmake/OpenRecoverConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenRecover)

set(CPACK_PACKAGE_NAME "OpenRecover")
set(CPACK_PACKAGE_VENDOR "OpenRecover")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
  "Read-only deleted-file recovery for disks and disk images")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
if(WIN32)
  set(CPACK_GENERATOR "ZIP")
  set(CPACK_PACKAGE_FILE_NAME "openrecover-${PROJECT_VERSION}-windows-x64")
else()
  set(CPACK_GENERATOR "TGZ")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CPACK_PACKAGE_FILE_NAME "openrecover-${PROJECT_VERSION}-linux-x86_64")
  else()
    set(CPACK_PACKAGE_FILE_NAME "openrecover-${PROJECT_VERSION}-linux-${CMAKE_SYSTEM_PROCESSOR}")
  endif()
endif()
include(CPack)
