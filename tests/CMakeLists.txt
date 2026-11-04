add_library(openrecover_test_support STATIC
  support/memory_device.cpp
  support/fake_win32_api.cpp
  support/fake_adb_transport.cpp
  support/test_util.cpp)
target_include_directories(openrecover_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/support)
target_link_libraries(openrecover_test_support PUBLIC openrecover_core)
openrecover_set_warnings(openrecover_test_support)

# openrecover_add_unit_test(<name> LABEL <label> [SOURCES ...])
function(openrecover_add_unit_test name)
  cmake_parse_arguments(T "" "LABEL" "SOURCES" ${ARGN})
  if(NOT T_SOURCES)
    set(T_SOURCES unit/${name}.cpp)
  endif()
  add_executable(${name} ${T_SOURCES})
  target_link_libraries(${name} PRIVATE openrecover_test_support Catch2::Catch2WithMain)
  openrecover_set_warnings(${name})
  add_test(NAME ${name} COMMAND ${name} --order lex --warn NoAssertions)
  # Catch2 returns 4 when every test case was skipped (e.g. optional tool missing).
  set_tests_properties(${name} PROPERTIES LABELS "${T_LABEL}" SKIP_RETURN_CODE 4)
endfunction()

# ---- M0 ----
openrecover_add_unit_test(test_bytes LABEL M0)
openrecover_add_unit_test(test_block_device LABEL M0)
openrecover_add_unit_test(test_win32_flags LABEL M0)
openrecover_add_unit_test(test_readonly_guard LABEL M0)
openrecover_add_unit_test(test_vhd_device LABEL M0)
target_compile_definitions(test_vhd_device PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/vhd")
openrecover_add_unit_test(test_vhdx_device LABEL M0)
target_compile_definitions(test_vhdx_device PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/vhdx")

# ---- M2 ----
openrecover_add_unit_test(test_ntfs_parse LABEL M2)
openrecover_add_unit_test(test_ntfs_record LABEL M2)
openrecover_add_unit_test(test_ntfs_runlist LABEL M2)
openrecover_add_unit_test(test_lznt1 LABEL M2)
openrecover_add_unit_test(test_ntfs_scanner LABEL M2)
openrecover_add_unit_test(test_ntfs_recyclebin LABEL M2)

# ---- M3 ----
openrecover_add_unit_test(test_bounded_reader LABEL M3)
openrecover_add_unit_test(test_carve_engine LABEL M3)
openrecover_add_unit_test(test_sig_bmp LABEL M3)
openrecover_add_unit_test(test_sig_tiff LABEL M3)
target_compile_definitions(test_sig_tiff PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/sig_tiff")
openrecover_add_unit_test(test_sig_wav LABEL M3)
target_compile_definitions(test_sig_wav PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/sig_wav")
openrecover_add_unit_test(test_sig_mp4 LABEL M3)
target_compile_definitions(test_sig_mp4 PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/sig_mp4")
openrecover_add_unit_test(test_sig_avi LABEL M3)
target_compile_definitions(test_sig_avi PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/sig_avi")
openrecover_add_unit_test(test_sig_mp3 LABEL M3)
target_compile_definitions(test_sig_mp3 PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/sig_mp3")
openrecover_add_unit_test(test_sig_cfb LABEL M3)
target_compile_definitions(test_sig_cfb PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/sig_cfb")
openrecover_add_unit_test(test_sig_sqlite LABEL M3)
target_compile_definitions(test_sig_sqlite PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/sig_sqlite")
openrecover_add_unit_test(test_sig_gif LABEL M3)
openrecover_add_unit_test(test_sig_jpeg LABEL M3)
openrecover_add_unit_test(test_sig_png LABEL M3)
openrecover_add_unit_test(test_sig_pdf LABEL M3)
openrecover_add_unit_test(test_sig_zip LABEL M3)

# ---- M1 ----
openrecover_add_unit_test(test_exfat_parse LABEL M1)
openrecover_add_unit_test(test_exfat_scanner LABEL M1)
openrecover_add_unit_test(test_exfat_fat LABEL M1)
openrecover_add_unit_test(test_exfat_dir LABEL M1)
openrecover_add_unit_test(test_exfat_malformed LABEL M1)
openrecover_add_unit_test(test_exfat_fragmented LABEL M1)
openrecover_add_unit_test(test_mbr_gpt LABEL M1)
openrecover_add_unit_test(test_fat32_parse LABEL M1)
openrecover_add_unit_test(test_fat32_scan LABEL M1)
openrecover_add_unit_test(test_ext4_parse LABEL M1)
openrecover_add_unit_test(test_ext4_dir LABEL M1)
openrecover_add_unit_test(test_ext4_scanner LABEL M1)
openrecover_add_unit_test(test_ext4_fuzz_seeds LABEL M1)
target_compile_definitions(test_ext4_fuzz_seeds PRIVATE
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz")

# ---- M4 ----
add_executable(fake_adb support/fake_adb_main.cpp)
openrecover_set_warnings(fake_adb)
if(MSVC)
  target_compile_definitions(fake_adb PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

openrecover_add_unit_test(test_android_policy LABEL M4)
openrecover_add_unit_test(test_android_transport LABEL M4)
openrecover_add_unit_test(test_usb_enumerator LABEL M4)
openrecover_add_unit_test(test_android_bridge LABEL M4)
target_compile_definitions(test_android_bridge PRIVATE
  OPENRECOVER_ANDROID_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/android/fake_sdcard"
  OPENRECOVER_PROFILE_DIR="${PROJECT_SOURCE_DIR}/profiles")
target_compile_definitions(test_android_transport PRIVATE
  OPENRECOVER_FAKE_ADB="$<TARGET_FILE:fake_adb>")
if(MSVC)
  target_compile_definitions(test_android_transport PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_dependencies(test_android_transport fake_adb)

openrecover_add_unit_test(test_android_sidecar LABEL M4)
target_compile_definitions(test_android_sidecar PRIVATE
  OPENRECOVER_FAKE_ADB="$<TARGET_FILE:fake_adb>"
  OPENRECOVER_SIDECAR_SCRIPT="${PROJECT_SOURCE_DIR}/tools/adb_sidecar/sidecar.py"
  OPENRECOVER_SIDECAR_POLICY_PY="${PROJECT_SOURCE_DIR}/tools/adb_sidecar/policy.py"
  OPENRECOVER_SIDECAR_STUB="${CMAKE_CURRENT_SOURCE_DIR}/support/sidecar_stub.py"
  OPENRECOVER_SIDECAR_POLICY_JSON="${OPENRECOVER_SIDECAR_POLICY_JSON}")
if(MSVC)
  target_compile_definitions(test_android_sidecar PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_dependencies(test_android_sidecar fake_adb adb_sidecar_policy)

# ---- M5 ----
openrecover_add_unit_test(test_report LABEL M5)

# Decompress the committed fixture images into the build tree at configure time.
set(OPENRECOVER_GOLDEN_DIR "${PROJECT_SOURCE_DIR}/tests/fixtures/golden")
set(OPENRECOVER_FIXTURE_DIR "")
if(Python3_Interpreter_FOUND)
  set(OPENRECOVER_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/fixtures/images")
  execute_process(
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/fixtures/decompress_gz.py
            ${PROJECT_SOURCE_DIR}/tests/fixtures/images
            ${OPENRECOVER_FIXTURE_DIR}
    RESULT_VARIABLE OPENRECOVER_FIXTURE_RESULT)
  if(NOT OPENRECOVER_FIXTURE_RESULT EQUAL 0)
    message(FATAL_ERROR "failed to decompress the committed disk-image fixtures")
  endif()
else()
  message(WARNING "Python3 not found: disk-image tests will be skipped")
endif()

openrecover_add_unit_test(test_carve_fixtures LABEL M3)
target_compile_definitions(test_carve_fixtures PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}"
  OPENRECOVER_GOLDEN_DIR="${OPENRECOVER_GOLDEN_DIR}")

openrecover_add_unit_test(test_fat32_recover LABEL M1)
target_compile_definitions(test_fat32_recover PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}"
  OPENRECOVER_GOLDEN_DIR="${OPENRECOVER_GOLDEN_DIR}")

openrecover_add_unit_test(test_exfat_recover LABEL M1)
target_compile_definitions(test_exfat_recover PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}"
  OPENRECOVER_GOLDEN_DIR="${OPENRECOVER_GOLDEN_DIR}")

openrecover_add_unit_test(test_ext4_recover LABEL M1)
target_compile_definitions(test_ext4_recover PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}"
  OPENRECOVER_GOLDEN_DIR="${OPENRECOVER_GOLDEN_DIR}")

# Single-byte corruption of the committed ext4 image, so the reader's failure modes on a
# damaged volume are tested on a real volume rather than only the in-memory fixture.
openrecover_add_unit_test(test_ext4_mutation LABEL M1)
target_compile_definitions(test_ext4_mutation PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}")

openrecover_add_unit_test(test_vhd_recover LABEL M1)
target_compile_definitions(test_vhd_recover PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}"
  OPENRECOVER_GOLDEN_DIR="${OPENRECOVER_GOLDEN_DIR}")

openrecover_add_unit_test(test_vhdx_recover LABEL M1)
target_compile_definitions(test_vhdx_recover PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}"
  OPENRECOVER_GOLDEN_DIR="${OPENRECOVER_GOLDEN_DIR}")

openrecover_add_unit_test(test_ntfs_recover LABEL M2)
target_compile_definitions(test_ntfs_recover PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}"
  OPENRECOVER_GOLDEN_DIR="${OPENRECOVER_GOLDEN_DIR}"
  OPENRECOVER_FUZZ_SEED_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz/ntfs_record")

# The high-level façade is what a consumer links against, so it is tested on the real fixtures.
openrecover_add_unit_test(test_recover_api LABEL M5)
target_compile_definitions(test_recover_api PRIVATE
  OPENRECOVER_FIXTURE_DIR="${OPENRECOVER_FIXTURE_DIR}")

if(Python3_Interpreter_FOUND)
  add_test(NAME readonly_static_check
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/check_readonly.py --root ${PROJECT_SOURCE_DIR})
  add_test(NAME readonly_static_selftest
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/check_readonly.py --selftest)
  set_tests_properties(readonly_static_check readonly_static_selftest PROPERTIES LABELS M0)
else()
  message(WARNING "Python3 not found: readonly_static_check will fail")
  add_test(NAME readonly_static_check COMMAND ${CMAKE_COMMAND} -E false)
  set_tests_properties(readonly_static_check PROPERTIES LABELS M0)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(readonly_probe support/readonly_probe.cpp)
  target_link_libraries(readonly_probe PRIVATE openrecover_core)
  openrecover_set_warnings(readonly_probe)

  openrecover_add_unit_test(test_readonly_syscalls LABEL M0)
  target_compile_definitions(test_readonly_syscalls PRIVATE OPENRECOVER_PROBE_PATH="$<TARGET_FILE:readonly_probe>")
  add_dependencies(test_readonly_syscalls readonly_probe)
endif()

# End-to-end CLI checks need the decompressed images (set above) and fake_adb.
if(Python3_Interpreter_FOUND AND OPENRECOVER_FIXTURE_DIR)
  add_test(NAME cli_e2e COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/e2e/cli_e2e.py
    --exe $<TARGET_FILE:openrecover>
    --fixtures "${OPENRECOVER_FIXTURE_DIR}"
    --golden "${OPENRECOVER_GOLDEN_DIR}"
    --work "${CMAKE_CURRENT_BINARY_DIR}/e2e-work"
    --fake-adb $<TARGET_FILE:fake_adb>
    --android-fixture "${PROJECT_SOURCE_DIR}/tests/fixtures/android/fake_sdcard"
    --profiles "${PROJECT_SOURCE_DIR}/profiles")
  set_tests_properties(cli_e2e PROPERTIES LABELS M5 TIMEOUT 300)

  add_test(NAME cli_stress_sparse COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/e2e/cli_stress.py
    --exe $<TARGET_FILE:openrecover>
    --fixture "${OPENRECOVER_FIXTURE_DIR}/carve_mixed.img"
    --work "${CMAKE_CURRENT_BINARY_DIR}/e2e-stress")
  set_tests_properties(cli_stress_sparse PROPERTIES LABELS M5 TIMEOUT 300)

  if(OPENRECOVER_NIGHTLY_TESTS)
    add_test(NAME cli_stress_sparse_nightly COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/e2e/cli_stress.py
      --exe $<TARGET_FILE:openrecover>
      --fixture "${OPENRECOVER_FIXTURE_DIR}/carve_mixed.img"
      --work "${CMAKE_CURRENT_BINARY_DIR}/e2e-stress-nightly"
      --nightly)
    set_tests_properties(cli_stress_sparse_nightly PROPERTIES LABELS M5-nightly TIMEOUT 3600)
  endif()
elseif(Python3_Interpreter_FOUND)
  message(WARNING "Disk-image fixtures unavailable: cli_e2e will be skipped")
endif()

# The example is a consumer: if the public API drifts, this is what fails first.
if(Python3_Interpreter_FOUND AND OPENRECOVER_FIXTURE_DIR AND OPENRECOVER_BUILD_EXAMPLES)
  add_test(NAME example_runs COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/e2e/example_runs.py
    $<TARGET_FILE:example_recover_image>
    "${OPENRECOVER_FIXTURE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/example-work")
  set_tests_properties(example_runs PROPERTIES LABELS M5 TIMEOUT 600)
endif()

# Packaging is checked by installing into the build tree and auditing the layout, which needs no
# compiler: the export set, the header closure, and the absence of build-tree paths.
if(Python3_Interpreter_FOUND)
  add_test(NAME install_layout COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/e2e/install_layout.py
    --cmake ${CMAKE_COMMAND}
    --build-dir ${CMAKE_BINARY_DIR}
    --prefix "${CMAKE_CURRENT_BINARY_DIR}/install-check")
  set_tests_properties(install_layout PROPERTIES LABELS M5 TIMEOUT 300)
endif()
