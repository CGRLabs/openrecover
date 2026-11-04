add_library(openrecover_core STATIC
  src/android/adb_command_policy.cpp
  src/android/adb_transport.cpp
  src/android/android_bridge.cpp
  src/android/child_process.cpp
  src/android/scan_profile.cpp
  src/android/sidecar_transport.cpp
  src/android/usb_enumerator.cpp
  src/common/bytes.cpp
  src/common/crc32.cpp
  src/common/crc32c.cpp
  src/common/error.cpp
  src/common/hash.cpp
  src/common/log.cpp
  src/carve/bounded_reader.cpp
  src/carve/carve_engine.cpp
  src/carve/sig_bmp.cpp
  src/carve/sig_cfb.cpp
  src/carve/sig_avi.cpp
  src/carve/sig_mp3.cpp
  src/carve/sig_mp4.cpp
  src/carve/sig_tiff.cpp
  src/carve/sig_wav.cpp
  src/carve/sig_gif.cpp
  src/carve/sig_jpeg.cpp
  src/carve/sig_png.cpp
  src/carve/sig_sqlite.cpp
  src/carve/sig_pdf.cpp
  src/carve/sig_zip.cpp
  src/carve/sig_generic.cpp
  src/carve/signature.cpp
  src/fs/detect.cpp
  src/fs/fat32.cpp
  src/fs/lznt1.cpp
  src/fs/ntfs.cpp
  src/fs/ntfs_attributes.cpp
  src/fs/ntfs_boot.cpp
  src/fs/exfat/exfat_boot.cpp
  src/fs/exfat/exfat_fat.cpp
  src/fs/exfat/exfat_dir.cpp
  src/fs/exfat/exfat_scanner.cpp
  src/fs/ext4/ext4_boot.cpp
  src/fs/ext4/ext4_checksum.cpp
  src/fs/ext4/ext4_group.cpp
  src/fs/ext4/ext4_inode.cpp
  src/fs/ext4/ext4_dir.cpp
  src/fs/ext4/ext4_scanner.cpp
  src/fs/ntfs_record.cpp
  src/fs/ntfs_runlist.cpp
  src/fs/ntfs_recyclebin.cpp
  src/io/block_device.cpp
  src/io/cached_device.cpp
  src/io/image_device.cpp
  src/io/output_sink.cpp
  src/io/partition_view.cpp
  src/io/readonly_guard.cpp
  src/io/vhd_device.cpp
  src/io/vhdx_device.cpp
  src/io/win_physical_device.cpp
  src/partition/gpt.cpp
  src/partition/mbr.cpp
  src/partition/partition_scanner.cpp
  src/recover/recover.cpp
  src/report/report.cpp
)

if(WIN32)
  target_sources(openrecover_core PRIVATE
    src/io/win/win32_api_real.cpp
    platform/windows/usb_enumerator_win.cpp)
  target_link_libraries(openrecover_core PRIVATE setupapi)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(openrecover_core PRIVATE
    src/io/linux/linux_block_device.cpp
    platform/linux/usb_enumerator_linux.cpp)
endif()

include(GNUInstallDirs)

target_include_directories(openrecover_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${PROJECT_SOURCE_DIR}/third_party)

# The fetched header-only dependencies are wrapped in BUILD_INTERFACE so they stay out of the
# exported interface: an installed consumer gets the same headers from the package's include
# directory instead of a target that only exists in a build tree.
target_link_libraries(openrecover_core
  PUBLIC $<BUILD_INTERFACE:tl::expected nlohmann_json::nlohmann_json>
  PRIVATE openrecover_miniz)

add_library(OpenRecover::core ALIAS openrecover_core)
set_target_properties(openrecover_core PROPERTIES EXPORT_NAME core)

target_compile_features(openrecover_core PUBLIC cxx_std_20)
set_target_properties(openrecover_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
openrecover_set_warnings(openrecover_core)
if(OPENRECOVER_BUILD_FUZZ)
  # The parsers, not just the harness, must be instrumented for ASan/UBSan and coverage.
  target_compile_options(openrecover_core PRIVATE
    -fsanitize=fuzzer-no-link,address,undefined
    -fno-omit-frame-pointer)
  target_link_options(openrecover_core INTERFACE -fsanitize=address,undefined)
endif()

install(TARGETS openrecover_core
  EXPORT OpenRecoverTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/openrecover"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# common/result.hpp is public API and includes <tl/expected.hpp>, so the package ships it.
install(FILES "${tl_expected_SOURCE_DIR}/include/tl/expected.hpp"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tl")
