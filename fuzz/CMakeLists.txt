set(OPENRECOVER_FUZZ_TARGETS
  fuzz_fat32_boot
  fuzz_fat32_dir
  fuzz_ext4_super
  fuzz_ext4_dir
  fuzz_ext4_inode
  fuzz_ntfs_record
  fuzz_ntfs_runlist
  fuzz_lznt1
  fuzz_recycle_info
  fuzz_sig_jpeg
  fuzz_sig_png
  fuzz_sig_pdf
  fuzz_sig_zip
  fuzz_sig_gif
  fuzz_sig_bmp
  fuzz_sig_tiff
  fuzz_sig_wav
  fuzz_sig_mp4
  fuzz_sig_avi
  fuzz_sig_mp3
  fuzz_sig_cfb
  fuzz_sig_sqlite
  fuzz_gpt
  fuzz_vhd
  fuzz_vhdx)

foreach(target IN LISTS OPENRECOVER_FUZZ_TARGETS)
  add_executable(${target}
    ${target}.cpp
    ${PROJECT_SOURCE_DIR}/tests/support/memory_device.cpp)
  target_include_directories(${target} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/tests/support)
  target_link_libraries(${target} PRIVATE openrecover_core)
  openrecover_set_warnings(${target})
  target_compile_options(${target} PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer)
  target_link_options(${target} PRIVATE
    -fsanitize=fuzzer,address,undefined)
endforeach()
