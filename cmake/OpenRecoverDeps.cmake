include(FetchContent)

# All dependencies are pinned by release archive + SHA-256.

FetchContent_Declare(tl_expected
  URL https://github.com/TartanLlama/expected/archive/refs/tags/v1.1.0.tar.gz
  URL_HASH SHA256=1db357f46dd2b24447156aaf970c4c40a793ef12a8a9c2ad9e096d9801368df6
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  EXCLUDE_FROM_ALL)

FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

FetchContent_Declare(cli11
  URL https://github.com/CLIUtils/CLI11/archive/refs/tags/v2.4.2.tar.gz
  URL_HASH SHA256=f2d893a65c3b1324c50d4e682c0cdc021dd0477ae2c048544f39eed6654b699a
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

FetchContent_Declare(miniz_src
  URL https://github.com/richgel999/miniz/releases/download/3.0.2/miniz-3.0.2.zip
  URL_HASH SHA256=ada38db0b703a56d3dd6d57bf84a9c5d664921d870d8fea4db153979fb5332c5
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(EXPECTED_BUILD_PACKAGE OFF CACHE BOOL "" FORCE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(CLI11_PRECOMPILED OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(tl_expected nlohmann_json cli11)

# miniz release zip ships the amalgamated miniz.c/miniz.h; build it directly.
FetchContent_MakeAvailable(miniz_src)
add_library(openrecover_miniz STATIC ${miniz_src_SOURCE_DIR}/miniz.c)
# Only the library's own translation units include miniz.h, and the package exports this
# archive, so its headers and its MINIZ_NO_* configuration stay inside the build tree.
target_include_directories(openrecover_miniz SYSTEM
  PUBLIC $<BUILD_INTERFACE:${miniz_src_SOURCE_DIR}>)
target_compile_definitions(openrecover_miniz PUBLIC
  $<BUILD_INTERFACE:MINIZ_NO_ZLIB_COMPATIBLE_NAMES MINIZ_NO_STDIO MINIZ_NO_ARCHIVE_APIS MINIZ_NO_TIME>)
set_target_properties(openrecover_miniz PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  target_compile_options(openrecover_miniz PRIVATE /W0)
else()
  target_compile_options(openrecover_miniz PRIVATE -w)
endif()
if(OPENRECOVER_BUILD_FUZZ)
  target_compile_options(openrecover_miniz PRIVATE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer)
endif()

if(OPENRECOVER_BUILD_TESTS)
  FetchContent_Declare(catch2
    URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.7.1.tar.gz
    URL_HASH SHA256=c991b247a1a0d7bb9c39aa35faf0fe9e19764213f28ffba3109388e62ee0269c
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(catch2)
  list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
  if(MSVC)
    # Catch2 decides at compile time whether exceptions exist. Without /EHsc it builds itself with
    # them off, so a failed REQUIRE cannot unwind: the runner aborts instead of reporting the
    # failure, and a hung process is what a CI job sees.
    foreach(catch_target IN ITEMS Catch2 Catch2WithMain)
      if(TARGET ${catch_target})
        target_compile_options(${catch_target} PRIVATE /EHsc)
      endif()
    endforeach()
  endif()
endif()
