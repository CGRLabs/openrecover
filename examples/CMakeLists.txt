# Usage examples. They link the library the way a consumer does and are built by default so a
# public-API break fails the normal build, but they are never installed.
add_executable(example_recover_image recover_image.cpp)
target_link_libraries(example_recover_image PRIVATE OpenRecover::core)
openrecover_set_warnings(example_recover_image)
