#include <cstddef>
#include <cstdint>

#include "fuzz_signature.hpp"
#include "openrecover/carve/sig_mp4.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::run_signature(openrecover::carve::Mp4Signature{}, data, size);
    return 0;
}
