#include <cstddef>
#include <cstdint>

#include "fuzz_signature.hpp"
#include "openrecover/carve/sig_avi.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::run_signature(openrecover::carve::AviSignature{}, data, size);
    return 0;
}
