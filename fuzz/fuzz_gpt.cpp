#include <cstddef>
#include <cstdint>
#include <vector>

#include "fuzz_common.hpp"
#include "memory_device.hpp"
#include "openrecover/partition/gpt.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::silence_logs();
    std::vector<uint8_t> copy;
    if (size != 0) copy.assign(data, data + size);
    openrecover::test::MemoryDevice device(copy);
    (void)openrecover::partition::parse_gpt(device);
    return 0;
}
