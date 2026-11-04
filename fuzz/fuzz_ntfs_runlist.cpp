#include <cstddef>
#include <cstdint>
#include <span>

#include "fuzz_common.hpp"
#include "openrecover/fs/ntfs_runlist.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::silence_logs();
    if (size < 16) return 0;
    uint64_t total_clusters = 0;
    uint64_t start_vcn = 0;
    for (int i = 0; i < 8; ++i) {
        total_clusters |= static_cast<uint64_t>(data[i]) << (8 * i);
        start_vcn |= static_cast<uint64_t>(data[8 + i]) << (8 * i);
    }
    (void)openrecover::fs::decode_runlist(
        std::span<const uint8_t>(data + 16, size - 16), start_vcn, total_clusters);
    return 0;
}
