#include <cstddef>
#include <cstdint>
#include <span>

#include "fuzz_common.hpp"
#include "openrecover/fs/ntfs_record.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::silence_logs();
    const auto parsed =
        openrecover::fs::parse_mft_record(std::span<const uint8_t>(data, size), 0);
    (void)parsed;
    return 0;
}
