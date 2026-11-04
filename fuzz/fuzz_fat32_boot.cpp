#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "fuzz_common.hpp"
#include "memory_device.hpp"
#include "openrecover/fs/fat32.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace openrecover;
    fuzz::silence_logs();
    const std::span<const uint8_t> bytes(data, size);
    const std::span<const uint8_t> sector =
        bytes.first(std::min<size_t>(size, 512));
    (void)fs::parse_fat32_bpb(sector, size);

    if (size >= 0x28) {
        uint64_t declared_size = 0;
        for (int i = 0; i < 8; ++i)
            declared_size |= static_cast<uint64_t>(data[i]) << (8 * i);
        (void)fs::parse_fat32_bpb(sector, declared_size);

        const uint64_t total_sectors =
            static_cast<uint64_t>(data[0x20]) | (static_cast<uint64_t>(data[0x21]) << 8) |
            (static_cast<uint64_t>(data[0x22]) << 16) | (static_cast<uint64_t>(data[0x23]) << 24);
        const uint64_t bytes_per_sector =
            static_cast<uint64_t>(data[0x0B]) | (static_cast<uint64_t>(data[0x0C]) << 8);
        if (total_sectors != 0 && bytes_per_sector != 0 &&
            total_sectors <= UINT64_MAX / bytes_per_sector) {
            (void)fs::parse_fat32_bpb(sector, total_sectors * bytes_per_sector);
        }
    }

    std::vector<uint8_t> copy;
    if (size != 0) copy.assign(data, data + size);
    test::MemoryDevice device(copy);
    (void)fs::read_fat32_bpb(device);
    return 0;
}
