#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "fuzz_common.hpp"
#include "memory_device.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/vhdx_device.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::silence_logs();
    std::vector<uint8_t> copy;
    if (size != 0) copy.assign(data, data + size);

    auto container = std::make_shared<openrecover::test::MemoryDevice>(copy);
    auto device = openrecover::io::open_vhdx(std::move(container));
    if (!device) return 0;
    openrecover::io::BlockDevice& disk = **device;

    // A mutated header can describe 64 TiB, so probe windows instead of the whole virtual
    // disk: the interesting surface is header/region/metadata validation, BAT decoding and
    // sector-bitmap translation.
    uint8_t buf[8192];
    const uint64_t virtual_bytes = disk.info().size_bytes;
    (void)disk.read(0, buf, static_cast<size_t>(std::min<uint64_t>(virtual_bytes, sizeof(buf))));
    (void)disk.read(virtual_bytes / 2, buf, sizeof(buf));
    (void)disk.read(virtual_bytes - std::min<uint64_t>(virtual_bytes, sizeof(buf)), buf,
                    static_cast<size_t>(std::min<uint64_t>(virtual_bytes, sizeof(buf))));
    (void)disk.read(virtual_bytes, buf, 16);
    (void)disk.bad_sectors();
    return 0;
}
