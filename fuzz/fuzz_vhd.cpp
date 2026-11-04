#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "fuzz_common.hpp"
#include "memory_device.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/vhd_device.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::silence_logs();
    std::vector<uint8_t> copy;
    if (size != 0) copy.assign(data, data + size);

    auto container = std::make_shared<openrecover::test::MemoryDevice>(copy);
    auto device = openrecover::io::open_vhd(std::move(container));
    if (!device) return 0;
    openrecover::io::BlockDevice& disk = **device;

    // A mutated footer can describe terabytes, so probe windows instead of the whole mapped
    // disk: the target is the block and sector-bitmap translation, not the volume size.
    uint8_t buf[8192];
    const uint64_t virtual_bytes = disk.info().size_bytes;
    (void)disk.read(0, buf, static_cast<size_t>(std::min<uint64_t>(virtual_bytes, sizeof(buf))));
    (void)disk.read(virtual_bytes / 2, buf, sizeof(buf));
    (void)disk.read(virtual_bytes, buf, 16);
    (void)disk.bad_sectors();
    return 0;
}
