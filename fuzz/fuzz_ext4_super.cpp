#include <cstddef>
#include <cstdint>
#include <vector>

#include "fuzz_common.hpp"
#include "memory_device.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace openrecover;
    fuzz::silence_logs();
    if (size < fs::ext4_layout::kSuperOffset + fs::ext4_layout::kSuperBytes) return 0;

    // The superblock's own reader validates the geometry against the device size, so the
    // input is presented as the whole volume rather than the one block that holds it.
    const std::vector<uint8_t> bytes(data, data + size);
    test::MemoryDevice dev(bytes, 512);
    auto super = fs::read_superblock(dev);
    if (!super) return 0;

    (void)super->group_count();
    // Sparse-super placement walks a power-of-three ladder; a group number the fuzzer
    // picked is as good a way as any to drive it.
    for (uint32_t group = 0; group < 64; ++group) (void)super->has_super_copy(group);
    (void)super->inode_csum_verifiable();
    (void)super->block_to_byte(super->blocks_count);
    return 0;
}
