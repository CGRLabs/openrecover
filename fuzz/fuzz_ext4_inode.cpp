#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "fuzz_common.hpp"
#include "fuzz_ext4_common.hpp"
#include "memory_device.hpp"
#include "openrecover/fs/ext4/ext4_inode.hpp"
#include "openrecover/fs/ext4/ext4_scanner.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace openrecover;
    fuzz::silence_logs();
    const fs::Ext4Super plain = fuzz::ext4_super(false);
    const fs::Ext4Super csum = fuzz::ext4_super(true);

    // The input doubles as the volume an inode's extent tree or indirect blocks point
    // into, so a child block number the fuzzer picked lands on bytes it also controls.
    const std::vector<uint8_t> bytes(data, data + size);
    test::MemoryDevice dev(bytes, 512);
    const std::span<const uint8_t> input(data, size);

    for (const fs::Ext4Super* s : {&plain, &csum}) {
        for (size_t off = 0; off + s->inode_size <= size; off += s->inode_size) {
            const uint32_t number = 11 + static_cast<uint32_t>(off / s->inode_size);
            auto inode = fs::parse_inode(input.subspan(off, s->inode_size), *s, number);
            if (!inode) continue;
            (void)fs::Ext4Scanner::inline_data(*inode);
            auto runs = fs::Ext4Scanner::map_inode(dev, *s, *inode);
            if (runs) (void)fs::Ext4Scanner::extents_from_runs(*runs, s->block_size, inode->size);
        }
    }
    return 0;
}
