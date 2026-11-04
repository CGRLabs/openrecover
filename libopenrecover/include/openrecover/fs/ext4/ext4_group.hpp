#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

// One block group descriptor: where the group's bitmaps and inode table live. The block
// numbers are absolute, which is how the kernel uses them -- no group-relative addition.
struct Ext4GroupDesc {
    uint64_t block_bitmap = 0;
    uint64_t inode_bitmap = 0;
    uint64_t inode_table = 0;
    uint32_t free_blocks_count = 0;
    uint32_t free_inodes_count = 0;
    uint32_t used_dirs_count = 0;
    uint16_t flags = 0;
    uint16_t itable_unused = 0;
    uint16_t checksum = 0;
    uint32_t checksum_value = 0;   // the full 32-bit CRC on a metadata_csum volume

    // The table entries whose checksum is wrong are still readable; a caller asks whether
    // an entry was verified before trusting its free counts.
    bool checksum_verified = false;

    // A group whose inode table was never written holds no deleted inode worth hunting.
    bool inode_table_uninit() const noexcept { return (flags & kBgInodeUninit) != 0; }
    bool inode_table_zeroed() const noexcept { return (flags & kBgInodeZeroed) != 0; }

    static constexpr uint16_t kBgInodeUninit = 0x0001;
    static constexpr uint16_t kBgBlockUninit = 0x0002;
    static constexpr uint16_t kBgInodeZeroed = 0x0004;
};

// Reads and verifies a single descriptor. `raw` must hold s.desc_size bytes.
Result<Ext4GroupDesc> parse_group_desc(std::span<const uint8_t> raw, const Ext4Super& s,
                                       uint32_t group);

// The descriptor table of a volume, read a block at a time and cached. Only the primary
// GDT is used; backup copies are located for geometry but never trusted over it.
class Ext4GroupTable {
public:
    Ext4GroupTable(std::shared_ptr<io::BlockDevice> dev, Ext4Super super);

    // The block number at which group `group`'s descriptor starts.
    uint64_t descriptor_block(uint32_t group) const;
    Result<Ext4GroupDesc> at(uint32_t group);

    uint64_t gdt_start_block() const noexcept { return gdt_start_; }
    uint64_t gdt_blocks() const noexcept { return gdt_blocks_; }

private:
    struct CacheBlock {
        uint64_t block = 0;
        std::vector<uint8_t> bytes;
    };

    Result<std::span<const uint8_t>> block(uint64_t blk);

    std::shared_ptr<io::BlockDevice> dev_;
    Ext4Super super_;
    uint64_t gdt_start_ = 0;
    uint64_t gdt_blocks_ = 0;
    std::vector<CacheBlock> cache_;  // small and LRU-ish; a scan touches them in order
};

}  // namespace openrecover::fs
