#include "openrecover/fs/ext4/ext4_group.hpp"

#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/fs/ext4/ext4_checksum.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {
namespace {

namespace lay = ext4_layout;

// ext4_group_desc_csum, the metadata_csum branch: the running CRC32c seeded with
// s_checksum_seed, fed the 4-byte group number, the descriptor up to bg_checksum, two zero
// bytes in place of that field, then whatever follows it in a 64-byte descriptor. The
// stored value is the low 16 bits, un-inverted.
uint32_t descriptor_csum32(std::span<const uint8_t> d, uint32_t seed, uint32_t group,
                           uint32_t desc_size) {
    const auto head = le32_bytes(group);
    uint32_t state = crc32c_continue(seed, head.data(), head.size());
    state = crc32c_continue(state, d.data(), lay::kBgChecksum);
    state = crc32c_zeros(state, 2);
    if (lay::kBgChecksum + 2 < desc_size)
        state = crc32c_continue(state, d.data() + lay::kBgChecksum + 2,
                                desc_size - (lay::kBgChecksum + 2));
    return state;
}

// The same function's crc16 branch, used on a GDT_CSUM volume that predates
// metadata_csum: the chain restarts from the UUID instead of a stored seed, and only a
// 64-byte descriptor has bytes past the checksum field.
uint16_t descriptor_csum16(std::span<const uint8_t> d, const uint8_t* uuid, uint32_t group,
                           bool is_64bit, uint32_t desc_size) {
    const auto head = le32_bytes(group);
    uint16_t crc = crc16_continue(0xFFFFu, uuid, 16);
    crc = crc16_continue(crc, head.data(), head.size());
    crc = crc16_continue(crc, d.data(), lay::kBgChecksum);
    if (is_64bit && lay::kBgChecksum + 2 < desc_size)
        crc = crc16_continue(crc, d.data() + lay::kBgChecksum + 2,
                             desc_size - (lay::kBgChecksum + 2));
    return crc;
}

}  // namespace

Result<Ext4GroupDesc> parse_group_desc(std::span<const uint8_t> raw, const Ext4Super& s,
                                       uint32_t group) {
    if (raw.size() < s.desc_size)
        return fail(ErrorCode::CorruptStructure, "ext4: group descriptor is truncated");
    if (group >= s.group_count())
        return fail(ErrorCode::InvalidArgument, "ext4: group number is past the volume");

    Ext4GroupDesc g;
    g.block_bitmap = u32_at(raw, lay::kBgBlockBitmap);
    g.inode_bitmap = u32_at(raw, lay::kBgInodeBitmap);
    g.inode_table = u32_at(raw, lay::kBgInodeTable);
    g.free_blocks_count = u16_at(raw, lay::kBgFreeBlocksCount);
    g.free_inodes_count = u16_at(raw, lay::kBgFreeInodesCount);
    g.used_dirs_count = u16_at(raw, lay::kBgUsedDirsCount);
    g.flags = u16_at(raw, lay::kBgFlags);
    g.itable_unused = u16_at(raw, lay::kBgItableUnused);
    g.checksum = u16_at(raw, lay::kBgChecksum);

    if (s.incompatible_64bit()) {
        g.block_bitmap |= static_cast<uint64_t>(u32_at(raw, lay::kBgBlockBitmapHi)) << 32;
        g.inode_bitmap |= static_cast<uint64_t>(u32_at(raw, lay::kBgInodeBitmapHi)) << 32;
        g.inode_table |= static_cast<uint64_t>(u32_at(raw, lay::kBgInodeTableHi)) << 32;
        g.free_blocks_count |= static_cast<uint32_t>(u16_at(raw, 44)) << 16;
        g.free_inodes_count |= static_cast<uint32_t>(u16_at(raw, 46)) << 16;
        g.used_dirs_count |= static_cast<uint32_t>(u16_at(raw, 48)) << 16;
    }

    // Every group's first block is offset by s_first_data_block, not just group 0: on a
    // 2 KiB or 4 KiB volume the whole filesystem is shifted by one block.
    const uint64_t group_start =
        static_cast<uint64_t>(group) * s.blocks_per_group + s.first_data_block;
    const uint64_t group_blocks =
        group_start >= s.blocks_count
            ? 0
            : (group_start + s.blocks_per_group > s.blocks_count ? s.blocks_count - group_start
                                                                 : s.blocks_per_group);

    // The three locations are absolute block numbers; a descriptor that points outside the
    // volume is either damaged or is bytes that are not a descriptor at all.
    if (g.block_bitmap >= s.blocks_count)
        return fail(ErrorCode::CorruptStructure, "ext4: block bitmap is past the volume");
    if (g.inode_bitmap >= s.blocks_count)
        return fail(ErrorCode::CorruptStructure, "ext4: inode bitmap is past the volume");
    if (g.inode_table >= s.blocks_count)
        return fail(ErrorCode::CorruptStructure, "ext4: inode table is past the volume");

    const uint64_t table_blocks =
        (static_cast<uint64_t>(s.inodes_per_group) * s.inode_size + s.block_size - 1) /
        s.block_size;
    const bool uninit = g.inode_table_uninit() || g.inode_table_zeroed();
    if (!uninit && g.inode_table + table_blocks > s.blocks_count)
        return fail(ErrorCode::CorruptStructure, "ext4: inode table runs past the volume");

    if (g.free_blocks_count > group_blocks)
        return fail(ErrorCode::CorruptStructure, "ext4: free-block count exceeds the group");
    if (g.free_inodes_count > s.inodes_per_group)
        return fail(ErrorCode::CorruptStructure, "ext4: free-inode count exceeds the group");

    if (s.metadata_csum()) {
        g.checksum_value = descriptor_csum32(raw, s.checksum_seed, group, s.desc_size);
        g.checksum_verified = static_cast<uint16_t>(g.checksum_value & 0xFFFFu) == g.checksum;
    } else if (s.gdt_csum()) {
        g.checksum_verified =
            descriptor_csum16(raw, s.uuid, group, s.incompatible_64bit(), s.desc_size) ==
            g.checksum;
    } else {
        g.checksum_verified = false;  // this volume type stores no descriptor checksum
    }

    return g;
}

Ext4GroupTable::Ext4GroupTable(std::shared_ptr<io::BlockDevice> dev, Ext4Super super)
    : dev_(std::move(dev)), super_(super) {
    // The superblock occupies bytes 1024..2047, so the descriptor table begins at the first
    // whole block above that range: block 2 with 1 KiB blocks, block 1 with 2 KiB or 4 KiB.
    gdt_start_ =
        (lay::kSuperOffset + lay::kSuperBytes + super_.block_size - 1) / super_.block_size;
    const uint64_t bytes = super_.group_count() * super_.desc_size;
    gdt_blocks_ = (bytes + super_.block_size - 1) / super_.block_size;
}

uint64_t Ext4GroupTable::descriptor_block(uint32_t group) const {
    const uint64_t byte = static_cast<uint64_t>(group) * super_.desc_size;
    return gdt_start_ + byte / super_.block_size;
}

Result<std::span<const uint8_t>> Ext4GroupTable::block(uint64_t blk) {
    for (const auto& c : cache_)
        if (c.block == blk)
            return std::span<const uint8_t>(c.bytes.data(), c.bytes.size());
    if (blk >= super_.blocks_count)
        return fail(ErrorCode::CorruptStructure, "ext4: descriptor block is past the volume");
    std::vector<uint8_t> buf(super_.block_size);
    auto got = io::read_fully(*dev_, super_.block_to_byte(blk), buf.data(), buf.size());
    if (!got || *got < buf.size())
        return fail(ErrorCode::IoError, "ext4: group descriptor table read failed");
    if (cache_.size() >= 8) cache_.erase(cache_.begin());
    cache_.push_back(CacheBlock{blk, std::move(buf)});
    const auto& stored = cache_.back();
    return std::span<const uint8_t>(stored.bytes.data(), stored.bytes.size());
}

Result<Ext4GroupDesc> Ext4GroupTable::at(uint32_t group) {
    if (group >= super_.group_count())
        return fail(ErrorCode::InvalidArgument, "ext4: group number is past the volume");
    const uint64_t byte_in_gdt = static_cast<uint64_t>(group) * super_.desc_size;
    const uint64_t blk = gdt_start_ + byte_in_gdt / super_.block_size;
    const uint32_t off = static_cast<uint32_t>(byte_in_gdt % super_.block_size);
    auto bytes = block(blk);
    if (!bytes) return fail(bytes.error());
    if (off + super_.desc_size > bytes->size())
        return fail(ErrorCode::CorruptStructure, "ext4: descriptor crosses the block edge");
    return parse_group_desc(bytes->subspan(off, super_.desc_size), super_, group);
}

}  // namespace openrecover::fs
