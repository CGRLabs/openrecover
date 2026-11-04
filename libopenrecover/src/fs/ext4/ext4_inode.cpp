#include "openrecover/fs/ext4/ext4_inode.hpp"

#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"
#include "openrecover/fs/ext4/ext4_checksum.hpp"

namespace openrecover::fs {
namespace {

namespace lay = ext4_layout;

}  // namespace

Result<Ext4ExtNode> parse_ext_node(std::span<const uint8_t> bytes, const Ext4Super& s,
                                   bool leaf) {
    if (bytes.size() < lay::kExtHeaderBytes)
        return fail(ErrorCode::CorruptStructure, "ext4: extent node is truncated");
    if (u16_at(bytes, 0) != lay::kExtMagic)
        return fail(ErrorCode::CorruptStructure, "ext4: extent magic 0xF30A is absent");

    Ext4ExtNode n;
    n.entries = u16_at(bytes, 2);
    n.max_entries = u16_at(bytes, 4);
    const uint32_t depth = u16_at(bytes, 6);
    n.generation = u32_at(bytes, 8);

    if (depth > lay::kExtMaxDepth)
        return fail(ErrorCode::CorruptStructure, "ext4: extent tree is too deep");
    if (bytes.size() > s.block_size)
        return fail(ErrorCode::CorruptStructure, "ext4: extent node is larger than a block");
    n.depth = static_cast<uint8_t>(depth);
    if (n.entries > n.max_entries)
        return fail(ErrorCode::CorruptStructure, "ext4: extent node holds more entries than it can");
    const size_t capacity = (bytes.size() - lay::kExtHeaderBytes) / lay::kExtentEntryBytes;
    if (n.entries > capacity)
        return fail(ErrorCode::CorruptStructure, "ext4: extent entries run past the node");
    if (leaf && n.depth != 0)
        return fail(ErrorCode::CorruptStructure, "ext4: expected a leaf extent node");
    if (!leaf && n.depth == 0)
        return fail(ErrorCode::CorruptStructure, "ext4: expected an index extent node");

    const uint8_t* p = bytes.data() + lay::kExtHeaderBytes;
    if (leaf) {
        n.leaves.reserve(n.entries);
        for (uint16_t i = 0; i < n.entries; ++i, p += lay::kExtentEntryBytes) {
            const std::span<const uint8_t> e(p, lay::kExtentEntryBytes);
            Ext4ExtNode::Leaf l;
            l.first_block = u32_at(e, 0);
            const uint16_t raw_len = u16_at(e, 4);
            // ee_len above 32768 is the unwritten bit plus the length below it.
            l.unwritten = raw_len > lay::kExtInitMaxLen;
            l.length = l.unwritten ? raw_len - lay::kExtInitMaxLen : raw_len;
            l.start_block = combine_block(u32_at(e, 8), u16_at(e, 6));
            // A punch-hole leaves a record with a real length and no physical block behind
            // it; a zero-length record is what e2fsck calls a corrupted extent tree.
            if (l.length == 0)
                return fail(ErrorCode::CorruptStructure, "ext4: extent record has zero length");
            l.hole = l.start_block == 0;
            n.leaves.push_back(l);
        }
    } else {
        n.index.reserve(n.entries);
        for (uint16_t i = 0; i < n.entries; ++i, p += lay::kExtentEntryBytes) {
            const std::span<const uint8_t> e(p, lay::kExtentEntryBytes);
            Ext4ExtNode::Index x;
            x.first_block = u32_at(e, 0);
            x.block = combine_block(u32_at(e, 4), u16_at(e, 8));
            // The slot that looks unused in an index entry carries the child tree's
            // generation, which is what a checksum over a subtree needs.
            x.generation = u16_at(e, 10);
            n.index.push_back(x);
        }
    }
    return n;
}

uint32_t inode_csum(std::span<const uint8_t> inode, const Ext4Super& s, uint32_t number) {
    // The seed is the volume seed extended by the inode number and then the generation,
    // both little-endian -- exactly what the kernel precomputes at iget time.
    const auto ino = le32_bytes(number);
    const auto gen = le32_bytes(u32_at(inode, lay::kInodeGeneration));
    uint32_t state = crc32c_continue(s.checksum_seed, ino.data(), ino.size());
    state = crc32c_continue(state, gen.data(), gen.size());

    state = crc32c_continue(state, inode.data(), lay::kInodeChecksumLo);
    state = crc32c_zeros(state, 2);  // i_checksum_lo, read as zero
    state = crc32c_continue(state, inode.data() + lay::kInodeChecksumLo + 2,
                            lay::kGoodOldInodeSize - (lay::kInodeChecksumLo + 2));

    if (inode.size() > lay::kGoodOldInodeSize) {
        state = crc32c_continue(state, inode.data() + lay::kGoodOldInodeSize,
                                lay::kInodeChecksumHi - lay::kGoodOldInodeSize);
        const uint16_t extra = u16_at(inode, lay::kInodeExtraISize);
        const bool has_hi = lay::kInodeChecksumHi + 2 <=
                            lay::kGoodOldInodeSize + static_cast<size_t>(extra);
        if (has_hi) {
            state = crc32c_zeros(state, 2);  // i_checksum_hi, read as zero
            state = crc32c_continue(state, inode.data() + lay::kInodeChecksumHi + 2,
                                    inode.size() - (lay::kInodeChecksumHi + 2));
        } else {
            // Without a stored high half the checksum covers the field's bytes as they are.
            state = crc32c_continue(state, inode.data() + lay::kInodeChecksumHi,
                                    inode.size() - lay::kInodeChecksumHi);
        }
    }
    return state;
}

Result<Ext4Inode> parse_inode(std::span<const uint8_t> raw, const Ext4Super& s,
                              uint32_t number) {
    if (s.inode_size < lay::kGoodOldInodeSize)
        return fail(ErrorCode::CorruptStructure, "ext4: inode size is below 128");
    if (raw.size() < s.inode_size)
        return fail(ErrorCode::CorruptStructure, "ext4: inode is truncated");

    Ext4Inode out;
    out.number = number;
    out.mode = u16_at(raw, lay::kInodeMode);
    out.uid = u16_at(raw, lay::kInodeUid);
    out.gid = u16_at(raw, lay::kInodeGid);
    out.links_count = u16_at(raw, lay::kInodeLinksCount);
    out.size = u32_at(raw, lay::kInodeSizeLo);
    out.blocks = u32_at(raw, lay::kInodeBlocks);
    out.flags = u32_at(raw, lay::kInodeFlags);
    out.atime = u32_at(raw, lay::kInodeAtime);
    out.ctime = u32_at(raw, lay::kInodeCtime);
    out.mtime = u32_at(raw, lay::kInodeMtime);
    out.dtime = u32_at(raw, lay::kInodeDtime);
    out.generation = u32_at(raw, lay::kInodeGeneration);
    out.ea_block = u32_at(raw, lay::kInodeFileAcl);

    // The 128-byte inode predates all of this; only a dynamic revision carries the halves,
    // and reading them from a fixed-layout inode would read past the record.
    if (s.rev_level >= 1) {
        out.size |= static_cast<uint64_t>(u32_at(raw, lay::kInodeSizeHi)) << 32;
        out.blocks |= static_cast<uint64_t>(u16_at(raw, lay::kInodeBlocksHi)) << 32;
        out.ea_block |= static_cast<uint64_t>(u16_at(raw, lay::kInodeFileAclHi)) << 32;
        out.uid |= static_cast<uint32_t>(u16_at(raw, lay::kInodeUidHi)) << 16;
        out.gid |= static_cast<uint32_t>(u16_at(raw, lay::kInodeGidHi)) << 16;
    }

    out.block_area.assign(raw.begin() + static_cast<long>(lay::kInodeBlockArea),
                          raw.begin() +
                              static_cast<long>(lay::kInodeBlockArea + lay::kInodeBlockAreaBytes));

    out.extents = (out.flags & kExt4ExtentFlag) != 0;
    out.inline_data = (out.flags & kExt4InlineDataFlag) != 0;
    out.encrypted = (out.flags & kExt4EncryptedFlag) != 0;
    out.compressed = (out.flags & kExt4CompressedFlag) != 0;

    if (s.inode_size > lay::kGoodOldInodeSize) {
        out.extra_isize = u16_at(raw, lay::kInodeExtraISize);
        // extra_isize counts the bytes between 128 and the end of the inode; an odd value
        // or one that runs off the end means this is not a coherent inode record.
        if ((out.extra_isize & 1u) != 0 ||
            out.extra_isize > s.inode_size - lay::kGoodOldInodeSize)
            return fail(ErrorCode::CorruptStructure, "ext4: inode extra-isize is out of range");
    }

    out.checksum = u16_at(raw, lay::kInodeChecksumLo);
    const bool has_hi =
        s.inode_size > lay::kGoodOldInodeSize &&
        lay::kInodeChecksumHi + 2 <= lay::kGoodOldInodeSize + static_cast<size_t>(out.extra_isize);
    if (has_hi) out.checksum |= static_cast<uint32_t>(u16_at(raw, lay::kInodeChecksumHi)) << 16;

    if (s.inode_csum_verifiable()) {
        const uint32_t want = inode_csum(raw, s, number);
        out.checksum_verified = has_hi ? want == out.checksum : (want & 0xFFFFu) == out.checksum;
    }

    return out;
}

Result<Ext4InodeLocation> inode_location(const Ext4Super& s, uint64_t group_inode_table,
                                         uint32_t number) {
    if (number == 0)
        return fail(ErrorCode::InvalidArgument, "ext4: inode 0 does not exist");
    if (number > s.inodes_count)
        return fail(ErrorCode::InvalidArgument, "ext4: inode number is past the volume");
    if (s.inodes_per_group == 0)
        return fail(ErrorCode::CorruptStructure, "ext4: inodes-per-group is zero");

    Ext4InodeLocation loc;
    loc.group = (number - 1) / s.inodes_per_group;
    loc.index_in_group = (number - 1) % s.inodes_per_group;
    if (loc.group >= s.group_count())
        return fail(ErrorCode::InvalidArgument, "ext4: inode group is past the volume");
    loc.byte_offset = s.block_to_byte(group_inode_table) +
                      static_cast<uint64_t>(loc.index_in_group) * s.inode_size;
    return loc;
}

}  // namespace openrecover::fs
