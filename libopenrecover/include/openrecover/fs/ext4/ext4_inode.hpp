#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"

namespace openrecover::fs {

// A decoded inode. A file that has been unlinked keeps its i_mode, its size and its block
// pointers; what changes is links_count and i_dtime, which is what `deleted` reads.
struct Ext4Inode {
    uint32_t number = 0;
    uint16_t mode = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint32_t links_count = 0;
    uint64_t size = 0;
    uint64_t blocks = 0;            // i_blocks, in 512-byte units unless HUGE_FILE is set
    uint32_t flags = 0;
    uint32_t dtime = 0;             // seconds since the epoch of deletion, 0 = not deleted
    uint32_t atime = 0, ctime = 0, mtime = 0;
    uint32_t generation = 0;
    uint64_t ea_block = 0;          // i_file_acl: an external xattr block, else inline EA
    bool extents = false;           // the extent-tree flavour of i_block
    bool inline_data = false;
    bool encrypted = false;
    bool compressed = false;
    std::vector<uint8_t> block_area;  // the 60 bytes at i_block, verbatim
    uint16_t extra_isize = 0;
    uint32_t checksum = 0;          // i_checksum_lo with i_checksum_hi above it
    bool checksum_verified = false;

    bool is_directory() const noexcept { return (mode & ext4_mode::kIfmt) == ext4_mode::kDir; }
    bool is_regular() const noexcept { return (mode & ext4_mode::kIfmt) == ext4_mode::kReg; }
    bool is_symlink() const noexcept { return (mode & ext4_mode::kIfmt) == ext4_mode::kLnk; }

    // The state an inode is in just after unlink(): the link count is gone and i_dtime
    // says when, while i_blocks still points at the file's own blocks until the allocator
    // takes them. i_mode is not part of this test -- it survives the unlink, and a freshly
    // allocated inode can briefly hold a zeroed mode, which is why e2fsprogs and the kernel
    // both key off links_count and dtime.
    bool deleted() const noexcept { return links_count == 0 && dtime != 0; }

    // Bytes actually allocated to this inode, which is what separates a sparse file from
    // one whose blocks were reused after deletion.
    uint64_t allocated_bytes(uint32_t block_size) const noexcept {
        // With HUGE_FILE the counter is in filesystem blocks (or clusters, but bigalloc is
        // refused at open time), and a truncated inode counter is what e2fsck warns about.
        return (flags & kExt4HugeFileFlag) != 0 ? blocks * block_size : blocks * 512ull;
    }
};

// One node of an extent tree: either leaf extents or internal index entries.
struct Ext4ExtNode {
    uint16_t entries = 0;
    uint16_t max_entries = 0;
    uint8_t depth = 0;
    uint32_t generation = 0;
    struct Leaf {
        uint32_t first_block = 0;   // first logical block
        uint32_t length = 0;        // in blocks, after the unwritten bit is taken apart
        uint64_t start_block = 0;   // first physical block
        bool unwritten = false;     // allocated, but never written
        bool hole = false;          // covers logical blocks with no storage behind them
    };
    struct Index {
        uint32_t first_block = 0;
        uint64_t block = 0;         // the child node's physical block
        uint32_t generation = 0;
    };
    std::vector<Leaf> leaves;
    std::vector<Index> index;
};

// Reads the 12-byte extent header at the start of a block or of i_block. A node whose
// magic is absent is not an extent tree: the caller falls back to indirect blocks.
// `leaf` says which entry kind the node claims to hold; a node that contradicts it is
// reported as corrupt rather than reinterpreted.
Result<Ext4ExtNode> parse_ext_node(std::span<const uint8_t> bytes, const Ext4Super& s,
                                   bool leaf);

// Decodes an inode from `inode_size` bytes. `number` is only carried through for the
// checksum, which mixes in the inode number and generation on a metadata_csum volume.
Result<Ext4Inode> parse_inode(std::span<const uint8_t> raw, const Ext4Super& s,
                              uint32_t number);

// The byte offset of inode `number` on the device. `group_inode_table` is the absolute
// block number from that group's descriptor.
struct Ext4InodeLocation {
    uint32_t group = 0;
    uint32_t index_in_group = 0;
    uint64_t byte_offset = 0;
};
Result<Ext4InodeLocation> inode_location(const Ext4Super& s, uint64_t group_inode_table,
                                         uint32_t number);

// The metadata_csum of an inode as the format defines it: the seed extended by the inode
// number and generation, then the inode bytes with the two checksum fields replaced by
// zeros of the same length. Returns the raw running state; the stored value is its low 16
// bits, plus the high 16 bits at i_checksum_hi when the inode is large enough to hold them.
uint32_t inode_csum(std::span<const uint8_t> inode, const Ext4Super& s, uint32_t number);

}  // namespace openrecover::fs
