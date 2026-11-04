#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"
#include "openrecover/fs/ext4/ext4_group.hpp"
#include "openrecover/fs/ext4/ext4_inode.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

// Where one group's metadata actually lives. Each group descriptor names its own bitmaps and
// inode table; flex_bg changes where the allocator stores them, not which descriptor owns them.
struct Ext4GroupMeta {
    uint64_t block_bitmap_block = 0;  // absolute block of this group's block bitmap
    uint64_t inode_bitmap_block = 0;  // absolute block of this group's inode bitmap
    uint64_t inode_table_byte = 0;    // byte offset of this group's inode table
    uint64_t blocks_covered = 0;      // blocks this group's block bitmap describes
    uint64_t inodes_covered = 0;      // inodes this group's inode bitmap describes
    // The table was never written, so it cannot hold a deleted inode.
    bool table_uninit = false;
    // bg_itable_unused: the never-allocated inodes at the end of this group's table.
    uint16_t itable_unused = 0;
};

// Which blocks and inodes are in use, read from the group bitmaps a block at a time.
// This is what lets a scan say whether a deleted file's data still belongs to it.
class Ext4AllocationMap final : public IAllocationMap {
public:
    Ext4AllocationMap(std::shared_ptr<io::BlockDevice> dev, Ext4Super super,
                      std::shared_ptr<Ext4GroupTable> groups);

    // ext4's allocation unit is the filesystem block, so the cluster interface maps onto
    // block numbers unchanged.
    bool is_cluster_allocated(uint64_t block) const override { return is_block_allocated(block); }
    uint64_t cluster_to_byte_offset(uint64_t block) const override;
    uint64_t cluster_count() const override { return super_.blocks_count; }

    bool is_block_allocated(uint64_t block) const;
    bool is_inode_allocated(uint32_t number) const;

    // The metadata locations of one group, taken from that group's own descriptor. A group
    // whose descriptor cannot be read is reported as uninitialised rather than failing, so a
    // scan skips it instead of guessing.
    Result<Ext4GroupMeta> group_meta(uint32_t group) const;

private:
    struct CacheEntry {
        uint64_t block = 0;
        std::vector<uint8_t> bytes;
    };

    // The loaded copy of one absolute block, or null when it could not be read.
    // Callers hold mutex_.
    const std::vector<uint8_t>* loaded(uint64_t block) const;
    uint32_t group_of_block(uint64_t block) const noexcept;

    std::shared_ptr<io::BlockDevice> dev_;
    Ext4Super super_;
    std::shared_ptr<Ext4GroupTable> groups_;
    mutable std::mutex mutex_;
    mutable std::vector<CacheEntry> cache_;
};

// Finds deleted files on an ext4 volume.
//
// Two independent sources are combined: the directory tree, where an unlinked entry keeps
// its name but loses its inode number, and the inode tables, where a freed inode keeps its
// block pointers and gains i_dtime. They are matched by timestamp -- unlink() stamps the
// directory's mtime and the inode's dtime with the same second -- and an ambiguous match
// keeps the inode-number name rather than guessing.
class Ext4Scanner final : public IFileSystemScanner {
public:
    static Result<std::unique_ptr<Ext4Scanner>> open(std::shared_ptr<io::BlockDevice> dev);

    FsKind kind() const override { return FsKind::Ext4; }
    const FsGeometry& geometry() const override { return geometry_; }
    Result<std::vector<RecoveredFile>> scan_deleted(const ScanOptions&, ProgressFn) override;
    Result<std::unique_ptr<IAllocationMap>> allocation_map() override;
    Result<size_t> read_file(const RecoveredFile&, uint64_t file_offset, uint8_t* dst,
                             size_t len) override;

    const Ext4Super& super() const noexcept { return super_; }
    Result<Ext4Inode> read_inode(uint32_t number);

    // One contiguous physical run of an inode's data blocks. `sparse` covers both the
    // holes of a sparse file and the unwritten extents a filesystem allocated but never
    // wrote, which read back as zeros.
    struct BlockRun {
        uint64_t logical_block = 0;  // where the run sits in the file
        uint64_t start_block = 0;    // physical block; 0 when sparse
        uint64_t length = 0;         // in blocks
        bool sparse = false;
    };

    // The block map of one inode: an extent tree when it has the EXTENTS flag, otherwise
    // the pre-extents direct and indirect blocks. Runs are returned in logical order and
    // cover every block the file's size needs; logical blocks no record claims are emitted
    // as sparse runs, so a caller never has to infer a hole.
    static Result<std::vector<BlockRun>> map_inode(io::BlockDevice& dev, const Ext4Super& super,
                                                   const Ext4Inode& inode);

    // The payload of an inline-data inode, when it fits in the space the format defines
    // inside i_block. Larger inline files are refused rather than guessed at.
    static Result<std::vector<uint8_t>> inline_data(const Ext4Inode& inode);

    static std::vector<Extent> extents_from_runs(const std::vector<BlockRun>& runs,
                                                 uint32_t block_size, uint64_t size_bytes);

private:
    Ext4Scanner(std::shared_ptr<io::BlockDevice> dev, Ext4Super super);

    std::shared_ptr<io::BlockDevice> dev_;
    Ext4Super super_;
    std::shared_ptr<Ext4GroupTable> groups_;
    std::shared_ptr<Ext4AllocationMap> map_;
    FsGeometry geometry_;
};

}  // namespace openrecover::fs
