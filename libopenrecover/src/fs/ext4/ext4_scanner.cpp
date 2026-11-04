#include "openrecover/fs/ext4/ext4_scanner.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/fs/ext4/ext4_dir.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {
namespace {

namespace lay = ext4_layout;

constexpr uint32_t kRootInode = 2;
constexpr size_t kMaxCachedBitmaps = 32;
constexpr size_t kMaxExtentNodes = 4096;
// The longest block map this build materialises for one inode: 1 Mi blocks, which covers a
// 4 GiB file on 4 KiB blocks. A file that needs more is mapped as far as this and then
// reported as truncated rather than exhausting memory.
constexpr uint64_t kMaxMappedBlocks = 1ull << 20;
// An inode claiming a larger size than this is either ancient or its bytes belong to
// something else; either way there is no honest recovery to be had from it.
constexpr uint64_t kMaxRecoverableSize = 1ull << 44;
// How much of one inode table is read at a time. A standard 4 KiB group holds 8192 inodes of
// 256 bytes, which is two of these.
constexpr uint64_t kMaxTableChunkBytes = 4ull << 20;

// The payload an inline-data inode can hold inside i_block: the 60 bytes of the block area
// minus the 12-byte extent header that precedes it. Inline files larger than this also use
// the extended-attribute area of the inode, whose span depends on fields this build does not
// decode, so those are reported rather than guessed at.
constexpr size_t kMaxInlineBytes = lay::kInodeBlockAreaBytes - lay::kExtHeaderBytes;

std::string join_path(const std::string& parent, const std::string& component) {
    if (parent.empty()) return component;
    return parent + "/" + component;
}

std::string build_note(const std::vector<std::string>& parts) {
    std::string note;
    for (const std::string& part : parts) {
        if (!note.empty()) note += "; ";
        note += part;
    }
    return note;
}

Result<std::vector<uint8_t>> read_block(io::BlockDevice& dev, const Ext4Super& s, uint64_t blk) {
    if (blk >= s.blocks_count)
        return fail(ErrorCode::CorruptStructure, "ext4: block number is past the volume");
    std::vector<uint8_t> buf(s.block_size);
    auto got = io::read_fully(dev, s.block_to_byte(blk), buf.data(), buf.size());
    if (!got || *got != buf.size())
        return fail(ErrorCode::IoError, "ext4: block read failed");
    return buf;
}

// ----------------------------------------------------------------------------- extent tree

// The leaves below one node, in logical order. The node decides for itself whether it is a
// leaf or an index; a node that is neither is reported rather than reinterpreted.
Result<std::vector<Ext4ExtNode::Leaf>> collect_leaves(io::BlockDevice& dev, const Ext4Super& s,
                                                      std::span<const uint8_t> node,
                                                      std::vector<uint64_t>& visited,
                                                      size_t& nodes_read) {
    auto as_leaf = parse_ext_node(node, s, true);
    if (as_leaf) return std::move(as_leaf->leaves);

    auto as_index = parse_ext_node(node, s, false);
    if (!as_index) {
        // Both readings failed. The depth field says which reading was closer, and its error
        // is the one that describes what is actually wrong with the node.
        const bool claims_leaf =
            node.size() >= lay::kExtHeaderBytes && u16_at(node, 6) == 0;
        return fail(claims_leaf ? as_leaf.error() : as_index.error());
    }

    std::vector<Ext4ExtNode::Leaf> out;
    out.reserve(static_cast<size_t>(as_index->index.size()) * 8);
    for (const Ext4ExtNode::Index& entry : as_index->index) {
        if (entry.block == 0 || entry.block >= s.blocks_count)
            return fail(ErrorCode::CorruptStructure,
                        "ext4: extent index points past the volume");
        if (std::find(visited.begin(), visited.end(), entry.block) != visited.end())
            return fail(ErrorCode::CorruptStructure, "ext4: extent tree revisits a block");
        if (nodes_read >= kMaxExtentNodes)
            return fail(ErrorCode::CorruptStructure,
                        "ext4: extent tree is larger than this build will walk");
        visited.push_back(entry.block);
        ++nodes_read;
        auto child_block = read_block(dev, s, entry.block);
        if (!child_block) return fail(child_block.error());
        auto child = collect_leaves(dev, s,
                                    std::span<const uint8_t>(child_block->data(),
                                                             child_block->size()),
                                    visited, nodes_read);
        if (!child) return fail(child.error());
        out.insert(out.end(), child->begin(), child->end());
    }
    return out;
}

// --------------------------------------------------------------------------- indirect blocks

// The number of logical blocks under an index tree of `level` levels, saturating at `cap`.
uint64_t subtree_blocks(uint64_t per_block, uint32_t level, uint64_t cap) {
    uint64_t v = 1;
    for (uint32_t i = 0; i < level; ++i) {
        if (per_block == 0 || v > cap / per_block) return cap;
        v *= per_block;
    }
    return std::min(v, cap);
}

// Appends the logical blocks covered by one i_block slot. `level` 0 means `ptr` is itself a
// data block; 1, 2 and 3 are the single-, double- and triple-indirect trees of slots 12, 13
// and 14. `capacity` is how many logical blocks this call may emit, which is what keeps a
// hole in a deep tree from filling the file with zeros it never claimed.
Result<void> emit_slot(io::BlockDevice& dev, const Ext4Super& s, uint64_t ptr, uint32_t level,
                       uint64_t capacity, std::vector<uint64_t>& out) {
    if (capacity == 0) return {};
    const uint64_t per_block = s.block_size / 4;
    // The budget is per call, not cumulative: a nested index has to compare against the
    // blocks it has itself appended, not the whole map so far.
    const size_t base = out.size();
    auto emitted = [base, &out]() noexcept {
        return static_cast<uint64_t>(out.size() - base);
    };

    if (level == 0) {
        out.push_back(ptr);
        return {};
    }
    if (ptr == 0) {
        // An unallocated index means every block under it is a hole.
        out.insert(out.end(), static_cast<size_t>(capacity), uint64_t{0});
        return {};
    }
    auto buf = read_block(dev, s, ptr);
    if (!buf) return fail(buf.error());
    const std::span<const uint8_t> bytes(buf->data(), buf->size());
    for (uint64_t i = 0; i < per_block && emitted() < capacity; ++i) {
        const uint64_t child = u32_at(bytes, static_cast<size_t>(i) * 4);
        const uint64_t room = capacity - emitted();
        auto step = emit_slot(dev, s, child, level - 1,
                              subtree_blocks(per_block, level - 1, room), out);
        if (!step) return fail(step.error());
    }
    return {};
}

// The physical block behind each of the first `limit` logical blocks of a pre-extents inode,
// 0 for a hole. `truncated` says the inode is bigger than the map that came back.
Result<std::vector<uint64_t>> indirect_blocks(io::BlockDevice& dev, const Ext4Super& s,
                                              const Ext4Inode& inode, uint64_t limit,
                                              bool& truncated) {
    std::vector<uint64_t> out;
    out.reserve(static_cast<size_t>(std::min<uint64_t>(limit, 1024)));
    const uint64_t per_block = s.block_size / 4;
    if (per_block == 0)
        return fail(ErrorCode::CorruptStructure, "ext4: block size cannot hold an index");

    for (uint32_t slot = 0; slot < 15 && out.size() < limit; ++slot) {
        const uint32_t level = slot < 12 ? 0 : slot - 11;
        const uint64_t ptr = u32_at(inode.block_area, static_cast<size_t>(slot) * 4);
        const uint64_t capacity =
            std::min(subtree_blocks(per_block, level, limit - out.size()), limit - out.size());
        if (capacity == 0) break;
        auto step = emit_slot(dev, s, ptr, level, capacity, out);
        if (!step) return fail(step.error());
    }
    if (out.size() < limit) truncated = true;
    return out;
}

void append_run(std::vector<Ext4Scanner::BlockRun>& runs, uint64_t& logical, uint64_t start,
                uint64_t length, bool sparse) {
    if (length == 0) return;
    if (!runs.empty()) {
        Ext4Scanner::BlockRun& back = runs.back();
        const bool joinable = back.sparse == sparse && back.logical_block + back.length == logical &&
                              (sparse || back.start_block + back.length == start);
        if (joinable) {
            back.length += length;
            logical += length;
            return;
        }
    }
    runs.push_back(Ext4Scanner::BlockRun{logical, start, length, sparse});
    logical += length;
}

}  // namespace

// ----------------------------------------------------------------------------- allocation

Ext4AllocationMap::Ext4AllocationMap(std::shared_ptr<io::BlockDevice> dev, Ext4Super super,
                                     std::shared_ptr<Ext4GroupTable> groups)
    : dev_(std::move(dev)), super_(super), groups_(std::move(groups)) {}

uint32_t Ext4AllocationMap::group_of_block(uint64_t block) const noexcept {
    if (super_.blocks_per_group == 0) return 0;
    // Blocks are numbered from s_first_data_block, so group n starts at n*blocks_per_group
    // plus that offset. A block past the last group is clamped rather than overflowed, which
    // is what the kernel does with the short tail of a volume.
    const uint64_t shifted =
        block >= super_.first_data_block ? block - super_.first_data_block : 0;
    const uint64_t count = super_.group_count();
    uint64_t group = super_.blocks_per_group == 0 ? 0 : shifted / super_.blocks_per_group;
    if (count == 0) return 0;
    if (group >= count) group = count - 1;
    return static_cast<uint32_t>(group);
}

Result<Ext4GroupMeta> Ext4AllocationMap::group_meta(uint32_t group) const {
    Ext4GroupMeta meta;
    std::lock_guard<std::mutex> lock(mutex_);
    // Every group descriptor names its own bitmaps and inode table. flex_bg changes where the
    // allocator puts them -- packed at the start of the cluster -- not which descriptor owns
    // them, so reading the cluster's first descriptor would hand every group the first
    // group's bitmap.
    auto desc = groups_->at(group);
    if (!desc) return fail(desc.error());

    meta.block_bitmap_block = desc->block_bitmap;
    meta.inode_bitmap_block = desc->inode_bitmap;
    meta.inode_table_byte = super_.block_to_byte(desc->inode_table);
    meta.blocks_covered = super_.blocks_per_group;
    meta.inodes_covered = super_.inodes_per_group;
    meta.table_uninit = desc->inode_table_uninit() || desc->inode_table_zeroed();
    meta.itable_unused = desc->itable_unused;
    return meta;
}

// Callers hold mutex_.
const std::vector<uint8_t>* Ext4AllocationMap::loaded(uint64_t block) const {
    for (const auto& entry : cache_)
        if (entry.block == block) return &entry.bytes;

    if (block >= super_.blocks_count) return nullptr;
    auto buf = std::vector<uint8_t>(super_.block_size);
    auto got = io::read_fully(*dev_, super_.block_to_byte(block), buf.data(), buf.size());
    if (!got || *got != buf.size()) return nullptr;
    if (cache_.size() >= kMaxCachedBitmaps) cache_.erase(cache_.begin());
    cache_.push_back(CacheEntry{block, std::move(buf)});
    return &cache_.back().bytes;
}

bool Ext4AllocationMap::is_block_allocated(uint64_t block) const {
    if (block >= super_.blocks_count) return true;  // outside the volume is "not free"
    const uint64_t group = group_of_block(block);
    auto meta = group_meta(static_cast<uint32_t>(group));
    if (!meta || meta->block_bitmap_block == 0) return true;  // unreadable is not "free"
    // A block bitmap's bit 0 is the first block of its own group, flex_bg included.
    const uint64_t first = super_.group_first_block(static_cast<uint32_t>(group));
    if (block < first || block - first >= meta->blocks_covered) return true;
    const uint64_t bit = block - first;

    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t byte_index = bit / 8;
    const auto* bytes = loaded(meta->block_bitmap_block + byte_index / super_.block_size);
    if (!bytes) return true;
    const size_t local = static_cast<size_t>(byte_index % super_.block_size);
    if (local >= bytes->size()) return true;
    return ((*bytes)[local] & (1u << (bit % 8))) != 0;
}

bool Ext4AllocationMap::is_inode_allocated(uint32_t number) const {
    if (number == 0 || number > super_.inodes_count) return true;
    if (super_.inodes_per_group == 0) return true;
    const uint64_t index = static_cast<uint64_t>(number) - 1;
    const uint32_t group = static_cast<uint32_t>(index / super_.inodes_per_group);
    auto meta = group_meta(group);
    if (!meta || meta->inode_bitmap_block == 0) return true;
    const uint64_t bit = index - static_cast<uint64_t>(group) * super_.inodes_per_group;
    if (bit >= meta->inodes_covered) return true;

    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t byte_index = bit / 8;
    const auto* bytes = loaded(meta->inode_bitmap_block + byte_index / super_.block_size);
    if (!bytes) return true;
    const size_t local = static_cast<size_t>(byte_index % super_.block_size);
    if (local >= bytes->size()) return true;
    return ((*bytes)[local] & (1u << (bit % 8))) != 0;
}

uint64_t Ext4AllocationMap::cluster_to_byte_offset(uint64_t block) const {
    return super_.block_to_byte(block);
}

// ----------------------------------------------------------------------------- scanner

Ext4Scanner::Ext4Scanner(std::shared_ptr<io::BlockDevice> dev, Ext4Super super)
    : dev_(std::move(dev)), super_(super) {
    geometry_.bytes_per_sector = 512;
    geometry_.bytes_per_cluster = super_.block_size;
    geometry_.total_clusters = super_.blocks_count;
}

Result<std::unique_ptr<Ext4Scanner>> Ext4Scanner::open(std::shared_ptr<io::BlockDevice> dev) {
    if (!dev) return fail(ErrorCode::InvalidArgument, "null device");
    auto super = read_superblock(*dev);
    if (!super) return fail(super.error());
    // INCOMPAT_RECOVER is cleared only after the journal has been replayed, and s_state keeps
    // the error bit a failed mount sets. This reader never writes, so it can neither replay
    // nor repair: warn that the metadata may lag the last committed transaction instead of
    // presenting the scan as exact.
    if ((super->feature_incompat & ext4_feature::kIncompatRecover) != 0 ||
        (super->state & ext4_layout::kStateValidFs) == 0 ||
        (super->state & ext4_layout::kStateErrorFs) != 0)
        log::warn("ext4 volume was not cleanly unmounted; its journal is not replayed, so "
                  "deleted-file results may lag the last commit");
    std::shared_ptr<io::BlockDevice> held = std::move(dev);
    std::shared_ptr<Ext4GroupTable> groups = std::make_shared<Ext4GroupTable>(held, *super);
    std::shared_ptr<Ext4AllocationMap> map =
        std::make_shared<Ext4AllocationMap>(held, *super, groups);
    auto scanner = std::unique_ptr<Ext4Scanner>(new Ext4Scanner(held, *super));
    scanner->groups_ = std::move(groups);
    scanner->map_ = std::move(map);
    return scanner;
}

Result<Ext4Inode> Ext4Scanner::read_inode(uint32_t number) {
    if (super_.inodes_per_group == 0 || number == 0 || number > super_.inodes_count)
        return fail(ErrorCode::InvalidArgument, "ext4: inode number is out of range");
    const uint32_t group = (number - 1) / super_.inodes_per_group;
    auto meta = map_->group_meta(group);
    if (!meta) return fail(meta.error());
    const uint64_t index = static_cast<uint64_t>(number - 1) % super_.inodes_per_group;
    std::vector<uint8_t> buf(super_.inode_size);
    auto got = io::read_fully(*dev_, meta->inode_table_byte + index * super_.inode_size,
                              buf.data(), buf.size());
    if (!got || *got != buf.size())
        return fail(ErrorCode::IoError, "ext4: inode read failed");
    return parse_inode(std::span<const uint8_t>(buf.data(), buf.size()), super_, number);
}

Result<std::vector<Ext4Scanner::BlockRun>> Ext4Scanner::map_inode(io::BlockDevice& dev,
                                                                  const Ext4Super& super,
                                                                  const Ext4Inode& inode) {
    std::vector<BlockRun> runs;
    if (inode.inline_data) return runs;  // the content is inside the inode, no blocks at all
    if (inode.size == 0) return runs;

    uint64_t needed = (inode.size + super.block_size - 1) / super.block_size;
    bool capped = needed > kMaxMappedBlocks;
    if (capped) needed = kMaxMappedBlocks;

    if (inode.extents) {
        std::vector<uint64_t> visited;
        size_t nodes = 0;
        auto leaves =
            collect_leaves(dev, super, std::span<const uint8_t>(inode.block_area), visited, nodes);
        if (!leaves) return fail(leaves.error());
        std::sort(leaves->begin(), leaves->end(),
                  [](const Ext4ExtNode::Leaf& a, const Ext4ExtNode::Leaf& b) {
                      return a.first_block < b.first_block;
                  });
        uint64_t logical = 0;
        for (const Ext4ExtNode::Leaf& leaf : *leaves) {
            if (logical >= needed) break;
            if (leaf.first_block >= needed) break;
            if (leaf.first_block < logical) continue;  // overlapping records are corruption
            if (leaf.first_block > logical)
                append_run(runs, logical, 0, leaf.first_block - logical, true);
            const uint64_t length =
                std::min<uint64_t>(leaf.length, static_cast<uint64_t>(needed - logical));
            append_run(runs, logical, leaf.start_block, length, leaf.hole || leaf.unwritten);
        }
        // A tree shorter than the file leaves the rest of the size unmapped; those blocks have
        // no claim on the volume at all, so they read as zeros.
        if (logical < needed) append_run(runs, logical, 0, needed - logical, true);
        return runs;
    }

    bool truncated = capped;
    auto blocks = indirect_blocks(dev, super, inode, needed, truncated);
    if (!blocks) return fail(blocks.error());
    uint64_t logical = 0;
    for (uint64_t blk : *blocks) {
        append_run(runs, logical, blk, 1, blk == 0);
        if (logical >= needed) break;
    }
    if (logical < needed) append_run(runs, logical, 0, needed - logical, true);
    return runs;
}

std::vector<Extent> Ext4Scanner::extents_from_runs(const std::vector<BlockRun>& runs,
                                                   uint32_t block_size, uint64_t size_bytes) {
    std::vector<Extent> extents;
    uint64_t logical = 0;  // bytes of file content covered so far
    for (const BlockRun& run : runs) {
        if (logical >= size_bytes || run.length == 0) continue;
        // A run that starts past the covered position leaves zeros in between.
        if (run.logical_block > logical / block_size) {
            Extent gap{};
            gap.offset_bytes = 0;
            gap.length_bytes = (run.logical_block - logical / block_size) * block_size;
            if (logical + gap.length_bytes > size_bytes) gap.length_bytes = size_bytes - logical;
            gap.sparse = true;
            extents.push_back(gap);
            logical += gap.length_bytes;
        }
        Extent extent{};
        extent.length_bytes = run.length * static_cast<uint64_t>(block_size);
        if (logical + extent.length_bytes > size_bytes)
            extent.length_bytes = size_bytes - logical;
        extent.sparse = run.sparse;
        extent.offset_bytes = run.sparse ? 0 : run.start_block * static_cast<uint64_t>(block_size);
        extents.push_back(extent);
        logical += extent.length_bytes;
    }
    return extents;
}

Result<std::vector<uint8_t>> Ext4Scanner::inline_data(const Ext4Inode& inode) {
    if (!inode.inline_data)
        return fail(ErrorCode::InvalidArgument, "ext4: inode has no inline data");
    if (inode.size > kMaxInlineBytes)
        return fail(ErrorCode::Unsupported,
                    "ext4: inline file is larger than the block area can hold");
    const size_t start = lay::kExtHeaderBytes;
    if (start > inode.block_area.size())
        return fail(ErrorCode::CorruptStructure, "ext4: inline data has no extent header");
    const size_t available = inode.block_area.size() - start;
    if (inode.size > available)
        return fail(ErrorCode::CorruptStructure, "ext4: inline data runs past i_block");
    return std::vector<uint8_t>(inode.block_area.begin() + static_cast<std::ptrdiff_t>(start),
                                inode.block_area.begin() +
                                    static_cast<std::ptrdiff_t>(start + inode.size));
}

Result<std::unique_ptr<IAllocationMap>> Ext4Scanner::allocation_map() {
    if (!map_) return fail(ErrorCode::CorruptStructure, "ext4: allocation map is unavailable");
    return std::unique_ptr<IAllocationMap>(new Ext4AllocationMap(dev_, super_, groups_));
}

namespace {

struct DeletedName {
    std::string path;
    uint32_t stamp = 0;  // the directory's i_mtime, which equals the unlink time
};

struct DirTask {
    uint32_t inode = 0;
    std::string path;
    uint32_t depth = 0;
};

bool name_less(const DeletedName& a, const DeletedName& b) {
    if (a.stamp != b.stamp) return a.stamp < b.stamp;
    return a.path < b.path;
}

}  // namespace

Result<std::vector<RecoveredFile>> Ext4Scanner::scan_deleted(const ScanOptions& options,
                                                             ProgressFn progress) {
    std::vector<RecoveredFile> out;
    std::vector<DeletedName> names;
    std::unordered_set<uint32_t> visited;
    std::deque<DirTask> queue;
    queue.push_back(DirTask{kRootInode, "", 0});

    // Phase 1: the live directory tree. An unlinked record keeps its name and loses its
    // inode number, so what this phase yields is names stamped with the second they were
    // removed -- the mtime of the directory that held them.
    while (!queue.empty()) {
        const DirTask task = queue.front();
        queue.pop_front();
        if (visited.count(task.inode) != 0) continue;
        visited.insert(task.inode);

        auto inode = read_inode(task.inode);
        if (!inode) {
            log::warn("cannot read ext4 directory inode " + std::to_string(task.inode) + ": " +
                      inode.error().message);
            continue;
        }
        if (!inode->is_directory()) continue;

        auto runs = map_inode(*dev_, super_, *inode);
        if (!runs) {
            log::warn("cannot map ext4 directory inode " + std::to_string(task.inode) + ": " +
                      runs.error().message);
            continue;
        }
        for (const BlockRun& run : *runs) {
            if (run.sparse) continue;
            for (uint64_t i = 0; i < run.length; ++i) {
                auto block = read_block(*dev_, super_, run.start_block + i);
                if (!block) {
                    log::warn("ext4 directory block read failed");
                    continue;
                }
                auto listing =
                    parse_ext4_dir_block(std::span<const uint8_t>(block->data(), block->size()),
                                         super_);
                if (!listing) {
                    log::warn("ext4 directory block is not walkable: " + listing.error().message);
                    continue;
                }
                if (listing->truncated)
                    log::warn("ext4 directory block in " +
                              (task.path.empty() ? "/" : task.path) + " ends mid-record");
                for (const Ext4DirEntry& entry : listing->entries) {
                    const std::string component = sanitize_component(entry.name);
                    if (component.empty()) continue;
                    const std::string child_path = join_path(task.path, component);
                    if (entry.deleted) {
                        // With the filetype feature the type survives the unlink, so a
                        // record known to be a directory is not worth pairing with a file.
                        if (super_.filetype() && entry.file_type != ext4_file_type::kRegular)
                            continue;
                        names.push_back(DeletedName{child_path, inode->mtime});
                        continue;
                    }
                    if (entry.inode == 0 || visited.count(entry.inode) != 0) continue;
                    bool recurse = entry.type_is_directory();
                    if (!recurse && !super_.filetype()) {
                        auto target = read_inode(entry.inode);
                        recurse = target && target->is_directory();
                    }
                    if (!recurse) continue;
                    if (task.depth + 1 > options.max_directory_depth) {
                        log::warn("ext4 directory depth limit reached at " + child_path);
                        continue;
                    }
                    queue.push_back(DirTask{entry.inode, child_path, task.depth + 1});
                }
            }
        }
        if (progress && !progress(visited.size(), visited.size() + queue.size()))
            return fail(ErrorCode::Cancelled, "scan cancelled");
    }

    // Phase 2: the inode tables, which is where the content is whether or not a name
    // survived. Pairs are (i_dtime, inode number) so the sweep, and therefore the report,
    // come out in a stable order.
    std::vector<std::pair<uint32_t, uint32_t>> freed;
    const uint64_t groups_count = super_.group_count();
    for (uint64_t group = 0; group < groups_count; ++group) {
        auto meta = map_->group_meta(static_cast<uint32_t>(group));
        if (!meta) {
            log::warn("cannot read ext4 group descriptor " + std::to_string(group) + ": " +
                      meta.error().message);
            continue;
        }
        if (meta->table_uninit) continue;
        // bg_itable_unused counts the never-allocated inodes at the end of the table.
        uint32_t usable = super_.inodes_per_group;
        if (meta->itable_unused > 0 && meta->itable_unused < usable)
            usable -= meta->itable_unused;

        // The table is a plain array of fixed-size records, so it is walked a few megabytes
        // at a time rather than one inode per read.
        uint32_t idx = 0;
        while (idx < usable) {
            const uint64_t run = std::min<uint64_t>(usable - idx, kMaxTableChunkBytes / super_.inode_size);
            if (run == 0) break;
            std::vector<uint8_t> buf(static_cast<size_t>(run) * super_.inode_size);
            auto got = io::read_fully(*dev_, meta->inode_table_byte +
                                                 static_cast<uint64_t>(idx) * super_.inode_size,
                                     buf.data(), buf.size());
            if (!got || *got != buf.size()) break;  // the table runs to the end of the volume
            for (uint64_t k = 0; k < run; ++k) {
                const uint32_t number =
                    static_cast<uint32_t>(group) * super_.inodes_per_group +
                    static_cast<uint32_t>(idx + k) + 1;
                if (number > super_.inodes_count) break;
                // The journal, quota and boot-accumulator slots are reserved; their inodes
                // are allocated by the filesystem itself, not left behind by a user.
                if (number < super_.first_ino) continue;
                auto inode = parse_inode(
                    std::span<const uint8_t>(buf.data() + k * super_.inode_size,
                                             super_.inode_size),
                    super_, number);
                if (!inode || !inode->deleted()) continue;
                if (inode->mode != 0 && !inode->is_regular()) continue;  // dirs, devices, links
                if (inode->size == 0 || inode->size > kMaxRecoverableSize) continue;
                freed.emplace_back(inode->dtime, number);
            }
            idx += static_cast<uint32_t>(run);
        }
        if (progress && !progress(group + 1, groups_count))
            return fail(ErrorCode::Cancelled, "scan cancelled");
    }

    std::sort(freed.begin(), freed.end());
    std::sort(names.begin(), names.end(), name_less);
    std::map<uint32_t, std::vector<const DeletedName*>> names_by_stamp;
    for (const DeletedName& name : names) names_by_stamp[name.stamp].push_back(&name);

    // Phase 3: rebuild each candidate. The inode is re-read here so the sweep above stayed a
    // cheap pass over table bytes.
    for (size_t i = 0; i < freed.size(); ++i) {
        const uint32_t number = freed[i].second;
        auto inode = read_inode(number);
        if (!inode) {
            log::warn("cannot re-read ext4 inode " + std::to_string(number));
            continue;
        }
        size_t run_end = i;
        while (run_end + 1 < freed.size() && freed[run_end + 1].first == freed[i].first) ++run_end;
        const bool single_inode_at_stamp = run_end == i;

        std::vector<std::string> notes;
        RecoveredFile file;
        file.origin = FileOrigin::FilesystemMetadata;
        file.size_bytes = inode->size;
        file.mtime_unix = inode->mtime != 0 ? std::optional<int64_t>(inode->mtime) : std::nullopt;
        file.atime_unix = inode->atime != 0 ? std::optional<int64_t>(inode->atime) : std::nullopt;
        file.ctime_unix = inode->ctime != 0 ? std::optional<int64_t>(inode->ctime) : std::nullopt;
        file.deleted_unix = std::optional<int64_t>(inode->dtime);
        file.confidence = Confidence::Low;

        // The slot was handed to somebody else after the deletion, so the bytes this inode
        // describes are no longer this file's.
        if (map_->is_inode_allocated(number)) {
            log::warn("skipping ext4 inode " + std::to_string(number) +
                      ": the inode has been reallocated");
            continue;
        }

        auto found = names_by_stamp.find(inode->dtime);
        const size_t candidate_names = found == names_by_stamp.end() ? 0 : found->second.size();
        const bool one_name = candidate_names == 1;
        if (single_inode_at_stamp && one_name) {
            file.path = found->second.front()->path;
            const size_t slash = file.path.find_last_of('/');
            file.name = slash == std::string::npos ? file.path : file.path.substr(slash + 1);
        } else {
            file.path = "inode-" + std::to_string(number);
            file.name = file.path;
            file.flags |= file_flags::PathUncertain;
            // Names did survive this second but more than one body competes for them, or the
            // deletion left no name at all -- two different things to tell a caller.
            notes.push_back(candidate_names == 0 ? "no_deleted_entry_with_this_timestamp"
                                                 : "ambiguous_name_at_deletion_time");
        }
        // Confidence describes the bytes, as it does on the other filesystems; what the name
        // did or did not survive is carried by PathUncertain. The inode record is the only
        // witness to this file's shape, and on a metadata_csum volume it says for itself
        // whether it is still the record the filesystem wrote.
        const bool record_verified = !super_.inode_csum_verifiable() || inode->checksum_verified;
        file.confidence = record_verified ? Confidence::High : Confidence::Medium;
        if (inode->mode == 0) notes.push_back("inode_mode_not_recorded");
        if (super_.inode_csum_verifiable() && !inode->checksum_verified)
            notes.push_back("inode_checksum_mismatch");
        if (inode->encrypted || inode->compressed) {
            file.flags |= file_flags::Unsupported;
            notes.push_back(inode->encrypted ? "encrypted_content" : "compressed_content");
            file.note = build_note(notes);
            out.push_back(std::move(file));
            continue;
        }

        if (inode->inline_data) {
            auto payload = inline_data(*inode);
            if (!payload) {
                file.flags |= file_flags::Unsupported;
                notes.push_back("inline_data_unreadable");
            } else {
                file.resident_data = std::move(*payload);
            }
            file.note = build_note(notes);
            out.push_back(std::move(file));
            continue;
        }

        auto runs = map_inode(*dev_, super_, *inode);
        if (!runs) {
            log::warn("cannot map ext4 inode " + std::to_string(number) + ": " +
                      runs.error().message);
            file.flags |= file_flags::Truncated;
            notes.push_back("block_map_unreadable");
            file.note = build_note(notes);
            out.push_back(std::move(file));
            continue;
        }
        file.extents = extents_from_runs(*runs, super_.block_size, inode->size);
        if (file.extents.empty()) {
            notes.push_back("no_data_blocks");
            file.note = build_note(notes);
            out.push_back(std::move(file));
            continue;
        }
        // A map that stopped at the built-in limit leaves the end of the file unrecovered.
        // A tree that is merely shorter than the size is not truncation -- those blocks were
        // never allocated, and read back as the zeros a hole is defined to hold.
        const uint64_t blocks_needed =
            (inode->size + super_.block_size - 1) / super_.block_size;
        if (blocks_needed > kMaxMappedBlocks) {
            file.flags |= file_flags::Truncated;
            notes.push_back("block_map_truncated");
            file.confidence = Confidence::Low;
        }

        // Reuse check: a deleted file's blocks stay free until something takes them, so a
        // block the allocator has since claimed no longer holds this file's bytes.
        bool reused = false;
        bool sparse = false;
        const uint64_t device_bytes = dev_->info().size_bytes;
        for (const BlockRun& run : *runs) {
            if (run.sparse) {
                sparse = true;
                continue;
            }
            if (run.start_block == 0 || run.start_block + run.length > super_.blocks_count) {
                reused = true;
                break;
            }
            for (uint64_t b = run.start_block; b < run.start_block + run.length; ++b) {
                if (map_->is_block_allocated(b)) {
                    reused = true;
                    break;
                }
            }
            if (reused) break;
        }
        for (const Extent& extent : file.extents)
            if (!extent.sparse && extent.offset_bytes + extent.length_bytes > device_bytes)
                reused = true;

        if (reused) {
            file.flags |= file_flags::ClustersReallocated;
            file.confidence = Confidence::Low;
            notes.push_back("data_blocks_reused_or_outside_volume");
        } else if (sparse) {
            notes.push_back("contains_holes_or_unwritten_extents");
        }
        file.note = build_note(notes);
        out.push_back(std::move(file));
    }

    if (progress && !progress(1, 1)) return fail(ErrorCode::Cancelled, "scan cancelled");
    return out;
}

Result<size_t> Ext4Scanner::read_file(const RecoveredFile& file, uint64_t file_offset,
                                      uint8_t* dst, size_t len) {
    if ((file.flags & file_flags::Unsupported) != 0)
        return fail(ErrorCode::Unsupported, "file content is not available: " + file.note);
    if (file_offset >= file.size_bytes) return size_t{0};
    const uint64_t wanted = std::min<uint64_t>(len, file.size_bytes - file_offset);
    if (wanted == 0) return size_t{0};

    if (file.resident_data) {
        const auto& data = *file.resident_data;
        if (file_offset >= data.size()) return size_t{0};
        const uint64_t take =
            std::min<uint64_t>(wanted, static_cast<uint64_t>(data.size()) - file_offset);
        std::memcpy(dst, data.data() + static_cast<size_t>(file_offset), static_cast<size_t>(take));
        return static_cast<size_t>(take);
    }

    uint64_t logical = 0;
    uint64_t done = 0;
    for (const Extent& extent : file.extents) {
        if (done >= wanted) break;
        const uint64_t end = logical + extent.length_bytes;
        if (file_offset >= end) {
            logical = end;
            continue;
        }
        const uint64_t within = file_offset > logical ? file_offset - logical : 0;
        const uint64_t take = std::min<uint64_t>(extent.length_bytes - within, wanted - done);
        if (extent.sparse) {
            std::memset(dst + done, 0, static_cast<size_t>(take));
        } else {
            auto got = io::read_fully(*dev_, extent.offset_bytes + within, dst + done,
                                      static_cast<size_t>(take));
            if (!got) return fail(got.error());
            if (*got != take) return fail(ErrorCode::IoError, "ext4: short extent read");
        }
        done += take;
        logical = end;
    }
    return static_cast<size_t>(done);
}

}  // namespace openrecover::fs
