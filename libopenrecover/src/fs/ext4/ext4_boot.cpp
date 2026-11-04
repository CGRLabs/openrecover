#include "openrecover/fs/ext4/ext4_boot.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/fs/ext4/ext4_checksum.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {
namespace {

namespace lay = ext4_layout;

// s_volume_name and s_last_mounted are fixed-size, space-padded, not NUL-terminated.
std::string padded(std::span<const uint8_t> b, size_t off, size_t len) {
    size_t end = len;
    while (end > 0 && (b[off + end - 1] == 0 || b[off + end - 1] == ' ')) --end;
    std::string out;
    out.reserve(end);
    for (size_t i = 0; i < end; ++i) {
        const uint8_t c = b[off + i];
        // A volume label is operator-supplied text that ends up in a report; keep it to
        // what a report can render without an escape hatch.
        out.push_back(c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '?');
    }
    return out;
}

constexpr uint32_t kMaxLogBlockSize = 16;   // 64 KiB blocks
constexpr uint32_t kMinBlocksPerGroup = 8;
constexpr uint32_t kMaxBlocksPerGroup = 32768;

std::string hex32(uint32_t v) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out(8, '0');
    for (int i = 7; i >= 0; --i) {
        out[static_cast<size_t>(i)] = kDigits[v & 0xFu];
        v >>= 4;
    }
    return out;
}

}  // namespace

uint64_t Ext4Super::group_count() const noexcept {
    if (blocks_per_group == 0 || blocks_count <= first_data_block) return 0;
    // With 2 KiB or 4 KiB blocks the superblock shares block 0 with the boot area, so the
    // first data block is 1 and no block group holds block 0. Counting from blocks_count
    // alone would add a phantom group whenever the last group ends one block short.
    return (blocks_count - first_data_block + blocks_per_group - 1) / blocks_per_group;
}

bool Ext4Super::has_super_copy(uint32_t group) const noexcept {
    // Without SPARSE_SUPER there is exactly one copy, in group 0.
    if (!sparse_super()) return group == 0;
    if (group == 0) return true;
    // The format keeps a copy in the groups numbered 3^k, 5^k and 7^k.
    for (uint64_t base = 3; base <= 7; base += 2) {
        for (uint64_t p = base; p <= group; p *= base) {
            if (p == group) return true;
            if (p > static_cast<uint64_t>(group) / base) break;
        }
    }
    return false;
}

Result<Ext4Super> read_superblock(io::BlockDevice& dev) {
    const uint64_t volume_size = dev.info().size_bytes;
    if (volume_size < lay::kSuperOffset + lay::kSuperBytes)
        return fail(ErrorCode::NoFilesystem, "ext4: source is too small to hold a superblock");

    std::array<uint8_t, lay::kSuperBytes> raw{};
    auto got = io::read_fully(dev, lay::kSuperOffset, raw.data(), raw.size());
    if (!got || *got < raw.size())
        return fail(ErrorCode::IoError, "ext4: superblock read failed");
    const std::span<const uint8_t> b(raw.data(), raw.size());

    if (u16_at(b, lay::kMagic) != lay::kMagicValue)
        return fail(ErrorCode::NoFilesystem, "ext4: superblock magic 0xEF53 is absent");

    Ext4Super s;
    s.inodes_count = u32_at(b, lay::kInodesCount);
    s.blocks_count = u32_at(b, lay::kBlocksCountLo) |
                     (static_cast<uint64_t>(u32_at(b, lay::kBlocksCountHi)) << 32);
    s.log_block_size = u32_at(b, lay::kLogBlockSize);
    s.blocks_per_group = u32_at(b, lay::kBlocksPerGroup);
    s.inodes_per_group = u32_at(b, lay::kInodesPerGroup);
    s.first_data_block = u32_at(b, lay::kFirstDataBlock);
    s.mtime = u32_at(b, lay::kMtime);
    s.wtime = u32_at(b, lay::kWtime);
    s.mnt_count = u16_at(b, lay::kMntCount);
    s.state = u16_at(b, lay::kState);
    s.errors = u16_at(b, lay::kErrors);
    s.rev_level = u32_at(b, lay::kRevLevel);
    s.creator_os = u32_at(b, lay::kCreatorOs);
    s.first_ino = u32_at(b, lay::kFirstIno);
    s.inode_size = u16_at(b, lay::kInodeSize);
    s.feature_compat = u32_at(b, lay::kFeatureCompat);
    s.feature_incompat = u32_at(b, lay::kFeatureIncompat);
    s.feature_ro_compat = u32_at(b, lay::kFeatureRoCompat);
    s.journal_ino = u32_at(b, lay::kJournalIno);
    s.last_orphan = u32_at(b, lay::kLastOrphan);
    s.desc_size = u16_at(b, lay::kDescSize);
    s.log_groups_per_flex = b[lay::kLogGroupsPerFlex];
    s.super_csum = u32_at(b, lay::kSuperChecksum);
    for (size_t i = 0; i < 16; ++i) s.uuid[i] = b[lay::kUuid + i];
    s.volume_name = padded(b, lay::kVolumeName, 16);
    s.last_mounted = padded(b, lay::kLastMounted, 64);

    if (s.log_block_size > kMaxLogBlockSize)
        return fail(ErrorCode::CorruptStructure, "ext4: block-size shift is out of range");
    s.block_size = 1024u << s.log_block_size;
    if (s.block_size < 512 || s.blocks_per_group < kMinBlocksPerGroup ||
        s.blocks_per_group > kMaxBlocksPerGroup)
        return fail(ErrorCode::CorruptStructure, "ext4: blocks-per-group is implausible");
    if (s.blocks_count == 0)
        return fail(ErrorCode::CorruptStructure, "ext4: block count is zero");
    // A volume that claims more bytes than the source holds is either truncated or the
    // magic landed on unrelated bytes; either way the geometry cannot be trusted.
    if (s.blocks_count * static_cast<uint64_t>(s.block_size) > volume_size + s.block_size)
        return fail(ErrorCode::CorruptStructure, "ext4: block count exceeds the source size");
    if (s.first_data_block != 0 && s.first_data_block != 1)
        return fail(ErrorCode::CorruptStructure, "ext4: first-data-block is neither 0 nor 1");
    // 1 KiB blocks give the superblock a block of its own, so block 0 is data and the first
    // data block is 0. With 2 KiB or 4 KiB blocks the superblock shares block 0 with the
    // boot area, so the data starts at block 1. Anything else is bytes that are not a
    // superblock.
    if (s.first_data_block != (s.block_size == 1024 ? 0u : 1u))
        return fail(ErrorCode::CorruptStructure,
                    "ext4: first-data-block contradicts the block size");
    if (s.inodes_per_group == 0 || s.inodes_per_group > s.block_size * 8)
        return fail(ErrorCode::CorruptStructure, "ext4: inodes-per-group is implausible");
    if (s.inodes_count < static_cast<uint64_t>(s.inodes_per_group))
        return fail(ErrorCode::CorruptStructure, "ext4: inode count is below one group");

    if (s.rev_level < 1) {
        s.inode_size = lay::kGoodOldInodeSize;  // pre-EA-layout volumes are fixed at 128
    } else if (s.inode_size < lay::kGoodOldInodeSize || (s.inode_size & (s.inode_size - 1)) != 0 ||
               s.inode_size > 32768) {
        return fail(ErrorCode::CorruptStructure, "ext4: inode size is not 2^n and >= 128");
    }
    if (s.first_ino < 2 || s.first_ino > s.inodes_count)
        return fail(ErrorCode::CorruptStructure, "ext4: first-inode number is out of range");

    const bool is64 = s.incompatible_64bit();
    if (s.desc_size == 0) s.desc_size = is64 ? 64 : 32;
    if (is64 && s.desc_size < 64)
        return fail(ErrorCode::CorruptStructure, "ext4: 64-bit volume with a 32-byte descriptor");
    if (!is64 && s.desc_size != 32)
        return fail(ErrorCode::CorruptStructure,
                    "ext4: descriptor size contradicts the 64-bit flag");

    // flex_bg packs the per-group bitmaps and inode tables at the start of a cluster of
    // groups. Each descriptor still owns its own bitmap and table, so the shift only decides
    // how large a cluster a writer may have described. e2fsprogs never writes above 7; a
    // larger value describes a cluster bigger than most volumes.
    if (s.flex_bg() && s.log_groups_per_flex > 7)
        return fail(ErrorCode::CorruptStructure, "ext4: flex block-group shift is out of range");

    if (const uint32_t refused = s.feature_incompat & ext4_feature::kUnsupportedIncompat)
        return fail(ErrorCode::Unsupported,
                    "ext4: unsupported incompat feature bit set (mask 0x" + hex32(refused) +
                        ") -- the bytes this tool would return are not the bytes the file had");
    if (const uint32_t refused = s.feature_ro_compat & ext4_feature::kUnsupportedRoCompat)
        return fail(ErrorCode::Unsupported,
                    "ext4: unsupported read-only feature bit set (mask 0x" + hex32(refused) + ")");

    // With INCOMPAT_CSUM_SEED the seed is stored; otherwise it is crc32c(~0) over the UUID,
    // which is what the kernel computes on mount. The feature bit decides, not whether the
    // stored bytes happen to be non-zero.
    if (s.csum_seed_stored()) {
        s.checksum_seed = u32_at(b, lay::kChecksumSeed);
    } else {
        s.checksum_seed = crc32c_raw_state(s.uuid, 16);
    }

    if (s.metadata_csum()) {
        // The stored checksum covers the superblock bytes up to s_checksum with a ~0 seed,
        // and is kept as the raw running state -- no final inversion.
        const uint32_t want = crc32c_continue(0xFFFFFFFFu, b.data(), lay::kSuperChecksum);
        s.super_csum_valid = (want == s.super_csum);
    }

    return s;
}

}  // namespace openrecover::fs
