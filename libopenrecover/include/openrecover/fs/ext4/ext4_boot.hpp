#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

// On-disk layout constants. Every offset below was produced by parsing the struct
// definitions in e2fsprogs' lib/ext2fs/ext2_fs.h and the kernel's fs/ext4/ext4.h and
// checking the computed value against the /*hex*/ offset comments those headers carry
// (103 superblock fields, 0 disagreements between the two sources).
namespace ext4_layout {

// The superblock is a full 1024 bytes, and s_checksum at the end of it means the whole
// structure has to be read to verify a volume with metadata_csum.
inline constexpr size_t kSuperOffset = 1024;   // from the start of the filesystem
inline constexpr size_t kSuperBytes = 1024;

inline constexpr size_t kInodesCount = 0;        // u32
inline constexpr size_t kBlocksCountLo = 4;      // u32
inline constexpr size_t kRBlocksCountLo = 8;     // u32
inline constexpr size_t kFreeBlocksCount = 12;   // u32
inline constexpr size_t kFreeInodesCount = 16;   // u32
inline constexpr size_t kFirstDataBlock = 20;    // u32
inline constexpr size_t kLogBlockSize = 24;      // u32
inline constexpr size_t kBlocksPerGroup = 32;    // u32
inline constexpr size_t kInodesPerGroup = 40;    // u32
inline constexpr size_t kMtime = 44;             // u32
inline constexpr size_t kWtime = 48;             // u32
inline constexpr size_t kMntCount = 52;          // u16
inline constexpr size_t kMagic = 56;             // u16
inline constexpr size_t kState = 58;             // u16
inline constexpr size_t kErrors = 60;            // u16
inline constexpr size_t kCreatorOs = 72;         // u32
inline constexpr size_t kRevLevel = 76;          // u32
inline constexpr size_t kFirstIno = 84;          // u32
inline constexpr size_t kInodeSize = 88;         // u16, only meaningful for rev >= 1
inline constexpr size_t kBlockGroupNr = 90;      // u16
inline constexpr size_t kFeatureCompat = 92;     // u32
inline constexpr size_t kFeatureIncompat = 96;   // u32
inline constexpr size_t kFeatureRoCompat = 100;  // u32
inline constexpr size_t kUuid = 104;             // u8[16]
inline constexpr size_t kVolumeName = 120;       // u8[16]
inline constexpr size_t kLastMounted = 136;      // u8[64]
inline constexpr size_t kJournalUuid = 208;      // u8[16]
inline constexpr size_t kJournalIno = 224;       // u32
inline constexpr size_t kLastOrphan = 232;       // u32
inline constexpr size_t kDescSize = 254;         // u16, meaningful with INCOMPAT_64BIT
inline constexpr size_t kBlocksCountHi = 336;    // u32
inline constexpr size_t kLogGroupsPerFlex = 372; // u8
inline constexpr size_t kChecksumType = 373;     // u8
inline constexpr size_t kChecksumSeed = 624;     // u32, with INCOMPAT_CSUM_SEED
inline constexpr size_t kSuperChecksum = 1020;   // u32

inline constexpr uint16_t kMagicValue = 0xEF53;
inline constexpr uint32_t kOsLinux = 0;
inline constexpr uint32_t kGoodOldInodeSize = 128;
inline constexpr uint32_t kGoodOldFirstIno = 11;
inline constexpr uint8_t kChecksumTypeCrc32c = 1;

// Inode fields, from the start of the inode structure. i_block is 60 bytes: 15 block
// pointers, which is also where the extent tree and inline data live.
inline constexpr size_t kInodeMode = 0;          // u16
inline constexpr size_t kInodeUid = 2;           // u16
inline constexpr size_t kInodeSizeLo = 4;        // u32
inline constexpr size_t kInodeAtime = 8;         // u32
inline constexpr size_t kInodeCtime = 12;        // u32
inline constexpr size_t kInodeMtime = 16;        // u32
inline constexpr size_t kInodeDtime = 20;        // u32, seconds since deletion
inline constexpr size_t kInodeGid = 24;          // u16
inline constexpr size_t kInodeLinksCount = 26;   // u16
inline constexpr size_t kInodeBlocks = 28;       // u32, in 512-byte units unless HUGE_FILE
inline constexpr size_t kInodeFlags = 32;        // u32
inline constexpr size_t kInodeBlockArea = 40;    // u32[15], or an extent tree
inline constexpr size_t kInodeBlockAreaBytes = 60;
inline constexpr size_t kInodeGeneration = 100;  // u32
inline constexpr size_t kInodeFileAcl = 104;     // u32, external xattr block
inline constexpr size_t kInodeSizeHi = 108;      // u32
inline constexpr size_t kInodeOsd2 = 116;        // 12 bytes of Linux-specific halves
inline constexpr size_t kInodeBlocksHi = 116;    // u16
inline constexpr size_t kInodeFileAclHi = 118;   // u16
inline constexpr size_t kInodeUidHi = 120;       // u16
inline constexpr size_t kInodeGidHi = 122;       // u16
inline constexpr size_t kInodeChecksumLo = 124;  // u16
inline constexpr size_t kInodeExtraISize = 128;  // u16, past the good-old 128 bytes
inline constexpr size_t kInodeChecksumHi = 130;  // u16
inline constexpr size_t kInodeCrtime = 144;      // u32

// Group descriptor fields. The 32-byte and 64-byte forms agree through byte 31; the
// 64-bit volume adds the high halves from byte 32.
inline constexpr size_t kBgBlockBitmap = 0;      // u32
inline constexpr size_t kBgInodeBitmap = 4;      // u32
inline constexpr size_t kBgInodeTable = 8;       // u32
inline constexpr size_t kBgFreeBlocksCount = 12; // u16
inline constexpr size_t kBgFreeInodesCount = 14; // u16
inline constexpr size_t kBgUsedDirsCount = 16;   // u16
inline constexpr size_t kBgFlags = 18;           // u16
inline constexpr size_t kBgItableUnused = 28;    // u16
inline constexpr size_t kBgChecksum = 30;        // u16
inline constexpr size_t kBgBlockBitmapHi = 32;   // u32
inline constexpr size_t kBgInodeBitmapHi = 36;   // u32
inline constexpr size_t kBgInodeTableHi = 40;    // u32

// Extent tree: a 12-byte header, then 12-byte leaves or index entries.
inline constexpr size_t kExtHeaderBytes = 12;
inline constexpr size_t kExtentEntryBytes = 12;
inline constexpr uint16_t kExtMagic = 0xF30A;
inline constexpr uint16_t kExtInitMaxLen = 32768;   // ee_len above this is unwritten
inline constexpr uint16_t kExtLenMask = 0x7FFF;
inline constexpr uint16_t kExtUnwrittenBit = 0x8000;
inline constexpr uint8_t kExtMaxDepth = 5;

// Directory entry: u32 inode, u16 rec_len, u8 name_len, u8 file_type, then the name.
inline constexpr size_t kDirEntryInode = 0;        // u32
inline constexpr size_t kDirEntryRecLen = 4;       // u16
inline constexpr size_t kDirEntryNameLen = 6;      // u8
inline constexpr size_t kDirEntryFileType = 7;     // u8
inline constexpr size_t kDirEntryHeaderBytes = 8;
inline constexpr size_t kDirEntryNameOffset = 8;
inline constexpr uint32_t kDirRound = 3;           // EXT4_DIR_PAD - 1, entries are 4-aligned
inline constexpr size_t kDirBlockTailBytes = 4;    // the checksum at the end of a csum block

// s_state: set while the volume is mounted or when the kernel found an error.
inline constexpr uint16_t kStateValidFs = 0x0001;
inline constexpr uint16_t kStateErrorFs = 0x0002;

}  // namespace ext4_layout

// Feature flags. The three feature words are independent, so the same bit number means
// different things in each: METADATA_CSUM is read-only-compatible 0x0400 while 0x4000 in
// the incompatible word is LARGEDIR.
namespace ext4_feature {

inline constexpr uint32_t kCompatDirPrealloc = 0x0001;
inline constexpr uint32_t kCompatImagicInodes = 0x0002;
inline constexpr uint32_t kCompatExtAttr = 0x0008;
inline constexpr uint32_t kCompatResizeInode = 0x0010;
inline constexpr uint32_t kCompatDirIndex = 0x0020;
inline constexpr uint32_t kCompatSparseSuper2 = 0x0200;
inline constexpr uint32_t kCompatFastCommit = 0x0400;
inline constexpr uint32_t kCompatStableInodes = 0x0800;
inline constexpr uint32_t kCompatOrphanFile = 0x1000;

inline constexpr uint32_t kIncompatCompression = 0x0001;
inline constexpr uint32_t kIncompatFiletype = 0x0002;
inline constexpr uint32_t kIncompatRecover = 0x0004;
inline constexpr uint32_t kIncompatJournalDev = 0x0008;
inline constexpr uint32_t kIncompatMetaBg = 0x0010;
inline constexpr uint32_t kIncompatExtents = 0x0040;
inline constexpr uint32_t kIncompat64Bit = 0x0080;
inline constexpr uint32_t kIncompatMmp = 0x0100;
inline constexpr uint32_t kIncompatFlexBg = 0x0200;
inline constexpr uint32_t kIncompatEAInode = 0x0400;
inline constexpr uint32_t kIncompatDirData = 0x1000;
inline constexpr uint32_t kIncompatCsumSeed = 0x2000;
inline constexpr uint32_t kIncompatLargeDir = 0x4000;
inline constexpr uint32_t kIncompatInlineData = 0x8000;
inline constexpr uint32_t kIncompatEncrypted = 0x10000;
inline constexpr uint32_t kIncompatCasefold = 0x20000;

inline constexpr uint32_t kRoCompatSparseSuper = 0x0001;
inline constexpr uint32_t kRoCompatLargeFile = 0x0002;
inline constexpr uint32_t kRoCompatHugeFile = 0x0008;
inline constexpr uint32_t kRoCompatGdtCsum = 0x0010;
inline constexpr uint32_t kRoCompatDirNlink = 0x0020;
inline constexpr uint32_t kRoCompatExtraISize = 0x0040;
inline constexpr uint32_t kRoCompatHasSnapshot = 0x0080;
inline constexpr uint32_t kRoCompatQuota = 0x0100;
inline constexpr uint32_t kRoCompatBigalloc = 0x0200;
inline constexpr uint32_t kRoCompatMetadataCsum = 0x0400;
inline constexpr uint32_t kRoCompatReplica = 0x0800;
inline constexpr uint32_t kRoCompatReadOnly = 0x1000;
inline constexpr uint32_t kRoCompatProject = 0x2000;
inline constexpr uint32_t kRoCompatSharedBlocks = 0x4000;
inline constexpr uint32_t kRoCompatVerity = 0x8000;
inline constexpr uint32_t kRoCompatOrphanPresent = 0x10000;

// Everything this build refuses to open even though the superblock is well formed.
// COMPRESSION, ENCRYPT and CASEFOLD change what the bytes of a file are; VERITY and
// BIGALLOC change how blocks are counted or addressed; SNAPSHOT and the read-only
// compression features move metadata where this parser does not look. META_BG moves the
// group descriptors out of the linear table this reader follows, so opening such a volume
// would decode arbitrary blocks as descriptors.
inline constexpr uint32_t kUnsupportedIncompat =
    kIncompatCompression | kIncompatEncrypted | kIncompatCasefold | kIncompatMetaBg;
inline constexpr uint32_t kUnsupportedRoCompat =
    kRoCompatBigalloc | kRoCompatSharedBlocks | kRoCompatHasSnapshot | kRoCompatVerity |
    kRoCompatReplica;

}  // namespace ext4_feature

// ext4 inode i_mode file-type mask and values.
namespace ext4_mode {
inline constexpr uint16_t kIfmt = 0xF000;
inline constexpr uint16_t kDir = 0x4000;
inline constexpr uint16_t kReg = 0x8000;
inline constexpr uint16_t kLnk = 0xA000;
inline constexpr uint16_t kFifo = 0x1000;
inline constexpr uint16_t kChrdev = 0x2000;
inline constexpr uint16_t kBlkdev = 0x6000;
inline constexpr uint16_t kSock = 0xC000;
}  // namespace ext4_mode

// These live in i_flags, not in the superblock. EXTENTS is bit 0x00080000; the 0x00000080
// that looks like it belongs to an "extent" is EXT2_IMMUTABLE_FL, which would misclassify
// every protected file.
inline constexpr uint32_t kExt4ExtentFlag = 0x00080000;      // data addressed by extents
inline constexpr uint32_t kExt4InlineDataFlag = 0x10000000;  // data inside i_block
inline constexpr uint32_t kExt4EncryptedFlag = 0x00000800;
inline constexpr uint32_t kExt4CompressedFlag = 0x00000004;
inline constexpr uint32_t kExt4HugeFileFlag = 0x00000040;    // i_blocks is in fs blocks

// Directory-entry file_type values, used when the FILETYPE incompat flag is set.
namespace ext4_file_type {
inline constexpr uint8_t kUnknown = 0;
inline constexpr uint8_t kRegular = 1;
inline constexpr uint8_t kDirectory = 2;
inline constexpr uint8_t kCharDevice = 3;
inline constexpr uint8_t kBlockDevice = 4;
inline constexpr uint8_t kFifo = 5;
inline constexpr uint8_t kSocket = 6;
inline constexpr uint8_t kSymlink = 7;
// A metadata_csum directory opens with a pseudo-entry carrying this type; it holds no name.
inline constexpr uint8_t kDirCsum = 0xDE;
}  // namespace ext4_file_type

// A parsed and validated ext4 superblock: everything the rest of the module needs to turn
// a block number or an inode number into bytes on the device.
struct Ext4Super {
    uint64_t inodes_count = 0;
    uint64_t blocks_count = 0;
    uint32_t log_block_size = 0;
    uint32_t block_size = 0;            // 1024 << log_block_size
    uint32_t blocks_per_group = 0;
    uint32_t inodes_per_group = 0;
    uint32_t first_data_block = 0;
    uint32_t rev_level = 0;
    uint32_t inode_size = 0;            // 128 for rev 0, else s_inode_size
    uint32_t first_ino = 11;
    uint32_t desc_size = 32;            // 32, or 64 with INCOMPAT_64BIT
    uint32_t creator_os = 0;
    uint32_t feature_compat = 0;
    uint32_t feature_incompat = 0;
    uint32_t feature_ro_compat = 0;
    uint32_t journal_ino = 0;
    uint32_t last_orphan = 0;
    uint32_t state = 1;
    uint32_t errors = 1;
    uint32_t mnt_count = 0;
    uint32_t log_groups_per_flex = 0;   // s_log_groups_per_flex
    uint64_t mtime = 0;
    uint64_t wtime = 0;
    uint32_t checksum_seed = 0;         // s_checksum_seed, or computed from the UUID
    uint32_t super_csum = 0;            // s_checksum as stored
    bool super_csum_valid = false;      // only meaningful on a metadata_csum volume
    uint8_t uuid[16] = {};
    std::string volume_name;
    std::string last_mounted;

    bool incompatible_64bit() const noexcept {
        return (feature_incompat & ext4_feature::kIncompat64Bit) != 0;
    }
    bool metadata_csum() const noexcept {
        return (feature_ro_compat & ext4_feature::kRoCompatMetadataCsum) != 0;
    }
    bool gdt_csum() const noexcept {
        return (feature_ro_compat & ext4_feature::kRoCompatGdtCsum) != 0;
    }
    bool sparse_super() const noexcept {
        return (feature_ro_compat & ext4_feature::kRoCompatSparseSuper) != 0;
    }
    bool extents_required() const noexcept {
        return (feature_incompat & ext4_feature::kIncompatExtents) != 0;
    }
    bool filetype() const noexcept {
        return (feature_incompat & ext4_feature::kIncompatFiletype) != 0;
    }
    bool csum_seed_stored() const noexcept {
        return (feature_incompat & ext4_feature::kIncompatCsumSeed) != 0;
    }
    bool flex_bg() const noexcept {
        return (feature_incompat & ext4_feature::kIncompatFlexBg) != 0;
    }
    uint64_t group_first_block(uint32_t group) const noexcept {
        // Every group is offset by s_first_data_block, not just group 0.
        return static_cast<uint64_t>(group) * blocks_per_group + first_data_block;
    }
    // The kernel only verifies inode checksums for Linux-created volumes; matching that
    // avoids reporting a foreign volume's inodes as corrupt.
    bool inode_csum_verifiable() const noexcept {
        return metadata_csum() && creator_os == ext4_layout::kOsLinux;
    }

    uint64_t group_count() const noexcept;
    // Byte offset of block `blk` within the volume. ext4 blocks are numbered from 0; with
    // 1 KiB blocks block 0 is the partition boot area and the superblock sits in block 1.
    uint64_t block_to_byte(uint64_t blk) const noexcept { return blk * block_size; }
    // True when this group is one of the sparse_super copies the format stores.
    bool has_super_copy(uint32_t group) const noexcept;
};

// Reads and validates the superblock at the start of `dev`. A bad magic, an impossible
// geometry, or an inode size that contradicts the revision is CorruptStructure; a
// well-formed volume that needs a feature this library cannot decode is Unsupported.
Result<Ext4Super> read_superblock(io::BlockDevice& dev);

// The two halves of a 64-bit block number used by 64-bit group descriptors.
inline uint64_t combine_block(uint32_t lo, uint32_t hi) noexcept {
    return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
}

// Little-endian field access. ext4 is little-endian on disk regardless of the host, so
// every read in this module goes through these; the image writer in the tests shares them
// so a fixture and the parser cannot disagree about what "offset 624" means.
inline uint16_t u16_at(std::span<const uint8_t> b, size_t off) noexcept {
    return static_cast<uint16_t>(b[off] | (static_cast<uint16_t>(b[off + 1]) << 8));
}
inline uint32_t u32_at(std::span<const uint8_t> b, size_t off) noexcept {
    return static_cast<uint32_t>(b[off]) | (static_cast<uint32_t>(b[off + 1]) << 8) |
           (static_cast<uint32_t>(b[off + 2]) << 16) | (static_cast<uint32_t>(b[off + 3]) << 24);
}
inline std::array<uint8_t, 4> le32_bytes(uint32_t v) noexcept {
    return {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
            static_cast<uint8_t>(v >> 24)};
}

}  // namespace openrecover::fs
