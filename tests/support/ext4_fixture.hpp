#pragma once

// A hand-authored ext4 volume holding a known set of deleted files.
//
// This build has no mkfs, no e2fsprogs and no real disk in its test environment, so the
// volumes the ext4 tests run on are written here a field at a time. Every value is placed
// with the same little-endian helpers the parser reads it back with, and every checksum is
// computed by the same CRC routines the verifier calls, so a fixture that disagrees with the
// reader fails rather than drifting.
//
// Geometry: 1 KiB blocks, 128 blocks per group, 2 groups, 16 inodes per group of 256 bytes.
// Small enough to hold in memory, wide enough that some deleted files sit in the second
// group and the sweep has to cross a group boundary to find them.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "openrecover/fs/ext4/ext4_boot.hpp"
#include "openrecover/fs/ext4/ext4_checksum.hpp"
#include "openrecover/fs/ext4/ext4_inode.hpp"

namespace openrecover::test {
namespace ext4fx {

namespace lay = fs::ext4_layout;

inline constexpr uint32_t kBlock = 1024;
inline constexpr uint32_t kBlocksPerGroup = 128;
inline constexpr uint32_t kBlocksCount = 256;
inline constexpr uint32_t kInodesPerGroup = 16;
inline constexpr uint32_t kInodesCount = 32;
inline constexpr uint32_t kInodeSize = 256;
inline constexpr uint32_t kExtraISize = 32;
inline constexpr uint32_t kDescSize = 32;
inline constexpr uint32_t kSeed = 0x12345678;
inline constexpr uint64_t kImageBytes = static_cast<uint64_t>(kBlocksCount) * kBlock;

inline constexpr uint32_t kSuperBlock = 1;   // 1 KiB blocks put the superblock in block 1
inline constexpr uint32_t kGdtBlock = 2;
inline constexpr uint32_t kGroup0BlockBitmap = 3;
inline constexpr uint32_t kGroup0InodeBitmap = 4;
inline constexpr uint32_t kGroup0InodeTable = 5;  // 16 * 256 bytes = 4 blocks
inline constexpr uint32_t kGroup1BlockBitmap = 128;
inline constexpr uint32_t kGroup1InodeBitmap = 129;
inline constexpr uint32_t kGroup1InodeTable = 130;

inline constexpr uint32_t kRootBlock = 10;
inline constexpr uint32_t kSubBlock = 11;
inline constexpr uint32_t kMiscBlock = 12;

// Inode numbers.
inline constexpr uint32_t kRootIno = 2;
inline constexpr uint32_t kNotesIno = 11;
inline constexpr uint32_t kSubIno = 12;
inline constexpr uint32_t kMiscIno = 13;
inline constexpr uint32_t kSecretIno = 14;
inline constexpr uint32_t kKeepIno = 15;
inline constexpr uint32_t kPhotoIno = 16;
inline constexpr uint32_t kABinIno = 17;
inline constexpr uint32_t kBBinIno = 18;
inline constexpr uint32_t kReallocIno = 19;
inline constexpr uint32_t kReusedIno = 20;
inline constexpr uint32_t kInlineIno = 21;
inline constexpr uint32_t kSparseIno = 22;
inline constexpr uint32_t kIndirectIno = 23;
inline constexpr uint32_t kBadCsumIno = 24;
inline constexpr uint32_t kEncryptedIno = 25;
inline constexpr uint32_t kUnwrittenIno = 26;

// Deletion seconds. unlink() stamps the containing directory's i_mtime and the inode's
// i_dtime with the same value, which is the only link between a name and a body.
inline constexpr uint32_t kDelSecret = 1700000500;    // root's mtime
inline constexpr uint32_t kDelPhoto = 1700000550;     // subdir's mtime
inline constexpr uint32_t kDelPair = 1700000600;      // misc's mtime: two names, two inodes
inline constexpr uint32_t kDelRealloc = 1700000650;   // slot handed to another file
inline constexpr uint32_t kDelReused = 1700000700;    // blocks taken by a later write
inline constexpr uint32_t kDelInline = 1700000750;
inline constexpr uint32_t kDelSparse = 1700000800;
inline constexpr uint32_t kDelIndirect = 1700000850;
inline constexpr uint32_t kDelBadCsum = 1700000900;
inline constexpr uint32_t kDelEncrypted = 1700000950;
inline constexpr uint32_t kDelUnwritten = 1700001000;  // allocated, never written
inline constexpr uint32_t kLiveMtime = 1700000002;

inline void put8(std::vector<uint8_t>& b, size_t off, uint8_t v) { b[off] = v; }

inline void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

inline void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}

inline void put_bytes(std::vector<uint8_t>& b, size_t off, const void* src, size_t len) {
    std::memcpy(b.data() + off, src, len);
}

// The byte pattern this volume writes into data block `blk`, and the first `take` bytes of
// it. A test asserts recovered content against these rather than against a copy of the
// pattern, so the fixture and the expectation cannot diverge.
inline std::vector<uint8_t> block_content(uint32_t blk) {
    std::vector<uint8_t> v(kBlock);
    for (uint32_t i = 0; i < kBlock; ++i)
        v[i] = static_cast<uint8_t>((blk * 131u + i * 17u) & 0xFFu);
    return v;
}

inline std::vector<uint8_t> block_prefix(uint32_t blk, size_t take) {
    std::vector<uint8_t> full = block_content(blk);
    full.resize(std::min(take, full.size()));
    return full;
}

// One leaf extent record: `len` blocks starting at physical `start`, which is a hole when 0
// and unwritten when the flag says the filesystem never wrote it.
struct Leaf {
    uint32_t first_block = 0;
    uint32_t len = 1;
    uint32_t start = 0;
    bool unwritten = false;
};

// One directory record. `at` is its byte offset in the block because a deleted record does
// not sit after the record before it: unlink() gave that record the deleted one's length,
// so the deleted name lives in the slack the lengthened record now claims.
struct DirRec {
    uint16_t at = 0;
    uint32_t inode = 0;  // 0 after an unlink, which leaves the name in place
    uint8_t type = 0;
    std::string name;
    uint16_t rec_len = 0;
};

// Where a value lives, in bytes from the start of the image. A test that wants to break one
// of these uses the same functions the builder wrote it with.
inline size_t block_byte(uint32_t blk) noexcept { return static_cast<size_t>(blk) * kBlock; }

inline size_t inode_byte(uint32_t ino) noexcept {
    const uint32_t table = ino <= kInodesPerGroup ? kGroup0InodeTable : kGroup1InodeTable;
    return block_byte(table) + static_cast<size_t>(ino - 1) % kInodesPerGroup * kInodeSize;
}

inline size_t descriptor_byte(uint32_t group) noexcept {
    return block_byte(kGdtBlock) + static_cast<size_t>(group) * kDescSize;
}

// The byte that holds one block's allocation bit, and the one holding an inode's.
inline size_t block_bit_byte(uint32_t blk) noexcept {
    const uint32_t group = blk / kBlocksPerGroup;
    const uint32_t bit = blk % kBlocksPerGroup;
    const uint32_t bm = group == 0 ? kGroup0BlockBitmap : kGroup1BlockBitmap;
    return block_byte(bm) + bit / 8;
}

inline size_t inode_bit_byte(uint32_t ino) noexcept {
    const uint32_t group = (ino - 1) / kInodesPerGroup;
    const uint32_t bit = (ino - 1) % kInodesPerGroup;
    const uint32_t bm = group == 0 ? kGroup0InodeBitmap : kGroup1InodeBitmap;
    return block_byte(bm) + bit / 8;
}

class Volume {
public:
    Volume() { build(); }

    std::vector<uint8_t>& data() noexcept { return img_; }
    const std::vector<uint8_t>& data() const noexcept { return img_; }

private:
    void set_block_bit(uint32_t blk) {
        img_[block_bit_byte(blk)] |= static_cast<uint8_t>(1u << (blk % 8));
    }
    void set_inode_bit(uint32_t ino) {
        img_[inode_bit_byte(ino)] |= static_cast<uint8_t>(1u << ((ino - 1) % 8));
    }

    void put_extent(std::vector<uint8_t>& area, size_t index, const Leaf& leaf) {
        const size_t e = lay::kExtHeaderBytes + index * lay::kExtentEntryBytes;
        put32(area, e + 0, leaf.first_block);
        const uint16_t raw_len =
            leaf.unwritten ? static_cast<uint16_t>(leaf.len + lay::kExtInitMaxLen)
                           : static_cast<uint16_t>(leaf.len);
        put16(area, e + 4, raw_len);
        put16(area, e + 6, static_cast<uint16_t>(leaf.start >> 16));
        put32(area, e + 8, leaf.start);
    }

    void put_ext_header(std::vector<uint8_t>& area, uint16_t entries, uint16_t max_entries,
                        uint16_t depth, uint32_t generation) {
        put16(area, 0, lay::kExtMagic);
        put16(area, 2, entries);
        put16(area, 4, max_entries);
        put16(area, 6, depth);
        put32(area, 8, generation);
    }

    std::vector<uint8_t> extent_area(const std::vector<Leaf>& leaves, uint32_t generation) {
        std::vector<uint8_t> area(lay::kInodeBlockAreaBytes, 0);
        put_ext_header(area, static_cast<uint16_t>(leaves.size()), 4, 0, generation);
        for (size_t i = 0; i < leaves.size(); ++i) put_extent(area, i, leaves[i]);
        return area;
    }

    // A pre-extents inode: twelve direct slots plus the single-indirect index at slot 12.
    std::vector<uint8_t> indirect_area(const std::array<uint32_t, 12>& direct, uint32_t single) {
        std::vector<uint8_t> area(lay::kInodeBlockAreaBytes, 0);
        for (size_t i = 0; i < 12; ++i) put32(area, i * 4, direct[i]);
        put32(area, 12 * 4, single);
        return area;
    }

    std::vector<uint8_t> inline_area(const std::string& payload) {
        std::vector<uint8_t> area(lay::kInodeBlockAreaBytes, 0);
        put_ext_header(area, 0, 1, 0, 0x5150);
        put_bytes(area, lay::kExtHeaderBytes, payload.data(), payload.size());
        return area;
    }

    // Records are placed at the offsets unlink() left them at, not laid end to end: a live
    // entry may claim the bytes of the one after it, which is where a deleted name survives.
    void write_dir_block(uint32_t blk, const std::vector<DirRec>& recs) {
        const size_t base = block_byte(blk);
        size_t prev_at = 0, prev_own = 0;
        for (const DirRec& rec : recs) {
            const size_t own = lay::kDirEntryHeaderBytes +
                               ((rec.name.size() + lay::kDirRound) & ~static_cast<size_t>(3));
            if (rec.rec_len < own)
                throw std::logic_error("ext4 fixture: record is shorter than its own name");
            if (static_cast<size_t>(rec.at) + rec.rec_len > kBlock)
                throw std::logic_error("ext4 fixture: records overrun the block");
            if (rec.at < prev_at + prev_own)
                throw std::logic_error("ext4 fixture: a record starts inside the name before it");
            const size_t off = base + rec.at;
            put32(img_, off + lay::kDirEntryInode, rec.inode);
            put16(img_, off + lay::kDirEntryRecLen, rec.rec_len);
            put8(img_, off + lay::kDirEntryNameLen, static_cast<uint8_t>(rec.name.size()));
            put8(img_, off + lay::kDirEntryFileType, rec.type);
            put_bytes(img_, off + lay::kDirEntryNameOffset, rec.name.data(), rec.name.size());
            prev_at = rec.at;
            prev_own = own;
        }
    }

    void write_inode(uint32_t ino, uint16_t mode, uint16_t links, uint32_t dtime, uint32_t mtime,
                     uint64_t size, uint32_t blocks512, uint32_t flags, uint32_t generation,
                     std::vector<uint8_t> area) {
        const size_t o = inode_byte(ino);
        put16(img_, o + lay::kInodeMode, mode);
        put16(img_, o + lay::kInodeUid, 1000);
        put16(img_, o + lay::kInodeGid, 1000);
        put32(img_, o + lay::kInodeSizeLo, static_cast<uint32_t>(size & 0xFFFFFFFFu));
        put32(img_, o + lay::kInodeSizeHi, static_cast<uint32_t>(size >> 32));
        put32(img_, o + lay::kInodeAtime, 1700000000);
        put32(img_, o + lay::kInodeCtime, 1700000001);
        put32(img_, o + lay::kInodeMtime, mtime);
        put32(img_, o + lay::kInodeDtime, dtime);
        put16(img_, o + lay::kInodeLinksCount, links);
        put32(img_, o + lay::kInodeBlocks, blocks512);
        put32(img_, o + lay::kInodeFlags, flags);
        put32(img_, o + lay::kInodeGeneration, generation);
        put16(img_, o + lay::kInodeExtraISize, kExtraISize);
        put_bytes(img_, o + lay::kInodeBlockArea, area.data(), area.size());
    }

    void write_superblock() {
        const size_t s = block_byte(kSuperBlock);
        put32(img_, s + lay::kInodesCount, kInodesCount);
        put32(img_, s + lay::kBlocksCountLo, kBlocksCount);
        put32(img_, s + lay::kFirstDataBlock, 0);  // 1 KiB blocks number data from block 0
        put32(img_, s + lay::kLogBlockSize, 0);
        put32(img_, s + lay::kBlocksPerGroup, kBlocksPerGroup);
        put32(img_, s + lay::kInodesPerGroup, kInodesPerGroup);
        put32(img_, s + lay::kMtime, 1700000000);
        put16(img_, s + lay::kMntCount, 3);
        put16(img_, s + lay::kMagic, lay::kMagicValue);
        put16(img_, s + lay::kState, 1);
        put16(img_, s + lay::kErrors, 1);
        put32(img_, s + lay::kCreatorOs, lay::kOsLinux);
        put32(img_, s + lay::kRevLevel, 1);
        put32(img_, s + lay::kFirstIno, 11);
        put16(img_, s + lay::kInodeSize, kInodeSize);
        put16(img_, s + lay::kBlockGroupNr, 0);
        put32(img_, s + lay::kFeatureCompat,
              fs::ext4_feature::kCompatDirIndex | fs::ext4_feature::kCompatExtAttr |
                  fs::ext4_feature::kCompatSparseSuper2);
        put32(img_, s + lay::kFeatureIncompat,
              fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents |
                  fs::ext4_feature::kIncompatCsumSeed);
        put32(img_, s + lay::kFeatureRoCompat,
              fs::ext4_feature::kRoCompatExtraISize | fs::ext4_feature::kRoCompatDirNlink |
                  fs::ext4_feature::kRoCompatMetadataCsum);
        for (int i = 0; i < 16; ++i) img_[s + lay::kUuid + i] = static_cast<uint8_t>(0xA0 + i);
        put_bytes(img_, s + lay::kVolumeName, "fixture", 7);
        put_bytes(img_, s + lay::kLastMounted, "/mnt/ext4fx", 11);
        put32(img_, s + lay::kJournalIno, 8);
        put16(img_, s + lay::kDescSize, kDescSize);
        put32(img_, s + lay::kChecksumSeed, kSeed);
        put8(img_, s + lay::kChecksumType, lay::kChecksumTypeCrc32c);
    }

    void write_descriptors() {
        const std::array<uint32_t, 2> bitmap{
            {kGroup0BlockBitmap, kGroup1BlockBitmap}};
        const std::array<uint32_t, 2> inode_bitmap{
            {kGroup0InodeBitmap, kGroup1InodeBitmap}};
        const std::array<uint32_t, 2> table{
            {kGroup0InodeTable, kGroup1InodeTable}};
        for (uint32_t g = 0; g < 2; ++g) {
            const size_t d = descriptor_byte(g);
            put32(img_, d + lay::kBgBlockBitmap, bitmap[g]);
            put32(img_, d + lay::kBgInodeBitmap, inode_bitmap[g]);
            put32(img_, d + lay::kBgInodeTable, table[g]);
            put16(img_, d + lay::kBgUsedDirsCount, g == 0 ? 3 : 0);
            put16(img_, d + lay::kBgItableUnused, 0);
        }
    }

    void write_directory_inodes() {
        write_dir_block(kRootBlock, {
            {0, kRootIno, fs::ext4_file_type::kDirectory, ".", 12},
            {12, kRootIno, fs::ext4_file_type::kDirectory, "..", 12},
            // rm removed secret.txt from this slot: its own record lost its inode number
            // and its length was folded into the entry before it.
            {24, kNotesIno, fs::ext4_file_type::kRegular, "notes.txt", 40},
            {44, 0, fs::ext4_file_type::kRegular, "secret.txt", 20},
            {64, kSubIno, fs::ext4_file_type::kDirectory, "subdir", 16},
            {80, kMiscIno, fs::ext4_file_type::kDirectory, "misc",
             static_cast<uint16_t>(kBlock - 80)},
        });
        write_dir_block(kSubBlock, {
            {0, kSubIno, fs::ext4_file_type::kDirectory, ".", 12},
            {12, kRootIno, fs::ext4_file_type::kDirectory, "..", 32},
            {24, 0, fs::ext4_file_type::kRegular, "photo.jpg", 20},
            {44, kKeepIno, fs::ext4_file_type::kRegular, "keep.dat",
             static_cast<uint16_t>(kBlock - 44)},
        });
        // Two unlinks in the same second: both names sit in the slack of "..", which absorbed
        // 12 + 16 + 16 bytes. Neither name can be matched to a body without guessing.
        write_dir_block(kMiscBlock, {
            {0, kMiscIno, fs::ext4_file_type::kDirectory, ".", 12},
            {12, kRootIno, fs::ext4_file_type::kDirectory, "..", 44},
            {24, 0, fs::ext4_file_type::kRegular, "a.bin", 16},
            {40, 0, fs::ext4_file_type::kRegular, "b.bin", 16},
        });

        write_inode(kRootIno, 0x41ED, 3, 0, kDelSecret, kBlock, 8, fs::kExt4ExtentFlag, 0x0002,
                    extent_area({{0, 1, kRootBlock}}, 0x0002));
        write_inode(kSubIno, 0x41ED, 2, 0, kDelPhoto, kBlock, 8, fs::kExt4ExtentFlag, 0x0012,
                    extent_area({{0, 1, kSubBlock}}, 0x0012));
        write_inode(kMiscIno, 0x41ED, 2, 0, kDelPair, kBlock, 8, fs::kExt4ExtentFlag, 0x0013,
                    extent_area({{0, 1, kMiscBlock}}, 0x0013));
    }

    void write_file_inodes() {
        // Still here: a live file must never appear in a deleted scan.
        write_inode(kNotesIno, 0x81A4, 1, 0, kLiveMtime, 1500, 16, fs::kExt4ExtentFlag, 0x1011,
                    extent_area({{0, 2, 20}}, 0x1011));
        write_inode(kKeepIno, 0x81A4, 1, 0, kLiveMtime, 600, 8, fs::kExt4ExtentFlag, 0x1015,
                    extent_area({{0, 1, 26}}, 0x1015));

        // The clean case: two free blocks, one deleted name at the same second.
        write_inode(kSecretIno, 0x81A4, 0, kDelSecret, 1700000400, 1500, 16, fs::kExt4ExtentFlag,
                    0x1014, extent_area({{0, 2, 22}}, 0x1014));
        write_inode(kPhotoIno, 0x81A4, 0, kDelPhoto, 1700000410, 2500, 24, fs::kExt4ExtentFlag,
                    0x1016, extent_area({{0, 3, 30}}, 0x1016));
        write_inode(kABinIno, 0x81A4, 0, kDelPair, 1700000420, 1024, 8, fs::kExt4ExtentFlag,
                    0x1017, extent_area({{0, 1, 40}}, 0x1017));
        write_inode(kBBinIno, 0x81A4, 0, kDelPair, 1700000420, 1024, 8, fs::kExt4ExtentFlag,
                    0x1018, extent_area({{0, 1, 42}}, 0x1018));

        // Deleted-shaped, but the allocator has since given this slot to somebody else.
        write_inode(kReallocIno, 0x81A4, 0, kDelRealloc, 1700000430, 1024, 8, fs::kExt4ExtentFlag,
                    0x1019, extent_area({{0, 1, 50}}, 0x1019));

        // Second group, and one of its blocks is claimed by the bitmap again.
        write_inode(kReusedIno, 0x81A4, 0, kDelReused, 1700000440, 2048, 16, fs::kExt4ExtentFlag,
                    0x1020, extent_area({{0, 2, 140}}, 0x1020));

        const std::string note_text = "recover me if you can!!";
        write_inode(kInlineIno, 0x81A4, 0, kDelInline, 1700000450, note_text.size(), 8,
                    fs::kExt4InlineDataFlag, 0x1021, inline_area(note_text));

        // Blocks 2-4 were never allocated and 5-6 are an explicit punch hole; both read as
        // zeros, and the file still has to come back the right length.
        write_inode(kSparseIno, 0x81A4, 0, kDelSparse, 1700000460, 8 * kBlock, 16,
                    fs::kExt4ExtentFlag, 0x1022,
                    extent_area({{0, 2, 150}, {5, 2, 0}}, 0x1022));

        // A pre-extents file: a hole in the direct slots and another inside its index block.
        std::array<uint32_t, 12> direct{};
        direct[0] = 160;
        direct[2] = 161;
        write_inode(kIndirectIno, 0x81A4, 0, kDelIndirect, 1700000470, 13 * kBlock + 5, 24, 0,
                    0x1023, indirect_area(direct, 162));

        write_inode(kBadCsumIno, 0x81A4, 0, kDelBadCsum, 1700000480, 1024, 8,
                    fs::kExt4ExtentFlag, 0x1024, extent_area({{0, 1, 180}}, 0x1024));
        write_inode(kEncryptedIno, 0x81A4, 0, kDelEncrypted, 1700000490, 1024, 8,
                    fs::kExt4ExtentFlag | fs::kExt4EncryptedFlag, 0x1025,
                    extent_area({{0, 1, 190}}, 0x1025));

        // Allocated but never written: the blocks hold another file's old bytes, and an
        // unwritten extent says those bytes were never this file's.
        write_inode(kUnwrittenIno, 0x81A4, 0, kDelUnwritten, 1700000495, 2048, 16,
                    fs::kExt4ExtentFlag, 0x1026,
                    extent_area({{0, 2, 200, true}}, 0x1026));
    }

    void write_data_blocks() {
        static const uint32_t kDataBlocks[] = {20,  21,  22,  23,  26,  30,  31,  32,  40,  42,
                                               50,  140, 141, 150, 151, 160, 161, 170, 180, 190,
                                               200, 201};
        for (uint32_t blk : kDataBlocks) {
            const std::vector<uint8_t> content = block_content(blk);
            put_bytes(img_, block_byte(blk), content.data(), content.size());
        }
        // The single-indirect block of inode 23: block 170 then a hole.
        put32(img_, block_byte(162) + 0, 170);
        put32(img_, block_byte(162) + 4, 0);
    }

    void write_bitmaps() {
        // Group 0: the volume's own metadata and the live files' blocks.
        for (uint32_t blk : std::array<uint32_t, 8>{
                 {1, 2, 3, 4, 5, 6, 7, 8}})
            set_block_bit(blk);
        for (uint32_t blk : std::array<uint32_t, 7>{{10, 11, 12, 20, 21, 26, 50}})
            set_block_bit(blk);
        // Group 1: metadata, plus the block a later write took over from a deleted file.
        for (uint32_t blk : std::array<uint32_t, 7>{
                 {128, 129, 130, 131, 132, 133, 140}})
            set_block_bit(blk);

        for (uint32_t ino : std::array<uint32_t, 6>{{1, 2, 11, 12, 13, 15}}) set_inode_bit(ino);
        set_inode_bit(kReallocIno);  // the slot is in use again, whatever its fields say
    }

    void finish_bitmaps() {
        for (uint32_t g = 0; g < 2; ++g) {
            const size_t bb = block_byte(g == 0 ? kGroup0BlockBitmap : kGroup1BlockBitmap);
            const size_t ib = block_byte(g == 0 ? kGroup0InodeBitmap : kGroup1InodeBitmap);
            uint32_t used_blocks = 0, used_inodes = 0;
            for (uint32_t i = 0; i < kBlocksPerGroup / 8; ++i)
                used_blocks += static_cast<uint32_t>(popcount(img_[bb + i]));
            for (uint32_t i = 0; i < kInodesPerGroup / 8; ++i)
                used_inodes += static_cast<uint32_t>(popcount(img_[ib + i]));
            put16(img_, descriptor_byte(g) + lay::kBgFreeBlocksCount,
                  static_cast<uint16_t>(kBlocksPerGroup - used_blocks));
            put16(img_, descriptor_byte(g) + lay::kBgFreeInodesCount,
                  static_cast<uint16_t>(kInodesPerGroup - used_inodes));
        }
    }

    static uint8_t popcount(uint8_t v) noexcept {
        uint8_t n = 0;
        for (; v; v = static_cast<uint8_t>(v & (v - 1))) ++n;
        return n;
    }

    void finish_checksums() {
        static const uint32_t kInodes[] = {kRootIno,   kNotesIno,   kSubIno,     kMiscIno,
                                           kSecretIno, kKeepIno,    kPhotoIno,   kABinIno,
                                           kBBinIno,   kReallocIno, kReusedIno,  kInlineIno,
                                           kSparseIno, kIndirectIno, kBadCsumIno, kEncryptedIno,
                                           kUnwrittenIno};
        for (uint32_t ino : kInodes) finish_inode(ino);

        const size_t s = block_byte(kSuperBlock);
        put32(img_, s + lay::kSuperChecksum,
              fs::crc32c_continue(0xFFFFFFFFu, img_.data() + s, lay::kSuperChecksum));

        for (uint32_t g = 0; g < 2; ++g) {
            const size_t d = descriptor_byte(g);
            std::span<const uint8_t> raw(img_.data() + d, kDescSize);
            uint32_t state = fs::crc32c_continue(kSeed, fs::le32_bytes(g).data(), 4);
            state = fs::crc32c_continue(state, raw.data(), lay::kBgChecksum);
            state = fs::crc32c_zeros(state, 2);
            put16(img_, d + lay::kBgChecksum, static_cast<uint16_t>(state & 0xFFFFu));
        }
    }

    void finish_inode(uint32_t ino) {
        const size_t o = inode_byte(ino);
        put16(img_, o + lay::kInodeChecksumLo, 0);
        put16(img_, o + lay::kInodeChecksumHi, 0);
        std::span<const uint8_t> raw(img_.data() + o, kInodeSize);
        const uint32_t state = fs::inode_csum(raw, super_stub(), ino);
        put16(img_, o + lay::kInodeChecksumLo, static_cast<uint16_t>(state & 0xFFFFu));
        put16(img_, o + lay::kInodeChecksumHi, static_cast<uint16_t>(state >> 16));
    }

    // inode_csum only reads the seed and the checksum feature from the superblock.
    static fs::Ext4Super super_stub() {
        fs::Ext4Super s;
        s.block_size = kBlock;
        s.inode_size = kInodeSize;
        s.creator_os = lay::kOsLinux;
        s.feature_ro_compat = fs::ext4_feature::kRoCompatMetadataCsum;
        s.checksum_seed = kSeed;
        return s;
    }

    void build() {
        img_.assign(static_cast<size_t>(kImageBytes), 0);
        write_superblock();
        write_descriptors();
        write_directory_inodes();
        write_file_inodes();
        write_data_blocks();
        write_bitmaps();
        finish_bitmaps();
        finish_checksums();

        // One inode whose record no longer matches its own checksum: the body is still
        // probably right, but the volume says the record was damaged.
        img_[inode_byte(kBadCsumIno) + lay::kInodeUid] ^= 0x01;
    }

    std::vector<uint8_t> img_;
};

}  // namespace ext4fx
}  // namespace openrecover::test
