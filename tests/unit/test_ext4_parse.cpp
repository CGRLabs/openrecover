#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"
#include "openrecover/fs/ext4/ext4_checksum.hpp"
#include "openrecover/fs/ext4/ext4_group.hpp"
#include "openrecover/fs/ext4/ext4_inode.hpp"

namespace {

using namespace openrecover;
using openrecover::test::MemoryDevice;
namespace lay = fs::ext4_layout;

void put8(std::vector<uint8_t>& b, size_t off, uint8_t v) { b[off] = v; }
void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}
void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}

constexpr uint32_t kBlock = 1024;
constexpr uint32_t kBlocksPerGroup = 128;
constexpr uint32_t kBlocksCount = 128;
constexpr uint32_t kInodesPerGroup = 16;
constexpr uint32_t kInodeSize = 256;
constexpr uint32_t kExtraISize = 32;
constexpr uint32_t kBitmapBlock = 3;
constexpr uint32_t kInodeBitmapBlock = 4;
constexpr uint32_t kInodeTableBlock = 5;
constexpr uint64_t kImageBytes = static_cast<uint64_t>(kBlocksCount) * kBlock;
// With 1 KiB blocks the superblock is block 1 and the GDT starts at block 2, so the
// descriptor offset is an absolute byte position, not "superblock plus two blocks".
constexpr size_t kGdtOffset = 2 * kBlock;

size_t inode_off(uint32_t ino) {
    // Where the parser itself looks: the group's inode table is a plain array of records
    // starting at the block the descriptor names.
    return static_cast<size_t>(kInodeTableBlock) * kBlock +
           (static_cast<size_t>(ino) - 1) % kInodesPerGroup * kInodeSize;
}

// Writes one 12-byte leaf extent into an extent node.
void put_extent(std::vector<uint8_t>& b, size_t node, size_t index, uint32_t first_block,
                uint32_t start_block, uint16_t len, bool unwritten) {
    const size_t e = node + lay::kExtHeaderBytes + index * lay::kExtentEntryBytes;
    put32(b, e + 0, first_block);
    const uint16_t raw_len = unwritten ? static_cast<uint16_t>(len + lay::kExtInitMaxLen) : len;
    put16(b, e + 4, raw_len);
    put16(b, e + 6, static_cast<uint16_t>(start_block >> 16));
    put32(b, e + 8, start_block);
}

void put_ext_header(std::vector<uint8_t>& b, size_t node, uint16_t entries, uint16_t max_entries,
                    uint16_t depth, uint32_t generation) {
    put16(b, node + 0, lay::kExtMagic);
    put16(b, node + 2, entries);
    put16(b, node + 4, max_entries);
    put16(b, node + 6, depth);
    put32(b, node + 8, generation);
}

// Fills the fields of an inode record; the checksum is left for finish_inode(). `links` is
// separate from `mode` because unlink() clears the link count and leaves the mode alone.
void put_inode_fields(std::vector<uint8_t>& b, uint32_t ino, uint16_t mode, uint32_t size_lo,
                      uint32_t blocks512, uint32_t flags, uint32_t dtime, uint32_t gen,
                      uint16_t links) {
    const size_t o = inode_off(ino);
    put16(b, o + lay::kInodeMode, mode);
    put16(b, o + lay::kInodeUid, 1000);
    put32(b, o + lay::kInodeSizeLo, size_lo);
    put32(b, o + lay::kInodeAtime, 1700000000);
    put32(b, o + lay::kInodeCtime, 1700000001);
    put32(b, o + lay::kInodeMtime, 1700000002);
    put32(b, o + lay::kInodeDtime, dtime);
    put16(b, o + lay::kInodeGid, 1000);
    put16(b, o + lay::kInodeLinksCount, links);
    put32(b, o + lay::kInodeBlocks, blocks512);
    put32(b, o + lay::kInodeFlags, flags);
    put32(b, o + lay::kInodeGeneration, gen);
    if (mode != 0 || dtime != 0) {
        put16(b, o + lay::kInodeExtraISize, kExtraISize);
        put32(b, o + lay::kInodeSizeHi, 0);
    }
}

// Computes and stores the metadata_csum of the inode the way mkfs does.
void finish_inode(std::vector<uint8_t>& b, uint32_t ino, uint32_t seed, bool with_hi) {
    const size_t o = inode_off(ino);
    put16(b, o + lay::kInodeChecksumLo, 0);
    put16(b, o + lay::kInodeChecksumHi, 0);
    std::span<const uint8_t> raw(b.data() + o, kInodeSize);
    const auto ino_le = fs::le32_bytes(ino);
    uint32_t state = fs::crc32c_continue(seed, ino_le.data(), ino_le.size());
    const auto gen_le = fs::le32_bytes(fs::u32_at(raw, lay::kInodeGeneration));
    state = fs::crc32c_continue(state, gen_le.data(), gen_le.size());
    state = fs::crc32c_continue(state, raw.data(), lay::kInodeChecksumLo);
    state = fs::crc32c_zeros(state, 2);
    state = fs::crc32c_continue(state, raw.data() + lay::kInodeChecksumLo + 2,
                               lay::kGoodOldInodeSize - (lay::kInodeChecksumLo + 2));
    state = fs::crc32c_continue(state, raw.data() + lay::kGoodOldInodeSize,
                                lay::kInodeChecksumHi - lay::kGoodOldInodeSize);
    state = fs::crc32c_zeros(state, 2);
    state = fs::crc32c_continue(state, raw.data() + lay::kInodeChecksumHi + 2,
                                kInodeSize - (lay::kInodeChecksumHi + 2));
    put16(b, o + lay::kInodeChecksumLo, static_cast<uint16_t>(state & 0xFFFFu));
    if (with_hi) put16(b, o + lay::kInodeChecksumHi, static_cast<uint16_t>(state >> 16));
}

std::vector<uint8_t> make_image() {
    std::vector<uint8_t> img(static_cast<size_t>(kImageBytes), 0);

    // --- superblock, at byte 1024 ---
    const size_t s = lay::kSuperOffset;
    put32(img, s + lay::kInodesCount, kInodesPerGroup);
    put32(img, s + lay::kBlocksCountLo, kBlocksCount);
    put32(img, s + lay::kFreeBlocksCount, 60);
    put32(img, s + lay::kFreeInodesCount, 10);
    put32(img, s + lay::kFirstDataBlock, 0);  // 1 KiB blocks: block 0 is data, 1 is the superblock
    put32(img, s + lay::kLogBlockSize, 0);    // 1024 << 0
    put32(img, s + lay::kBlocksPerGroup, kBlocksPerGroup);
    put32(img, s + lay::kInodesPerGroup, kInodesPerGroup);
    put32(img, s + lay::kMtime, 1700000000);
    put16(img, s + lay::kMntCount, 3);
    put16(img, s + lay::kMagic, lay::kMagicValue);
    put16(img, s + lay::kState, 1);
    put16(img, s + lay::kErrors, 1);
    put32(img, s + lay::kCreatorOs, 0);
    put32(img, s + lay::kRevLevel, 1);
    put32(img, s + lay::kFirstIno, 11);
    put16(img, s + lay::kInodeSize, kInodeSize);
    put16(img, s + lay::kBlockGroupNr, 0);
    put32(img, s + lay::kFeatureCompat, fs::ext4_feature::kCompatDirIndex |
                                          fs::ext4_feature::kCompatExtAttr);
    put32(img, s + lay::kFeatureIncompat, fs::ext4_feature::kIncompatFiletype |
                                            fs::ext4_feature::kIncompatExtents |
                                            fs::ext4_feature::kIncompatCsumSeed);
    put32(img, s + lay::kFeatureRoCompat, fs::ext4_feature::kRoCompatMetadataCsum |
                                            fs::ext4_feature::kRoCompatExtraISize);
    for (int i = 0; i < 16; ++i) img[s + lay::kUuid + i] = static_cast<uint8_t>(0xA0 + i);
    std::memcpy(img.data() + s + lay::kVolumeName, "testlabel", 9);
    std::memcpy(img.data() + s + lay::kLastMounted, "/mnt/data", 9);
    put32(img, s + lay::kJournalIno, 8);
    put32(img, s + lay::kLastOrphan, 0);
    put16(img, s + lay::kDescSize, 32);
    put32(img, s + lay::kChecksumSeed, 0x12345678);
    put8(img, s + lay::kChecksumType, lay::kChecksumTypeCrc32c);

    // --- group descriptor 0, in the GDT that follows the superblock ---
    put32(img, kGdtOffset + lay::kBgBlockBitmap, kBitmapBlock);
    put32(img, kGdtOffset + lay::kBgInodeBitmap, kInodeBitmapBlock);
    put32(img, kGdtOffset + lay::kBgInodeTable, kInodeTableBlock);
    put16(img, kGdtOffset + lay::kBgFreeBlocksCount, 60);
    put16(img, kGdtOffset + lay::kBgFreeInodesCount, 10);
    put16(img, kGdtOffset + lay::kBgUsedDirsCount, 2);
    put16(img, kGdtOffset + lay::kBgFlags, 0);
    put16(img, kGdtOffset + lay::kBgItableUnused, 2);

    // --- inodes ---
    // 11: live extent-based file, four extents in i_block.
    put_inode_fields(img, 11, 0x81A4 /*-rw-r--r--*/, 40000, 80, fs::kExt4ExtentFlag, 0, 0x1111, 1);
    put_ext_header(img, inode_off(11) + lay::kInodeBlockArea, 3, 4, 0, 0x1111);
    put_extent(img, inode_off(11) + lay::kInodeBlockArea, 0, 0, 20, 4, false);
    put_extent(img, inode_off(11) + lay::kInodeBlockArea, 1, 4, 30, 4, true);
    put_extent(img, inode_off(11) + lay::kInodeBlockArea, 2, 8, 40, 2, false);

    // 12: deleted file. unlink() cleared i_links_count and stamped i_dtime but left i_mode
    // and the extent tree alone, because the allocator has not taken those blocks yet.
    put_inode_fields(img, 12, 0x81A4, 9000, 24, fs::kExt4ExtentFlag, 1700009999, 0x2222, 0);
    put_ext_header(img, inode_off(12) + lay::kInodeBlockArea, 1, 4, 0, 0x2222);
    put_extent(img, inode_off(12) + lay::kInodeBlockArea, 0, 0, 60, 2, false);

    // 13: inline-data file, 20 bytes stored after the extent header in i_block.
    put_inode_fields(img, 13, 0x81A4, 20, 8, fs::kExt4InlineDataFlag, 0, 0x3333, 1);
    put_ext_header(img, inode_off(13) + lay::kInodeBlockArea, 0, 1, 0, 0x3333);
    put16(img, inode_off(13) + lay::kInodeUidHi, 1);  // uid above 65535
    std::memcpy(img.data() + inode_off(13) + lay::kInodeBlockArea + lay::kExtHeaderBytes,
                "inline payload here!", 20);

    // 14: pre-extents file: one direct block, one single-indirect block, and a size that
    // only fits 32 bits because i_size_high says so.
    put_inode_fields(img, 14, 0x81A4, 100000, 200, 0, 0, 0x4444, 1);
    put32(img, inode_off(14) + lay::kInodeSizeHi, 1);
    put32(img, inode_off(14) + lay::kInodeBlockArea + 0 * 4, 70);
    put32(img, inode_off(14) + lay::kInodeBlockArea + 12 * 4, 71);
    for (uint32_t i = 0; i < 256; ++i)
        put32(img, static_cast<size_t>(71) * kBlock + i * 4, i < 12 ? 80 + i : 0);

    // 2: the root directory, non-extent with one direct block.
    put_inode_fields(img, 2, 0x41ED /*drwxr-xr-x*/, 1024, 8, 0, 0, 0x0002, 2);
    put32(img, inode_off(2) + lay::kInodeBlockArea, 100);

    const uint32_t seed = 0x12345678;
    for (uint32_t ino : {2u, 11u, 12u, 13u, 14u}) finish_inode(img, ino, seed, true);

    // Superblock checksum: crc32c(~0) over everything before s_checksum, stored raw.
    uint32_t sb_csum = fs::crc32c_continue(0xFFFFFFFFu, img.data() + lay::kSuperOffset,
                                           lay::kSuperChecksum);
    put32(img, lay::kSuperOffset + lay::kSuperChecksum, sb_csum);

    // Group descriptor checksum: the metadata_csum rule -- seed, group number, descriptor
    // with bg_checksum read as zero, and the 16 low bits stored.
    uint32_t g_csum = fs::crc32c_continue(seed, fs::le32_bytes(0).data(), 4);
    g_csum = fs::crc32c_continue(g_csum, img.data() + kGdtOffset, lay::kBgChecksum);
    g_csum = fs::crc32c_zeros(g_csum, 2);
    put16(img, kGdtOffset + lay::kBgChecksum, static_cast<uint16_t>(g_csum & 0xFFFFu));

    return img;
}

// Every geometry mutation has to be refused with the code the parser claims, rather than
// parsed into a plausible-looking volume that points outside the device.
void expect_super_rejected(const std::vector<uint8_t>& img, ErrorCode code) {
    MemoryDevice dev(img, 512);
    auto s = fs::read_superblock(dev);
    CHECK_FALSE(s.has_value());
    if (s) return;
    CHECK(s.error().code == code);
}

fs::Ext4Super make_super(uint32_t block_size = kBlock) {
    fs::Ext4Super s;
    s.inodes_count = kInodesPerGroup;
    s.blocks_count = kBlocksCount;
    s.log_block_size = 0;
    s.block_size = block_size;
    s.blocks_per_group = kBlocksPerGroup;
    s.inodes_per_group = kInodesPerGroup;
    // A 1 KiB volume gives the superblock its own block, so block 0 is ordinary data.
    s.first_data_block = block_size == 1024 ? 0 : 1;
    s.rev_level = 1;
    s.inode_size = kInodeSize;
    s.first_ino = 11;
    s.desc_size = 32;
    s.checksum_seed = 0x12345678;
    return s;
}

}  // namespace

TEST_CASE("ext4 crc32c matches the published check value", "[ext4][checksum]") {
    const char* input = "123456789";
    CHECK(fs::ext4_crc32c(reinterpret_cast<const uint8_t*>(input), 9) == 0xE3069283u);
    // CRC16-CCITT-FALSE, the same string, is the other published check value.
    CHECK(fs::ext4_crc16(reinterpret_cast<const uint8_t*>(input), 9) == 0x29B1u);
    // Running the state across four zero bytes is the same as feeding four zero bytes.
    std::vector<uint8_t> zeros(4, 0);
    CHECK(fs::crc32c_zeros(0x12345678u, 4) ==
          fs::crc32c_continue(0x12345678u, zeros.data(), zeros.size()));
}

TEST_CASE("ext4 superblock parse", "[ext4][boot]") {
    auto img = make_image();
    MemoryDevice dev(img, 512);
    auto s = fs::read_superblock(dev);
    REQUIRE(s.has_value());
    CHECK(s->block_size == 1024);
    CHECK(s->blocks_count == kBlocksCount);
    CHECK(s->blocks_per_group == kBlocksPerGroup);
    CHECK(s->inodes_per_group == kInodesPerGroup);
    CHECK(s->inode_size == kInodeSize);
    CHECK(s->first_ino == 11);
    CHECK(s->desc_size == 32);
    CHECK(s->volume_name == "testlabel");
    CHECK(s->last_mounted == "/mnt/data");
    CHECK(s->metadata_csum());
    CHECK(s->filetype());
    CHECK(s->checksum_seed == 0x12345678);
    CHECK(s->super_csum_valid);
    CHECK(s->group_count() == 1);

    SECTION("a corrupt superblock checksum is reported, not silently accepted") {
        img[lay::kSuperOffset + lay::kMtime] ^= 0xFF;
        MemoryDevice dev2(img, 512);
        auto bad = fs::read_superblock(dev2);
        REQUIRE(bad.has_value());
        CHECK_FALSE(bad->super_csum_valid);
    }
    SECTION("a stored seed is used only when CSUM_SEED is set") {
        img[lay::kSuperOffset + lay::kChecksumSeed] = 0;  // keep the bytes, drop the flag
        put32(img, lay::kSuperOffset + lay::kFeatureIncompat,
              fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents);
        uint32_t sb_csum = fs::crc32c_continue(0xFFFFFFFFu, img.data() + lay::kSuperOffset,
                                               lay::kSuperChecksum);
        put32(img, lay::kSuperOffset + lay::kSuperChecksum, sb_csum);
        MemoryDevice dev2(img, 512);
        auto s2 = fs::read_superblock(dev2);
        REQUIRE(s2.has_value());
        CHECK(s2->checksum_seed == fs::crc32c_raw_state(s2->uuid, 16));
    }
}

TEST_CASE("ext4 superblock rejects impossible geometry", "[ext4][boot]") {
    auto img = make_image();
    SECTION("magic") {
        put16(img, lay::kSuperOffset + lay::kMagic, 0x1234);
        expect_super_rejected(img, ErrorCode::NoFilesystem);
    }
    SECTION("volume larger than the device") {
        put32(img, lay::kSuperOffset + lay::kBlocksCountLo, 100000);
        expect_super_rejected(img, ErrorCode::CorruptStructure);
    }
    SECTION("inodes-per-group above the bitmap it claims to fit") {
        put32(img, lay::kSuperOffset + lay::kInodesPerGroup, 100000);
        expect_super_rejected(img, ErrorCode::CorruptStructure);
    }
    SECTION("a block-size shift that would overflow the geometry") {
        put32(img, lay::kSuperOffset + lay::kLogBlockSize, 40);
        expect_super_rejected(img, ErrorCode::CorruptStructure);
    }
    SECTION("descriptor size contradicting the 64-bit flag") {
        put16(img, lay::kSuperOffset + lay::kDescSize, 64);
        expect_super_rejected(img, ErrorCode::CorruptStructure);
    }
    SECTION("first-data-block contradicting the block size") {
        // Only a 1 KiB volume numbers its blocks from 0; 2 KiB and 4 KiB volumes start at 1
        // because the superblock shares their first block with the boot area.
        put32(img, lay::kSuperOffset + lay::kFirstDataBlock, 1);
        expect_super_rejected(img, ErrorCode::CorruptStructure);
    }
    SECTION("a flex cluster bigger than the format can address") {
        put32(img, lay::kSuperOffset + lay::kFeatureIncompat,
              fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents |
                  fs::ext4_feature::kIncompatCsumSeed | fs::ext4_feature::kIncompatFlexBg);
        put8(img, lay::kSuperOffset + lay::kLogGroupsPerFlex, 8);
        expect_super_rejected(img, ErrorCode::CorruptStructure);
    }
}

TEST_CASE("ext4 superblock refuses features it cannot decode honestly", "[ext4][boot]") {
    for (uint32_t incompat : {fs::ext4_feature::kIncompatEncrypted,
                              fs::ext4_feature::kIncompatCasefold,
                              fs::ext4_feature::kIncompatCompression,
                              fs::ext4_feature::kIncompatMetaBg}) {
        auto img = make_image();
        put32(img, lay::kSuperOffset + lay::kFeatureIncompat,
              fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents |
                  fs::ext4_feature::kIncompatCsumSeed | incompat);
        uint32_t sb_csum = fs::crc32c_continue(0xFFFFFFFFu, img.data() + lay::kSuperOffset,
                                               lay::kSuperChecksum);
        put32(img, lay::kSuperOffset + lay::kSuperChecksum, sb_csum);
        MemoryDevice dev(img, 512);
        auto s = fs::read_superblock(dev);
        REQUIRE_FALSE(s.has_value());
        CHECK(s.error().code == ErrorCode::Unsupported);
    }
    // METADATA_CSUM is a read-only-compatible bit; LARGEDIR is the incompat 0x4000 that
    // sits at the same bit number, and it is readable.
    auto img = make_image();
    put32(img, lay::kSuperOffset + lay::kFeatureIncompat,
          fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents |
              fs::ext4_feature::kIncompatCsumSeed | fs::ext4_feature::kIncompatLargeDir);
    uint32_t sb_csum = fs::crc32c_continue(0xFFFFFFFFu, img.data() + lay::kSuperOffset,
                                           lay::kSuperChecksum);
    put32(img, lay::kSuperOffset + lay::kSuperChecksum, sb_csum);
    MemoryDevice dev(img, 512);
    CHECK(fs::read_superblock(dev).has_value());
}

TEST_CASE("ext4 counts block groups from the first data block", "[ext4][boot]") {
    // 4 KiB blocks, so block 0 holds the superblock and block 1 is the first data block.
    // Nine blocks with eight per group is one group of blocks 1..8; counting from
    // s_blocks_count alone would invent a second group for a block that does not exist.
    std::vector<uint8_t> img(9 * 4096, 0);
    const size_t s = lay::kSuperOffset;
    put32(img, s + lay::kInodesCount, 16);
    put32(img, s + lay::kBlocksCountLo, 9);
    put32(img, s + lay::kFirstDataBlock, 1);
    put32(img, s + lay::kLogBlockSize, 2);  // 1024 << 2
    put32(img, s + lay::kBlocksPerGroup, 8);
    put32(img, s + lay::kInodesPerGroup, 16);
    put16(img, s + lay::kMagic, lay::kMagicValue);
    put16(img, s + lay::kState, 1);
    put16(img, s + lay::kErrors, 1);
    put32(img, s + lay::kRevLevel, 1);
    put32(img, s + lay::kFirstIno, 11);
    put16(img, s + lay::kInodeSize, kInodeSize);
    put32(img, s + lay::kFeatureIncompat,
          fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents);
    put16(img, s + lay::kDescSize, 32);

    MemoryDevice dev(img, 512);
    auto super = fs::read_superblock(dev);
    REQUIRE(super.has_value());
    CHECK(super->block_size == 4096);
    CHECK(super->first_data_block == 1);
    CHECK(super->group_count() == 1);
    CHECK(super->group_first_block(0) == 1);
    CHECK(super->block_to_byte(1) == 4096);
    // The descriptor table starts in block 1 on a 4 KiB volume, not block 2.
    fs::Ext4GroupTable groups(std::make_shared<MemoryDevice>(img, 512), *super);
    CHECK(groups.gdt_start_block() == 1);
}

TEST_CASE("ext4 group descriptor parse and checksum", "[ext4][group]") {
    auto img = make_image();
    MemoryDevice dev(img, 512);
    auto super = fs::read_superblock(dev);
    REQUIRE(super.has_value());
    auto table = std::make_shared<MemoryDevice>(img, 512);
    fs::Ext4GroupTable groups(table, *super);
    CHECK(groups.gdt_start_block() == 2);
    auto g = groups.at(0);
    REQUIRE(g.has_value());
    CHECK(g->block_bitmap == kBitmapBlock);
    CHECK(g->inode_bitmap == kInodeBitmapBlock);
    CHECK(g->inode_table == kInodeTableBlock);
    CHECK(g->free_blocks_count == 60);
    CHECK(g->free_inodes_count == 10);
    CHECK(g->used_dirs_count == 2);
    CHECK(g->itable_unused == 2);
    CHECK(g->checksum_verified);
    CHECK_FALSE(groups.at(1).has_value());

    SECTION("a mutated descriptor fails its checksum but still parses") {
        img[kGdtOffset + lay::kBgFreeBlocksCount] ^= 0x01;
        fs::Ext4GroupTable g2(std::make_shared<MemoryDevice>(img, 512), *super);
        auto d = g2.at(0);
        REQUIRE(d.has_value());
        CHECK_FALSE(d->checksum_verified);
        CHECK(d->free_blocks_count != 60);
    }
}

TEST_CASE("a 64-bit descriptor is checksummed over all 64 bytes", "[ext4][group]") {
    auto img = make_image();
    const size_t s = lay::kSuperOffset;
    put32(img, s + lay::kFeatureIncompat,
          fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents |
              fs::ext4_feature::kIncompatCsumSeed | fs::ext4_feature::kIncompat64Bit);
    put16(img, s + lay::kDescSize, 64);
    // A byte in the high half that the 32-byte rule never reads.
    img[kGdtOffset + 63] = 0xA5;

    uint32_t sb_csum =
        fs::crc32c_continue(0xFFFFFFFFu, img.data() + s, lay::kSuperChecksum);
    put32(img, s + lay::kSuperChecksum, sb_csum);

    put16(img, kGdtOffset + lay::kBgChecksum, 0);
    uint32_t g_csum = fs::crc32c_continue(0x12345678u, fs::le32_bytes(0).data(), 4);
    g_csum = fs::crc32c_continue(g_csum, img.data() + kGdtOffset, lay::kBgChecksum);
    g_csum = fs::crc32c_zeros(g_csum, 2);
    g_csum = fs::crc32c_continue(g_csum, img.data() + kGdtOffset + lay::kBgChecksum + 2,
                                 64 - (lay::kBgChecksum + 2));
    put16(img, kGdtOffset + lay::kBgChecksum, static_cast<uint16_t>(g_csum & 0xFFFFu));

    MemoryDevice dev(img, 512);
    auto super = fs::read_superblock(dev);
    REQUIRE(super.has_value());
    CHECK(super->desc_size == 64);
    CHECK(super->incompatible_64bit());
    fs::Ext4GroupTable groups(std::make_shared<MemoryDevice>(img, 512), *super);
    auto d = groups.at(0);
    REQUIRE(d.has_value());
    CHECK(d->checksum_verified);

    SECTION("the tail is part of the checksum") {
        img[kGdtOffset + 63] ^= 0xFF;
        fs::Ext4GroupTable changed(std::make_shared<MemoryDevice>(img, 512), *super);
        auto c = changed.at(0);
        REQUIRE(c.has_value());
        CHECK_FALSE(c->checksum_verified);
    }
}

TEST_CASE("ext4 crc16 group descriptors predate metadata_csum", "[ext4][group]") {
    auto img = make_image();
    put32(img, lay::kSuperOffset + lay::kFeatureRoCompat,
          fs::ext4_feature::kRoCompatSparseSuper | fs::ext4_feature::kRoCompatGdtCsum);
    // The gdt_csum rule chains the UUID, the group number, then the descriptor up to
    // bg_checksum with nothing after it in a 32-byte entry.
    uint16_t c = fs::crc16_continue(0xFFFFu, img.data() + lay::kSuperOffset + lay::kUuid, 16);
    const uint8_t zero_group[4] = {0, 0, 0, 0};
    c = fs::crc16_continue(c, zero_group, 4);
    c = fs::crc16_continue(c, img.data() + kGdtOffset, lay::kBgChecksum);
    put16(img, kGdtOffset + lay::kBgChecksum, c);
    MemoryDevice dev(img, 512);
    auto super = fs::read_superblock(dev);
    REQUIRE(super.has_value());
    CHECK_FALSE(super->metadata_csum());
    CHECK(super->gdt_csum());
    fs::Ext4GroupTable groups(std::make_shared<MemoryDevice>(img, 512), *super);
    auto d = groups.at(0);
    REQUIRE(d.has_value());
    CHECK(d->checksum_verified);
}

TEST_CASE("ext4 inode parse", "[ext4][inode]") {
    auto img = make_image();
    MemoryDevice dev(img, 512);
    auto s = fs::read_superblock(dev);
    REQUIRE(s.has_value());

    auto live = fs::parse_inode(std::span<const uint8_t>(img.data() + inode_off(11), kInodeSize),
                               *s, 11);
    REQUIRE(live.has_value());
    CHECK(live->links_count == 1);
    CHECK_FALSE(live->deleted());  // links survive, so this file is still in use
    CHECK(live->is_regular());
    CHECK(live->size == 40000);
    CHECK(live->blocks == 80);
    CHECK(live->allocated_bytes(s->block_size) == 80 * 512);
    CHECK(live->uid == 1000u);
    CHECK(live->extents);
    CHECK(live->mtime == 1700000002);
    CHECK(live->generation == 0x1111);
    CHECK(live->extra_isize == kExtraISize);
    CHECK(live->checksum_verified);
    CHECK(live->block_area.size() == lay::kInodeBlockAreaBytes);

    auto node = fs::parse_ext_node(live->block_area, *s, true);
    REQUIRE(node.has_value());
    REQUIRE(node->leaves.size() == 3);
    CHECK(node->depth == 0);
    CHECK(node->max_entries == 4);
    CHECK(node->leaves[0].first_block == 0);
    CHECK(node->leaves[0].start_block == 20);
    CHECK(node->leaves[0].length == 4);
    CHECK_FALSE(node->leaves[0].unwritten);
    CHECK(node->leaves[1].unwritten);
    CHECK(node->leaves[1].length == 4);  // the unwritten bit is not part of the length
    CHECK(node->leaves[1].start_block == 30);

    auto dead = fs::parse_inode(std::span<const uint8_t>(img.data() + inode_off(12), kInodeSize),
                                *s, 12);
    REQUIRE(dead.has_value());
    CHECK(dead->deleted());            // links_count is zero and i_dtime says when
    CHECK(dead->is_regular());         // i_mode survived the unlink, as it always does
    CHECK(dead->dtime == 1700009999);  // but the deletion timestamp survived
    CHECK(dead->extents);
    CHECK(dead->allocated_bytes(s->block_size) == 24 * 512);
    auto dead_ext = fs::parse_ext_node(dead->block_area, *s, true);
    REQUIRE(dead_ext.has_value());
    REQUIRE(dead_ext->leaves.size() == 1);
    CHECK(dead_ext->leaves[0].start_block == 60);

    auto inl = fs::parse_inode(std::span<const uint8_t>(img.data() + inode_off(13), kInodeSize),
                              *s, 13);
    REQUIRE(inl.has_value());
    CHECK(inl->inline_data);
    CHECK_FALSE(inl->extents);
    CHECK(inl->size == 20);
    CHECK(inl->uid == ((1u << 16) | 1000u));  // i_uid_high extends the 16-bit field

    auto old = fs::parse_inode(std::span<const uint8_t>(img.data() + inode_off(14), kInodeSize),
                              *s, 14);
    REQUIRE(old.has_value());
    CHECK_FALSE(old->extents);
    CHECK(old->size == ((1ull << 32) + 100000));  // i_size_high is part of the file length
    // The pre-extents shape: direct block 0 and the single-indirect pointer at slot 12.
    CHECK(fs::u32_at(old->block_area, 0) == 70);
    CHECK(fs::u32_at(old->block_area, 12 * 4) == 71);
    auto not_extent = fs::parse_ext_node(old->block_area, *s, true);
    REQUIRE_FALSE(not_extent.has_value());
    CHECK(not_extent.error().code == ErrorCode::CorruptStructure);

    SECTION("a flipped data byte invalidates the inode checksum") {
        img[inode_off(11) + lay::kInodeMtime] ^= 0x01;
        auto bad = fs::parse_inode(std::span<const uint8_t>(img.data() + inode_off(11), kInodeSize),
                                   *s, 11);
        REQUIRE(bad.has_value());
        CHECK_FALSE(bad->checksum_verified);
    }
}

TEST_CASE("ext4 inode location arithmetic", "[ext4][inode]") {
    const auto s = make_super();
    auto loc = fs::inode_location(s, kInodeTableBlock, 11);
    REQUIRE(loc.has_value());
    CHECK(loc->group == 0);
    CHECK(loc->index_in_group == 10);
    CHECK(loc->byte_offset == kInodeTableBlock * kBlock + 10 * kInodeSize);
    CHECK(loc->byte_offset == inode_off(11));

    auto second = fs::inode_location(s, kInodeTableBlock, 1);
    REQUIRE(second.has_value());
    CHECK(second->index_in_group == 0);

    CHECK_FALSE(fs::inode_location(s, kInodeTableBlock, 0).has_value());
    CHECK_FALSE(fs::inode_location(s, kInodeTableBlock, kInodesPerGroup + 1).has_value());
}
