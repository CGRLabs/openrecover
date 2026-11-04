#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/common/crc32.hpp"
#include "openrecover/partition/gpt.hpp"
#include "openrecover/partition/mbr.hpp"
#include "openrecover/partition/partition_scanner.hpp"

namespace {

using openrecover::partition::PartitionInfo;
using openrecover::partition::PartitionScheme;
using openrecover::test::MemoryDevice;

constexpr size_t kSector = 512;
constexpr size_t kMbrTable = 0x1BE;

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

void sign_sector(std::vector<uint8_t>& img, size_t lba) {
    img[lba * kSector + 510] = 0x55;
    img[lba * kSector + 511] = 0xAA;
}

void write_mbr_entry(std::vector<uint8_t>& img, size_t table_lba, size_t index, uint8_t type, uint32_t start,
                     uint32_t count) {
    const size_t off = table_lba * kSector + kMbrTable + index * 16;
    img[off + 4] = type;
    put32(img, off + 8, start);
    put32(img, off + 12, count);
}

std::vector<uint8_t> make_mbr_disk(uint64_t sectors) {
    std::vector<uint8_t> img(static_cast<size_t>(sectors * kSector), 0);
    sign_sector(img, 0);
    return img;
}

std::unique_ptr<MemoryDevice> device_of(const std::vector<uint8_t>& img, uint32_t sector_size = 512) {
    return std::make_unique<MemoryDevice>(img, sector_size, "partition-test");
}

constexpr std::array<uint8_t, 16> kMsBasicData = {0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
                                                  0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7};

struct GptLayout {
    uint64_t sectors = 2048;
    uint64_t start_lba = 100;
    uint64_t end_lba = 300;
};

void write_gpt_header(std::vector<uint8_t>& img, uint64_t lba, uint64_t my_lba, uint64_t alternate_lba,
                      uint64_t entry_lba, uint32_t entry_count, uint32_t entry_size, uint32_t entries_crc,
                      uint64_t sectors) {
    const size_t off = static_cast<size_t>(lba * kSector);
    std::memcpy(img.data() + off, "EFI PART", 8);
    put32(img, off + 8, 0x00010000);
    put32(img, off + 12, 92);
    put32(img, off + 16, 0);
    put32(img, off + 20, 0);
    put64(img, off + 24, my_lba);
    put64(img, off + 32, alternate_lba);
    put64(img, off + 40, 34);
    put64(img, off + 48, sectors - 34);
    for (size_t i = 0; i < 16; ++i) img[off + 56 + i] = static_cast<uint8_t>(0xA0 + i);
    put64(img, off + 72, entry_lba);
    put32(img, off + 80, entry_count);
    put32(img, off + 84, entry_size);
    put32(img, off + 88, entries_crc);
    put32(img, off + 16, openrecover::crc32(std::span<const uint8_t>(img.data() + off, 92)));
}

std::vector<uint8_t> make_gpt_image(const GptLayout& layout, bool corrupt_primary_header = false,
                                    bool corrupt_primary_entries = false, bool corrupt_backup_header = false) {
    std::vector<uint8_t> img(static_cast<size_t>(layout.sectors * kSector), 0);
    write_mbr_entry(img, 0, 0, 0xEE, 1, static_cast<uint32_t>(layout.sectors - 1));
    sign_sector(img, 0);

    std::vector<uint8_t> entries(128 * 128, 0);
    std::memcpy(entries.data(), kMsBasicData.data(), kMsBasicData.size());
    for (size_t i = 0; i < 16; ++i) entries[16 + i] = static_cast<uint8_t>(i + 1);
    put64(entries, 32, layout.start_lba);
    put64(entries, 40, layout.end_lba);
    const char16_t name[] = u"Data";
    for (size_t i = 0; i < 4; ++i) put16(entries, 56 + i * 2, static_cast<uint16_t>(name[i]));
    const uint32_t entries_crc =
        openrecover::crc32(std::span<const uint8_t>(entries.data(), entries.size()));

    constexpr uint64_t kPrimaryEntriesLba = 2;
    const uint64_t backup_entries_lba = layout.sectors - 33;
    std::memcpy(img.data() + kPrimaryEntriesLba * kSector, entries.data(), entries.size());
    std::memcpy(img.data() + backup_entries_lba * kSector, entries.data(), entries.size());

    write_gpt_header(img, 1, 1, layout.sectors - 1, kPrimaryEntriesLba, 128, 128, entries_crc, layout.sectors);
    write_gpt_header(img, layout.sectors - 1, layout.sectors - 1, 1, backup_entries_lba, 128, 128, entries_crc,
                     layout.sectors);

    if (corrupt_primary_header) img[1 * kSector + 16] ^= 0xFF;
    if (corrupt_primary_entries) img[kPrimaryEntriesLba * kSector + 56] ^= 0xFF;
    if (corrupt_backup_header) img[(layout.sectors - 1) * kSector + 16] ^= 0xFF;
    return img;
}

void check_partition(const PartitionInfo& p, uint32_t index, uint64_t start, uint64_t length,
                     const char* description, PartitionScheme scheme) {
    CHECK(p.index == index);
    CHECK(p.start_byte == start);
    CHECK(p.length_byte == length);
    CHECK(p.type_desc == description);
    CHECK(p.scheme == scheme);
}

}  // namespace

TEST_CASE("MBR primary partitions are decoded", "[mbr]") {
    auto img = make_mbr_disk(4096);
    write_mbr_entry(img, 0, 0, 0x07, 100, 200);
    write_mbr_entry(img, 0, 1, 0x0C, 400, 300);
    auto dev = device_of(img);

    auto parts = openrecover::partition::scan_partitions(*dev);
    REQUIRE(parts.has_value());
    REQUIRE(parts->size() == 2);
    check_partition((*parts)[0], 0, 100 * kSector, 200 * kSector, "NTFS/exFAT", PartitionScheme::Mbr);
    check_partition((*parts)[1], 1, 400 * kSector, 300 * kSector, "FAT32 (LBA)", PartitionScheme::Mbr);

    auto direct = openrecover::partition::parse_mbr(*dev);
    REQUIRE(direct.has_value());
    REQUIRE(direct->size() == 2);
}

TEST_CASE("MBR extended chain yields logical partitions", "[mbr]") {
    auto img = make_mbr_disk(4096);
    write_mbr_entry(img, 0, 0, 0x0F, 100, 1000);
    write_mbr_entry(img, 0, 1, 0x83, 2000, 100);

    write_mbr_entry(img, 100, 0, 0x07, 1, 50);
    write_mbr_entry(img, 100, 1, 0x0F, 200, 100);
    sign_sector(img, 100);

    write_mbr_entry(img, 300, 0, 0x0B, 1, 60);
    sign_sector(img, 300);

    auto dev = device_of(img);
    auto parts = openrecover::partition::scan_partitions(*dev);
    REQUIRE(parts.has_value());
    REQUIRE(parts->size() == 3);
    check_partition((*parts)[0], 0, 2000 * kSector, 100 * kSector, "Linux", PartitionScheme::Mbr);
    check_partition((*parts)[1], 1, 101 * kSector, 50 * kSector, "NTFS/exFAT", PartitionScheme::Mbr);
    check_partition((*parts)[2], 2, 301 * kSector, 60 * kSector, "FAT32", PartitionScheme::Mbr);
}

TEST_CASE("MBR extended chain stops on a loop", "[mbr]") {
    auto img = make_mbr_disk(4096);
    write_mbr_entry(img, 0, 0, 0x05, 100, 1000);

    write_mbr_entry(img, 100, 0, 0x06, 1, 10);
    write_mbr_entry(img, 100, 1, 0x05, 100, 100);
    sign_sector(img, 100);

    write_mbr_entry(img, 200, 0, 0x0B, 1, 10);
    write_mbr_entry(img, 200, 1, 0x05, 0, 100);
    sign_sector(img, 200);

    auto dev = device_of(img);
    auto parts = openrecover::partition::scan_partitions(*dev);
    REQUIRE(parts.has_value());
    REQUIRE(parts->size() == 2);
    CHECK((*parts)[0].start_byte == 101 * kSector);
    CHECK((*parts)[1].start_byte == 201 * kSector);
}

TEST_CASE("MBR without signature is rejected", "[mbr]") {
    const std::vector<uint8_t> img(4096 * kSector, 0);
    auto dev = device_of(img);
    auto parts = openrecover::partition::scan_partitions(*dev);
    REQUIRE_FALSE(parts.has_value());
    CHECK(parts.error().code == openrecover::ErrorCode::NoFilesystem);
}

TEST_CASE("Unpartitioned FAT32 and NTFS boot sectors are whole-device volumes", "[mbr]") {
    SECTION("FAT32") {
        auto img = make_mbr_disk(4096);
        img[0] = 0xEB;
        img[1] = 0x3C;
        img[2] = 0x90;
        put16(img, 0x0B, 512);
        img[0x0D] = 4;
        put16(img, 0x0E, 32);
        img[0x10] = 2;
        put32(img, 0x20, 4096);
        put32(img, 0x24, 32);
        put32(img, 0x2C, 2);
        auto dev = device_of(img);
        auto parts = openrecover::partition::scan_partitions(*dev);
        REQUIRE(parts.has_value());
        REQUIRE(parts->size() == 1);
        check_partition((*parts)[0], 0, 0, img.size(), "whole-device volume", PartitionScheme::Superfloppy);
    }
    SECTION("NTFS") {
        auto img = make_mbr_disk(4096);
        std::memcpy(img.data() + 3, "NTFS    ", 8);
        auto dev = device_of(img);
        auto parts = openrecover::partition::scan_partitions(*dev);
        REQUIRE(parts.has_value());
        REQUIRE(parts->size() == 1);
        CHECK((*parts)[0].scheme == PartitionScheme::Superfloppy);
    }
}

TEST_CASE("GPT primary header and entries are parsed", "[gpt]") {
    auto img = make_gpt_image(GptLayout{});
    auto dev = device_of(img);
    auto parts = openrecover::partition::parse_gpt(*dev);
    REQUIRE(parts.has_value());
    REQUIRE(parts->size() == 1);
    check_partition((*parts)[0], 0, 100 * kSector, 201 * kSector, "Microsoft basic data (Data)",
                    PartitionScheme::Gpt);

    auto scanned = openrecover::partition::scan_partitions(*dev);
    REQUIRE(scanned.has_value());
    REQUIRE(scanned->size() == 1);
    CHECK((*scanned)[0].scheme == PartitionScheme::Gpt);
}

TEST_CASE("GPT falls back to the backup header", "[gpt]") {
    SECTION("primary header CRC is wrong") {
        auto img = make_gpt_image(GptLayout{}, true, false, false);
        auto dev = device_of(img);
        auto parts = openrecover::partition::parse_gpt(*dev);
        REQUIRE(parts.has_value());
        REQUIRE(parts->size() == 1);
        CHECK((*parts)[0].start_byte == 100 * kSector);
    }
    SECTION("primary entry array CRC is wrong") {
        auto img = make_gpt_image(GptLayout{}, false, true, false);
        auto dev = device_of(img);
        auto parts = openrecover::partition::parse_gpt(*dev);
        REQUIRE(parts.has_value());
        REQUIRE(parts->size() == 1);
        CHECK((*parts)[0].length_byte == 201 * kSector);
    }
    SECTION("both copies invalid") {
        auto img = make_gpt_image(GptLayout{}, true, false, true);
        auto dev = device_of(img);
        auto parts = openrecover::partition::parse_gpt(*dev);
        REQUIRE_FALSE(parts.has_value());

        auto scanned = openrecover::partition::scan_partitions(*dev);
        REQUIRE(scanned.has_value());
        REQUIRE(scanned->size() == 1);
        CHECK((*scanned)[0].scheme == PartitionScheme::Mbr);
        CHECK((*scanned)[0].start_byte == 1 * kSector);
        CHECK((*scanned)[0].length_byte == 2047 * kSector);
        CHECK((*scanned)[0].type_desc == "GPT protective (invalid GPT, MBR fallback)");
    }
}

TEST_CASE("GPT entries outside the device are skipped", "[gpt]") {
    GptLayout layout;
    layout.end_lba = layout.sectors;
    auto img = make_gpt_image(layout);
    auto dev = device_of(img);
    auto parts = openrecover::partition::parse_gpt(*dev);
    REQUIRE(parts.has_value());
    CHECK(parts->empty());
}
