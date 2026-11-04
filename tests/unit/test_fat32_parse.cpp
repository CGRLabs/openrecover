#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/fat32.hpp"
#include "openrecover/fs/filesystem.hpp"

namespace {

using namespace openrecover;
using openrecover::fs::Fat32Bpb;
using openrecover::fs::FatAllocationMap;
using openrecover::fs::FatLfnEntry;
using openrecover::fs::FatReader;
using openrecover::fs::FatShortEntry;
using openrecover::test::MemoryDevice;

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

struct Layout {
    uint16_t bytes_per_sector = 512;
    uint8_t sectors_per_cluster = 1;
    uint16_t reserved_sectors = 32;
    uint8_t num_fats = 1;
    uint32_t total_sectors = 2048;
    uint32_t fat_size_sectors = 64;
    uint16_t ext_flags = 0;
    uint32_t root_cluster = 2;
    uint16_t backup_boot_sector = 6;
};

std::vector<uint8_t> boot_sector(const Layout& l) {
    std::vector<uint8_t> bs(512, 0);
    bs[0] = 0xEB;
    bs[1] = 0x3C;
    bs[2] = 0x90;
    std::memcpy(bs.data() + 3, "MSWIN4.1", 8);
    put16(bs, 0x0B, l.bytes_per_sector);
    bs[0x0D] = l.sectors_per_cluster;
    put16(bs, 0x0E, l.reserved_sectors);
    bs[0x10] = l.num_fats;
    bs[0x15] = 0xF8;
    put16(bs, 0x18, 0x3F);
    put16(bs, 0x1A, 0xFF);
    put32(bs, 0x1C, 0);
    put32(bs, 0x20, l.total_sectors);
    put32(bs, 0x24, l.fat_size_sectors);
    put16(bs, 0x28, l.ext_flags);
    put32(bs, 0x2C, l.root_cluster);
    put16(bs, 0x30, 1);
    put16(bs, 0x32, l.backup_boot_sector);
    bs[0x40] = 0x80;
    bs[0x42] = 0x29;
    put32(bs, 0x43, 0x12345678);
    std::memcpy(bs.data() + 0x47, "NO NAME    ", 11);
    std::memcpy(bs.data() + 0x52, "FAT32   ", 8);
    bs[0x1FE] = 0x55;
    bs[0x1FF] = 0xAA;
    return bs;
}

uint64_t volume_bytes(const Layout& l) {
    return static_cast<uint64_t>(l.total_sectors) * l.bytes_per_sector;
}

std::vector<uint8_t> make_image(const Layout& l) {
    std::vector<uint8_t> img(static_cast<size_t>(volume_bytes(l)), 0);
    const auto bs = boot_sector(l);
    std::memcpy(img.data(), bs.data(), bs.size());
    return img;
}

void write_fat_entry(std::vector<uint8_t>& img, const Layout& l, uint8_t fat_index, uint32_t cluster,
                     uint32_t value) {
    const uint64_t off = (static_cast<uint64_t>(l.reserved_sectors) +
                          static_cast<uint64_t>(fat_index) * l.fat_size_sectors) *
                             l.bytes_per_sector +
                         static_cast<uint64_t>(cluster) * 4;
    put32(img, static_cast<size_t>(off), value);
}

uint16_t fat_date(unsigned year, unsigned month, unsigned day) {
    return static_cast<uint16_t>(((year - 1980) << 9) | (month << 5) | day);
}

uint16_t fat_time(unsigned hour, unsigned minute, unsigned second) {
    return static_cast<uint16_t>((hour << 11) | (minute << 5) | (second / 2));
}

std::array<uint8_t, 11> short11(std::string_view s) {
    std::array<uint8_t, 11> out{};
    out.fill(' ');
    for (size_t i = 0; i < s.size() && i < out.size(); ++i)
        out[i] = static_cast<uint8_t>(s[i]);
    return out;
}

std::vector<uint8_t> short_raw(const std::array<uint8_t, 11>& name, uint8_t attr, uint8_t nt_res,
                               uint32_t cluster, uint32_t size, uint16_t crt_date = 0,
                               uint16_t crt_time = 0, uint16_t wrt_date = 0,
                               uint16_t wrt_time = 0, uint16_t acc_date = 0) {
    std::vector<uint8_t> raw(32, 0);
    std::memcpy(raw.data(), name.data(), name.size());
    raw[11] = attr;
    raw[12] = nt_res;
    raw[13] = 7;
    put16(raw, 14, crt_time);
    put16(raw, 16, crt_date);
    put16(raw, 18, acc_date);
    put16(raw, 20, static_cast<uint16_t>((cluster >> 16) & 0x0FFF));
    put16(raw, 22, wrt_time);
    put16(raw, 24, wrt_date);
    put16(raw, 26, static_cast<uint16_t>(cluster & 0xFFFF));
    put32(raw, 28, size);
    return raw;
}

std::u16string to_u16(std::string_view s) {
    std::u16string out;
    for (char c : s) out.push_back(static_cast<char16_t>(static_cast<unsigned char>(c)));
    return out;
}

FatLfnEntry lfn_entry(uint8_t ord, uint8_t checksum, std::u16string_view text) {
    FatLfnEntry e;
    e.ord = ord;
    e.checksum = checksum;
    e.deleted = ord == 0xE5;
    e.name.fill(0xFFFF);
    for (size_t i = 0; i < text.size() && i < e.name.size(); ++i)
        e.name[i] = static_cast<uint16_t>(text[i]);
    if (text.size() < e.name.size()) e.name[text.size()] = 0x0000;
    return e;
}

fs::Fat32Bpb reader_bpb() {
    fs::Fat32Bpb b;
    b.bytes_per_sector = 512;
    b.sectors_per_cluster = 1;
    b.reserved_sectors = 32;
    b.num_fats = 1;
    b.total_sectors = 2048;
    b.fat_size_sectors = 256;
    b.root_cluster = 2;
    b.bytes_per_cluster = 512;
    b.fat_start_byte = 0;
    b.data_start_byte = 131072;
    b.cluster_count = 2000;
    b.max_valid_cluster = 30000;
    b.active_fat = 0;
    return b;
}

std::shared_ptr<MemoryDevice> fat_device(std::vector<uint8_t>& fat) {
    return std::make_shared<MemoryDevice>(fat, 512, "fat-reader");
}

}  // namespace

TEST_CASE("FAT32 BPB accepts a valid 512-byte-sector volume") {
    Layout l;
    const auto bs = boot_sector(l);
    auto bpb = fs::parse_fat32_bpb(bs, volume_bytes(l));
    REQUIRE(bpb);
    CHECK(bpb->bytes_per_sector == 512);
    CHECK(bpb->sectors_per_cluster == 1);
    CHECK(bpb->reserved_sectors == 32);
    CHECK(bpb->num_fats == 1);
    CHECK(bpb->bytes_per_cluster == 512);
    CHECK(bpb->fat_start_byte == 32 * 512);
    CHECK(bpb->data_start_byte == (32 + 64) * 512);
    CHECK(bpb->cluster_count == 2048 - 32 - 64);
    CHECK(bpb->max_valid_cluster == 2048 - 32 - 64 + 1);
    CHECK(bpb->active_fat == 0);
}

TEST_CASE("FAT32 BPB accepts 4096-byte sectors and an E9 jump") {
    Layout l;
    l.bytes_per_sector = 4096;
    l.sectors_per_cluster = 8;
    l.num_fats = 2;
    l.total_sectors = 4096;
    l.fat_size_sectors = 64;
    auto bs = boot_sector(l);
    bs[0] = 0xE9;
    bs[1] = 0x00;
    bs[2] = 0x00;
    auto bpb = fs::parse_fat32_bpb(bs, volume_bytes(l));
    REQUIRE(bpb);
    CHECK(bpb->bytes_per_cluster == 4096u * 8);
    CHECK(bpb->fat_start_byte == 32ull * 4096);
    CHECK(bpb->data_start_byte == 160ull * 4096);
    CHECK(bpb->cluster_count == (4096 - 160) / 8);
    CHECK(bpb->max_valid_cluster == (4096 - 160) / 8 + 1);
}

TEST_CASE("FAT32 BPB rejects malformed boot sectors") {
    Layout l;
    auto bs = boot_sector(l);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l) - 512));

    bs = boot_sector(l);
    put16(bs, 0x16, 1);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put16(bs, 0x11, 512);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put16(bs, 0x13, 1);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    bs[0x1FE] = 0;
    bs[0x1FF] = 0;
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put16(bs, 0x0B, 256);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    bs[0x0D] = 3;
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put16(bs, 0x0E, 0);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    bs[0x10] = 3;
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put32(bs, 0x20, 0);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put32(bs, 0x24, 0);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put32(bs, 0x2C, 1);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put32(bs, 0x20, l.total_sectors + 1);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    put32(bs, 0x24, 2016);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    bs = boot_sector(l);
    bs.resize(511);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));
}

TEST_CASE("FAT32 ExtFlags selects the active FAT") {
    Layout l;
    l.num_fats = 2;
    l.ext_flags = 0x0081;
    auto bs = boot_sector(l);
    auto bpb = fs::parse_fat32_bpb(bs, volume_bytes(l));
    REQUIRE(bpb);
    CHECK(bpb->active_fat == 1);
    CHECK(bpb->data_start_byte == (32 + 2 * 64) * 512);

    l.ext_flags = 0x0082;
    bs = boot_sector(l);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));

    l.ext_flags = 0x0081;
    l.num_fats = 1;
    bs = boot_sector(l);
    CHECK_FALSE(fs::parse_fat32_bpb(bs, volume_bytes(l)));
}

TEST_CASE("FAT32 backup boot sector is used when the primary is corrupt") {
    Layout l;
    std::vector<uint8_t> img = make_image(l);
    const auto bs = boot_sector(l);
    img[0x1FE] = 0;
    img[0x1FF] = 0;
    std::memcpy(img.data() + static_cast<size_t>(l.backup_boot_sector) * l.bytes_per_sector,
                bs.data(), bs.size());

    MemoryDevice dev(img, 512, "fat-backup");
    auto bpb = fs::read_fat32_bpb(dev);
    REQUIRE(bpb);
    CHECK(bpb->total_sectors == l.total_sectors);
    CHECK(dev.read_count() >= 2);

    img[static_cast<size_t>(l.backup_boot_sector) * l.bytes_per_sector + 0x1FE] = 0;
    img[static_cast<size_t>(l.backup_boot_sector) * l.bytes_per_sector + 0x1FF] = 0;
    MemoryDevice broken(img, 512, "fat-broken");
    auto failed = fs::read_fat32_bpb(broken);
    REQUIRE_FALSE(failed);
    CHECK(failed.error().code == ErrorCode::CorruptStructure);
}

TEST_CASE("FAT chain walker stops at EOC, free, bad, cycles and out-of-range links") {
    const fs::Fat32Bpb b = reader_bpb();
    std::vector<uint8_t> fat(static_cast<size_t>(b.fat_size_sectors) * b.bytes_per_sector, 0);
    auto set = [&](uint32_t cluster, uint32_t value) {
        put32(fat, static_cast<size_t>(cluster) * 4, value);
    };

    SECTION("EOC") {
        set(2, 3);
        set(3, 4);
        set(4, fs::kFatEndOfChain);
        auto dev = fat_device(fat);
        FatReader reader(dev, b);
        auto chain = reader.chain(2);
        REQUIRE(chain);
        CHECK(*chain == std::vector<uint32_t>{2, 3, 4});
    }
    SECTION("free cluster terminates") {
        set(2, 3);
        set(3, 0);
        set(4, 5);
        auto dev = fat_device(fat);
        FatReader reader(dev, b);
        auto chain = reader.chain(2);
        REQUIRE(chain);
        CHECK(*chain == std::vector<uint32_t>{2, 3});
    }
    SECTION("bad cluster terminates") {
        set(2, 3);
        set(3, fs::kFatBad);
        auto dev = fat_device(fat);
        FatReader reader(dev, b);
        auto chain = reader.chain(2);
        REQUIRE(chain);
        CHECK(*chain == std::vector<uint32_t>{2, 3});
    }
    SECTION("cycle terminates") {
        set(2, 3);
        set(3, 2);
        auto dev = fat_device(fat);
        FatReader reader(dev, b);
        auto chain = reader.chain(2);
        REQUIRE(chain);
        CHECK(*chain == std::vector<uint32_t>{2, 3});
    }
    SECTION("out-of-range link terminates") {
        set(2, b.max_valid_cluster + 1);
        auto dev = fat_device(fat);
        FatReader reader(dev, b);
        auto chain = reader.chain(2);
        REQUIRE(chain);
        CHECK(*chain == std::vector<uint32_t>{2});
    }
    SECTION("invalid start fails") {
        auto dev = fat_device(fat);
        FatReader reader(dev, b);
        CHECK_FALSE(reader.chain(0));
        CHECK_FALSE(reader.chain(1));
        CHECK_FALSE(reader.chain(b.max_valid_cluster + 1));
        CHECK_FALSE(reader.entry(0));
        CHECK_FALSE(reader.entry(b.max_valid_cluster + 1));
    }
    SECTION("entry masks reserved high bits") {
        set(2, 0xF0000003u);
        auto dev = fat_device(fat);
        FatReader reader(dev, b);
        auto value = reader.entry(2);
        REQUIRE(value);
        CHECK(*value == 3);
    }
    SECTION("multiple FATs use the active one") {
        fs::Fat32Bpb two = b;
        two.fat_size_sectors = 128;
        two.num_fats = 2;
        two.active_fat = 1;
        std::vector<uint8_t> two_fat(static_cast<size_t>(two.fat_size_sectors) * 2 * 512, 0);
        put32(two_fat, static_cast<size_t>(2) * 4, fs::kFatEndOfChain);
        const size_t fat1 = static_cast<size_t>(two.fat_size_sectors) * 512;
        put32(two_fat, fat1 + static_cast<size_t>(2) * 4, 7);
        put32(two_fat, fat1 + static_cast<size_t>(7) * 4, fs::kFatEndOfChain);
        auto dev = fat_device(two_fat);
        FatReader reader(dev, two);
        auto chain = reader.chain(2);
        REQUIRE(chain);
        CHECK(*chain == std::vector<uint32_t>{2, 7});
    }
}

TEST_CASE("FatReader window cache crosses the 64 KiB boundary") {
    fs::Fat32Bpb b = reader_bpb();
    std::vector<uint8_t> fat(static_cast<size_t>(b.fat_size_sectors) * b.bytes_per_sector, 0);
    put32(fat, 2 * 4, 0x0FFFFFFF);
    put32(fat, 20000 * 4, 0x0FFFFFF8);
    auto dev = fat_device(fat);
    FatReader reader(dev, b);
    auto first = reader.entry(2);
    REQUIRE(first);
    CHECK(*first == 0x0FFFFFFF);
    CHECK(dev->read_count() == 1);
    auto second = reader.entry(20000);
    REQUIRE(second);
    CHECK(*second == 0x0FFFFFF8);
    CHECK(dev->read_count() == 2);
}

TEST_CASE("FatAllocationMap reports allocated clusters conservatively") {
    const fs::Fat32Bpb b = reader_bpb();
    std::vector<uint8_t> fat(static_cast<size_t>(b.fat_size_sectors) * b.bytes_per_sector, 0);
    put32(fat, 2 * 4, 3);
    put32(fat, 3 * 4, fs::kFatEndOfChain);
    auto dev = fat_device(fat);
    auto reader = std::make_shared<FatReader>(dev, b);
    FatAllocationMap map(reader);
    CHECK(map.is_cluster_allocated(2));
    CHECK(map.is_cluster_allocated(3));
    CHECK_FALSE(map.is_cluster_allocated(4));
    CHECK(map.is_cluster_allocated(0));
    CHECK(map.is_cluster_allocated(b.max_valid_cluster + 1));
    CHECK(map.cluster_count() == b.cluster_count);
    CHECK(map.cluster_to_byte_offset(2) == b.data_start_byte);
    CHECK(map.cluster_to_byte_offset(3) == b.data_start_byte + b.bytes_per_cluster);
}

TEST_CASE("FAT short entry decoding and 0x05 rule") {
    SECTION("fields and 28-bit cluster") {
        auto raw = short_raw(short11("FILE    TXT"), 0x21, 0, 0x12345678, 0x11223344);
        put16(raw, 20, 0xF234);
        const FatShortEntry e = fs::decode_short_entry(raw);
        CHECK(e.name == short11("FILE    TXT"));
        CHECK(e.attr == 0x21);
        CHECK(e.first_cluster == 0x02345678);
        CHECK(e.file_size == 0x11223344);
        CHECK_FALSE(e.deleted);
        CHECK_FALSE(e.end_of_directory);
        CHECK_FALSE(e.is_directory());
        CHECK(e.is_volume_label() == false);
    }
    SECTION("0x05 means a real first byte of 0xE5") {
        auto raw = short_raw(short11("XILE    TXT"), 0x20, 0, 2, 10);
        raw[0] = 0x05;
        const FatShortEntry e = fs::decode_short_entry(raw);
        CHECK(fs::decode_short_name(e) == std::string("\xCF\x83ILE.TXT"));
    }
    SECTION("deleted marker and first-character loss") {
        auto raw = short_raw(short11("XILE    TXT"), 0x20, 0, 2, 10);
        raw[0] = 0xE5;
        const FatShortEntry e = fs::decode_short_entry(raw);
        CHECK(e.deleted);
        CHECK(fs::decode_short_name(e, true) == "_ILE.TXT");
    }
    SECTION("NTRes lowercase bits") {
        auto raw = short_raw(short11("README  TXT"), 0x20, 0x08, 2, 10);
        CHECK(fs::decode_short_name(fs::decode_short_entry(raw)) == "readme.TXT");
        raw[12] = 0x10;
        CHECK(fs::decode_short_name(fs::decode_short_entry(raw)) == "README.txt");
        raw[12] = 0x18;
        CHECK(fs::decode_short_name(fs::decode_short_entry(raw)) == "readme.txt");
    }
    SECTION("attributes") {
        auto raw = short_raw(short11("DIR        "), 0x10, 0, 2, 0);
        CHECK(fs::decode_short_entry(raw).is_directory());
        raw[11] = 0x08;
        CHECK(fs::decode_short_entry(raw).is_volume_label());
        raw[11] = 0x0F;
        CHECK(fs::decode_short_entry(raw).is_lfn());
        raw[0] = 0x00;
        CHECK(fs::decode_short_entry(raw).end_of_directory);
    }
    SECTION("truncated entry") {
        std::vector<uint8_t> raw(16, 0);
        const FatShortEntry e = fs::decode_short_entry(raw);
        CHECK(e.file_size == 0);
        CHECK(fs::decode_short_name(e).empty() == false);
    }
}

TEST_CASE("FAT timestamps validate fields and assume UTC") {
    CHECK(fs::fat_datetime_to_unix(fat_date(1980, 1, 1), 0) == 315532800);
    CHECK(fs::fat_datetime_to_unix(fat_date(1980, 2, 29), 0) == 320630400);
    CHECK(fs::fat_datetime_to_unix(fat_date(2000, 2, 29), fat_time(12, 34, 56)) == 951827696);
    CHECK(fs::fat_datetime_to_unix(fat_date(2107, 12, 31), fat_time(23, 59, 58)) == 4354819198);
    CHECK(fs::fat_datetime_to_unix(fat_date(2024, 3, 5), fat_time(6, 7, 8)) == 1709618828);

    CHECK_FALSE(fs::fat_datetime_to_unix(0, 0));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2000, 0, 1), 0));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2000, 13, 1), 0));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2000, 1, 0), 0));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2023, 2, 29), 0));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2000, 1, 32), 0));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2000, 1, 1), fat_time(24, 0, 0)));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2000, 1, 1), fat_time(0, 60, 0)));
    CHECK_FALSE(fs::fat_datetime_to_unix(fat_date(2000, 1, 1), 30));
}

TEST_CASE("LFN assembler joins a three-part name in sequence order") {
    const auto short_name = short11("THISISA TXT");
    const uint8_t checksum = fs::short_name_checksum(short_name);
    const std::string long_name = "This is a very long file name.txt";
    const std::u16string units = to_u16(long_name);

    std::vector<FatLfnEntry> stack;
    stack.push_back(lfn_entry(0x43, checksum, std::u16string_view(units).substr(26)));
    stack.push_back(lfn_entry(0x02, checksum, std::u16string_view(units).substr(13, 13)));
    stack.push_back(lfn_entry(0x01, checksum, std::u16string_view(units).substr(0, 13)));

    auto name = fs::assemble_lfn(stack, short_name, false);
    REQUIRE(name);
    CHECK(*name == long_name);

    auto wrong_checksum = stack;
    wrong_checksum[1].checksum = static_cast<uint8_t>(checksum + 1);
    CHECK_FALSE(fs::assemble_lfn(wrong_checksum, short_name, false));

    auto wrong_sequence = stack;
    wrong_sequence[0].ord = 0x44;
    CHECK_FALSE(fs::assemble_lfn(wrong_sequence, short_name, false));

    auto missing_last = stack;
    missing_last[0].ord = 0x03;
    CHECK_FALSE(fs::assemble_lfn(missing_last, short_name, false));

    std::vector<FatLfnEntry> empty;
    CHECK_FALSE(fs::assemble_lfn(empty, short_name, false));
}

TEST_CASE("Deleted LFN uses checksum brute force for the lost first character") {
    const auto original_short = short11("DELETED TXT");
    const uint8_t checksum = fs::short_name_checksum(original_short);
    auto deleted_short = original_short;
    deleted_short[0] = 0xE5;

    const std::string long_name = "Deleted Long Name.txt";
    const std::u16string units = to_u16(long_name);
    std::vector<FatLfnEntry> stack;
    stack.push_back(lfn_entry(0xE5, checksum, std::u16string_view(units).substr(13)));
    stack.push_back(lfn_entry(0xE5, checksum, std::u16string_view(units).substr(0, 13)));

    auto name = fs::assemble_lfn(stack, deleted_short, true);
    REQUIRE(name);
    CHECK(*name == long_name);

    std::set<int> reachable;
    for (uint32_t c = 0x21; c <= 0xFF; ++c) {
        auto candidate = deleted_short;
        candidate[0] = static_cast<uint8_t>(c);
        reachable.insert(fs::short_name_checksum(candidate));
    }
    uint8_t impossible = 0;
    while (reachable.count(impossible) != 0) ++impossible;
    for (auto& e : stack) e.checksum = impossible;
    CHECK_FALSE(fs::assemble_lfn(stack, deleted_short, true));

    auto live_mixed = stack;
    live_mixed[0].ord = 0x42;
    live_mixed[0].deleted = false;
    live_mixed[1].checksum = checksum;
    CHECK_FALSE(fs::assemble_lfn(live_mixed, deleted_short, true));
}

TEST_CASE("detect_and_open recognizes FAT32 and rejects other filesystems") {
    SECTION("FAT32") {
        Layout l;
        std::vector<uint8_t> img = make_image(l);
        auto dev = std::make_shared<MemoryDevice>(img, 512, "detect-fat");
        auto scanner = fs::detect_and_open(dev);
        REQUIRE(scanner);
        CHECK((*scanner)->kind() == fs::FsKind::Fat32);
        CHECK((*scanner)->geometry().bytes_per_sector == 512);
        CHECK((*scanner)->geometry().bytes_per_cluster == 512);
        CHECK((*scanner)->geometry().total_clusters == 2048 - 32 - 64);
    }
    SECTION("FAT32 through a backup boot sector") {
        Layout l;
        std::vector<uint8_t> img = make_image(l);
        img[0x1FE] = 0;
        img[0x1FF] = 0;
        const auto bs = boot_sector(l);
        std::memcpy(img.data() + 6 * 512, bs.data(), bs.size());
        auto dev = std::make_shared<MemoryDevice>(img, 512, "detect-backup");
        auto scanner = fs::detect_and_open(dev);
        REQUIRE(scanner);
        CHECK((*scanner)->kind() == fs::FsKind::Fat32);
    }
    SECTION("NTFS magic is delegated to the NTFS detector") {
        std::vector<uint8_t> img(1024, 0);
        std::memcpy(img.data() + 3, "NTFS    ", 8);
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;
        auto dev = std::make_shared<MemoryDevice>(img, 512, "detect-ntfs");
        auto scanner = fs::detect_and_open(dev);
        REQUIRE_FALSE(scanner);
        CHECK(scanner.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("unknown filesystem") {
        std::vector<uint8_t> img(1024, 0);
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;
        auto dev = std::make_shared<MemoryDevice>(img, 512, "detect-unknown");
        auto scanner = fs::detect_and_open(dev);
        REQUIRE_FALSE(scanner);
        CHECK(scanner.error().code == ErrorCode::Unsupported);
    }
    SECTION("device smaller than a boot sector") {
        std::vector<uint8_t> img(256, 0);
        auto dev = std::make_shared<MemoryDevice>(img, 512, "detect-small");
        auto scanner = fs::detect_and_open(dev);
        REQUIRE_FALSE(scanner);
        CHECK(scanner.error().code == ErrorCode::NoFilesystem);
    }
    SECTION("null device") {
        auto scanner = fs::detect_and_open(nullptr);
        REQUIRE_FALSE(scanner);
        CHECK(scanner.error().code == ErrorCode::InvalidArgument);
    }
}
