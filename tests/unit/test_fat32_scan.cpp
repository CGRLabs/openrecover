#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/fs/fat32.hpp"
#include "openrecover/fs/filesystem.hpp"

namespace {

using namespace openrecover;
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
    uint32_t total_sectors = 512;
    uint32_t fat_size_sectors = 64;
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
    put32(bs, 0x20, l.total_sectors);
    put32(bs, 0x24, l.fat_size_sectors);
    put32(bs, 0x2C, 2);
    put16(bs, 0x30, 1);
    put16(bs, 0x32, 6);
    bs[0x40] = 0x80;
    bs[0x42] = 0x29;
    put32(bs, 0x43, 0x12345678);
    std::memcpy(bs.data() + 0x47, "NO NAME    ", 11);
    std::memcpy(bs.data() + 0x52, "FAT32   ", 8);
    bs[0x1FE] = 0x55;
    bs[0x1FF] = 0xAA;
    return bs;
}

std::array<uint8_t, 11> short11(std::string_view s) {
    std::array<uint8_t, 11> out{};
    out.fill(' ');
    for (size_t i = 0; i < s.size() && i < out.size(); ++i)
        out[i] = static_cast<uint8_t>(s[i]);
    return out;
}

std::u16string to_u16(std::string_view s) {
    std::u16string out;
    for (char c : s) out.push_back(static_cast<char16_t>(static_cast<unsigned char>(c)));
    return out;
}

uint16_t fat_date(unsigned year, unsigned month, unsigned day) {
    return static_cast<uint16_t>(((year - 1980) << 9) | (month << 5) | day);
}

uint16_t fat_time(unsigned hour, unsigned minute, unsigned second) {
    return static_cast<uint16_t>((hour << 11) | (minute << 5) | (second / 2));
}

struct ScanVolume {
    Layout l;
    std::vector<uint8_t> img;

    ScanVolume() : img(static_cast<size_t>(l.total_sectors) * l.bytes_per_sector, 0) {
        const auto bs = boot_sector(l);
        std::memcpy(img.data(), bs.data(), bs.size());
    }

    uint64_t cluster_off(uint32_t cluster) const {
        return (static_cast<uint64_t>(l.reserved_sectors) +
                static_cast<uint64_t>(l.num_fats) * l.fat_size_sectors +
                static_cast<uint64_t>(cluster - 2) * l.sectors_per_cluster) *
               l.bytes_per_sector;
    }

    void set_fat(uint32_t cluster, uint32_t value) {
        const uint64_t off =
            static_cast<uint64_t>(l.reserved_sectors) * l.bytes_per_sector +
            static_cast<uint64_t>(cluster) * 4;
        put32(img, static_cast<size_t>(off), value);
    }

    uint8_t* entry(uint32_t cluster, size_t index) {
        return img.data() + cluster_off(cluster) + index * 32;
    }

    void fill_cluster(uint32_t cluster, uint8_t seed) {
        uint8_t* p = img.data() + cluster_off(cluster);
        for (size_t i = 0; i < l.bytes_per_sector; ++i)
            p[i] = static_cast<uint8_t>((i * 37 + static_cast<size_t>(seed) * 11) & 0xFF);
    }
};

void put_short(uint8_t* p, const std::array<uint8_t, 11>& name, uint8_t attr, uint32_t cluster,
               uint32_t size, uint16_t wrt_date = 0, uint16_t wrt_time = 0) {
    std::memset(p, 0, 32);
    std::memcpy(p, name.data(), name.size());
    p[11] = attr;
    p[20] = static_cast<uint8_t>((cluster >> 16) & 0x0F);
    p[22] = static_cast<uint8_t>(wrt_time);
    p[23] = static_cast<uint8_t>(wrt_time >> 8);
    p[24] = static_cast<uint8_t>(wrt_date);
    p[25] = static_cast<uint8_t>(wrt_date >> 8);
    p[26] = static_cast<uint8_t>(cluster);
    p[27] = static_cast<uint8_t>(cluster >> 8);
    for (int i = 0; i < 4; ++i) p[28 + i] = static_cast<uint8_t>(size >> (8 * i));
}

void put_lfn(uint8_t* p, uint8_t ord, uint8_t checksum, std::u16string_view text) {
    std::memset(p, 0, 32);
    p[0] = ord;
    p[11] = 0x0F;
    p[12] = 0;
    p[13] = checksum;
    std::array<uint16_t, 13> units;
    units.fill(0xFFFF);
    for (size_t i = 0; i < text.size() && i < units.size(); ++i)
        units[i] = static_cast<uint16_t>(text[i]);
    if (text.size() < units.size()) units[text.size()] = 0;
    auto set = [&](size_t offset, uint16_t u) {
        p[offset] = static_cast<uint8_t>(u);
        p[offset + 1] = static_cast<uint8_t>(u >> 8);
    };
    size_t pos = 0;
    for (size_t i = 0; i < 5; ++i) set(1 + i * 2, units[pos++]);
    for (size_t i = 0; i < 6; ++i) set(14 + i * 2, units[pos++]);
    for (size_t i = 0; i < 2; ++i) set(28 + i * 2, units[pos++]);
}

uint8_t impossible_checksum(const std::array<uint8_t, 11>& name) {
    std::set<int> reachable;
    for (uint32_t c = 0x21; c <= 0xFF; ++c) {
        auto candidate = name;
        candidate[0] = static_cast<uint8_t>(c);
        reachable.insert(fs::short_name_checksum(candidate));
    }
    uint8_t value = 0;
    while (reachable.count(value) != 0) ++value;
    return value;
}

ScanVolume make_scan_volume() {
    ScanVolume v;

    v.set_fat(2, 6);
    v.set_fat(6, fs::kFatEndOfChain);
    v.set_fat(3, fs::kFatEndOfChain);
    v.set_fat(4, fs::kFatEndOfChain);
    v.set_fat(5, fs::kFatEndOfChain);
    v.set_fat(9, fs::kFatEndOfChain);
    v.set_fat(17, 18);
    v.set_fat(18, 17);
    v.set_fat(20, fs::kFatEndOfChain);

    for (uint32_t cluster : {8u, 10u, 11u, 12u, 13u, 14u, 15u, 16u, 19u, 20u, 21u, 417u})
        v.fill_cluster(cluster, static_cast<uint8_t>(cluster));

    const uint8_t olddir_checksum = fs::short_name_checksum(short11("OLDDIR     "));
    const uint8_t along_checksum = fs::short_name_checksum(short11("ALONG   TXT"));
    const std::u16string along_name = to_u16("A long deleted name.txt");

    put_short(v.entry(2, 0), short11("."), 0x10, 2, 0);
    put_short(v.entry(2, 1), short11(".."), 0x10, 0, 0);
    put_short(v.entry(2, 2), short11("TESTVOL"), 0x08, 0, 0);
    put_short(v.entry(2, 3), short11("DOCS"), 0x10, 3, 0);
    put_short(v.entry(2, 4), short11("PICS"), 0x10, 4, 0);
    put_short(v.entry(2, 5), short11("LOOP"), 0x10, 2, 0);
    put_short(v.entry(2, 6), short11("DELTXT  TXT"), 0x20, 10, 100, fat_date(2024, 3, 5),
              fat_time(6, 7, 8));
    v.entry(2, 6)[0] = 0xE5;
    put_short(v.entry(2, 7), short11("EMPTY   TXT"), 0x20, 0, 0);
    v.entry(2, 7)[0] = 0xE5;
    put_short(v.entry(2, 8), short11("REUSED  BIN"), 0x20, 20, 1024);
    v.entry(2, 8)[0] = 0xE5;
    put_short(v.entry(2, 9), short11("LAST    BIN"), 0x20, 417, 512);
    v.entry(2, 9)[0] = 0xE5;
    put_short(v.entry(2, 10), short11("BEYOND  BIN"), 0x20, 417, 1024);
    v.entry(2, 10)[0] = 0xE5;

    put_lfn(v.entry(2, 11), 0xE5, olddir_checksum, to_u16("OldDir"));
    put_short(v.entry(2, 12), short11("OLDDIR     "), 0x10, 7, 0);
    v.entry(2, 12)[0] = 0xE5;

    put_lfn(v.entry(2, 13), 0xE5, impossible_checksum(short11("MISMAT  TXT")),
            to_u16("Wrong.txt"));
    put_short(v.entry(2, 14), short11("MISMAT  TXT"), 0x20, 14, 10);
    v.entry(2, 14)[0] = 0xE5;

    put_lfn(v.entry(2, 15), 0xE5, along_checksum, std::u16string_view(along_name).substr(13));
    put_lfn(v.entry(6, 0), 0xE5, along_checksum, std::u16string_view(along_name).substr(0, 13));
    put_short(v.entry(6, 1), short11("ALONG   TXT"), 0x20, 11, 600);
    v.entry(6, 1)[0] = 0xE5;
    put_short(v.entry(6, 3), short11("AFTER   TXT"), 0x20, 15, 5);
    v.entry(6, 3)[0] = 0xE5;
    put_short(v.entry(6, 4), short11("CYCLE"), 0x10, 17, 0);
    put_short(v.entry(6, 5), short11("BADDIR"), 0x10, 23, 0);
    v.entry(6, 5)[0] = 0xE5;

    put_short(v.entry(3, 0), short11("."), 0x10, 3, 0);
    put_short(v.entry(3, 1), short11(".."), 0x10, 2, 0);
    put_short(v.entry(3, 2), short11("LIVE    TXT"), 0x20, 30, 20);
    put_short(v.entry(3, 3), short11("SUBDIR"), 0x10, 9, 0);
    put_short(v.entry(3, 4), short11("DOCSDEL TXT"), 0x20, 16, 7);
    v.entry(3, 4)[0] = 0xE5;

    put_short(v.entry(4, 0), short11("."), 0x10, 4, 0);
    put_short(v.entry(4, 1), short11(".."), 0x10, 2, 0);
    put_short(v.entry(4, 2), short11("2024"), 0x10, 5, 0);

    put_short(v.entry(5, 0), short11("."), 0x10, 5, 0);
    put_short(v.entry(5, 1), short11(".."), 0x10, 4, 0);

    put_short(v.entry(7, 0), short11("."), 0x10, 7, 0);
    put_short(v.entry(7, 1), short11(".."), 0x10, 2, 0);
    put_short(v.entry(7, 2), short11("INNER   TXT"), 0x20, 8, 50);
    v.entry(7, 2)[0] = 0xE5;

    put_short(v.entry(9, 0), short11("."), 0x10, 9, 0);
    put_short(v.entry(9, 1), short11(".."), 0x10, 3, 0);
    put_short(v.entry(9, 2), short11("NESTED  TXT"), 0x20, 13, 3);
    v.entry(9, 2)[0] = 0xE5;

    put_short(v.entry(17, 0), short11("."), 0x10, 17, 0);
    put_short(v.entry(17, 1), short11(".."), 0x10, 2, 0);
    put_short(v.entry(17, 2), short11("CYCTXT  TXT"), 0x20, 19, 4);
    v.entry(17, 2)[0] = 0xE5;
    put_short(v.entry(18, 0), short11("TAIL    TXT"), 0x20, 21, 6);
    v.entry(18, 0)[0] = 0xE5;

    return v;
}

const RecoveredFile* find_file(const std::vector<RecoveredFile>& files, std::string_view path) {
    for (const auto& f : files)
        if (f.path == path) return &f;
    return nullptr;
}

}  // namespace

TEST_CASE("FAT32 scan_deleted harvests deleted files, long names and directories") {
    ScanVolume volume = make_scan_volume();
    const std::string hash_before = sha256_hex(volume.img);
    auto dev = std::make_shared<MemoryDevice>(volume.img, 512, "fat-scan");
    auto scanner = fs::Fat32Scanner::open(dev);
    REQUIRE(scanner);

    auto files = (*scanner)->scan_deleted({}, nullptr);
    REQUIRE(files);
    CHECK(files->size() == 12);

    const RecoveredFile* deltxt = find_file(*files, "_ELTXT.TXT");
    REQUIRE(deltxt);
    CHECK(deltxt->name == "_ELTXT.TXT");
    CHECK(deltxt->size_bytes == 100);
    CHECK(deltxt->confidence == Confidence::High);
    REQUIRE(deltxt->extents.size() == 1);
    CHECK(deltxt->extents[0].offset_bytes == volume.cluster_off(10));
    CHECK(deltxt->extents[0].length_bytes == 100);
    CHECK(deltxt->mtime_unix == 1709618828);
    CHECK(deltxt->note.find("contiguous_assumption") != std::string::npos);
    CHECK(deltxt->note.find("fat_local_time_assumed_utc") != std::string::npos);
    CHECK((deltxt->flags & file_flags::NameFirstCharGuessed) != 0);

    const RecoveredFile* empty = find_file(*files, "_MPTY.TXT");
    REQUIRE(empty);
    CHECK(empty->size_bytes == 0);
    CHECK(empty->extents.empty());
    CHECK(empty->confidence == Confidence::High);
    CHECK((empty->flags & file_flags::NameFirstCharGuessed) != 0);

    const RecoveredFile* reused = find_file(*files, "_EUSED.BIN");
    REQUIRE(reused);
    CHECK(reused->size_bytes == 1024);
    CHECK(reused->confidence == Confidence::Low);
    CHECK((reused->flags & file_flags::ClustersReallocated) != 0);
    REQUIRE(reused->extents.size() == 1);
    CHECK(reused->extents[0].offset_bytes == volume.cluster_off(20));

    const RecoveredFile* last = find_file(*files, "_AST.BIN");
    REQUIRE(last);
    CHECK(last->size_bytes == 512);
    CHECK(last->confidence == Confidence::High);
    REQUIRE(last->extents.size() == 1);
    CHECK(last->extents[0].offset_bytes == volume.cluster_off(417));
    CHECK(last->extents[0].offset_bytes + 512 == volume.img.size());

    const RecoveredFile* mismatched = find_file(*files, "_ISMAT.TXT");
    REQUIRE(mismatched);
    CHECK(mismatched->size_bytes == 10);
    CHECK(mismatched->confidence == Confidence::High);
    CHECK((mismatched->flags & file_flags::NameFirstCharGuessed) != 0);

    const RecoveredFile* long_name = find_file(*files, "A long deleted name.txt");
    REQUIRE(long_name);
    CHECK(long_name->name == "A long deleted name.txt");
    CHECK(long_name->size_bytes == 600);
    CHECK(long_name->confidence == Confidence::High);
    CHECK((long_name->flags & file_flags::NameFirstCharGuessed) == 0);
    REQUIRE(long_name->extents.size() == 1);
    CHECK(long_name->extents[0].offset_bytes == volume.cluster_off(11));
    CHECK(long_name->extents[0].length_bytes == 600);

    REQUIRE(find_file(*files, "_FTER.TXT"));
    REQUIRE(find_file(*files, "DOCS/_OCSDEL.TXT"));
    REQUIRE(find_file(*files, "OldDir/_NNER.TXT"));
    REQUIRE(find_file(*files, "CYCLE/_YCTXT.TXT"));
    REQUIRE(find_file(*files, "CYCLE/_AIL.TXT"));
    REQUIRE(find_file(*files, "DOCS/SUBDIR/_ESTED.TXT"));

    CHECK(find_file(*files, "_EYOND.BIN") == nullptr);
    for (const auto& f : *files) {
        CHECK(f.path.find("BADDIR") == std::string::npos);
        CHECK(f.path.find("BEYOND") == std::string::npos);
        CHECK((f.flags & file_flags::Fragmented) == 0);
    }

    CHECK(sha256_hex(dev->contents()) == hash_before);
}

TEST_CASE("FAT32 read_file serves contiguous extents with arbitrary offsets") {
    ScanVolume volume = make_scan_volume();
    auto dev = std::make_shared<MemoryDevice>(volume.img, 512, "fat-read");
    auto scanner = fs::Fat32Scanner::open(dev);
    REQUIRE(scanner);
    auto files = (*scanner)->scan_deleted({}, nullptr);
    REQUIRE(files);

    const RecoveredFile* deltxt = find_file(*files, "_ELTXT.TXT");
    REQUIRE(deltxt);
    std::vector<uint8_t> expected(100);
    std::memcpy(expected.data(), volume.img.data() + volume.cluster_off(10), expected.size());

    std::vector<uint8_t> got(100, 0);
    auto read = (*scanner)->read_file(*deltxt, 0, got.data(), got.size());
    REQUIRE(read);
    CHECK(*read == 100);
    CHECK(got == expected);

    std::array<uint8_t, 20> tail{};
    auto tail_read = (*scanner)->read_file(*deltxt, 90, tail.data(), tail.size());
    REQUIRE(tail_read);
    CHECK(*tail_read == 10);
    CHECK(std::equal(tail.begin(), tail.begin() + 10, expected.begin() + 90));

    std::array<uint8_t, 1> past{};
    auto past_read = (*scanner)->read_file(*deltxt, 100, past.data(), past.size());
    REQUIRE(past_read);
    CHECK(*past_read == 0);

    const RecoveredFile* long_name = find_file(*files, "A long deleted name.txt");
    REQUIRE(long_name);
    std::vector<uint8_t> expected_long(600);
    std::memcpy(expected_long.data(), volume.img.data() + volume.cluster_off(11), 512);
    std::memcpy(expected_long.data() + 512, volume.img.data() + volume.cluster_off(12), 88);

    std::vector<uint8_t> assembled;
    for (uint64_t offset = 0; offset < 600; offset += 37) {
        std::array<uint8_t, 37> chunk{};
        const size_t len = static_cast<size_t>(std::min<uint64_t>(37, 600 - offset));
        auto chunk_read = (*scanner)->read_file(*long_name, offset, chunk.data(), len);
        REQUIRE(chunk_read);
        CHECK(*chunk_read == len);
        assembled.insert(assembled.end(), chunk.begin(), chunk.begin() + static_cast<ptrdiff_t>(len));
    }
    CHECK(assembled == expected_long);

    const RecoveredFile* empty = find_file(*files, "_MPTY.TXT");
    REQUIRE(empty);
    std::array<uint8_t, 4> none{};
    auto empty_read = (*scanner)->read_file(*empty, 0, none.data(), none.size());
    REQUIRE(empty_read);
    CHECK(*empty_read == 0);
}

TEST_CASE("FAT32 scan options and allocation map") {
    ScanVolume volume = make_scan_volume();
    auto dev = std::make_shared<MemoryDevice>(volume.img, 512, "fat-options");
    auto scanner = fs::Fat32Scanner::open(dev);
    REQUIRE(scanner);

    fs::ScanOptions shallow;
    shallow.max_directory_depth = 0;
    auto files = (*scanner)->scan_deleted(shallow, nullptr);
    REQUIRE(files);
    CHECK(files->size() == 7);
    for (const auto& f : *files) {
        REQUIRE(!f.path.empty());
        CHECK(f.path.find('/') == std::string::npos);
    }

    auto cancelled = (*scanner)->scan_deleted({}, [](uint64_t, uint64_t) { return false; });
    REQUIRE_FALSE(cancelled);
    CHECK(cancelled.error().code == ErrorCode::Cancelled);

    auto map = (*scanner)->allocation_map();
    REQUIRE(map);
    CHECK((*map)->cluster_count() == 416);
    CHECK((*map)->is_cluster_allocated(20));
    CHECK((*map)->is_cluster_allocated(2));
    CHECK_FALSE((*map)->is_cluster_allocated(10));
    CHECK_FALSE((*map)->is_cluster_allocated(417));
    CHECK((*map)->is_cluster_allocated(5000));
    CHECK((*map)->cluster_to_byte_offset(2) == volume.cluster_off(2));
    CHECK((*map)->cluster_to_byte_offset(3) == volume.cluster_off(3));
}
