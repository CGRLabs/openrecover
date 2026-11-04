#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/exfat/exfat_scanner.hpp"
#include "openrecover/fs/filesystem.hpp"

namespace {

using namespace openrecover;
using openrecover::test::MemoryDevice;

constexpr uint32_t kBps = 512;
constexpr uint32_t kFatOffset = 24;
constexpr uint32_t kFatLength = 8;
constexpr uint32_t kHeapOffset = 32;
constexpr uint32_t kClusterCount = 100;
constexpr uint32_t kClusterBytes = 512;

class ExfatBuilder {
public:
    ExfatBuilder() : img_((kHeapOffset + kClusterCount + 10) * kBps, 0) {}

    std::vector<uint8_t> finish() { return std::move(img_); }

    uint8_t* cluster(uint32_t index) {
        return img_.data() + (kHeapOffset + index - 2) * kClusterBytes;
    }

    void boot() {
        img_[0] = 0xEB;
        img_[1] = 0x76;
        img_[2] = 0x90;
        std::memcpy(img_.data() + 3, "EXFAT   ", 8);
        const uint64_t total = kHeapOffset + kClusterCount + 10;
        put64(img_.data() + 0x48, total);
        put32(img_.data() + 0x50, kFatOffset);
        put32(img_.data() + 0x54, kFatLength);
        put32(img_.data() + 0x58, kHeapOffset);
        put32(img_.data() + 0x5C, kClusterCount);
        put32(img_.data() + 0x60, 2);
        img_[0x6C] = 9;
        img_[0x6D] = 0;
        img_[0x6E] = 1;
        img_[0x1FE] = 0x55;
        img_[0x1FF] = 0xAA;
    }

    void fat(uint32_t cluster_index, uint32_t value) {
        put32(img_.data() + kFatOffset * kBps + cluster_index * 4, value);
    }

    void bitmap_bit(uint32_t cluster_index) {
        const uint32_t bit = cluster_index - 2;
        uint8_t* byte = cluster(3) + bit / 8;
        *byte = static_cast<uint8_t>(*byte | (1u << (bit % 8)));
    }

    size_t entry(size_t index) { return index * 32; }

    size_t entry_set(uint8_t* dir, size_t index, bool deleted, uint16_t attributes,
                     uint32_t first_cluster, uint64_t size, bool no_fat_chain,
                     const std::string& name) {
        const uint8_t primary = deleted ? 0x05 : 0x85;
        const uint8_t stream = deleted ? 0x40 : 0xC0;
        const uint8_t name_type = deleted ? 0x41 : 0xC1;
        const size_t name_entries = (name.size() + 14) / 15;
        auto* p = dir + entry(index);
        p[0] = primary;
        p[1] = static_cast<uint8_t>(1 + name_entries);
        put16(p + 4, attributes);
        auto* s = dir + entry(index + 1);
        s[0] = stream;
        s[1] = static_cast<uint8_t>(0x01 | (no_fat_chain ? 0x02 : 0x00));
        s[3] = static_cast<uint8_t>(name.size());
        put64(s + 8, size);
        put32(s + 20, first_cluster);
        put64(s + 24, size);
        for (size_t n = 0; n < name_entries; ++n) {
            auto* ne = dir + entry(index + 2 + n);
            ne[0] = name_type;
            for (size_t c = 0; c < 15; ++c) {
                const size_t pos = n * 15 + c;
                const uint16_t unit = pos < name.size() ? static_cast<uint8_t>(name[pos]) : 0;
                ne[2 + c * 2] = static_cast<uint8_t>(unit & 0xFF);
                ne[2 + c * 2 + 1] = static_cast<uint8_t>(unit >> 8);
            }
        }

        uint16_t checksum = 0;
        for (size_t e = 0; e < 2 + name_entries; ++e) {
            for (size_t i = 0; i < 32; ++i) {
                if (e == 0 && (i == 2 || i == 3)) continue;
                checksum = static_cast<uint16_t>(((checksum << 15) | (checksum >> 1)) +
                                                 dir[entry(index + e) + i]);
            }
        }
        put16(p + 2, checksum);
        return index + 2 + name_entries;
    }

    void bitmap_entry(uint8_t* dir, size_t index, uint32_t first_cluster, uint64_t bytes) {
        auto* p = dir + entry(index);
        p[0] = 0x81;
        put32(p + 20, first_cluster);
        put64(p + 24, bytes);
    }

    void fill(uint32_t cluster_index, uint8_t value, size_t bytes = kClusterBytes) {
        std::memset(cluster(cluster_index), value, bytes);
    }

private:
    static void put16(uint8_t* p, uint16_t v) {
        p[0] = static_cast<uint8_t>(v & 0xFF);
        p[1] = static_cast<uint8_t>(v >> 8);
    }
    static void put32(uint8_t* p, uint32_t v) {
        for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
    }
    static void put64(uint8_t* p, uint64_t v) {
        for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
    }

    std::vector<uint8_t> img_;
};

std::vector<uint8_t> make_scanner_image() {
    ExfatBuilder b;
    b.boot();
    b.fat(2, 0xFFFFFFFFu);
    b.fat(3, 0xFFFFFFFFu);
    b.fat(7, 9);
    b.fat(9, 0xFFFFFFFFu);
    b.fat(12, 0xFFFFFFFFu);

    b.bitmap_entry(b.cluster(2), 0, 3, 13);
    size_t index = 1;
    index = b.entry_set(b.cluster(2), index, false, 0x10, 12, 512, true, "Live");
    index = b.entry_set(b.cluster(2), index, true, 0x20, 5, 700, true, "deleted.bin");
    index = b.entry_set(b.cluster(2), index, true, 0x20, 7, 600, false, "frag.bin");
    index = b.entry_set(b.cluster(2), index, true, 0x10, 10, 512, true, "Old");
    index = b.entry_set(b.cluster(2), index, true, 0x20, 14, 10, true, "reused.bin");
    (void)index;

    size_t live_index = b.entry_set(b.cluster(12), 0, true, 0x20, 13, 7, true, "nested.txt");
    b.entry_set(b.cluster(12), live_index, true, 0x20, 0, 0, true, "empty.txt");
    b.entry_set(b.cluster(10), 0, true, 0x20, 11, 5, true, "child.txt");

    b.fill(5, 'A');
    b.fill(6, 'A');
    b.fill(7, 'B');
    b.fill(9, 'C');
    b.fill(11, 'x', 5);
    b.fill(13, 'n', 7);
    b.fill(14, 'R', 10);

    b.bitmap_bit(2);
    b.bitmap_bit(3);
    b.bitmap_bit(12);
    b.bitmap_bit(14);
    return b.finish();
}

const RecoveredFile* find_file(const std::vector<RecoveredFile>& files, const std::string& path) {
    const auto it = std::find_if(files.begin(), files.end(),
                                 [&](const RecoveredFile& f) { return f.path == path; });
    return it == files.end() ? nullptr : &*it;
}

std::vector<uint8_t> read_all(fs::IFileSystemScanner& scanner, const RecoveredFile& file) {
    std::vector<uint8_t> data(static_cast<size_t>(file.size_bytes));
    uint64_t offset = 0;
    while (offset < file.size_bytes) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(97, file.size_bytes - offset));
        auto got = scanner.read_file(file, offset, data.data() + offset, chunk);
        REQUIRE(got);
        REQUIRE(*got == chunk);
        offset += chunk;
    }
    return data;
}

}  // namespace

TEST_CASE("exFAT scan recovers deleted files, directories and reuse confidence",
          "[exfat][scanner]") {
    auto img = make_scanner_image();
    auto device = std::make_shared<MemoryDevice>(img, 512);
    auto scanner = fs::ExfatScanner::open(device);
    REQUIRE(scanner);
    CHECK((*scanner)->kind() == fs::FsKind::ExFat);
    CHECK((*scanner)->geometry().bytes_per_cluster == 512);

    auto files = (*scanner)->scan_deleted(fs::ScanOptions{}, {});
    REQUIRE(files);
    CHECK(files->size() == 6);

    const RecoveredFile* contiguous = find_file(*files, "deleted.bin");
    REQUIRE(contiguous != nullptr);
    CHECK(contiguous->size_bytes == 700);
    CHECK(contiguous->confidence == Confidence::High);
    REQUIRE(contiguous->extents.size() == 1);
    CHECK(contiguous->extents[0].length_bytes == 700);
    const auto data = read_all(**scanner, *contiguous);
    CHECK(std::count(data.begin(), data.end(), 'A') == 700);

    const RecoveredFile* fragmented = find_file(*files, "frag.bin");
    REQUIRE(fragmented != nullptr);
    REQUIRE(fragmented->extents.size() == 2);
    CHECK(fragmented->extents[0].length_bytes == 512);
    CHECK(fragmented->extents[1].length_bytes == 88);
    const auto fragmented_data = read_all(**scanner, *fragmented);
    CHECK(fragmented_data[0] == 'B');
    CHECK(fragmented_data[511] == 'B');
    CHECK(fragmented_data[512] == 'C');

    const RecoveredFile* nested_live = find_file(*files, "Live/nested.txt");
    REQUIRE(nested_live != nullptr);
    CHECK(nested_live->confidence == Confidence::High);

    const RecoveredFile* nested_deleted_dir = find_file(*files, "Old/child.txt");
    REQUIRE(nested_deleted_dir != nullptr);
    CHECK(nested_deleted_dir->size_bytes == 5);

    const RecoveredFile* reused = find_file(*files, "reused.bin");
    REQUIRE(reused != nullptr);
    CHECK(reused->confidence == Confidence::Low);
    CHECK((reused->flags & file_flags::ClustersReallocated) != 0);

    const RecoveredFile* empty = find_file(*files, "Live/empty.txt");
    REQUIRE(empty != nullptr);
    CHECK(empty->size_bytes == 0);
    CHECK(empty->confidence == Confidence::High);

    CHECK(find_file(*files, "child.txt") == nullptr);
    CHECK(reused->origin == FileOrigin::FilesystemMetadata);
}

TEST_CASE("exFAT allocation map follows the bitmap", "[exfat][scanner]") {
    auto img = make_scanner_image();
    auto device = std::make_shared<MemoryDevice>(img, 512);
    auto scanner = fs::ExfatScanner::open(device);
    REQUIRE(scanner);
    auto map = (*scanner)->allocation_map();
    REQUIRE(map);
    CHECK((*map)->cluster_count() == kClusterCount);
    CHECK((*map)->is_cluster_allocated(2));
    CHECK((*map)->is_cluster_allocated(3));
    CHECK((*map)->is_cluster_allocated(12));
    CHECK((*map)->is_cluster_allocated(14));
    CHECK_FALSE((*map)->is_cluster_allocated(5));
    CHECK_FALSE((*map)->is_cluster_allocated(13));
    CHECK((*map)->is_cluster_allocated(1));
    CHECK((*map)->is_cluster_allocated(kClusterCount + 2));
}

TEST_CASE("exFAT is detected by signature", "[exfat][scanner]") {
    auto img = make_scanner_image();
    auto device = std::make_shared<MemoryDevice>(img, 512);
    auto scanner = fs::detect_and_open(device);
    REQUIRE(scanner);
    CHECK((*scanner)->kind() == fs::FsKind::ExFat);
}
