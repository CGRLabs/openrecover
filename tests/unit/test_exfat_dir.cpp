#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/exfat/exfat_boot.hpp"
#include "openrecover/fs/exfat/exfat_dir.hpp"
#include "openrecover/fs/exfat/exfat_fat.hpp"

namespace {
using namespace openrecover;
using openrecover::test::MemoryDevice;

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}
void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}
void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

std::vector<uint8_t> make_image_with_dir() {
    const uint32_t bps = 512;
    const uint32_t fat_offset = 24;
    const uint32_t fat_len = 8;
    const uint32_t heap_offset = 32;
    const uint32_t cluster_count = 100;
    const uint64_t total_sectors = heap_offset + cluster_count + 10;

    std::vector<uint8_t> img((heap_offset + cluster_count + 10) * bps, 0);

    img[0] = 0xEB; img[1] = 0x76; img[2] = 0x90;
    std::memcpy(img.data() + 3, "EXFAT   ", 8);
    put64(img, 0x48, total_sectors);
    put32(img, 0x50, fat_offset);
    put32(img, 0x54, fat_len);
    put32(img, 0x58, heap_offset);
    put32(img, 0x5C, cluster_count);
    put32(img, 0x60, 2);
    img[0x6C] = 9;
    img[0x6D] = 0;
    img[0x6E] = 1;
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    auto fat_byte = [&](uint32_t cluster) { return (size_t)((fat_offset * bps) + cluster * 4); };
    put32(img, fat_byte(2), 0xFFFFFFFFu);
    put32(img, fat_byte(5), 0xFFFFFFFFu);

    const size_t cluster2_off = (heap_offset + (2 - 2)) * bps;
    size_t e = cluster2_off;
    img[e + 0] = 0x85;
    img[e + 1] = 2;
    put16(img, e + 4, 0x0020);
    size_t s = e + 32;
    img[s + 0] = 0xC0;
    img[s + 1] = 0;
    img[s + 3] = 4;
    put64(img, s + 8, 5);
    put32(img, s + 20, 5);
    put64(img, s + 24, 5);
    size_t n = s + 32;
    img[n + 0] = 0xC1;
    const char* nm = "test";
    for (int i = 0; i < 4; ++i) {
        img[n + 2 + i * 2] = static_cast<uint8_t>(nm[i]);
        img[n + 2 + i * 2 + 1] = 0;
    }

    uint16_t checksum = 0;
    for (size_t entry = 0; entry < 3; ++entry) {
        for (size_t i = 0; i < 32; ++i) {
            if (entry == 0 && (i == 2 || i == 3)) continue;
            checksum = static_cast<uint16_t>(((checksum << 15) | (checksum >> 1)) +
                                             img[e + entry * 32 + i]);
        }
    }
    put16(img, e + 2, checksum);

    return img;
}
}

TEST_CASE("exFAT directory parse", "[exfat][dir]") {
    auto img = make_image_with_dir();
    MemoryDevice dev(img, 512);
    auto boot = fs::read_exfat_boot(dev);
    REQUIRE(boot);
    auto listing = fs::read_exfat_directory(dev, *boot, boot->first_cluster_of_root);
    REQUIRE(listing);
    REQUIRE(listing->files.size() == 1);
    CHECK(listing->files[0].name == "test");
    CHECK(listing->files[0].size == 5);
    CHECK(listing->files[0].first_cluster == 5);
    CHECK(!listing->files[0].deleted);
}
