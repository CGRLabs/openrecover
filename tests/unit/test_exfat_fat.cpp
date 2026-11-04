#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/exfat/exfat_boot.hpp"
#include "openrecover/fs/exfat/exfat_fat.hpp"

namespace {
using namespace openrecover;
using openrecover::test::MemoryDevice;

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}

std::vector<uint8_t> make_image() {
    const uint32_t bps = 512;
    const uint32_t fat_offset = 24;
    const uint32_t fat_len = 8;
    const uint32_t heap_offset = 32;
    const uint32_t cluster_count = 100;
    const uint64_t total_sectors = heap_offset + cluster_count + 10;

    std::vector<uint8_t> img((heap_offset + cluster_count + 10) * bps, 0);

    img[0] = 0xEB;
    img[1] = 0x76;
    img[2] = 0x90;
    std::memcpy(img.data() + 3, "EXFAT   ", 8);
    for (int i = 0; i < 8; ++i) img[0x48 + i] = static_cast<uint8_t>(total_sectors >> (8 * i));
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

    auto fat_byte = [&](uint32_t cluster) { return (fat_offset * bps) + cluster * 4; };
    put32(img, fat_byte(2), 3);
    put32(img, fat_byte(3), 4);
    put32(img, fat_byte(4), 0xFFFFFFFFu);

    return img;
}
}

TEST_CASE("exFAT FAT chain walk", "[exfat][fat]") {
    auto img = make_image();
    MemoryDevice dev(img, 512);
    auto boot = fs::read_exfat_boot(dev);
    REQUIRE(boot);
    auto chain = fs::read_exfat_chain(dev, *boot, 2);
    REQUIRE(chain);
    CHECK(chain->size() == 3);
    CHECK((*chain)[0] == 2);
    CHECK((*chain)[1] == 3);
    CHECK((*chain)[2] == 4);
    CHECK(fs::exfat_chain_contiguous(*chain));
}
