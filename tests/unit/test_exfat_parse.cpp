#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/exfat/exfat_boot.hpp"

namespace {
using namespace openrecover;
using openrecover::test::MemoryDevice;

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}
void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}

std::vector<uint8_t> make_boot() {
    std::vector<uint8_t> bs(1000 * 512, 0);
    bs[0] = 0xEB;
    bs[1] = 0x76;
    bs[2] = 0x90;
    std::memcpy(bs.data() + 3, "EXFAT   ", 8);
    put64(bs, 0x48, 1000);
    put32(bs, 0x50, 24);
    put32(bs, 0x54, 8);
    put32(bs, 0x58, 32);
    put32(bs, 0x5C, 100);
    put32(bs, 0x60, 2);
    bs[0x6C] = 9;
    bs[0x6D] = 0;
    bs[0x6E] = 1;
    bs[0x1FE] = 0x55;
    bs[0x1FF] = 0xAA;
    return bs;
}
}

TEST_CASE("exFAT boot sector parse", "[exfat][boot]") {
    auto bs = make_boot();
    MemoryDevice dev(bs, 512);
    CHECK(bs.size() == 1000 * 512);
    auto boot = fs::read_exfat_boot(dev);
    REQUIRE(boot);
    CHECK(boot->bytes_per_sector == 512);
    CHECK(boot->sectors_per_cluster == 1);
    CHECK(boot->cluster_count == 100);
    CHECK(boot->first_cluster_of_root == 2);
    CHECK(boot->fat_offset_sectors == 24);
}
