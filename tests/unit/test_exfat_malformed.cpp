#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/exfat/exfat_boot.hpp"

namespace {
using openrecover::test::MemoryDevice;

std::vector<uint8_t> make_boot(size_t size, bool bad_sig = false) {
    std::vector<uint8_t> b(size, 0);
    if (size >= 512) {
        b[0] = 0xEB;
        b[1] = 0x76;
        b[2] = 0x90;
        std::memcpy(b.data() + 3, "EXFAT   ", 8);
        auto put32 = [&](std::vector<uint8_t>& buf, size_t off, uint32_t v){ for (int i=0;i<4;++i) buf[off+i]=static_cast<uint8_t>(v>>(8*i)); };
        auto put64 = [&](std::vector<uint8_t>& buf, size_t off, uint64_t v){ for (int i=0;i<8;++i) buf[off+i]=static_cast<uint8_t>(v>>(8*i)); };
        put64(b, 0x48, 1000);
        put32(b, 0x50, 24);
        put32(b, 0x54, 8);
        put32(b, 0x58, 32);
        put32(b, 0x5C, 100);
        put32(b, 0x60, 2);
        b[0x6C] = 9;
        b[0x6D] = 0;
        b[0x6E] = 1;
        b[0x1FE] = bad_sig ? 0x00 : 0x55;
        b[0x1FF] = bad_sig ? 0x00 : 0xAA;
    }
    return b;
}
}

TEST_CASE("exFAT malformed boot sector", "[exfat][malformed]") {
    {
        auto img = make_boot(511);
        MemoryDevice dev(img, 512);
        auto boot = openrecover::fs::read_exfat_boot(dev);
        CHECK_FALSE(boot);
    }
    {
        auto img = make_boot(512, true);
        MemoryDevice dev(img, 512);
        auto boot = openrecover::fs::read_exfat_boot(dev);
        CHECK_FALSE(boot);
    }
}
