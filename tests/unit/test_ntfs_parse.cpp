#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/ntfs_boot.hpp"

namespace {

using namespace openrecover;
using openrecover::test::MemoryDevice;

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

struct BootFields {
    uint16_t bytes_per_sector = 512;
    uint8_t sectors_per_cluster = 8;
    uint64_t total_sectors = 16384;
    uint64_t mft_lcn = 4;
    uint64_t mft_mirror_lcn = 8;
    int8_t clusters_per_record = static_cast<int8_t>(0xF6);
    int8_t clusters_per_index_buffer = 1;
    uint64_t serial = 0x4F52435600000001;
};

std::vector<uint8_t> make_boot(const BootFields& f) {
    std::vector<uint8_t> bs(512, 0);
    bs[0] = 0xEB;
    bs[1] = 0x52;
    bs[2] = 0x90;
    std::memcpy(bs.data() + 3, "NTFS    ", 8);
    put16(bs, 0x0B, f.bytes_per_sector);
    bs[0x0D] = f.sectors_per_cluster;
    put64(bs, 0x28, f.total_sectors);
    put64(bs, 0x30, f.mft_lcn);
    put64(bs, 0x38, f.mft_mirror_lcn);
    bs[0x40] = static_cast<uint8_t>(f.clusters_per_record);
    bs[0x44] = static_cast<uint8_t>(f.clusters_per_index_buffer);
    put64(bs, 0x48, f.serial);
    bs[0x1FE] = 0x55;
    bs[0x1FF] = 0xAA;
    return bs;
}

Result<fs::NtfsBoot> parse(const BootFields& f, uint64_t volume_size = 8ull << 20) {
    const std::vector<uint8_t> boot = make_boot(f);
    return fs::parse_ntfs_boot(boot, volume_size);
}

}  // namespace

TEST_CASE("NTFS boot sector yields the volume geometry", "[ntfs][boot]") {
    auto boot = parse(BootFields{});
    REQUIRE(boot);
    CHECK(boot->bytes_per_sector == 512);
    CHECK(boot->sectors_per_cluster == 8);
    CHECK(boot->bytes_per_cluster == 4096);
    CHECK(boot->total_sectors == 16384);
    CHECK(boot->total_clusters == 2048);
    CHECK(boot->mft_lcn == 4);
    CHECK(boot->mft_mirror_lcn == 8);
    CHECK(boot->mft_byte_offset() == 4 * 4096);
    CHECK(boot->mft_mirror_byte_offset() == 8 * 4096);
    CHECK(boot->clusters_per_record == -10);
    CHECK(boot->record_size == 1024);
    CHECK(boot->clusters_per_index_buffer == 1);
    CHECK(boot->index_buffer_size == 4096);
    CHECK(boot->volume_serial == 0x4F52435600000001);
}

TEST_CASE("NTFS boot sector supports every sector and cluster encoding", "[ntfs][boot]") {
    SECTION("512-byte sectors, one sector per cluster") {
        BootFields f;
        f.sectors_per_cluster = 1;
        f.total_sectors = 32768;
        f.mft_lcn = 8;
        f.mft_mirror_lcn = 16;
        f.clusters_per_index_buffer = 1;
        auto boot = parse(f, 16ull << 20);
        REQUIRE(boot);
        CHECK(boot->bytes_per_cluster == 512);
        CHECK(boot->total_clusters == 32768);
        CHECK(boot->index_buffer_size == 512);
        CHECK(boot->record_size == 1024);
    }
    SECTION("1024-byte sectors and a negative index encoding") {
        BootFields f;
        f.bytes_per_sector = 1024;
        f.sectors_per_cluster = 8;
        f.total_sectors = 16384;
        f.clusters_per_record = static_cast<int8_t>(0xF4);
        f.clusters_per_index_buffer = static_cast<int8_t>(0xF4);
        f.mft_lcn = 2;
        f.mft_mirror_lcn = 4;
        auto boot = parse(f, 16ull << 20);
        REQUIRE(boot);
        CHECK(boot->bytes_per_cluster == 8192);
        CHECK(boot->record_size == 4096);
        CHECK(boot->index_buffer_size == 4096);
    }
    SECTION("4096-byte sectors") {
        BootFields f;
        f.bytes_per_sector = 4096;
        f.sectors_per_cluster = 1;
        f.total_sectors = 4096;
        f.clusters_per_record = static_cast<int8_t>(0xF6);
        f.clusters_per_index_buffer = 1;
        f.mft_lcn = 1;
        f.mft_mirror_lcn = 2;
        auto boot = parse(f, 16ull << 20);
        REQUIRE(boot);
        CHECK(boot->bytes_per_sector == 4096);
        CHECK(boot->bytes_per_cluster == 4096);
        CHECK(boot->total_clusters == 4096);
        CHECK(boot->record_size == 1024);
    }
    SECTION("128 sectors per cluster is a direct power of two") {
        BootFields f;
        f.sectors_per_cluster = 0x80;
        f.total_sectors = 16384;
        f.mft_lcn = 0;
        f.mft_mirror_lcn = 2;
        auto boot = parse(f, 8ull << 20);
        REQUIRE(boot);
        CHECK(boot->sectors_per_cluster == 128);
        CHECK(boot->bytes_per_cluster == 65536);
        CHECK(boot->total_clusters == 128);
    }
    SECTION("0xF4 is the 2^12 sector encoding") {
        BootFields f;
        f.sectors_per_cluster = 0xF4;
        f.total_sectors = 16384;
        f.mft_lcn = 0;
        f.mft_mirror_lcn = 1;
        auto boot = parse(f, 8ull << 20);
        REQUIRE(boot);
        CHECK(boot->sectors_per_cluster == 4096);
        CHECK(boot->bytes_per_cluster == 2u * 1024 * 1024);
        CHECK(boot->total_clusters == 4);
    }
    SECTION("0xF6 is the 2^10 sector encoding") {
        BootFields f;
        f.sectors_per_cluster = 0xF6;
        f.total_sectors = 16384;
        f.mft_lcn = 1;
        f.mft_mirror_lcn = 2;
        auto boot = parse(f, 8ull << 20);
        REQUIRE(boot);
        CHECK(boot->sectors_per_cluster == 1024);
        CHECK(boot->bytes_per_cluster == 512u * 1024);
        CHECK(boot->total_clusters == 16);
    }
    SECTION("positive record-size encoding multiplies the cluster size") {
        BootFields f;
        f.clusters_per_record = static_cast<int8_t>(2);
        auto boot = parse(f);
        REQUIRE(boot);
        CHECK(boot->record_size == 8192);
    }
    SECTION("negative record-size encoding is a byte count") {
        BootFields f;
        f.clusters_per_record = static_cast<int8_t>(0xF0);
        auto boot = parse(f);
        REQUIRE(boot);
        CHECK(boot->record_size == 65536);
    }
}

TEST_CASE("NTFS boot sector rejects invalid geometry", "[ntfs][boot]") {
    SECTION("unsupported bytes per sector") {
        BootFields f;
        f.bytes_per_sector = 256;
        auto boot = parse(f);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("zero or non-power-of-two sectors per cluster") {
        for (uint8_t spc : {uint8_t{0}, uint8_t{3}, uint8_t{0x81}}) {
            BootFields f;
            f.sectors_per_cluster = spc;
            auto boot = parse(f);
            REQUIRE_FALSE(boot);
            CHECK(boot.error().code == ErrorCode::CorruptStructure);
        }
    }
    SECTION("zero total sectors") {
        BootFields f;
        f.total_sectors = 0;
        auto boot = parse(f);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("volume larger than the device") {
        BootFields f;
        f.total_sectors = 40000;
        auto boot = parse(f, 8ull << 20);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("MFT or mirror outside the volume") {
        for (uint64_t lcn : {uint64_t{2048}, uint64_t{9999}}) {
            BootFields f;
            f.mft_lcn = lcn;
            auto boot = parse(f);
            REQUIRE_FALSE(boot);
            CHECK(boot.error().code == ErrorCode::CorruptStructure);
        }
        BootFields f;
        f.mft_mirror_lcn = 2048;
        auto boot = parse(f);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("NTFS boot sector rejects invalid record sizes", "[ntfs][boot]") {
    SECTION("zero encoding") {
        BootFields f;
        f.clusters_per_record = 0;
        auto boot = parse(f);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("non-power-of-two positive encoding") {
        BootFields f;
        f.sectors_per_cluster = 1;
        f.total_sectors = 32768;
        f.clusters_per_record = static_cast<int8_t>(10);
        f.mft_mirror_lcn = 16;
        auto boot = parse(f, 16ull << 20);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("negative shift out of range") {
        BootFields f;
        f.clusters_per_record = static_cast<int8_t>(0x80);
        auto boot = parse(f);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("record size at the 512-byte minimum") {
        BootFields f;
        f.sectors_per_cluster = 1;
        f.total_sectors = 32768;
        f.clusters_per_record = static_cast<int8_t>(1);
        f.mft_mirror_lcn = 16;
        auto boot = parse(f, 16ull << 20);
        REQUIRE(boot);
        CHECK(boot->record_size == 512);
    }
    SECTION("record crosses the end of the volume") {
        BootFields f;
        f.sectors_per_cluster = 8;
        f.total_sectors = 128;
        f.mft_lcn = 15;
        f.mft_mirror_lcn = 0;
        f.clusters_per_record = static_cast<int8_t>(16);
        auto boot = parse(f, 65536);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("invalid index buffer encoding") {
        BootFields f;
        f.clusters_per_index_buffer = 0;
        auto boot = parse(f);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("NTFS boot sector rejects bad signatures", "[ntfs][boot]") {
    SECTION("missing OEM identifier") {
        BootFields f;
        auto bytes = make_boot(f);
        std::memcpy(bytes.data() + 3, "FAT32   ", 8);
        auto boot = fs::parse_ntfs_boot(bytes, 8ull << 20);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::NoFilesystem);
    }
    SECTION("missing 55 AA signature") {
        BootFields f;
        auto bytes = make_boot(f);
        bytes[0x1FE] = 0;
        auto boot = fs::parse_ntfs_boot(bytes, 8ull << 20);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("short buffer") {
        BootFields f;
        auto bytes = make_boot(f);
        bytes.resize(400);
        auto boot = fs::parse_ntfs_boot(bytes, 8ull << 20);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("read_ntfs_boot falls back to the backup boot sector", "[ntfs][boot]") {
    constexpr uint64_t kVolume = 8ull << 20;
    const std::vector<uint8_t> good = make_boot(BootFields{});

    SECTION("primary boot sector") {
        std::vector<uint8_t> image(kVolume, 0);
        std::memcpy(image.data(), good.data(), good.size());
        MemoryDevice dev(image);
        auto boot = fs::read_ntfs_boot(dev);
        REQUIRE(boot);
        CHECK(boot->bytes_per_cluster == 4096);
        CHECK(boot->volume_serial == 0x4F52435600000001);
    }
    SECTION("backup at the last sector") {
        std::vector<uint8_t> image(kVolume, 0);
        std::memcpy(image.data() + kVolume - 512, good.data(), good.size());
        MemoryDevice dev(image);
        auto boot = fs::read_ntfs_boot(dev);
        REQUIRE(boot);
        CHECK(boot->total_clusters == 2048);
    }
    SECTION("both copies invalid") {
        std::vector<uint8_t> image(kVolume, 0);
        MemoryDevice dev(image);
        auto boot = fs::read_ntfs_boot(dev);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("device too small") {
        std::vector<uint8_t> image(256, 0);
        MemoryDevice dev(image);
        auto boot = fs::read_ntfs_boot(dev);
        REQUIRE_FALSE(boot);
        CHECK(boot.error().code == ErrorCode::NoFilesystem);
    }
}
