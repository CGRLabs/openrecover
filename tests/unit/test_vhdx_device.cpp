#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/io/image_device.hpp"
#include "openrecover/io/vhdx_device.hpp"
#include "test_util.hpp"
#include "vhdx_builder.hpp"

using namespace openrecover;
using namespace openrecover::io;
using openrecover::test::MemoryDevice;
using openrecover::test::TempDir;
using openrecover::test::VhdxBlockMode;

namespace {

constexpr uint64_t kMaxVirtualBytes = 64ull << 40;

std::vector<uint8_t> read_vec(BlockDevice& dev, uint64_t off, size_t len) {
    std::vector<uint8_t> buf(len, 0xCC);
    auto r = dev.read(off, buf.data(), len);
    REQUIRE(r.has_value());
    buf.resize(r->bytes_read);
    return buf;
}

std::shared_ptr<BlockDevice> open_bytes(const std::vector<uint8_t>& bytes) {
    auto dev = open_vhdx(std::make_shared<MemoryDevice>(bytes));
    if (!dev) std::fprintf(stderr, "open failed: %s\n", dev.error().to_string().c_str());
    REQUIRE(dev.has_value());
    return std::shared_ptr<BlockDevice>(std::move(*dev));
}

void repair_headers(std::vector<uint8_t>& data) {
    test::put_crc32c(data, test::kVhdxHeader1, test::kVhdxHeaderBytes, 4);
    test::put_crc32c(data, test::kVhdxHeader2, test::kVhdxHeaderBytes, 4);
}

void repair_regions(std::vector<uint8_t>& data) {
    test::put_crc32c(data, test::kVhdxRegion1, test::kVhdxRegionBytes, 4);
    test::put_crc32c(data, test::kVhdxRegion2, test::kVhdxRegionBytes, 4);
}

bool accepted_error(ErrorCode code) {
    return code == ErrorCode::CorruptStructure || code == ErrorCode::Unsupported ||
           code == ErrorCode::InvalidArgument;
}

// Invariants every opened VHDX must keep: a stable virtual size, a supported sector size,
// reads that fill exactly the requested window, and bytes that either exist in the
// container or are the zero the format says an absent block reads as.
std::string device_violation(BlockDevice& dev, const std::vector<uint8_t>& container) {
    const DeviceInfo& info = dev.info();
    if (info.size_bytes == 0 || info.size_bytes > kMaxVirtualBytes)
        return "virtual size " + std::to_string(info.size_bytes) + " is out of range";
    if (info.logical_sector_size != 512 && info.logical_sector_size != 4096)
        return "logical sector size is not 512 or 4096";
    if (info.physical_sector_size != 512 && info.physical_sector_size != 4096)
        return "physical sector size is not 512 or 4096";

    std::vector<bool> present(256, false);
    for (uint8_t byte : container) present[byte] = true;
    present[0] = true;  // absent blocks are defined to read as zeros

    const uint64_t span = std::min<uint64_t>(info.size_bytes, 3 * 1024 * 1024);
    std::vector<uint8_t> whole(static_cast<size_t>(span), 0xA5);
    auto full = dev.read(0, whole.data(), whole.size());
    if (!full) return "read at 0 failed: " + full.error().to_string();
    if (full->bytes_read != whole.size()) return "short read at 0";
    for (size_t i = 0; i < whole.size(); ++i)
        if (!present[whole[i]]) return "byte " + std::to_string(i) + " was never read";

    for (uint64_t off = 0; off < span; off += 4093) {
        const size_t len = static_cast<size_t>(std::min<uint64_t>(300 + (off % 11) * 40, span - off));
        std::vector<uint8_t> part(len, 0x5A);
        auto r = dev.read(off, part.data(), len);
        if (!r) return "read at " + std::to_string(off) + " failed: " + r.error().to_string();
        if (r->bytes_read != len) return "short read at " + std::to_string(off);
        if (!std::equal(part.begin(), part.end(), whole.begin() + static_cast<std::ptrdiff_t>(off)))
            return "read at " + std::to_string(off) + " disagrees with the whole pass";
    }

    std::vector<uint8_t> past(64, 0);
    auto beyond = dev.read(info.size_bytes, past.data(), past.size());
    if (!beyond) return "read past the end failed: " + beyond.error().to_string();
    if (beyond->bytes_read != 0) return "a read past the virtual size returned bytes";
    return {};
}

struct SweepTally {
    size_t cases = 0;
    size_t opens = 0;
    size_t refusals = 0;
    std::string first_violation;
    std::string offender;

    void fail(const std::string& label, std::string why) {
        if (first_violation.empty()) {
            first_violation = std::move(why);
            offender = label;
        }
    }
    std::string counts() const {
        return std::to_string(cases) + " cases, " + std::to_string(opens) + " opened, " +
               std::to_string(refusals) + " refused";
    }
};

void sweep_one(const std::vector<uint8_t>& data, SweepTally& tally, const std::string& label) {
    ++tally.cases;
    auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
    if (!dev) {
        if (!accepted_error(dev.error().code))
            tally.fail(label, "refused with " + dev.error().to_string());
        else
            ++tally.refusals;
        return;
    }
    ++tally.opens;
    if (auto why = device_violation(**dev, data); !why.empty()) tally.fail(label, why);
}

class QuietLogs {
public:
    QuietLogs() { log::set_sink([](LogLevel, std::string_view) {}); }
    QuietLogs(const QuietLogs&) = delete;
    QuietLogs& operator=(const QuietLogs&) = delete;
    ~QuietLogs() { log::set_sink(nullptr); }
};

std::vector<uint8_t> small_volume(size_t n = 4096) {
    std::vector<uint8_t> volume(n);
    for (size_t i = 0; i < n; ++i) volume[i] = static_cast<uint8_t>((i * 37 + 11) % 251 + 1);
    // Leave a couple of sectors empty so the partial-block bitmap has clear bits.
    std::fill(volume.begin() + 1024, volume.begin() + 2048, uint8_t{0});
    std::fill(volume.begin() + 3072, volume.begin() + 3584, uint8_t{0});
    return volume;
}

}  // namespace

TEST_CASE("A VHDX fully-present block presents its bytes", "[vhdx]") {
    const auto volume = small_volume();
    const auto container = test::make_vhdx(volume);
    auto dev = open_bytes(container);
    CHECK(dev->info().size_bytes == volume.size());
    CHECK(dev->info().is_image);
    CHECK(dev->info().logical_sector_size == 512);
    CHECK(dev->info().physical_sector_size == 512);
    CHECK(dev->info().container == "vhdx");
    CHECK(dev->info().description.find("vhdx") != std::string::npos);
    CHECK(read_vec(*dev, 0, volume.size()) == volume);
    CHECK(read_vec(*dev, 2000, 64) ==
          std::vector<uint8_t>(volume.begin() + 2000, volume.begin() + 2064));
    CHECK(read_vec(*dev, 4000, 200).size() == 96);
    CHECK(read_vec(*dev, 4096, 10).empty());
    CHECK(dev->bad_sectors().empty());
}

TEST_CASE("VHDX absent, undefined and zero blocks read back as zeros", "[vhdx]") {
    const size_t block = test::kVhdxMiB;
    std::vector<uint8_t> volume(3 * block);
    for (size_t i = 0; i < volume.size(); ++i) volume[i] = static_cast<uint8_t>(i % 251 + 1);
    for (VhdxBlockMode mode : {VhdxBlockMode::kNotPresent, VhdxBlockMode::kUndefined,
                               VhdxBlockMode::kZero}) {
        INFO("mode: " << static_cast<int>(mode));
        const auto container = test::make_vhdx(volume, {mode, mode, mode});
        auto dev = open_bytes(container);
        CHECK(dev->info().size_bytes == volume.size());
        CHECK(read_vec(*dev, 0, volume.size()) == std::vector<uint8_t>(volume.size(), 0));
    }
}

TEST_CASE("A VHDX partly-present block follows its sector bitmap", "[vhdx]") {
    const auto volume = small_volume();
    const auto container = test::make_vhdx(volume, {VhdxBlockMode::kPartial});
    auto dev = open_bytes(container);
    CHECK(read_vec(*dev, 0, volume.size()) == volume);

    // Clearing a bit makes that sector read as zeros; setting one makes it real again.
    auto altered = container;
    const size_t bitmap = test::kVhdxPayloadStart;
    altered[bitmap] = 0;
    auto masked = open_bytes(altered);
    CHECK(read_vec(*masked, 0, 4096) == std::vector<uint8_t>(4096, 0));

    // An unaligned span crosses from an allocated sector into the cleared ones.
    std::vector<uint8_t> span = read_vec(*dev, 1000, 100);
    REQUIRE(span.size() == 100);
    std::vector<uint8_t> want(volume.begin() + 1000, volume.begin() + 1024);
    want.insert(want.end(), 76, uint8_t{0});
    CHECK(span == want);
}

TEST_CASE("VHDX header copies cover for each other", "[vhdx]") {
    const auto volume = small_volume();
    SECTION("the first header may be torn") {
        auto data = test::make_vhdx(volume);
        test::put_le32(data, test::kVhdxHeader1 + 4, 0);  // checksum now wrong
        auto dev = open_bytes(data);
        CHECK(read_vec(*dev, 0, volume.size()) == volume);
    }
    SECTION("the second header may be torn") {
        auto data = test::make_vhdx(volume);
        test::put_le32(data, test::kVhdxHeader2 + 4, 0);
        auto dev = open_bytes(data);
        CHECK(read_vec(*dev, 0, volume.size()) == volume);
    }
    SECTION("both headers torn is corrupt") {
        auto data = test::make_vhdx(volume);
        test::put_le32(data, test::kVhdxHeader1 + 4, 0);
        test::put_le32(data, test::kVhdxHeader2 + 4, 0);
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("an unknown header version is not usable") {
        auto data = test::make_vhdx(volume);
        test::put_le16(data, test::kVhdxHeader1 + 66, 2);
        repair_headers(data);
        auto dev = open_bytes(data);  // the second header still says version 1
        CHECK(read_vec(*dev, 0, volume.size()) == volume);

        test::put_le16(data, test::kVhdxHeader2 + 66, 2);
        repair_headers(data);
        auto refused = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(refused.has_value());
        CHECK(refused.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("VHDX region table copies cover for each other", "[vhdx]") {
    const auto volume = small_volume();
    SECTION("the first copy may be torn") {
        auto data = test::make_vhdx(volume);
        test::put_le32(data, test::kVhdxRegion1 + 4, 0);
        auto dev = open_bytes(data);
        CHECK(read_vec(*dev, 0, volume.size()) == volume);
    }
    SECTION("both copies torn is corrupt") {
        auto data = test::make_vhdx(volume);
        test::put_le32(data, test::kVhdxRegion1 + 4, 0);
        test::put_le32(data, test::kVhdxRegion2 + 4, 0);
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a required region past the end is corrupt") {
        auto data = test::make_vhdx(volume);
        for (size_t at : {test::kVhdxRegion1, test::kVhdxRegion2})
            test::put_le32(data, at + test::kVhdxRegionEntries + 24, 0xFFFFFFFFu);
        repair_regions(data);
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a required region this reader does not know is unsupported") {
        auto data = test::make_vhdx(volume);
        for (size_t at : {test::kVhdxRegion1, test::kVhdxRegion2}) {
            test::put_le32(data, at + 8, 3);
            const std::array<uint8_t, 16> unknown = {1, 2, 3, 4, 5, 6, 7, 8,
                                                     9, 10, 11, 12, 13, 14, 15, 16};
            test::put_guid(data, at + test::kVhdxRegionEntries + 64, unknown);
            test::put_le32(data, at + test::kVhdxRegionEntries + 64 + 24, 4096);
            test::put_le32(data, at + test::kVhdxRegionEntries + 64 + 28, 1);
            test::put_crc32c(data, at, test::kVhdxRegionBytes, 4);
        }
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::Unsupported);
    }
    SECTION("a table without the metadata region is corrupt") {
        auto data = test::make_vhdx(volume);
        for (size_t at : {test::kVhdxRegion1, test::kVhdxRegion2}) {
            test::put_le32(data, at + 8, 1);
            test::put_crc32c(data, at, test::kVhdxRegionBytes, 4);
        }
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("VHDX refuses disks whose bytes live in a parent", "[vhdx]") {
    const auto volume = small_volume();
    SECTION("the differencing flag") {
        test::VhdxBuildOptions opts;
        opts.has_parent = true;
        auto data = test::make_vhdx(volume, {}, opts);
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::Unsupported);
    }
    SECTION("a parent locator item") {
        test::VhdxBuildOptions opts;
        opts.parent_locator = true;
        auto data = test::make_vhdx(volume, {}, opts);
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::Unsupported);
    }
}

TEST_CASE("VHDX metadata is judged by value", "[vhdx]") {
    const auto volume = small_volume();
    const size_t meta = test::kVhdxMetadataOffset;

    auto refused_with = [&](size_t at, size_t width, uint64_t value, ErrorCode want) {
        auto data = test::make_vhdx(volume);
        for (size_t i = 0; i < width; ++i)
            data[at + i] = static_cast<uint8_t>(value >> (i * 8));
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == want);
    };

    SECTION("block size outside the format's range") {
        refused_with(meta + test::kVhdxParamsAt, 4, 512 * 1024, ErrorCode::CorruptStructure);
        refused_with(meta + test::kVhdxParamsAt, 4, 3u * test::kVhdxMiB, ErrorCode::CorruptStructure);
        refused_with(meta + test::kVhdxParamsAt, 4, 512ull * test::kVhdxMiB, ErrorCode::CorruptStructure);
    }
    SECTION("reserved file-parameter flags") {
        refused_with(meta + test::kVhdxParamsAt + 4, 4, 4, ErrorCode::CorruptStructure);
    }
    SECTION("virtual size out of range") {
        refused_with(meta + test::kVhdxSizeAt, 8, 0, ErrorCode::CorruptStructure);
        refused_with(meta + test::kVhdxSizeAt, 8, 100, ErrorCode::CorruptStructure);
        refused_with(meta + test::kVhdxSizeAt, 8, kMaxVirtualBytes + 512, ErrorCode::CorruptStructure);
    }
    SECTION("sector size") {
        refused_with(meta + test::kVhdxLogicalAt, 4, 1024, ErrorCode::CorruptStructure);
        refused_with(meta + test::kVhdxPhysicalAt, 4, 256, ErrorCode::CorruptStructure);
    }
    SECTION("a missing required item") {
        auto data = test::make_vhdx(volume);
        test::put_le16(data, meta + 10, 3);  // drops the physical sector size
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("VHDX block allocation states are judged by value", "[vhdx]") {
    const auto volume = small_volume();
    auto refused_with = [&](uint64_t entry, ErrorCode want) {
        auto data = test::make_vhdx(volume);
        test::put_le64(data, test::kVhdxBatOffset, entry);
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == want);
    };
    SECTION("an undefined state is not a block state") { refused_with(6, ErrorCode::CorruptStructure); }
    SECTION("an unmapped block needs a parent") { refused_with(3, ErrorCode::CorruptStructure); }
    SECTION("a present block with no file offset") { refused_with(4, ErrorCode::CorruptStructure); }
    SECTION("a BAT smaller than the disk") {
        auto data = test::make_vhdx(volume);
        for (size_t at : {test::kVhdxRegion1, test::kVhdxRegion2}) {
            test::put_le32(data, at + test::kVhdxRegionEntries + 24, 4);
            test::put_crc32c(data, at, test::kVhdxRegionBytes, 4);
        }
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("A truncated VHDX reads its present bytes and zeros the rest", "[vhdx]") {
    const auto volume = small_volume(4096);
    auto container = test::make_vhdx(volume);
    container.resize(test::kVhdxPayloadStart + 1024);  // payload block cut inside
    auto dev = open_bytes(container);
    CHECK(dev->info().size_bytes == volume.size());
    CHECK(read_vec(*dev, 0, 1024) == std::vector<uint8_t>(volume.begin(), volume.begin() + 1024));
    CHECK(read_vec(*dev, 1024, 3072) == std::vector<uint8_t>(3072, 0));
}

TEST_CASE("VHDX sector sizes come from the metadata", "[vhdx]") {
    std::vector<uint8_t> volume(8192);
    for (size_t i = 0; i < volume.size(); ++i) volume[i] = static_cast<uint8_t>(i % 97 + 1);
    test::VhdxBuildOptions opts;
    opts.logical_sector = 4096;
    opts.physical_sector = 4096;
    const auto container = test::make_vhdx(volume, {}, opts);
    auto dev = open_bytes(container);
    CHECK(dev->info().logical_sector_size == 4096);
    CHECK(dev->info().physical_sector_size == 4096);
    CHECK(read_vec(*dev, 0, volume.size()) == volume);
}

TEST_CASE("VHDX reads are thread-safe", "[vhdx]") {
    const auto volume = small_volume(3 * test::kVhdxMiB);
    const auto container = test::make_vhdx(
        volume, {VhdxBlockMode::kPartial, VhdxBlockMode::kZero, VhdxBlockMode::kPartial});
    auto dev = open_bytes(container);
    std::vector<std::thread> threads;
    std::vector<std::vector<uint8_t>> results(6);
    for (size_t t = 0; t < results.size(); ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 20; ++i) {
                const uint64_t off = static_cast<uint64_t>((t * 7000 + i * 4093) % 4096);
                std::vector<uint8_t> buf(2048, 0);
                auto r = dev->read(off, buf.data(), buf.size());
                if (r) results[t] = buf;
            }
        });
    }
    for (auto& th : threads) th.join();
    for (size_t t = 0; t < results.size(); ++t) {
        const uint64_t off = static_cast<uint64_t>((t * 7000 + 19 * 4093) % 4096);
        CHECK(results[t] == std::vector<uint8_t>(volume.begin() + static_cast<std::ptrdiff_t>(off),
                                                 volume.begin() + static_cast<std::ptrdiff_t>(off) + 2048));
    }
}

TEST_CASE("open_image classifies VHDX files as containers", "[vhdx][image]") {
    TempDir dir;
    const auto volume = small_volume();
    const auto container = test::make_vhdx(volume);
    test::create_test_file(dir.path() / "disk.vhdx", container);
    auto dev = open_image(dir.path() / "disk.vhdx", OpenOptions{});
    REQUIRE(dev.has_value());
    CHECK((*dev)->info().size_bytes == volume.size());
    CHECK((*dev)->info().container == "vhdx");
    CHECK(read_vec(**dev, 0, volume.size()) == volume);
}

TEST_CASE("A file too small for VHDX tables is refused", "[vhdx]") {
    std::vector<uint8_t> tiny(1024, 0);
    std::memcpy(tiny.data(), "vhdxfile", 8);
    auto dev = open_vhdx(std::make_shared<MemoryDevice>(tiny));
    REQUIRE_FALSE(dev.has_value());
    CHECK(dev.error().code == ErrorCode::CorruptStructure);
}

TEST_CASE("Single-byte VHDX mutations open the disk or refuse it, never anything else",
          "[vhdx][fuzz]") {
    QuietLogs quiet;
    const auto volume = small_volume(2 * test::kVhdxMiB);
    const auto base =
        test::make_vhdx(volume, {VhdxBlockMode::kPartial, VhdxBlockMode::kFull});
    SweepTally tally;

    auto sweep_range = [&](size_t from, size_t to, uint8_t mask, size_t stride) {
        for (size_t i = from; i < to; i += stride) {
            auto data = base;
            data[i] ^= mask;
            sweep_one(data, tally, "byte " + std::to_string(i) + " xor " + std::to_string(mask));
        }
    };
    sweep_range(0, 64, 0xFF, 1);                                    // file identifier
    sweep_range(test::kVhdxHeader1, test::kVhdxHeader1 + test::kVhdxHeaderBytes, 0xFF, 1);
    sweep_range(test::kVhdxHeader2, test::kVhdxHeader2 + test::kVhdxHeaderBytes, 0xFF, 1);
    sweep_range(test::kVhdxRegion1, test::kVhdxRegion1 + 256, 0xFF, 1);
    sweep_range(test::kVhdxRegion2, test::kVhdxRegion2 + 256, 0xFF, 1);
    sweep_range(test::kVhdxBatOffset, test::kVhdxBatOffset + 16, 0xFF, 1);
    sweep_range(test::kVhdxMetadataOffset, test::kVhdxMetadataOffset + 352, 0xFF, 1);

    INFO(tally.counts());
    CHECK(tally.first_violation.empty());
    if (!tally.first_violation.empty()) INFO(tally.offender << " -- " << tally.first_violation);
    CHECK(tally.opens > tally.cases / 4);
}

TEST_CASE("Checksum-repaired VHDX fields are judged by value", "[vhdx][fuzz]") {
    QuietLogs quiet;
    const auto volume = small_volume();
    const auto base = test::make_vhdx(volume);
    SweepTally tally;

    const uint64_t values[] = {0, 1, 2, 4, 8, 512, 1024, 4096, 1024 * 1024, 2 * 1024 * 1024,
                               256ull * 1024 * 1024, 0x7FFFFFFFull, 0xFFFFFFFFull,
                               static_cast<uint64_t>(base.size()) - 1,
                               static_cast<uint64_t>(base.size()),
                               static_cast<uint64_t>(base.size()) + 1, kMaxVirtualBytes,
                               kMaxVirtualBytes + 512, UINT64_MAX};
    auto patch = [&](size_t at, size_t width, uint64_t value) {
        auto data = base;
        for (size_t i = 0; i < width; ++i)
            data[at + i] = static_cast<uint8_t>(value >> (i * 8));
        return data;
    };

    for (uint64_t value : values) {
        // Header fields, with both checksums repaired so the value itself is judged.
        for (auto [at, width] : {std::pair<size_t, size_t>{test::kVhdxHeader1 + 66, 2},
                                 {test::kVhdxHeader1 + 8, 8}}) {
            auto data = patch(at, width, value);
            repair_headers(data);
            sweep_one(data, tally, "header " + std::to_string(at) + " = " + std::to_string(value));
        }
        // Region table entries, with both tables repaired. The file offsets are 64-bit and
        // the lengths 32-bit, so each width is patched with its own loop.
        for (size_t at : {test::kVhdxRegion1 + test::kVhdxRegionEntries + 16,
                          test::kVhdxRegion1 + test::kVhdxRegionEntries + 32 + 16}) {
            auto data = patch(at, 8, value);
            repair_regions(data);
            sweep_one(data, tally, "region offset " + std::to_string(at) + " = " + std::to_string(value));
        }
        for (size_t at : {test::kVhdxRegion1 + test::kVhdxRegionEntries + 24,
                          test::kVhdxRegion1 + test::kVhdxRegionEntries + 32 + 24,
                          test::kVhdxRegion1 + test::kVhdxRegionEntries + 28,
                          test::kVhdxRegion1 + test::kVhdxRegionEntries + 32 + 28}) {
            auto data = patch(at, 4, value);
            repair_regions(data);
            sweep_one(data, tally, "region field " + std::to_string(at) + " = " + std::to_string(value));
        }
        // Metadata and BAT values have no checksum over them.
        for (auto [at, width] : {std::pair<size_t, size_t>{test::kVhdxMetadataOffset + test::kVhdxParamsAt, 4},
                                 {test::kVhdxMetadataOffset + test::kVhdxSizeAt, 8},
                                 {test::kVhdxMetadataOffset + test::kVhdxLogicalAt, 4},
                                 {test::kVhdxMetadataOffset + test::kVhdxPhysicalAt, 4}}) {
            auto data = patch(at, width, value);
            sweep_one(data, tally, "metadata " + std::to_string(at) + " = " + std::to_string(value));
        }
        auto bat = patch(test::kVhdxBatOffset, 8, value);
        sweep_one(bat, tally, "bat = " + std::to_string(value));
    }

    INFO(tally.counts());
    CHECK(tally.first_violation.empty());
    if (!tally.first_violation.empty()) INFO(tally.offender << " -- " << tally.first_violation);
    CHECK(tally.refusals > 0);
}

TEST_CASE("The committed VHDX fuzz seeds open as the containers they claim to be", "[vhdx][fuzz]") {
    const std::filesystem::path root{std::string(OPENRECOVER_FUZZ_SEED_DIR)};
    REQUIRE(std::filesystem::is_directory(root));
    std::vector<std::filesystem::path> seeds;
    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        if (entry.is_regular_file()) seeds.push_back(entry.path());
    }
    std::sort(seeds.begin(), seeds.end());
    REQUIRE_FALSE(seeds.empty());

    // Every valid seed carries a 4096-byte disk whose one block is zero, undefined or not
    // present, so each must read back as zeros over the full virtual size.
    const std::vector<uint8_t> zeros(4096, 0);
    for (const auto& path : seeds) {
        const std::string name = path.filename().string();
        INFO("seed: " << name);
        const std::vector<uint8_t> bytes = test::load_test_file(path);
        auto dev = open_vhdx(std::make_shared<MemoryDevice>(bytes));
        if (name.rfind("invalid_", 0) == 0) {
            REQUIRE_FALSE(dev.has_value());
            CHECK(accepted_error(dev.error().code));
            continue;
        }
        REQUIRE(dev.has_value());
        CHECK(device_violation(**dev, bytes).empty());
        CHECK((*dev)->info().size_bytes == 4096);
        CHECK(read_vec(**dev, 0, 4096) == zeros);
    }
}
