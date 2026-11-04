#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/io/image_device.hpp"
#include "openrecover/io/vhd_device.hpp"
#include "test_util.hpp"
#include "vhd_builder.hpp"

using namespace openrecover;
using namespace openrecover::io;
using openrecover::test::MemoryDevice;
using openrecover::test::TempDir;

namespace {

constexpr size_t kSector = 512;
constexpr uint64_t kMaxVirtualBytes = 0xFF000000ull * kSector;

std::vector<uint8_t> make_fixed_container(const std::vector<uint8_t>& volume, size_t padding = 0) {
    test::VhdFooterOptions opts;
    opts.type = test::kVhdFixed;
    opts.size = volume.size();
    std::vector<uint8_t> out = volume;
    out.resize(out.size() + padding, uint8_t{0});
    const auto footer = test::make_vhd_footer(opts);
    out.insert(out.end(), footer.begin(), footer.end());
    return out;
}

// A 4096-byte dynamic disk with block size 1024: block 0 is absent from the container,
// block 1 is whole, block 2 is absent, block 3 holds only its first sector.
struct DynamicFixture {
    std::vector<uint8_t> volume = test::patterned_bytes(4096, 11);
    std::vector<uint8_t> container;
    std::vector<uint8_t> expected;

    DynamicFixture() {
        const size_t block = 1024;
        const size_t bitmap = kSector;
        const size_t b1 = 1536;
        const size_t b3 = 3072;
        const size_t bat = 4608;
        // The footer sits in the last 512 bytes; the space between the BAT and it is padding.
        const size_t total = 5632;

        container.assign(total, 0);
        test::VhdFooterOptions foot_opts;
        foot_opts.type = test::kVhdDynamic;
        foot_opts.size = volume.size();
        foot_opts.data_offset = kSector;
        const auto footer = test::make_vhd_footer(foot_opts);
        // A dynamic disk keeps a copy of the footer at offset 0 as well.
        std::copy(footer.begin(), footer.end(), container.begin());
        std::copy(footer.begin(), footer.end(), container.end() - kSector);

        const auto header = test::make_vhd_dynamic_header({bat, 4, static_cast<uint32_t>(block)});
        std::copy(header.begin(), header.end(), container.begin() + kSector);

        std::vector<uint8_t> full(bitmap, 0);
        test::set_sector_bits(full, 0, 2);
        std::copy(full.begin(), full.end(), container.begin() + static_cast<std::ptrdiff_t>(b1));
        std::copy(volume.begin() + 1024, volume.begin() + 2048, container.begin() + static_cast<std::ptrdiff_t>(b1 + bitmap));

        std::vector<uint8_t> half(bitmap, 0);
        test::set_sector_bits(half, 0, 1);
        std::copy(half.begin(), half.end(), container.begin() + static_cast<std::ptrdiff_t>(b3));
        std::copy(volume.begin() + 3072, volume.begin() + 3584, container.begin() + static_cast<std::ptrdiff_t>(b3 + bitmap));

        test::put_be32(container, bat, test::kVhdUnallocated);
        test::put_be32(container, bat + 4, static_cast<uint32_t>(b1));
        test::put_be32(container, bat + 8, test::kVhdUnallocated);
        test::put_be32(container, bat + 12, static_cast<uint32_t>(b3));

        expected = volume;
        std::fill(expected.begin(), expected.begin() + 1024, uint8_t{0});
        std::fill(expected.begin() + 2048, expected.begin() + 3072, uint8_t{0});
        std::fill(expected.begin() + 3584, expected.begin() + 4096, uint8_t{0});
    }
};

std::vector<uint8_t> read_vec(BlockDevice& dev, uint64_t off, size_t len) {
    std::vector<uint8_t> buf(len, 0xCC);
    auto r = dev.read(off, buf.data(), len);
    REQUIRE(r.has_value());
    buf.resize(r->bytes_read);
    return buf;
}

// Same, but assertion-free so worker threads can use it (Catch2 REQUIRE must not throw off-thread).
std::vector<uint8_t> read_vec_quiet(BlockDevice& dev, uint64_t off, size_t len) {
    std::vector<uint8_t> buf(len, 0xCC);
    auto r = dev.read(off, buf.data(), len);
    if (!r) return buf;
    buf.resize(r->bytes_read);
    return buf;
}

}  // namespace

TEST_CASE("Fixed VHD presents the volume without the footer", "[vhd]") {
    const auto volume = test::patterned_bytes(4096, 3);
    auto container = std::make_shared<MemoryDevice>(make_fixed_container(volume));
    auto dev = open_vhd(std::move(container));
    REQUIRE(dev.has_value());
    REQUIRE(*dev);
    CHECK((*dev)->info().size_bytes == 4096);
    CHECK((*dev)->info().is_image);
    CHECK((*dev)->info().logical_sector_size == 512);
    CHECK((*dev)->info().container == "vhd fixed");
    CHECK((*dev)->info().description.find("vhd fixed") != std::string::npos);
    CHECK(read_vec(**dev, 0, 4096) == volume);
    CHECK(read_vec(**dev, 2000, 64) == std::vector<uint8_t>(volume.begin() + 2000, volume.begin() + 2064));
    // Reads clamp to the virtual size, never past it into the footer.
    CHECK(read_vec(**dev, 4000, 200).size() == 96);
    CHECK(read_vec(**dev, 4096, 10).empty());
}

TEST_CASE("Fixed VHD reports container bad sectors that are inside the volume", "[vhd]") {
    // Sector 4 is inside the 4096-byte virtual disk; sector 10 is in trailing padding past it.
    auto raw = std::make_unique<MemoryDevice>(make_fixed_container(test::patterned_bytes(4096, 3), 2048));
    raw->bad_sector(4);
    raw->bad_sector(10);
    std::shared_ptr<BlockDevice> container(std::move(raw));
    auto dev = open_vhd(std::move(container));
    REQUIRE(dev.has_value());
    // Sectors only count once the device has actually tried to read them.
    CHECK(read_vec(**dev, 0, 4096).size() == 4096);
    auto bad = (*dev)->bad_sectors();
    CHECK(std::find(bad.begin(), bad.end(), 4) != bad.end());
    CHECK(std::find(bad.begin(), bad.end(), 10) == bad.end());
}

TEST_CASE("Dynamic VHD translates the block allocation table", "[vhd]") {
    DynamicFixture fx;
    auto container = std::make_shared<MemoryDevice>(fx.container);
    auto dev = open_vhd(std::move(container));
    REQUIRE(dev.has_value());
    REQUIRE(*dev);
    CHECK((*dev)->info().size_bytes == 4096);
    CHECK((*dev)->info().description.find("vhd dynamic") != std::string::npos);
    CHECK(read_vec(**dev, 0, 4096) == fx.expected);
    CHECK((*dev)->bad_sectors().empty());

    // Unaligned spans across an allocated/unallocated boundary resolve per sector.
    std::vector<uint8_t> span = read_vec(**dev, 1000, 100);
    REQUIRE(span.size() == 100);
    std::vector<uint8_t> want(24, 0);
    want.insert(want.end(), fx.expected.begin() + 1024, fx.expected.begin() + 1100);
    CHECK(span == want);

    // The half-populated block: first sector real, second sector zeros.
    CHECK(read_vec(**dev, 3584, 128) == std::vector<uint8_t>(128, 0));
    CHECK(read_vec(**dev, 3072, 128) == std::vector<uint8_t>(fx.expected.begin() + 3072, fx.expected.begin() + 3200));
}

TEST_CASE("Dynamic VHD reads are thread-safe", "[vhd]") {
    DynamicFixture fx;
    auto container = std::make_shared<MemoryDevice>(fx.container);
    auto dev = open_vhd(std::move(container));
    REQUIRE(dev.has_value());
    std::vector<std::thread> threads;
    std::vector<std::vector<uint8_t>> results(6);
    for (size_t t = 0; t < results.size(); ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 20; ++i)
                results[t] = read_vec_quiet(**dev, static_cast<uint64_t>((t * 600 + i * 37) % 3600), 400);
        });
    }
    for (auto& th : threads) th.join();
    for (size_t t = 0; t < results.size(); ++t) {
        const uint64_t off = static_cast<uint64_t>((t * 600 + 19 * 37) % 3600);
        CHECK(results[t] == std::vector<uint8_t>(fx.expected.begin() + static_cast<std::ptrdiff_t>(off),
                                                 fx.expected.begin() + static_cast<std::ptrdiff_t>(off) + 400));
    }
}

TEST_CASE("VHD footer validation", "[vhd]") {
    SECTION("differencing disks need the parent chain") {
        auto volume = test::patterned_bytes(2048, 5);
        test::VhdFooterOptions opts;
        opts.type = test::kVhdDifferencing;
        opts.size = volume.size();
        std::vector<uint8_t> data = volume;
        const auto footer = test::make_vhd_footer(opts);
        data.insert(data.end(), footer.begin(), footer.end());
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::Unsupported);
    }
    SECTION("a broken footer checksum is corrupt") {
        auto data = make_fixed_container(test::patterned_bytes(2048, 5));
        data[data.size() - 300] ^= 0xFF;  // reserved area, after the checksum was computed
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("an unknown format version is corrupt") {
        auto data = make_fixed_container(test::patterned_bytes(2048, 5));
        test::put_be32(data, data.size() - kSector + 12, 0x00020000);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("an out-of-range virtual size is corrupt") {
        auto data = make_fixed_container(test::patterned_bytes(2048, 5));
        test::put_be64(data, data.size() - kSector + 48, kMaxVirtualBytes + kSector);
        test::put_be32(data, data.size() - kSector + 64, test::block_checksum(
                                                            {data.end() - static_cast<std::ptrdiff_t>(kSector), data.end()}, 64));
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a container too small to hold a footer") {
        std::vector<uint8_t> tiny(256, 0x5A);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(tiny));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::Unsupported);
    }
}

TEST_CASE("Dynamic VHD rejects a malformed block list", "[vhd]") {
    DynamicFixture fx;
    SECTION("a non power-of-two block size") {
        auto data = fx.container;
        test::put_be32(data, kSector + 32, 1000);
        test::put_be32(data, kSector + 36, test::block_checksum({data.begin() + static_cast<std::ptrdiff_t>(kSector),
                                                                data.begin() + static_cast<std::ptrdiff_t>(kSector + test::kVhdHeader)},
                                                                36));
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a block table shorter than the disk") {
        auto data = fx.container;
        test::put_be32(data, kSector + 28, 2);  // max_table_entries
        test::put_be32(data, kSector + 36, test::block_checksum({data.begin() + static_cast<std::ptrdiff_t>(kSector),
                                                                data.begin() + static_cast<std::ptrdiff_t>(kSector + test::kVhdHeader)},
                                                                36));
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a block table pointing past the container") {
        auto data = fx.container;
        test::put_be64(data, kSector + 16, data.size() + 4096);
        test::put_be32(data, kSector + 36, test::block_checksum({data.begin() + static_cast<std::ptrdiff_t>(kSector),
                                                                data.begin() + static_cast<std::ptrdiff_t>(kSector + test::kVhdHeader)},
                                                                36));
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a missing dynamic header signature") {
        auto data = fx.container;
        std::memcpy(data.data() + kSector, "cxsparxe", 8);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("open_image classifies VHD files as containers", "[vhd][image]") {
    TempDir dir;
    const auto volume = test::patterned_bytes(4096, 13);
    test::create_test_file(dir.path() / "disk.vhd", make_fixed_container(volume));
    auto dev = open_image(dir.path() / "disk.vhd", OpenOptions{});
    REQUIRE(dev.has_value());
    CHECK((*dev)->info().size_bytes == 4096);
    CHECK((*dev)->info().description.find("vhd fixed") != std::string::npos);
    std::vector<uint8_t> buf(4096, 0);
    auto r = (*dev)->read(0, buf.data(), buf.size());
    REQUIRE(r.has_value());
    CHECK(r->bytes_read == 4096);
    CHECK(buf == volume);
}

TEST_CASE("A truncated dynamic block reads back as zeros", "[vhd]") {
    DynamicFixture fx;
    auto data = fx.container;
    test::put_be32(data, 4608 + 4, static_cast<uint32_t>(data.size()));  // block 1 past the end
    auto container = std::make_shared<MemoryDevice>(data);
    auto dev = open_vhd(std::move(container));
    REQUIRE(dev.has_value());
    auto buf = read_vec(**dev, 1024, 512);
    CHECK(buf == std::vector<uint8_t>(512, 0));
    // The rest of the disk is unaffected.
    CHECK(read_vec(**dev, 0, 4096).size() == 4096);
}

namespace {

constexpr size_t kSweepSpan = 16384;
constexpr size_t kBatOffset = 4608;

// A 13-valued alphabet, so a byte the device fabricated instead of reading -- an unfilled
// buffer, a stale cache line -- cannot pass for a byte that exists in the container.
std::vector<uint8_t> sweep_volume(size_t n) {
    std::vector<uint8_t> out(n);
    for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>((i * 31 + 7) % 13 + 1);
    return out;
}

// The only verdicts a correct parser may reach for a broken container. A refusal with any
// other code -- an IoError from a device that has no bad sectors, say -- is a regression.
bool accepted_error(ErrorCode code) {
    return code == ErrorCode::CorruptStructure || code == ErrorCode::Unsupported ||
           code == ErrorCode::InvalidArgument;
}

// Invariants that must hold for every container the sweeps can produce. Returns an empty
// string when the opened device is clean, else the first violation it found.
std::string device_violation(BlockDevice& dev, const std::vector<uint8_t>& container) {
    const DeviceInfo& info = dev.info();
    if (info.size_bytes == 0 || info.size_bytes > kMaxVirtualBytes)
        return "virtual size " + std::to_string(info.size_bytes) + " is out of range";
    if (info.logical_sector_size != kSector) return "logical sector size is no longer 512";
    if (info.container == "vhd fixed" && info.size_bytes + kSector > container.size())
        return "a fixed device maps the trailing footer into the volume";

    std::vector<bool> present(256, false);
    for (uint8_t byte : container) present[byte] = true;

    const uint64_t span = std::min<uint64_t>(info.size_bytes, kSweepSpan);
    std::vector<uint8_t> whole(static_cast<size_t>(span), 0xA5);
    auto full = dev.read(0, whole.data(), whole.size());
    if (!full) return "read at 0 failed: " + full.error().to_string();
    if (full->bytes_read != whole.size())
        return "read at 0 returned " + std::to_string(full->bytes_read) + " of " + std::to_string(span);
    for (size_t i = 0; i < whole.size(); ++i) {
        if (!present[whole[i]])
            return "byte " + std::to_string(i) + " is not a byte the container holds";
    }

    // Translation must be a pure function of the offset: odd-sized, odd-aligned windows have
    // to agree with the single pass, otherwise a block or bitmap was resolved twice
    // differently.
    for (uint64_t off = 0; off < span; off += 617) {
        const size_t len = static_cast<size_t>(std::min<uint64_t>(300 + (off % 7) * 40, span - off));
        std::vector<uint8_t> part(len, 0x5A);
        auto r = dev.read(off, part.data(), len);
        if (!r) return "read at " + std::to_string(off) + " failed: " + r.error().to_string();
        if (r->bytes_read != len) return "short read at " + std::to_string(off);
        if (!std::equal(part.begin(), part.end(), whole.begin() + static_cast<std::ptrdiff_t>(off)))
            return "read at " + std::to_string(off) + " disagrees with the whole-disk pass";
    }

    std::vector<uint8_t> beyond(64, 0);
    auto past = dev.read(info.size_bytes, beyond.data(), beyond.size());
    if (!past) return "read at the end of the disk failed: " + past.error().to_string();
    if (past->bytes_read != 0) return "a read past the virtual size returned bytes";
    for (uint64_t sector : dev.bad_sectors()) {
        if (sector * kSector >= info.size_bytes) return "bad sector reported outside the virtual disk";
    }
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
    auto container = std::make_shared<MemoryDevice>(data);
    auto dev = open_vhd(std::move(container));
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

// The reader checks the footer checksum before it looks at any value, so a mutation of a
// single field is only interesting once the checksums agree again. This recomputes the
// trailing footer, the leading copy a dynamic disk keeps, and the dynamic header.
void repair_vhd(std::vector<uint8_t>& data, bool dynamic) {
    const size_t tail = data.size() - kSector;
    std::vector<uint8_t> foot({data.begin() + static_cast<std::ptrdiff_t>(tail), data.end()});
    test::put_be32(foot, 64, test::block_checksum(foot, 64));
    std::copy(foot.begin(), foot.end(), data.begin() + static_cast<std::ptrdiff_t>(tail));
    if (!dynamic) return;
    std::copy(foot.begin(), foot.end(), data.begin());
    std::vector<uint8_t> head({data.begin() + static_cast<std::ptrdiff_t>(kSector),
                               data.begin() + static_cast<std::ptrdiff_t>(kSector + test::kVhdHeader)});
    test::put_be32(head, 36, test::block_checksum(head, 36));
    std::copy(head.begin(), head.end(), data.begin() + static_cast<std::ptrdiff_t>(kSector));
}

void sweep_field(std::vector<uint8_t>& data, bool dynamic, size_t offset, size_t width, uint64_t value,
                 const std::string& label, SweepTally& tally) {
    REQUIRE(offset + width <= data.size());
    for (size_t i = width; i > 0; --i)
        data[offset + width - i] = static_cast<uint8_t>(value >> ((i - 1) * 8));
    repair_vhd(data, dynamic);
    sweep_one(data, tally, label + " = " + std::to_string(value));
}

struct FieldPatch {
    const char* name;
    bool in_footer;  // relative to the trailing footer, which moves with the container size
    size_t offset;
    size_t width;
};

void sweep_patches(const std::vector<uint8_t>& base, bool dynamic, const FieldPatch* patches,
                   size_t patch_count, const uint64_t* values, size_t value_count, SweepTally& tally) {
    const size_t foot = base.size() - kSector;
    for (size_t p = 0; p < patch_count; ++p) {
        const size_t offset = patches[p].in_footer ? foot + patches[p].offset : patches[p].offset;
        for (size_t v = 0; v < value_count; ++v) {
            auto data = base;
            sweep_field(data, dynamic, offset, patches[p].width, values[v], patches[p].name, tally);
        }
    }
}

// Nearly every mutant trips the parser's "this block is truncated" warnings, which would
// bury the test output in tens of thousands of lines.
class QuietLogs {
public:
    QuietLogs() { log::set_sink([](LogLevel, std::string_view) {}); }
    QuietLogs(const QuietLogs&) = delete;
    QuietLogs& operator=(const QuietLogs&) = delete;
    ~QuietLogs() { log::set_sink(nullptr); }
};

}  // namespace

TEST_CASE("Single-byte mutations open the disk or refuse it, never anything else", "[vhd][fuzz]") {
    QuietLogs quiet;
    const auto fixed = make_fixed_container(sweep_volume(2048));
    const DynamicFixture fx;
    SweepTally fixed_tally;
    SweepTally dynamic_tally;

    // 0xFF flips every bit at once and is applied at every byte position; the one-bit masks
    // reach the same verdicts, so they are sampled to keep the sweep a few seconds instead
    // of half a minute. Every mutant costs a cached block read either way.
    auto sweep_both = [&](uint8_t mask, size_t stride) {
        for (size_t i = 0; i < fixed.size(); i += stride) {
            auto data = fixed;
            data[i] ^= mask;
            sweep_one(data, fixed_tally,
                      "fixed byte " + std::to_string(i) + " xor " + std::to_string(mask));
        }
        for (size_t i = 0; i < fx.container.size(); i += stride) {
            auto data = fx.container;
            data[i] ^= mask;
            sweep_one(data, dynamic_tally,
                      "dynamic byte " + std::to_string(i) + " xor " + std::to_string(mask));
        }
    };
    sweep_both(0xFF, 1);
    sweep_both(0x01, 8);
    sweep_both(0x80, 8);

    INFO("fixed: " << fixed_tally.counts());
    INFO("dynamic: " << dynamic_tally.counts());
    CHECK(fixed_tally.first_violation.empty());
    CHECK(dynamic_tally.first_violation.empty());
    if (!fixed_tally.first_violation.empty())
        INFO("fixed offender: " << fixed_tally.offender << " -- " << fixed_tally.first_violation);
    if (!dynamic_tally.first_violation.empty())
        INFO("dynamic offender: " << dynamic_tally.offender << " -- " << dynamic_tally.first_violation);
    // A sweep that never reaches the read path proves nothing, and most of these mutants
    // still describe a readable disk: only the footer, header and table fields are checked.
    CHECK(fixed_tally.opens > fixed_tally.cases / 2);
    CHECK(dynamic_tally.opens > dynamic_tally.cases / 2);
}

TEST_CASE("Checksum-repaired VHD fields are judged by value", "[vhd][fuzz]") {
    QuietLogs quiet;
    const auto volume = sweep_volume(4096);
    const DynamicFixture fx;

    const uint64_t values[] = {
        0, 1, 2, 3, 4, 5, 511, 512, 1024, 2048, 3000, 4096, 0xFFFFull, 0x10000ull,
        0x7FFFFFFFull, 0x80000000ull, 0xFFFFFFFEull, 0xFFFFFFFFull, 0x100000000ull,
        static_cast<uint64_t>(fx.container.size()) - 1, static_cast<uint64_t>(fx.container.size()),
        static_cast<uint64_t>(fx.container.size()) + 1, kMaxVirtualBytes,
        kMaxVirtualBytes + kSector, UINT64_MAX - 1, UINT64_MAX};
    const size_t value_count = sizeof(values) / sizeof(values[0]);

    const FieldPatch dynamic_patches[] = {
        {"footer.version", true, 12, 4},        {"footer.data_offset", true, 16, 8},
        {"footer.original_size", true, 40, 8},  {"footer.current_size", true, 48, 8},
        {"footer.type", true, 60, 4},           {"header.table_offset", false, kSector + 16, 8},
        {"header.version", false, kSector + 24, 4}, {"header.max_entries", false, kSector + 28, 4},
        {"header.block_size", false, kSector + 32, 4}, {"header.reserved", false, kSector + 64, 4}};
    const FieldPatch fixed_patches[] = {
        {"footer.version", true, 12, 4},       {"footer.data_offset", true, 16, 8},
        {"footer.original_size", true, 40, 8}, {"footer.current_size", true, 48, 8},
        {"footer.type", true, 60, 4}};

    SweepTally dynamic_tally;
    SweepTally fixed_tally;
    sweep_patches(fx.container, true, dynamic_patches,
                  sizeof(dynamic_patches) / sizeof(dynamic_patches[0]), values, value_count, dynamic_tally);
    sweep_patches(make_fixed_container(volume), false, fixed_patches,
                  sizeof(fixed_patches) / sizeof(fixed_patches[0]), values, value_count, fixed_tally);

    INFO("dynamic: " << dynamic_tally.counts());
    INFO("fixed: " << fixed_tally.counts());
    CHECK(dynamic_tally.first_violation.empty());
    CHECK(fixed_tally.first_violation.empty());
    if (!dynamic_tally.first_violation.empty())
        INFO("dynamic offender: " << dynamic_tally.offender << " -- " << dynamic_tally.first_violation);
    if (!fixed_tally.first_violation.empty())
        INFO("fixed offender: " << fixed_tally.offender << " -- " << fixed_tally.first_violation);
    CHECK(dynamic_tally.refusals > 0);
    CHECK(fixed_tally.refusals > 0);
}

TEST_CASE("Repaired footer and header values refuse exactly the disks they should", "[vhd][fuzz]") {
    QuietLogs quiet;
    DynamicFixture fx;
    const size_t foot = fx.container.size() - kSector;

    SECTION("a differencing disk is unsupported even with a valid checksum") {
        auto data = fx.container;
        test::put_be32(data, foot + 60, test::kVhdDifferencing);
        test::put_be32(data, foot + 64, 0);  // deliberately stale, to prove the fallback order
        repair_vhd(data, true);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::Unsupported);
    }
    SECTION("the largest disk the format allows needs a table past the reader's cap") {
        auto data = fx.container;
        test::put_be64(data, foot + 48, kMaxVirtualBytes);
        repair_vhd(data, true);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::Unsupported);
    }
    SECTION("a block size above 1 GiB is corrupt, one at the cap reads as sparse") {
        auto data = fx.container;
        test::put_be32(data, kSector + 32, 1u << 31);
        repair_vhd(data, true);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::CorruptStructure);

        data = fx.container;
        test::put_be32(data, kSector + 32, 1u << 30);
        repair_vhd(data, true);
        auto huge = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE(huge.has_value());
        CHECK((*huge)->info().size_bytes == 4096);
        // The 1 GiB block's sector bitmap does not fit in the container, so nothing is
        // provably allocated and the whole disk reads back as zeros.
        CHECK(read_vec(**huge, 0, 4096) == std::vector<uint8_t>(4096, 0));
    }
    SECTION("a declared entry count of zero means no limit") {
        auto data = fx.container;
        test::put_be32(data, kSector + 28, 0);
        repair_vhd(data, true);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE(dev.has_value());
        CHECK(device_violation(**dev, data).empty());
        CHECK(read_vec(**dev, 0, 4096) == fx.expected);
    }
    SECTION("a backup copy of the footer keeps a damaged primary readable") {
        auto data = fx.container;
        std::memset(data.data() + foot, 0, kSector);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(data));
        REQUIRE(dev.has_value());
        CHECK((*dev)->info().size_bytes == 4096);
        CHECK(read_vec(**dev, 0, 4096) == fx.expected);
    }
}

TEST_CASE("Block table and sector bitmap mutations stay inside the container", "[vhd][fuzz]") {
    QuietLogs quiet;
    DynamicFixture fx;
    SweepTally tally;

    const uint32_t entries[] = {0, 1, 512, 1024, 1536, 2048, 3072, static_cast<uint32_t>(kBatOffset),
                                static_cast<uint32_t>(fx.container.size()) - 1,
                                static_cast<uint32_t>(fx.container.size()),
                                static_cast<uint32_t>(fx.container.size()) + 1, 0x7FFFFFFFu,
                                0xFFFFFFFEu, test::kVhdUnallocated};
    for (size_t entry = 0; entry < 4; ++entry) {
        for (uint32_t value : entries) {
            auto data = fx.container;
            test::put_be32(data, kBatOffset + 4 * entry, value);
            sweep_one(data, tally, "bat[" + std::to_string(entry) + "] = " + std::to_string(value));
        }
    }
    // Sector bits decide which bytes are real. Flipping one may change the data a read
    // returns, never the shape of the answer.
    for (size_t base : {static_cast<size_t>(1536), static_cast<size_t>(3072)}) {
        for (size_t i = 0; i < kSector; ++i) {
            auto data = fx.container;
            data[base + i] ^= 0xFF;
            sweep_one(data, tally, "bitmap byte " + std::to_string(base + i));
        }
    }

    INFO(tally.counts());
    CHECK(tally.first_violation.empty());
    if (!tally.first_violation.empty()) INFO(tally.offender << " -- " << tally.first_violation);
    CHECK(tally.opens > tally.cases / 2);
}

TEST_CASE("The committed VHD fuzz seeds open as the containers they claim to be", "[vhd][fuzz]") {
    const std::filesystem::path root{std::string(OPENRECOVER_FUZZ_SEED_DIR)};
    REQUIRE(std::filesystem::is_directory(root));
    std::vector<std::filesystem::path> seeds;
    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        if (entry.is_regular_file()) seeds.push_back(entry.path());
    }
    std::sort(seeds.begin(), seeds.end());
    REQUIRE_FALSE(seeds.empty());

    // The builders in tools/fixtures put the same volume into every seed: the 13-valued sweep
    // with a 1 KiB run of zeros, so each seed also exercises the sparse read path.
    auto want = sweep_volume(4096);
    std::fill(want.begin() + 1024, want.begin() + 2048, uint8_t{0});
    for (const auto& path : seeds) {
        const std::string name = path.filename().string();
        INFO("seed: " << name);
        const std::vector<uint8_t> bytes = test::load_test_file(path);
        auto dev = open_vhd(std::make_shared<MemoryDevice>(bytes));
        if (name.rfind("invalid_", 0) == 0) {
            REQUIRE_FALSE(dev.has_value());
            CHECK(accepted_error(dev.error().code));
            continue;
        }
        REQUIRE(dev.has_value());
        CHECK(device_violation(**dev, bytes).empty());
        CHECK((*dev)->info().size_bytes == 4096);
        CHECK(read_vec(**dev, 0, 4096) == want);
    }
}
