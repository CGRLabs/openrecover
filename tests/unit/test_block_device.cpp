#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <random>
#include <thread>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/cached_device.hpp"
#include "openrecover/io/partition_view.hpp"
#include "openrecover/io/readonly_guard.hpp"
#include "test_util.hpp"

using namespace openrecover;
using namespace openrecover::io;
using openrecover::test::MemoryDevice;
using openrecover::test::TempDir;

namespace {

constexpr size_t kMiB = 1u << 20;

struct ImageFixture {
    TempDir dir;
    std::filesystem::path path;
    std::vector<uint8_t> data;

    explicit ImageFixture(size_t size = kMiB, uint32_t seed = 0) {
        data = test::patterned_bytes(size, seed);
        path = dir.path() / "disk.img";
        test::create_test_file(path, data);
    }
};

std::vector<uint8_t> read_vec(BlockDevice& dev, uint64_t off, size_t len, ReadResult* rr_out = nullptr) {
    std::vector<uint8_t> buf(len, 0xCC);
    auto r = dev.read(off, buf.data(), len);
    REQUIRE(r.has_value());
    if (rr_out) *rr_out = *r;
    buf.resize(r->bytes_read);
    return buf;
}

std::vector<uint8_t> slice(const std::vector<uint8_t>& v, size_t off, size_t len) {
    if (off >= v.size()) return {};
    len = std::min(len, v.size() - off);
    return {v.begin() + static_cast<std::ptrdiff_t>(off), v.begin() + static_cast<std::ptrdiff_t>(off + len)};
}

}  // namespace

TEST_CASE("ImageDevice opens a flat image read-only with exact geometry", "[block_device]") {
    ImageFixture fx;
    auto dev = open_image(fx.path, OpenOptions{});
    REQUIRE(dev.has_value());
    const auto& info = (*dev)->info();
    CHECK(info.size_bytes == kMiB);
    CHECK(info.logical_sector_size == 512);
    CHECK(info.is_image);
    CHECK_FALSE(info.shared_write_fallback);
    CHECK(dynamic_cast<GuardedDevice*>(dev->get()) != nullptr);
}

TEST_CASE("ImageDevice unaligned reads", "[block_device]") {
    ImageFixture fx;
    for (uint64_t cache : {uint64_t{0}, uint64_t{64} << 20}) {
        OpenOptions opts;
        opts.cache_bytes = cache;
        auto dev = open_image(fx.path, opts);
        REQUIRE(dev.has_value());
        CHECK(read_vec(**dev, 513, 1000) == slice(fx.data, 513, 1000));
        CHECK(read_vec(**dev, 1, 1) == slice(fx.data, 1, 1));
        CHECK(read_vec(**dev, 511, 2) == slice(fx.data, 511, 2));
        CHECK(read_vec(**dev, 0, kMiB) == fx.data);
        CHECK(read_vec(**dev, 12345, 300000) == slice(fx.data, 12345, 300000));
    }
}

TEST_CASE("ImageDevice EOF semantics", "[block_device]") {
    ImageFixture fx;
    auto dev = open_image(fx.path, OpenOptions{});
    REQUIRE(dev.has_value());
    ReadResult rr;
    SECTION("read across EOF is short") {
        auto v = read_vec(**dev, kMiB - 100, 1000, &rr);
        CHECK(rr.bytes_read == 100);
        CHECK(v == slice(fx.data, kMiB - 100, 100));
        CHECK_FALSE(rr.had_bad_sectors);
    }
    SECTION("read at exactly EOF returns 0 bytes") {
        read_vec(**dev, kMiB, 10, &rr);
        CHECK(rr.bytes_read == 0);
    }
    SECTION("read beyond EOF returns 0 bytes") {
        read_vec(**dev, kMiB + 4096, 10, &rr);
        CHECK(rr.bytes_read == 0);
        read_vec(**dev, UINT64_MAX - 5, 10, &rr);
        CHECK(rr.bytes_read == 0);
    }
    SECTION("zero-length read") {
        read_vec(**dev, 0, 0, &rr);
        CHECK(rr.bytes_read == 0);
    }
}

TEST_CASE("ImageDevice last partial sector is readable", "[block_device]") {
    ImageFixture fx(kMiB + 100, 3);
    auto dev = open_image(fx.path, OpenOptions{});
    REQUIRE(dev.has_value());
    CHECK((*dev)->info().size_bytes == kMiB + 100);
    CHECK(read_vec(**dev, kMiB - 10, 500) == slice(fx.data, kMiB - 10, 110));
}

TEST_CASE("ImageDevice 4096-byte sector override", "[block_device]") {
    ImageFixture fx;
    OpenOptions opts;
    opts.sector_size = 4096;
    auto dev = open_image(fx.path, opts);
    REQUIRE(dev.has_value());
    CHECK((*dev)->info().logical_sector_size == 4096);
    CHECK((*dev)->info().physical_sector_size == 4096);
    CHECK(read_vec(**dev, 513, 1000) == slice(fx.data, 513, 1000));
    CHECK(read_vec(**dev, 4095, 4098) == slice(fx.data, 4095, 4098));

    opts.sector_size = 1000;
    auto bad = open_image(fx.path, opts);
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().code == ErrorCode::InvalidArgument);
}

TEST_CASE("ImageDevice open errors", "[block_device]") {
    TempDir dir;
    SECTION("missing file") {
        auto r = open_image(dir.path() / "nope.img", OpenOptions{});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == ErrorCode::NotFound);
    }
    SECTION("directory") {
        auto r = open_image(dir.path(), OpenOptions{});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == ErrorCode::InvalidArgument);
    }
    SECTION("unsupported container formats are rejected") {
        std::vector<uint8_t> e01(1024, 0);
        std::memcpy(e01.data(), "EVF\x09\x0D\x0A\xFF\x00", 8);
        test::create_test_file(dir.path() / "x.E01", e01);
        auto r2 = open_image(dir.path() / "x.E01", OpenOptions{});
        REQUIRE_FALSE(r2.has_value());
        CHECK(r2.error().code == ErrorCode::Unsupported);

        std::vector<uint8_t> vmdk(1024, 0);
        std::memcpy(vmdk.data(), "KDMV", 4);
        test::create_test_file(dir.path() / "disk.vmdk", vmdk);
        auto r3 = open_image(dir.path() / "disk.vmdk", OpenOptions{});
        REQUIRE_FALSE(r3.has_value());
        CHECK(r3.error().code == ErrorCode::Unsupported);
    }
    SECTION("a VHDX cookie with an unusable header is corrupt, not flat") {
        std::vector<uint8_t> vhdx(1024, 0);
        std::memcpy(vhdx.data(), "vhdxfile", 8);
        test::create_test_file(dir.path() / "disk.vhdx", vhdx);
        auto r = open_image(dir.path() / "disk.vhdx", OpenOptions{});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a VHD cookie with an unusable footer is corrupt, not flat") {
        std::vector<uint8_t> vhd(4096, 0);
        std::memcpy(vhd.data() + vhd.size() - 512, "conectix", 8);
        test::create_test_file(dir.path() / "fixed.vhd", vhd);
        auto r = open_image(dir.path() / "fixed.vhd", OpenOptions{});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("empty image is a valid zero-length device") {
        test::create_test_file(dir.path() / "empty.img", {});
        auto r = open_image(dir.path() / "empty.img", OpenOptions{});
        REQUIRE(r.has_value());
        CHECK((*r)->info().size_bytes == 0);
    }
}

TEST_CASE("open_source dispatches image paths", "[block_device]") {
    ImageFixture fx;
    auto dev = open_source(fx.path.string(), OpenOptions{});
    REQUIRE(dev.has_value());
    CHECK((*dev)->info().size_bytes == kMiB);
    auto bad = open_source("\\\\.\\PhysicalDrive", OpenOptions{});
    REQUIRE_FALSE(bad.has_value());
}

TEST_CASE("image file content is unchanged after reading", "[block_device][readonly]") {
    ImageFixture fx;
    const std::string before = test::sha256_of_file(fx.path);
    {
        auto dev = open_image(fx.path, OpenOptions{});
        REQUIRE(dev.has_value());
        auto h = sha256_of_device(**dev);
        REQUIRE(h.has_value());
        CHECK(*h == before);
        auto* g = dynamic_cast<GuardedDevice*>(dev->get());
        REQUIRE(g);
        CHECK(g->read_count() > 0);
        CHECK(GuardedDevice::bytes_written() == 0);
        CHECK_NOTHROW(g->assert_untouched(before));
        CHECK_THROWS_AS(g->assert_untouched(std::string(64, '0')), ReadOnlyViolation);
    }
    CHECK(test::sha256_of_file(fx.path) == before);
}

TEST_CASE("PartitionView clamping", "[block_device][partition_view]") {
    auto data = test::patterned_bytes(64 * 1024, 5);
    auto parent = std::make_shared<MemoryDevice>(data);

    PartitionView view(parent, 4096, 8192);
    CHECK(view.info().size_bytes == 8192);
    CHECK(view.parent_offset() == 4096);
    CHECK(read_vec(view, 0, 16) == slice(data, 4096, 16));
    ReadResult rr;
    auto tail = read_vec(view, 8000, 500, &rr);
    CHECK(rr.bytes_read == 192);
    CHECK(tail == slice(data, 4096 + 8000, 192));
    read_vec(view, 8192, 1, &rr);
    CHECK(rr.bytes_read == 0);

    SECTION("length beyond parent is clamped to the parent") {
        PartitionView big(parent, 60 * 1024, 1u << 30);
        CHECK(big.info().size_bytes == 4 * 1024);
        CHECK(read_vec(big, 0, 1u << 20) == slice(data, 60 * 1024, 4 * 1024));
    }
    SECTION("offset beyond parent yields an empty view") {
        PartitionView none(parent, 1u << 20, 4096);
        CHECK(none.info().size_bytes == 0);
        read_vec(none, 0, 10, &rr);
        CHECK(rr.bytes_read == 0);
    }
    SECTION("bad sectors are reported relative to the view") {
        parent->bad_sector(10);  // byte 5120 -> view sector 2
        read_vec(view, 0, 8192, &rr);
        CHECK(rr.had_bad_sectors);
        CHECK(view.bad_sectors() == std::vector<uint64_t>{2});
    }
    SECTION("nested views compose") {
        auto outer = std::make_shared<PartitionView>(parent, 1024, 32 * 1024);
        PartitionView inner(outer, 512, 1024);
        CHECK(read_vec(inner, 100, 2000) == slice(data, 1024 + 512 + 100, 924));
    }
}

TEST_CASE("CachedDevice equals uncached byte-for-byte on 10000 seeded random reads", "[block_device][cache]") {
    ImageFixture fx;
    auto raw = open_image(fx.path, OpenOptions{.allow_shared_write_sharing = false, .cache_bytes = 0, .sector_size = 0});
    REQUIRE(raw.has_value());
    std::shared_ptr<BlockDevice> uncached = std::move(*raw);

    auto mem_data = test::patterned_bytes(5 * kMiB + 777, 9);
    auto mem = std::make_shared<MemoryDevice>(mem_data);

    struct Pair {
        std::shared_ptr<BlockDevice> ref;
        uint64_t cap;
    };
    for (const Pair& p : {Pair{uncached, 64ull << 20}, Pair{mem, 2 * kMiB}}) {
        CachedDevice cached(p.ref, p.cap);
        std::mt19937_64 rng(0x5EED0001);
        const uint64_t size = p.ref->info().size_bytes;
        std::vector<uint8_t> a, b;
        for (int i = 0; i < 10000; ++i) {
            const uint64_t off = rng() % (size + 2048);
            const size_t len = static_cast<size_t>(rng() % (i % 100 == 0 ? 3 * kMiB : 70000));
            a.assign(len, 0xAA);
            b.assign(len, 0x55);
            auto ra = p.ref->read(off, a.data(), len);
            auto rb = cached.read(off, b.data(), len);
            REQUIRE(ra.has_value());
            REQUIRE(rb.has_value());
            REQUIRE(ra->bytes_read == rb->bytes_read);
            REQUIRE(std::memcmp(a.data(), b.data(), ra->bytes_read) == 0);
        }
        CHECK(cached.inner_reads() > 0);
    }
}

TEST_CASE("CachedDevice serves repeated reads from cache and is thread-safe", "[block_device][cache]") {
    auto data = test::patterned_bytes(8 * kMiB, 11);
    auto mem = std::make_shared<MemoryDevice>(data);
    CachedDevice cached(mem, 16 * kMiB);
    read_vec(cached, 100, 1000);
    const auto inner_after_first = mem->read_count();
    for (int i = 0; i < 50; ++i) read_vec(cached, 100 + static_cast<uint64_t>(i), 1000);
    CHECK(mem->read_count() == inner_after_first);

    std::vector<std::thread> threads;
    std::atomic<int> mismatches{0};
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t] {
            std::mt19937_64 rng(1000 + static_cast<uint64_t>(t));
            std::vector<uint8_t> buf;
            for (int i = 0; i < 2000; ++i) {
                uint64_t off = rng() % data.size();
                size_t len = static_cast<size_t>(rng() % 200000);
                buf.assign(len, 0);
                auto r = cached.read(off, buf.data(), len);
                if (!r || std::memcmp(buf.data(), data.data() + off, r->bytes_read) != 0 ||
                    r->bytes_read != std::min<uint64_t>(len, data.size() - off))
                    ++mismatches;
            }
        });
    }
    for (auto& th : threads) th.join();
    CHECK(mismatches.load() == 0);
}

TEST_CASE("CachedDevice propagates bad sectors and I/O errors", "[block_device][cache]") {
    auto data = test::patterned_bytes(3 * kMiB, 13);
    SECTION("bad sector") {
        auto mem = std::make_shared<MemoryDevice>(data);
        mem->bad_sector(2050);  // inside block 1
        CachedDevice cached(mem, 8 * kMiB);
        ReadResult rr;
        auto v = read_vec(cached, 0, 4096, &rr);
        CHECK_FALSE(rr.had_bad_sectors);
        CHECK(v == slice(data, 0, 4096));
        v = read_vec(cached, 2050 * 512 - 10, 600, &rr);
        CHECK(rr.had_bad_sectors);
        CHECK(std::all_of(v.begin() + 10, v.begin() + 522, [](uint8_t c) { return c == 0; }));
        CHECK(slice(v, 0, 10) == slice(data, 2050 * 512 - 10, 10));
        CHECK(slice(v, 522, 78) == slice(data, 2051 * 512, 78));
        v = read_vec(cached, 2051 * 512, 100, &rr);
        CHECK_FALSE(rr.had_bad_sectors);
        CHECK(cached.bad_sectors() == std::vector<uint64_t>{2050});
    }
    SECTION("I/O error") {
        auto mem = std::make_shared<MemoryDevice>(data);
        mem->fail_at(kMiB + 5);
        CachedDevice cached(mem, 8 * kMiB);
        std::vector<uint8_t> buf(100);
        CHECK(cached.read(0, buf.data(), buf.size()).has_value());
        auto r = cached.read(kMiB, buf.data(), buf.size());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == ErrorCode::IoError);
    }
}

TEST_CASE("MemoryDevice fault injection", "[block_device][support]") {
    auto data = test::patterned_bytes(4096);
    MemoryDevice dev(data);
    dev.fail_at(1000);
    std::vector<uint8_t> buf(100);
    CHECK(dev.read(0, buf.data(), 100).has_value());
    CHECK_FALSE(dev.read(950, buf.data(), 100).has_value());
    CHECK(dev.read_count() == 2);
}

TEST_CASE("read_fully loops to the requested length", "[block_device]") {
    auto data = test::patterned_bytes(10000);
    auto mem = std::make_shared<MemoryDevice>(data);
    std::vector<uint8_t> buf(20000);
    auto n = read_fully(*mem, 5000, buf.data(), buf.size());
    REQUIRE(n.has_value());
    CHECK(*n == 5000);
    buf.resize(*n);
    CHECK(buf == slice(data, 5000, 5000));
}
