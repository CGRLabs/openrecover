#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <type_traits>
#include <vector>

#include "fake_win32_api.hpp"
#include "memory_device.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/cached_device.hpp"
#include "openrecover/io/output_sink.hpp"
#include "openrecover/io/partition_view.hpp"
#include "openrecover/io/readonly_guard.hpp"
#include "openrecover/io/win_physical_device.hpp"
#include "test_util.hpp"

namespace fs = std::filesystem;
using namespace openrecover;
using namespace openrecover::io;
using openrecover::test::TempDir;

namespace {

// Negative compile-time checks: no mutating member is reachable on any device type.
template <typename D>
concept HasWrite = requires(D& d, uint64_t o, const uint8_t* p, size_t n) { d.write(o, p, n); };
template <typename D>
concept HasWriteSpan = requires(D& d, uint64_t o, std::span<const uint8_t> s) { d.write(o, s); };
template <typename D>
concept HasFlush = requires(D& d) { d.flush(); };
template <typename D>
concept HasTrim = requires(D& d, uint64_t o, uint64_t n) { d.trim(o, n); };
template <typename D>
concept HasDiscard = requires(D& d, uint64_t o, uint64_t n) { d.discard(o, n); };
template <typename D>
concept HasResize = requires(D& d, uint64_t n) { d.resize(n); };
template <typename D>
concept HasTruncate = requires(D& d, uint64_t n) { d.truncate(n); };
template <typename D>
concept HasIoctl = requires(D& d, uint32_t c) { d.ioctl(c); };
template <typename D>
concept HasIoControl = requires(D& d, uint32_t c) { d.IoControl(c); };
template <typename D>
concept HasNativeHandle = requires(D& d) { d.native_handle(); };
template <typename D>
concept HasHandle = requires(D& d) { d.handle(); };
template <typename D>
concept HasRawHandle = requires(D& d) { d.raw_handle(); };
template <typename D>
concept HasFd = requires(D& d) { d.fd(); };

template <typename D>
constexpr bool kNoMutation = !HasWrite<D> && !HasWriteSpan<D> && !HasFlush<D> && !HasTrim<D> && !HasDiscard<D> &&
                             !HasResize<D> && !HasTruncate<D> && !HasIoctl<D> && !HasIoControl<D> &&
                             !HasNativeHandle<D> && !HasHandle<D> && !HasRawHandle<D> && !HasFd<D> &&
                             !std::is_copy_constructible_v<D> && !std::is_copy_assignable_v<D>;

static_assert(kNoMutation<BlockDevice>);
static_assert(kNoMutation<GuardedDevice>);
static_assert(kNoMutation<CachedDevice>);
static_assert(kNoMutation<PartitionView>);
static_assert(kNoMutation<WinPhysicalDevice>);
static_assert(kNoMutation<test::MemoryDevice>);
static_assert(kNoMutation<const BlockDevice>);

// read() takes a destination buffer only; there is no overload taking a const source buffer.
static_assert(std::is_same_v<decltype(&BlockDevice::read), Result<ReadResult> (BlockDevice::*)(uint64_t, uint8_t*, size_t)>);
static_assert(!std::is_invocable_v<decltype(&BlockDevice::read), BlockDevice&, uint64_t, const uint8_t*, size_t>);
static_assert(GuardedDevice::bytes_written() == 0);
static_assert(std::is_base_of_v<std::logic_error, ReadOnlyViolation>);

std::vector<uint8_t> bytes_of(std::string_view s) { return {s.begin(), s.end()}; }

size_t count_entries(const fs::path& dir) {
    size_t n = 0;
    for (auto it = fs::recursive_directory_iterator(dir); it != fs::recursive_directory_iterator(); ++it) ++n;
    return n;
}

bool has_temp_files(const fs::path& dir) {
    for (auto& e : fs::recursive_directory_iterator(dir))
        if (e.path().filename().string().rfind(".~", 0) == 0) return true;
    return false;
}

class FailingSource final : public ByteSource {
public:
    Result<size_t> read_some(uint8_t* dst, size_t len) override {
        if (calls_++ == 0) {
            std::fill(dst, dst + std::min<size_t>(len, 10), uint8_t{'x'});
            return std::min<size_t>(len, 10);
        }
        return fail(ErrorCode::IoError, "source died");
    }

private:
    int calls_ = 0;
};

}  // namespace

TEST_CASE("fatal_write_attempt throws ReadOnlyViolation with location", "[readonly]") {
    std::string msg;
    try {
        OR_FATAL_WRITE("planted write");
    } catch (const ReadOnlyViolation& e) {
        msg = e.what();
    }
    CHECK(msg.find("planted write") != std::string::npos);
    CHECK(msg.find("test_readonly_guard.cpp") != std::string::npos);

    // Called through a volatile pointer so the [[noreturn]] call does not trip unreachable-code warnings.
    void (*volatile fatal)(const char*, const char*, int) = &fatal_write_attempt;
    CHECK_THROWS_AS(fatal(nullptr, nullptr, 0), ReadOnlyViolation);
    CHECK_THROWS_AS(fatal("x", "f", 1), std::logic_error);
}

TEST_CASE("GuardedDevice counts reads and verifies content", "[readonly]") {
    auto data = test::patterned_bytes(100000);
    auto mem = std::make_shared<test::MemoryDevice>(data);
    GuardedDevice g(mem);
    std::vector<uint8_t> buf(10);
    REQUIRE(g.read(0, buf.data(), buf.size()).has_value());
    REQUIRE(g.read(5, buf.data(), buf.size()).has_value());
    CHECK(g.read_count() == 2);
    CHECK(g.bytes_written() == 0);
    const std::string h = sha256_hex(data);
    CHECK_NOTHROW(g.assert_untouched(h));
    CHECK_THROWS_AS(g.assert_untouched("deadbeef"), ReadOnlyViolation);
    CHECK_THROWS_AS(GuardedDevice(nullptr), std::invalid_argument);
}

TEST_CASE("wrap_standard always applies the guard", "[readonly]") {
    auto mem = std::make_shared<test::MemoryDevice>(test::patterned_bytes(4096));
    OpenOptions no_cache;
    no_cache.cache_bytes = 0;
    for (const OpenOptions& o : {OpenOptions{}, no_cache}) {
        auto dev = wrap_standard(mem, o);
        CHECK(dynamic_cast<GuardedDevice*>(dev.get()) != nullptr);
        CHECK(dev->info().size_bytes == 4096);
    }
}

TEST_CASE("OutputSink rejects an output directory containing the source image", "[readonly][sink]") {
    TempDir tmp;
    fs::create_directories(tmp.path() / "evidence");
    const fs::path image = tmp.path() / "evidence" / "disk.img";
    test::create_test_file(image, test::patterned_bytes(4096));
    const size_t entries_before = count_entries(tmp.path());
    const auto src = SourceIdentity::image(image);

    for (const fs::path& out : {tmp.path() / "evidence", tmp.path(), tmp.path() / "evidence" / ".",
                                tmp.path() / "evidence" / ".." / "evidence"}) {
        INFO(out.string());
        auto sink = OutputSink::open(out, src);
        REQUIRE_FALSE(sink.has_value());
        CHECK(sink.error().code == ErrorCode::OutputOnSourceDevice);
    }
    // A relative image path is resolved against the working directory before comparison.
    const fs::path old_cwd = fs::current_path();
    fs::current_path(tmp.path() / "evidence");
    auto sink_rel = OutputSink::open(tmp.path(), SourceIdentity::image("disk.img"));
    fs::current_path(old_cwd);
    REQUIRE_FALSE(sink_rel.has_value());
    CHECK(sink_rel.error().code == ErrorCode::OutputOnSourceDevice);

    CHECK(count_entries(tmp.path()) == entries_before);

    auto ok = OutputSink::open(tmp.path() / "recovered", src);
    REQUIRE(ok.has_value());
    CHECK(fs::is_directory(tmp.path() / "recovered"));
}

TEST_CASE("OutputSink refuses a physical-drive source on the same disk before creating anything", "[readonly][sink]") {
#if defined(_WIN32)
    TempDir tmp;
    auto api = std::make_shared<test::FakeWin32Api>();
    const fs::path out = tmp.path() / "new" / "out";

    api->disk_number_for_path = 3;
    auto same = OutputSink::open(out, SourceIdentity::physical_drive(3), api);
    REQUIRE_FALSE(same.has_value());
    CHECK(same.error().code == ErrorCode::OutputOnSourceDevice);
    CHECK_FALSE(fs::exists(tmp.path() / "new"));
    REQUIRE(api->disk_number_queries.size() == 1);

    api->disk_number_for_path = std::nullopt;
    auto unknown = OutputSink::open(out, SourceIdentity::physical_drive(3), api);
    REQUIRE_FALSE(unknown.has_value());
    CHECK(unknown.error().code == ErrorCode::OutputOnSourceDevice);
    CHECK_FALSE(fs::exists(tmp.path() / "new"));

    api->disk_number_for_path = 0;
    auto other = OutputSink::open(out, SourceIdentity::physical_drive(3), api);
    REQUIRE(other.has_value());
    CHECK(fs::is_directory(out));
#else
    TempDir tmp;
    auto r = OutputSink::open(tmp.path() / "out", SourceIdentity::physical_drive(3));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == ErrorCode::Unsupported);
#endif
}

TEST_CASE("SourceIdentity classification", "[sink]") {
    auto d = SourceIdentity::from_source_string("\\\\.\\PhysicalDrive12");
    CHECK(d.kind == SourceIdentity::Kind::WindowsPhysicalDrive);
    CHECK(d.drive_number == 12);
    auto i = SourceIdentity::from_source_string("disk.img");
    CHECK(i.kind == SourceIdentity::Kind::ImageFile);
}

TEST_CASE("OutputSink contains path traversal inside the root", "[readonly][sink]") {
    TempDir tmp;
    auto sink = OutputSink::open(tmp.path() / "out", SourceIdentity{});
    REQUIRE(sink.has_value());
    const fs::path root = (*sink)->root();

    for (const char* evil : {"../escape.txt", "../../escape.txt", "a/../../escape.txt", "/etc/escape.txt",
                             "..\\..\\escape.txt", "C:/escape.txt", "./../escape.txt", "a/./b/../../../escape.txt"}) {
        INFO(evil);
        MemoryByteSource src(std::string_view("payload"));
        auto w = (*sink)->write_file(evil, src);
        REQUIRE(w.has_value());
        CHECK(path_is_within(w->path, root));
        for (const auto& comp : fs::path(w->relative)) {
            CHECK(comp != "..");
            CHECK(comp != ".");
        }
    }
    CHECK_FALSE(fs::exists(tmp.path() / "escape.txt"));
    CHECK_FALSE(fs::exists(tmp.path().parent_path() / "escape.txt"));
    CHECK_FALSE(fs::exists(fs::path("/etc/escape.txt")));

    auto parts = OutputSink::sanitize_relative("a//b/../c:d/CON");
    CHECK(parts == std::vector<std::string>{"a", "b", "_", "c_d", "_CON"});

    MemoryByteSource empty_src(std::string_view("x"));
    auto bad = (*sink)->write_file("///", empty_src);
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().code == ErrorCode::InvalidArgument);
}

TEST_CASE("OutputSink refuses to follow a symlink out of the root", "[readonly][sink]") {
    TempDir tmp;
    fs::create_directories(tmp.path() / "outside");
    auto sink = OutputSink::open(tmp.path() / "out", SourceIdentity{});
    REQUIRE(sink.has_value());
    std::error_code ec;
    fs::create_directory_symlink(tmp.path() / "outside", (*sink)->root() / "link", ec);
    if (ec) SKIP("cannot create directory symlinks here: " << ec.message());
    MemoryByteSource src(std::string_view("payload"));
    auto w = (*sink)->write_file("link/x.txt", src);
    REQUIRE_FALSE(w.has_value());
    CHECK(w.error().code == ErrorCode::PolicyViolation);
    CHECK(fs::is_empty(tmp.path() / "outside"));
}

TEST_CASE("OutputSink never overwrites", "[readonly][sink]") {
    TempDir tmp;
    auto sink = OutputSink::open(tmp.path() / "out", SourceIdentity{});
    REQUIRE(sink.has_value());
    const fs::path root = (*sink)->root();

    MemoryByteSource a(std::string_view("first"));
    MemoryByteSource b(std::string_view("second"));
    MemoryByteSource c(std::string_view("third"));
    auto w1 = (*sink)->write_file("docs/a.txt", a);
    auto w2 = (*sink)->write_file("docs/a.txt", b);
    auto w3 = (*sink)->write_file("docs/a.txt", c);
    REQUIRE(w1.has_value());
    REQUIRE(w2.has_value());
    REQUIRE(w3.has_value());
    CHECK(w1->relative == "docs/a.txt");
    CHECK(w2->relative == "docs/a (1).txt");
    CHECK(w3->relative == "docs/a (2).txt");
    CHECK(test::load_test_file(root / "docs" / "a.txt") == bytes_of("first"));
    CHECK(test::load_test_file(root / "docs" / "a (1).txt") == bytes_of("second"));
    CHECK(test::load_test_file(root / "docs" / "a (2).txt") == bytes_of("third"));

    SECTION("files created by someone else are preserved") {
        test::create_test_file(root / "keep.bin", bytes_of("original"));
        MemoryByteSource d(std::string_view("new"));
        auto w = (*sink)->write_file("keep.bin", d);
        REQUIRE(w.has_value());
        CHECK(w->relative == "keep (1).bin");
        CHECK(test::load_test_file(root / "keep.bin") == bytes_of("original"));
    }
    SECTION("names without extension and dotfiles") {
        MemoryByteSource d1(std::string_view("1")), d2(std::string_view("2")), d3(std::string_view("3")),
            d4(std::string_view("4"));
        CHECK((*sink)->write_file("README", d1)->relative == "README");
        CHECK((*sink)->write_file("README", d2)->relative == "README (1)");
        CHECK((*sink)->write_file(".profile", d3)->relative == ".profile");
        CHECK((*sink)->write_file(".profile", d4)->relative == ".profile (1)");
    }
    CHECK_FALSE(has_temp_files(root));
}

TEST_CASE("OutputSink hashes content, sets mtime, and cleans up on failure", "[sink]") {
    TempDir tmp;
    auto sink = OutputSink::open(tmp.path() / "out", SourceIdentity{});
    REQUIRE(sink.has_value());

    auto data = test::patterned_bytes(3 * 1024 * 1024 + 17, 4);
    MemoryByteSource src(data);
    const int64_t mtime = 1700000000;
    auto w = (*sink)->write_file("big/file.bin", src, mtime);
    REQUIRE(w.has_value());
    CHECK(w->size == data.size());
    CHECK(w->sha256 == sha256_hex(data));
    CHECK(test::sha256_of_file(w->path) == w->sha256);
    auto ft = fs::last_write_time(w->path);
#if defined(_MSC_VER)
    auto sys_tp = std::chrono::clock_cast<std::chrono::system_clock>(ft);
#else
    auto sys_tp = std::chrono::file_clock::to_sys(ft);
#endif
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(sys_tp.time_since_epoch()).count();
    CHECK(secs == mtime);

    FailingSource bad;
    auto f = (*sink)->write_file("broken.bin", bad);
    REQUIRE_FALSE(f.has_value());
    CHECK(f.error().code == ErrorCode::IoError);
    CHECK_FALSE(fs::exists((*sink)->root() / "broken.bin"));
    CHECK_FALSE(has_temp_files((*sink)->root()));

    MemoryByteSource zero(std::string_view(""));
    auto z = (*sink)->write_file("empty.dat", zero);
    REQUIRE(z.has_value());
    CHECK(z->size == 0);
    CHECK(fs::file_size(z->path) == 0);
}

TEST_CASE("OutputSink unicode names round-trip", "[sink]") {
    TempDir tmp;
    auto sink = OutputSink::open(tmp.path() / "out", SourceIdentity{});
    REQUIRE(sink.has_value());
    MemoryByteSource src(std::string_view("u"));
    auto w = (*sink)->write_file("\xE6\x97\xA5\xE6\x9C\xAC/caf\xC3\xA9.txt", src);
    REQUIRE(w.has_value());
    CHECK(w->relative == "\xE6\x97\xA5\xE6\x9C\xAC/caf\xC3\xA9.txt");
    CHECK(fs::exists(w->path));
}

TEST_CASE("path_is_within", "[sink]") {
    CHECK(path_is_within(fs::path("/a/b/c"), fs::path("/a/b")));
    CHECK(path_is_within(fs::path("/a/b"), fs::path("/a/b")));
    CHECK(path_is_within(fs::path("/a/b"), fs::path("/a/b/")));
    CHECK_FALSE(path_is_within(fs::path("/a/bc"), fs::path("/a/b")));
    CHECK_FALSE(path_is_within(fs::path("/a"), fs::path("/a/b")));
    CHECK_FALSE(path_is_within(fs::path("/a/b/../c"), fs::path("/a/b")));
}
