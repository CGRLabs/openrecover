#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "fake_win32_api.hpp"
#include "openrecover/io/readonly_guard.hpp"
#include "openrecover/io/win_physical_device.hpp"
#include "test_util.hpp"

using namespace openrecover;
using namespace openrecover::io;
using openrecover::test::FakeWin32Api;

namespace {

// Access-right bits that must never be requested. Values from the Windows SDK:
// "GENERIC_WRITE" 0x40000000, "GENERIC_ALL" 0x10000000, "FILE_WRITE_DATA" 0x0002, "FILE_APPEND_DATA" 0x0004,
// "DELETE" 0x00010000, "WRITE_DAC" 0x00040000, "WRITE_OWNER" 0x00080000, "GENERIC_EXECUTE" 0x20000000.
constexpr uint32_t kForbiddenAccessBits =
    0x40000000u | 0x10000000u | 0x0002u | 0x0004u | 0x00010000u | 0x00040000u | 0x00080000u | 0x20000000u;
// CREATE_NEW 1, CREATE_ALWAYS 2, OPEN_ALWAYS 4, TRUNCATE_EXISTING 5.
constexpr uint32_t kForbiddenDispositions[] = {1u, 2u, 4u, 5u};
// IOCTL_DISK_SET_DRIVE_LAYOUT_EX and FSCTL_LOCK_VOLUME (plus other destructive codes).
constexpr uint32_t kIoctlDiskSetDriveLayoutEx = 0x0007C054u;
constexpr uint32_t kFsctlLockVolume = 0x00090018u;
constexpr uint32_t kFsctlDismountVolume = 0x00090020u;
constexpr uint32_t kIoctlDiskFormatTracks = 0x0007C018u;
constexpr uint32_t kIoctlStorageEjectMedia = 0x002D4808u;

const std::string kDrive1 = "\\\\.\\PhysicalDrive1";

std::shared_ptr<FakeWin32Api> make_fake(size_t disk_size = 64 * 1024, uint32_t sector = 512) {
    auto f = std::make_shared<FakeWin32Api>();
    f->disk = test::patterned_bytes(disk_size, 21);
    f->sector_size = sector;
    f->physical_sector_size = std::max<uint32_t>(sector, 4096);
    f->device_number = 1;
    return f;
}

void check_read_only_create(const FakeWin32Api::CreateCall& c, uint32_t expected_share) {
    CHECK(c.access == win::kGenericRead);
    CHECK(c.access == 0x80000000u);
    CHECK((c.access & kForbiddenAccessBits) == 0);
    CHECK(c.share == expected_share);
    CHECK(c.disposition == win::kOpenExisting);
    CHECK(c.disposition == 3u);
    for (uint32_t d : kForbiddenDispositions) CHECK(c.disposition != d);
    CHECK(c.flags == (win::kFileAttributeNormal | win::kFileFlagRandomAccess));
}

std::vector<uint8_t> read_all(BlockDevice& dev, uint64_t off, size_t len, ReadResult& rr) {
    std::vector<uint8_t> buf(len, 0xCC);
    auto r = dev.read(off, buf.data(), len);
    REQUIRE(r.has_value());
    rr = *r;
    buf.resize(r->bytes_read);
    return buf;
}

}  // namespace

TEST_CASE("CreateFileW receives exactly the read-only arguments", "[win32]") {
    auto api = make_fake();
    auto dev = open_win_device(kDrive1, OpenOptions{}, api);
    REQUIRE(dev.has_value());
    REQUIRE(api->creates.size() == 1);
    check_read_only_create(api->creates[0], win::kFileShareRead);
    CHECK(api->creates[0].share == 0x00000001u);
    CHECK(api->creates[0].path == L"\\\\.\\PhysicalDrive1");
    CHECK_FALSE((*dev)->info().shared_write_fallback);
    CHECK_FALSE((*dev)->info().is_image);
}

TEST_CASE("geometry is queried only through allowlisted control codes", "[win32]") {
    auto api = make_fake(1u << 20, 4096);
    auto dev = open_win_device(kDrive1, OpenOptions{}, api);
    REQUIRE(dev.has_value());
    const auto& info = (*dev)->info();
    CHECK(info.size_bytes == 1u << 20);
    CHECK(info.logical_sector_size == 4096);
    CHECK(info.physical_sector_size == 4096);
    CHECK(info.description == kDrive1);
    REQUIRE_FALSE(api->ioctls.empty());
    for (const auto& c : api->ioctls) {
        bool allowed = std::find(std::begin(win::kAllowedIoctls), std::end(win::kAllowedIoctls), c.code) !=
                       std::end(win::kAllowedIoctls);
        CHECK(allowed);
    }
    auto api512 = make_fake(1u << 20, 512);
    auto dev512 = open_win_device(kDrive1, OpenOptions{}, api512);
    REQUIRE(dev512.has_value());
    CHECK((*dev512)->info().logical_sector_size == 512);
    CHECK((*dev512)->info().physical_sector_size == 4096);
}

TEST_CASE("length falls back to geometry DiskSize; both failing is an IoError", "[win32]") {
    auto api = make_fake(1u << 20);
    api->length_ok = false;
    auto dev = open_win_device(kDrive1, OpenOptions{}, api);
    REQUIRE(dev.has_value());
    CHECK((*dev)->info().size_bytes == 1u << 20);

    auto api2 = make_fake(1u << 20);
    api2->length_ok = false;
    api2->geometry_ok = false;
    auto dev2 = open_win_device(kDrive1, OpenOptions{}, api2);
    REQUIRE_FALSE(dev2.has_value());
    CHECK(dev2.error().code == ErrorCode::IoError);
    CHECK(api2->close_calls == 1);
}

TEST_CASE("device-number mismatch and non-disk handles are rejected", "[win32]") {
    auto api = make_fake();
    api->device_number = 2;
    auto dev = open_win_device(kDrive1, OpenOptions{}, api);
    REQUIRE_FALSE(dev.has_value());
    CHECK(dev.error().code == ErrorCode::IoError);
    CHECK(api->close_calls == 1);

    auto api2 = make_fake();
    api2->file_type = 2;  // FILE_TYPE_CHAR
    auto dev2 = open_win_device(kDrive1, OpenOptions{}, api2);
    REQUIRE_FALSE(dev2.has_value());
    CHECK(dev2.error().code == ErrorCode::Unsupported);
    CHECK(api2->close_calls == 1);
}

TEST_CASE("physical drive path validation", "[win32][path]") {
    for (const char* bad : {"\\\\.\\PhysicalDrive", "\\\\.\\PhysicalDrive1x", "C:\\foo", "\\\\.\\PHYSICALDRIVE0\\..\\",
                            "\\\\.\\PHYSICALDRIVE0", "\\\\.\\PhysicalDrive1234", "\\\\.\\PhysicalDrive-1",
                            "\\\\.\\PhysicalDrive 1", "\\\\?\\PhysicalDrive0", "\\\\.\\PhysicalDrive0\\", "",
                            "/dev/sda", "\\\\.\\PhysicalDrive0\\..\\C:"}) {
        INFO(bad);
        CHECK_FALSE(is_valid_physical_drive_path(bad));
        auto api = make_fake();
        auto r = open_win_device(bad, OpenOptions{}, api);
        CHECK_FALSE(r.has_value());
        CHECK(api->creates.empty());
    }
    for (const char* good : {"\\\\.\\PhysicalDrive0", "\\\\.\\PhysicalDrive7", "\\\\.\\PhysicalDrive999"})
        CHECK(is_valid_physical_drive_path(good));

    CHECK(is_valid_volume_path("\\\\.\\C:"));
    CHECK(is_valid_volume_path("\\\\.\\z:"));
    CHECK_FALSE(is_valid_volume_path("\\\\.\\C:\\"));
    CHECK_FALSE(is_valid_volume_path("\\\\.\\CD:"));
    CHECK_FALSE(is_valid_volume_path("\\\\.\\1:"));
    CHECK_FALSE(is_valid_volume_path("C:"));
}

TEST_CASE("volume paths use the identical read-only flags", "[win32]") {
    auto api = make_fake();
    auto dev = open_win_device("\\\\.\\E:", OpenOptions{}, api);
    REQUIRE(dev.has_value());
    REQUIRE(api->creates.size() == 1);
    check_read_only_create(api->creates[0], win::kFileShareRead);
    for (const auto& c : api->ioctls) CHECK(c.code != win::kIoctlStorageGetDeviceNumber);
}

TEST_CASE("ERROR_SHARING_VIOLATION maps to DeviceBusy with no retry by default", "[win32][share]") {
    auto api = make_fake();
    api->open_errors = {win::kErrorSharingViolation};
    auto dev = open_win_device(kDrive1, OpenOptions{}, api);
    REQUIRE_FALSE(dev.has_value());
    CHECK(dev.error().code == ErrorCode::DeviceBusy);
    CHECK(dev.error().message.find("Offline") != std::string::npos);
    CHECK(api->creates.size() == 1);
}

TEST_CASE("allow_shared_write_sharing retries exactly once, still GENERIC_READ", "[win32][share]") {
    OpenOptions opts;
    opts.allow_shared_write_sharing = true;

    SECTION("retry succeeds") {
        auto api = make_fake();
        api->open_errors = {win::kErrorSharingViolation};
        auto dev = open_win_device(kDrive1, opts, api);
        REQUIRE(dev.has_value());
        REQUIRE(api->creates.size() == 2);
        check_read_only_create(api->creates[0], win::kFileShareRead);
        check_read_only_create(api->creates[1], win::kFileShareRead | win::kFileShareWrite);
        CHECK(api->creates[1].share == 0x00000003u);
        CHECK((*dev)->info().shared_write_fallback);
    }
    SECTION("retry fails: no further attempts") {
        auto api = make_fake();
        api->open_errors = {win::kErrorSharingViolation, win::kErrorSharingViolation, win::kErrorSharingViolation};
        auto dev = open_win_device(kDrive1, opts, api);
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::DeviceBusy);
        CHECK(api->creates.size() == 2);
    }
    SECTION("other errors are not retried") {
        auto api = make_fake();
        api->open_errors = {win::kErrorAccessDenied};
        auto dev = open_win_device(kDrive1, opts, api);
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == ErrorCode::PermissionDenied);
        CHECK(api->creates.size() == 1);
    }
}

TEST_CASE("open error mapping", "[win32]") {
    struct Case {
        uint32_t win_error;
        ErrorCode expected;
    };
    for (Case c : {Case{win::kErrorAccessDenied, ErrorCode::PermissionDenied},
                   Case{win::kErrorFileNotFound, ErrorCode::NotFound}, Case{win::kErrorPathNotFound, ErrorCode::NotFound},
                   Case{win::kErrorSharingViolation, ErrorCode::DeviceBusy}, Case{87u, ErrorCode::IoError}}) {
        auto api = make_fake();
        api->open_errors = {c.win_error};
        auto dev = open_win_device(kDrive1, OpenOptions{}, api);
        REQUIRE_FALSE(dev.has_value());
        CHECK(dev.error().code == c.expected);
        if (c.expected == ErrorCode::PermissionDenied)
            CHECK(dev.error().message.find("Administrator") != std::string::npos);
        if (c.expected == ErrorCode::IoError) {
            CHECK(dev.error().message.find("87") != std::string::npos);
            CHECK(dev.error().message.find("fake error 87") != std::string::npos);
        }
    }
}

TEST_CASE("safe_ioctl rejects every non-allowlisted control code", "[win32][ioctl]") {
    auto api = make_fake();
    uint8_t out[64] = {};
    uint32_t ret = 0;
    for (uint32_t code :
         {kIoctlDiskSetDriveLayoutEx, kFsctlLockVolume, kFsctlDismountVolume, kIoctlDiskFormatTracks,
          kIoctlStorageEjectMedia, 0u, 0xFFFFFFFFu}) {
        INFO(code);
        CHECK_THROWS_AS(win::safe_ioctl(*api, FakeWin32Api::fake_handle(), code, nullptr, 0, out, sizeof out, &ret),
                        ReadOnlyViolation);
    }
    CHECK(api->ioctls.empty());
    for (uint32_t code : win::kAllowedIoctls)
        CHECK_NOTHROW(win::safe_ioctl(*api, FakeWin32Api::fake_handle(), code, nullptr, 0, out, sizeof out, &ret));
    CHECK(api->ioctls.size() == std::size(win::kAllowedIoctls));
}

TEST_CASE("sector-aligned reads return exact bytes for unaligned requests", "[win32][read]") {
    auto api = make_fake(3u << 20);
    auto dev = open_win_device(kDrive1, OpenOptions{}, api);
    REQUIRE(dev.has_value());
    const auto& disk = api->disk;
    ReadResult rr;
    struct R {
        uint64_t off;
        size_t len;
    };
    for (R r : {R{513, 1000}, R{0, 512}, R{1, 1}, R{511, 2}, R{(1u << 20) - 7, 20}, R{100, (2u << 20) + 333},
                R{(3u << 20) - 50, 500}}) {
        auto v = read_all(**dev, r.off, r.len, rr);
        const size_t expect = static_cast<size_t>(std::min<uint64_t>(r.len, disk.size() - r.off));
        REQUIRE(v.size() == expect);
        CHECK(std::equal(v.begin(), v.end(), disk.begin() + static_cast<std::ptrdiff_t>(r.off)));
        CHECK_FALSE(rr.had_bad_sectors);
    }
    read_all(**dev, 3u << 20, 10, rr);
    CHECK(rr.bytes_read == 0);
}

TEST_CASE("bad-sector retry zero-fills and records the sector (ERROR_CRC)", "[win32][read][badsector]") {
    for (uint32_t err : {win::kErrorCrc, win::kErrorSectorNotFound, win::kErrorReadFault, win::kErrorIoDevice}) {
        INFO(err);
        auto api = make_fake(64 * 1024);
        api->bad = {10, 11, 40};
        api->bad_sector_error = err;
        auto dev = open_win_device(kDrive1, OpenOptions{}, api);
        REQUIRE(dev.has_value());
        ReadResult rr;
        auto v = read_all(**dev, 0, 64 * 1024, rr);
        REQUIRE(v.size() == 64 * 1024);
        CHECK(rr.had_bad_sectors);
        for (size_t i = 0; i < v.size(); ++i) {
            const uint64_t sec = i / 512;
            const bool is_bad = sec == 10 || sec == 11 || sec == 40;
            if (is_bad ? v[i] != 0 : v[i] != api->disk[i]) {
                FAIL("byte " << i << " wrong");
            }
        }
        CHECK((*dev)->bad_sectors() == std::vector<uint64_t>{10, 11, 40});

        auto clean = read_all(**dev, 12 * 512, 1000, rr);
        CHECK_FALSE(rr.had_bad_sectors);
        CHECK(std::equal(clean.begin(), clean.end(), api->disk.begin() + 12 * 512));

        auto partial = read_all(**dev, 10 * 512 + 100, 1000, rr);
        CHECK(rr.had_bad_sectors);
        CHECK(std::all_of(partial.begin(), partial.begin() + 924, [](uint8_t b) { return b == 0; }));
        CHECK(std::equal(partial.begin() + 924, partial.end(), api->disk.begin() + 12 * 512));
    }
}

TEST_CASE("other ReadFile errors are IoError without zero-fill", "[win32][read]") {
    auto api = make_fake();
    auto dev = open_win_device(kDrive1, OpenOptions{}, api);
    REQUIRE(dev.has_value());
    api->read_error = 1u;
    std::vector<uint8_t> buf(1000, 0xCC);
    auto r = (*dev)->read(0, buf.data(), buf.size());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == ErrorCode::IoError);
    CHECK((*dev)->bad_sectors().empty());
}

TEST_CASE("image files are opened through the shim with the same read-only flags", "[win32][image]") {
    auto api = make_fake(10000);
    auto dev = open_win_image(L"C:\\evidence\\disk.img", "disk.img", OpenOptions{}, api);
    REQUIRE(dev.has_value());
    REQUIRE(api->creates.size() == 1);
    check_read_only_create(api->creates[0], win::kFileShareRead);
    CHECK((*dev)->info().is_image);
    CHECK((*dev)->info().size_bytes == 10000);
    CHECK(api->ioctls.empty());
    ReadResult rr;
    auto v = read_all(**dev, 9000, 5000, rr);
    CHECK(v.size() == 1000);
    CHECK(std::equal(v.begin(), v.end(), api->disk.begin() + 9000));

    OpenOptions opts;
    opts.sector_size = 4096;
    auto api2 = make_fake(10000);
    auto dev2 = open_win_image(L"x.img", "x.img", opts, api2);
    REQUIRE(dev2.has_value());
    CHECK((*dev2)->info().logical_sector_size == 4096);
    auto v2 = read_all(**dev2, 4000, 6000, rr);
    CHECK(v2.size() == 6000);
    CHECK(std::equal(v2.begin(), v2.end(), api2->disk.begin() + 4000));
}

TEST_CASE("handles are closed exactly once", "[win32]") {
    auto api = make_fake();
    {
        auto dev = open_win_device(kDrive1, OpenOptions{}, api);
        REQUIRE(dev.has_value());
        CHECK(api->close_calls == 0);
    }
    CHECK(api->close_calls == 1);
}
