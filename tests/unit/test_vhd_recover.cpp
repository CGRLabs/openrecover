#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "golden_files.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using nlohmann::json;
namespace fsys = openrecover::fs;
namespace io = openrecover::io;

constexpr uint64_t kVolumeBytes = 8u << 20;

std::filesystem::path fixture_image(const char* name) {
    return std::filesystem::path(OPENRECOVER_FIXTURE_DIR) / name;
}

void require_fixtures() {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("VHD fixture images were not generated (Python3 unavailable)");
    if (!std::filesystem::exists(fixture_image("fat32_vhd_fixed.img")))
        SKIP("VHD fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
}

json load_golden(const char* name) {
    const std::filesystem::path path = std::filesystem::path(OPENRECOVER_GOLDEN_DIR) / name;
    if (!std::filesystem::exists(path)) SKIP("golden file is missing: " << path.string());
    const auto bytes = test::load_test_file(path);
    return json::parse(bytes.begin(), bytes.end());
}

std::shared_ptr<io::BlockDevice> open_fixture(const std::filesystem::path& path) {
    auto device = io::open_image(path, io::OpenOptions{});
    REQUIRE(device.has_value());
    return std::shared_ptr<io::BlockDevice>(std::move(*device));
}

// Reads the whole device in fixed chunks; used to compare a container with the flat image.
std::string device_sha256(io::BlockDevice& dev) {
    Sha256Hasher hasher;
    std::vector<uint8_t> buf(64u << 10);
    uint64_t offset = 0;
    while (offset < dev.info().size_bytes) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<uint64_t>(buf.size(), dev.info().size_bytes - offset));
        auto got = dev.read(offset, buf.data(), want);
        REQUIRE(got.has_value());
        REQUIRE(got->bytes_read == want);
        hasher.update(buf.data(), want);
        offset += want;
    }
    return hasher.finish_hex();
}

struct RecoveryThroughContainer {
    RecoveryThroughContainer(const char* image, const char* golden, const char* flavour)
        : before(test::sha256_of_file(fixture_image(image))) {
        CHECK(before == load_golden(golden).at("image_sha256").get<std::string>());
        device = open_fixture(fixture_image(image));
        INFO("container: " << flavour);
        REQUIRE(device->info().size_bytes == kVolumeBytes);
        CHECK(device->info().description.find(flavour) != std::string::npos);
        auto opened = fsys::detect_and_open(device);
        REQUIRE(opened.has_value());
        CHECK((*opened)->kind() == fsys::FsKind::Fat32);
        files = (*opened)->scan_deleted(fsys::ScanOptions{}, {});
        REQUIRE(files.has_value());
        scanner = std::move(*opened);
    }

    std::string before;
    std::shared_ptr<io::BlockDevice> device;
    std::unique_ptr<fsys::IFileSystemScanner> scanner;
    Result<std::vector<RecoveredFile>> files{std::vector<RecoveredFile>{}};
};

}  // namespace

TEST_CASE("A fixed VHD presents the same volume as the flat image", "[M1][vhd][fixture]") {
    require_fixtures();
    auto flat = open_fixture(fixture_image("fat32_basic.img"));
    auto vhd = open_fixture(fixture_image("fat32_vhd_fixed.img"));
    REQUIRE(flat->info().size_bytes == kVolumeBytes);
    REQUIRE(vhd->info().size_bytes == kVolumeBytes);
    CHECK(device_sha256(*flat) == device_sha256(*vhd));
}

TEST_CASE("A dynamic VHD presents the same volume as the flat image", "[M1][vhd][fixture]") {
    require_fixtures();
    auto flat = open_fixture(fixture_image("fat32_basic.img"));
    auto vhd = open_fixture(fixture_image("fat32_vhd_dynamic.img"));
    // The dynamic container is mostly unallocated but must still expose the full virtual size.
    REQUIRE(vhd->info().size_bytes == kVolumeBytes);
    CHECK(device_sha256(*flat) == device_sha256(*vhd));
    const std::string digest = test::sha256_of_file(fixture_image("fat32_vhd_dynamic.img"));
    CHECK(digest == load_golden("fat32_vhd_dynamic.golden.json").at("image_sha256").get<std::string>());
}

TEST_CASE("FAT32 recovery through a fixed VHD matches the flat golden", "[M1][vhd][fixture]") {
    require_fixtures();
    RecoveryThroughContainer run("fat32_vhd_fixed.img", "fat32_vhd_fixed.golden.json", "vhd fixed");
    const json golden = load_golden("fat32_vhd_fixed.golden.json");
    CHECK(test::actual_files_json(*run.files) == golden.at("files"));
    REQUIRE(run.files->size() == 9);

    const json& hashes = golden.at("hashes");
    for (const RecoveredFile& file : *run.files) {
        INFO("path: " << file.path);
        const auto expected = hashes.find(file.path);
        REQUIRE(expected != hashes.end());
        CHECK(sha256_hex(test::read_all(*run.scanner, file)) == expected.value().get<std::string>());
    }
    CHECK(run.before == test::sha256_of_file(fixture_image("fat32_vhd_fixed.img")));
}

TEST_CASE("FAT32 recovery through a dynamic VHD matches the flat golden", "[M1][vhd][fixture]") {
    require_fixtures();
    RecoveryThroughContainer run("fat32_vhd_dynamic.img", "fat32_vhd_dynamic.golden.json", "vhd dynamic");
    const json golden = load_golden("fat32_vhd_dynamic.golden.json");
    CHECK(test::actual_files_json(*run.files) == golden.at("files"));
    REQUIRE(run.files->size() == 9);

    const json& hashes = golden.at("hashes");
    for (const RecoveredFile& file : *run.files) {
        INFO("path: " << file.path);
        const auto expected = hashes.find(file.path);
        REQUIRE(expected != hashes.end());
        CHECK(sha256_hex(test::read_all(*run.scanner, file)) == expected.value().get<std::string>());
    }
    CHECK(run.before == test::sha256_of_file(fixture_image("fat32_vhd_dynamic.img")));
}
