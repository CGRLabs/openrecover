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
        SKIP("VHDX fixture images were not generated (Python3 unavailable)");
    if (!std::filesystem::exists(fixture_image("fat32_vhdx_full.img")))
        SKIP("VHDX fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
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
    RecoveryThroughContainer(const char* image, const char* golden) {
        before = test::sha256_of_file(fixture_image(image));
        CHECK(before == load_golden(golden).at("image_sha256").get<std::string>());
        device = open_fixture(fixture_image(image));
        REQUIRE(device->info().size_bytes == kVolumeBytes);
        CHECK(device->info().container == "vhdx");
        CHECK(device->info().description.find("vhdx") != std::string::npos);
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

void check_recovery(const char* image, const char* golden_name) {
    RecoveryThroughContainer run(image, golden_name);
    const json golden = load_golden(golden_name);
    CHECK(test::actual_files_json(*run.files) == golden.at("files"));
    REQUIRE(run.files->size() == 9);

    const json& hashes = golden.at("hashes");
    for (const RecoveredFile& file : *run.files) {
        INFO("path: " << file.path);
        const auto expected = hashes.find(file.path);
        REQUIRE(expected != hashes.end());
        CHECK(sha256_hex(test::read_all(*run.scanner, file)) == expected.value().get<std::string>());
    }
    CHECK(run.before == test::sha256_of_file(fixture_image(image)));
}

}  // namespace

TEST_CASE("A fully-present VHDX presents the same volume as the flat image", "[M1][vhdx][fixture]") {
    require_fixtures();
    auto flat = open_fixture(fixture_image("fat32_basic.img"));
    auto vhdx = open_fixture(fixture_image("fat32_vhdx_full.img"));
    REQUIRE(flat->info().size_bytes == kVolumeBytes);
    REQUIRE(vhdx->info().size_bytes == kVolumeBytes);
    CHECK(device_sha256(*flat) == device_sha256(*vhdx));
}

TEST_CASE("A sparse VHDX presents the same volume as the flat image", "[M1][vhdx][fixture]") {
    require_fixtures();
    auto flat = open_fixture(fixture_image("fat32_basic.img"));
    auto vhdx = open_fixture(fixture_image("fat32_vhdx_sparse.img"));
    // Zero blocks and the sectors the bitmap omits must still read as the flat volume's zeros.
    REQUIRE(vhdx->info().size_bytes == kVolumeBytes);
    CHECK(device_sha256(*flat) == device_sha256(*vhdx));
    const std::string digest = test::sha256_of_file(fixture_image("fat32_vhdx_sparse.img"));
    CHECK(digest == load_golden("fat32_vhdx_sparse.golden.json").at("image_sha256").get<std::string>());
}

TEST_CASE("FAT32 recovery through a fully-present VHDX matches the flat golden",
          "[M1][vhdx][fixture]") {
    require_fixtures();
    check_recovery("fat32_vhdx_full.img", "fat32_vhdx_full.golden.json");
}

TEST_CASE("FAT32 recovery through a sparse VHDX matches the flat golden", "[M1][vhdx][fixture]") {
    require_fixtures();
    check_recovery("fat32_vhdx_sparse.img", "fat32_vhdx_sparse.golden.json");
}
