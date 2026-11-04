#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "openrecover/common/hash.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/fat32.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/partition_view.hpp"
#include "openrecover/partition/partition_scanner.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using nlohmann::json;
namespace fsys = openrecover::fs;

constexpr uint64_t kPartitionOffset = 1u << 20;
constexpr uint64_t kVolumeBytes = 8u << 20;

std::filesystem::path fixture_image(const char* name) {
    return std::filesystem::path(OPENRECOVER_FIXTURE_DIR) / name;
}

void require_fixtures() {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("FAT32 fixture images were not generated (Python3 unavailable)");
    if (!std::filesystem::exists(fixture_image("fat32_basic.img")))
        SKIP("FAT32 fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
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

json actual_files_json(const std::vector<RecoveredFile>& files) {
    json out = json::array();
    for (const RecoveredFile& file : files) {
        json extents = json::array();
        for (const Extent& extent : file.extents) {
            extents.push_back({{"offset_bytes", extent.offset_bytes},
                               {"length_bytes", extent.length_bytes},
                               {"sparse", extent.sparse}});
        }
        json item;
        item["path"] = file.path;
        item["name"] = file.name;
        item["size_bytes"] = file.size_bytes;
        item["extents"] = std::move(extents);
        item["confidence"] = confidence_name(file.confidence);
        item["flags"] = flag_names(file.flags);
        item["note"] = file.note;
        item["mtime_unix"] = file.mtime_unix ? json(*file.mtime_unix) : json(nullptr);
        item["ctime_unix"] = file.ctime_unix ? json(*file.ctime_unix) : json(nullptr);
        item["atime_unix"] = file.atime_unix ? json(*file.atime_unix) : json(nullptr);
        item["origin"] = origin_name(file.origin);
        out.push_back(std::move(item));
    }
    std::sort(out.begin(), out.end(), [](const json& a, const json& b) {
        return a.at("path").get<std::string>() < b.at("path").get<std::string>();
    });
    return out;
}

const RecoveredFile* find_file(const std::vector<RecoveredFile>& files, const std::string& path) {
    const auto it = std::find_if(files.begin(), files.end(),
                                 [&](const RecoveredFile& file) { return file.path == path; });
    return it == files.end() ? nullptr : &*it;
}

std::vector<uint8_t> read_all(fsys::IFileSystemScanner& scanner, const RecoveredFile& file) {
    std::vector<uint8_t> data(static_cast<size_t>(file.size_bytes));
    uint64_t offset = 0;
    while (offset < file.size_bytes) {
        const size_t chunk =
            static_cast<size_t>(std::min<uint64_t>(777, file.size_bytes - offset));
        auto got = scanner.read_file(file, offset, data.data() + static_cast<size_t>(offset), chunk);
        REQUIRE(got.has_value());
        REQUIRE(*got == chunk);
        offset += chunk;
    }
    return data;
}

}  // namespace

TEST_CASE("fat32_basic matches the committed golden and preserves the image",
          "[M1][fat32][fixture]") {
    require_fixtures();
    const json golden = load_golden("fat32_basic.golden.json");
    const auto image_path = fixture_image("fat32_basic.img");
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    auto device = open_fixture(image_path);
    auto scanner = fsys::detect_and_open(device);
    REQUIRE(scanner.has_value());
    CHECK((*scanner)->kind() == fsys::FsKind::Fat32);
    CHECK((*scanner)->geometry().bytes_per_cluster == 2048);

    auto files = (*scanner)->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());
    CHECK(actual_files_json(*files) == golden.at("files"));

    const json& hashes = golden.at("hashes");
    size_t verified = 0;
    for (const RecoveredFile& file : *files) {
        if (file.confidence != Confidence::High) continue;
        INFO("path: " << file.path);
        const auto expected = hashes.find(file.path);
        REQUIRE(expected != hashes.end());
        const std::vector<uint8_t> data = read_all(**scanner, file);
        CHECK(sha256_hex(data) == expected.value().get<std::string>());
        ++verified;
    }
    CHECK(verified == files->size());
    CHECK(verified == 9);

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("fat32_reused reports a reallocated file as Low", "[M1][fat32][fixture]") {
    require_fixtures();
    const json golden = load_golden("fat32_reused.golden.json");
    const auto image_path = fixture_image("fat32_reused.img");
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    auto device = open_fixture(image_path);
    auto scanner = fsys::detect_and_open(device);
    REQUIRE(scanner.has_value());
    auto files = (*scanner)->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());
    CHECK(actual_files_json(*files) == golden.at("files"));
    REQUIRE(files->size() == 2);

    const RecoveredFile* reused = find_file(*files, "Reused report.docx");
    REQUIRE(reused != nullptr);
    CHECK(reused->confidence == Confidence::Low);
    CHECK((reused->flags & file_flags::ClustersReallocated) != 0);
    CHECK(reused->extents.size() == 1);

    const RecoveredFile* kept = find_file(*files, "_eep.txt");
    REQUIRE(kept != nullptr);
    CHECK(kept->confidence == Confidence::High);
    CHECK((kept->flags & file_flags::ClustersReallocated) == 0);

    const json& hashes = golden.at("hashes");
    const auto expected = hashes.find(kept->path);
    REQUIRE(expected != hashes.end());
    CHECK(sha256_hex(read_all(**scanner, *kept)) == expected.value().get<std::string>());

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("fat32_basic is found inside MBR and GPT containers", "[M1][fat32][fixture]") {
    require_fixtures();
    const json golden = load_golden("fat32_basic.golden.json");

    for (const char* name : {"fat32_in_mbr.img", "fat32_in_gpt.img"}) {
        INFO("image: " << name);
        const auto image_path = fixture_image(name);
        const std::string before = test::sha256_of_file(image_path);
        auto device = open_fixture(image_path);

        auto partitions = partition::scan_partitions(*device);
        REQUIRE(partitions.has_value());
        REQUIRE(partitions->size() == 1);
        CHECK(partitions->front().start_byte == kPartitionOffset);
        CHECK(partitions->front().length_byte == kVolumeBytes);

        auto view = std::make_shared<io::PartitionView>(
            device, partitions->front().start_byte, partitions->front().length_byte);
        auto scanner = fsys::detect_and_open(view);
        REQUIRE(scanner.has_value());
        auto files = (*scanner)->scan_deleted(fsys::ScanOptions{}, {});
        REQUIRE(files.has_value());
        CHECK(actual_files_json(*files) == golden.at("files"));

        CHECK(before == test::sha256_of_file(image_path));
    }
}
