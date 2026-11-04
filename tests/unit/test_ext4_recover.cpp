#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "golden_files.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/ext4/ext4_scanner.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/partition/partition_scanner.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using nlohmann::json;
namespace fsys = openrecover::fs;
namespace stdfs = std::filesystem;

stdfs::path fixture_image(const char* name) {
    return stdfs::path(OPENRECOVER_FIXTURE_DIR) / name;
}

void require_fixtures() {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("ext4 fixture images were not generated (Python3 unavailable)");
    if (!stdfs::exists(fixture_image("ext4_basic.img")))
        SKIP("ext4 fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
}

json load_golden(const char* name) {
    const stdfs::path path = stdfs::path(OPENRECOVER_GOLDEN_DIR) / name;
    if (!stdfs::exists(path)) SKIP("golden file is missing: " << path.string());
    const auto bytes = test::load_test_file(path);
    return json::parse(bytes.begin(), bytes.end());
}

struct Opened {
    std::shared_ptr<io::BlockDevice> dev;
    std::unique_ptr<fsys::Ext4Scanner> scanner;
    std::vector<RecoveredFile> files;
};

Opened open_case(const char* image) {
    Opened o;
    auto device = io::open_image(fixture_image(image), io::OpenOptions{});
    REQUIRE(device.has_value());
    o.dev = std::shared_ptr<io::BlockDevice>(std::move(*device));
    auto scanner = fsys::Ext4Scanner::open(o.dev);
    REQUIRE(scanner.has_value());
    o.scanner = std::move(*scanner);
    auto files = o.scanner->scan_deleted(fsys::ScanOptions{}, nullptr);
    REQUIRE(files.has_value());
    o.files = std::move(*files);
    return o;
}

std::vector<std::string> sorted_flags(uint32_t flags) {
    auto out = flag_names(flags);
    std::sort(out.begin(), out.end());
    return out;
}

// One golden document against one image: the geometry the builder claims, the exact set of
// files the scan must return, and the bytes each of them must read back as.
void check_against_golden(const char* image, const json& golden) {
    REQUIRE(golden.at("image").get<std::string>() + ".img" == std::string(image) + ".img");
    const auto bytes = test::load_test_file(fixture_image(image));
    REQUIRE(bytes.size() == golden.at("volume_bytes").get<uint64_t>());
    CHECK(sha256_hex(std::span<const uint8_t>(bytes.data(), bytes.size())) ==
          golden.at("image_sha256").get<std::string>());

    Opened o = open_case(image);
    const json& geo = golden.at("geometry");
    CHECK(o.scanner->geometry().bytes_per_cluster == geo.at("block_size").get<uint32_t>());
    CHECK(o.scanner->geometry().total_clusters == geo.at("blocks_count").get<uint64_t>());
    CHECK(o.scanner->super().group_count() == geo.at("groups").get<uint64_t>());
    CHECK(o.scanner->super().inode_size == geo.at("inode_size").get<uint32_t>());
    CHECK(o.scanner->super().super_csum_valid);
    CHECK(o.scanner->super().inode_csum_verifiable());

    const json& expected = golden.at("deleted");
    // A scan that found one file the golden does not mention is as wrong as one that missed
    // it, so the sizes are compared before the contents.
    REQUIRE(o.files.size() == expected.size());
    for (const json& entry : expected) {
        const std::string path = entry.at("path").get<std::string>();
        const RecoveredFile* file = test::find_file(o.files, path);
        REQUIRE(file != nullptr);
        std::string shape = "flags [";
        for (const std::string& flag : sorted_flags(file->flags)) shape += flag + " ";
        shape += "], extents [";
        for (const Extent& extent : file->extents)
            shape += extent.sparse ? "hole:" + std::to_string(extent.length_bytes) + " "
                                   : std::to_string(extent.offset_bytes) + "+" +
                                         std::to_string(extent.length_bytes) + " ";
        shape += "], note '";
        shape += file->note;
        shape += "'";
        INFO(shape);
        CHECK(file->name == entry.at("name").get<std::string>());
        CHECK(file->size_bytes == entry.at("size_bytes").get<uint64_t>());
        CHECK(std::string(confidence_name(file->confidence)) ==
              entry.at("confidence").get<std::string>());
        CHECK(sorted_flags(file->flags) == entry.at("flags").get<std::vector<std::string>>());
        CHECK(file->deleted_unix == entry.at("deleted_unix").get<int64_t>());
        CHECK(file->mtime_unix == entry.at("mtime_unix").get<int64_t>());
        for (const json& needle : entry.at("note_contains")) {
            const std::string text = needle.get<std::string>();
            CHECK(file->note.find(text) != std::string::npos);
        }
        // Every extent has to stay inside the volume, or the reader would seek past it.
        for (const Extent& extent : file->extents) {
            if (extent.sparse) continue;
            CHECK(extent.offset_bytes + extent.length_bytes <= bytes.size());
        }
        if (entry.at("sha256").is_null()) {
            // Content this build refuses to hand back: an encrypted file's bytes are not
            // its plaintext, and saying so beats returning them.
            std::vector<uint8_t> sink(static_cast<size_t>(file->size_bytes));
            auto got = o.scanner->read_file(*file, 0, sink.data(), sink.size());
            CHECK_FALSE(got.has_value());
            if (!got) CHECK(got.error().code == ErrorCode::Unsupported);
        } else {
            const auto data = test::read_all(*o.scanner, *file);
            CHECK(sha256_hex(std::span<const uint8_t>(data.data(), data.size())) ==
                  entry.at("sha256").get<std::string>());
        }
    }

    for (const json& path : golden.at("absent"))
        CHECK(test::find_file(o.files, path.get<std::string>()) == nullptr);

    // The live files are still on the volume -- the scan left them out because they are not
    // deleted, not because their bytes went missing.
    for (const json& entry : golden.at("live")) {
        std::vector<uint8_t> data(entry.at("size_bytes").get<uint64_t>());
        auto got = io::read_fully(*o.dev, entry.at("offset_bytes").get<uint64_t>(), data.data(),
                                  data.size());
        REQUIRE(got.has_value());
        CHECK(sha256_hex(std::span<const uint8_t>(data.data(), data.size())) ==
              entry.at("sha256").get<std::string>());
    }
}

}  // namespace

TEST_CASE("ext4 fixture image recovers exactly the files its golden lists",
          "[ext4][fixtures]") {
    require_fixtures();
    SECTION("basic volume: deleted blocks are still free") {
        check_against_golden("ext4_basic.img", load_golden("ext4_basic.golden.json"));
    }
    SECTION("reused volume: every deleted file's blocks were taken again") {
        check_against_golden("ext4_reused.img", load_golden("ext4_reused.golden.json"));
    }
}

TEST_CASE("ext4 fixture opens through the filesystem seam", "[ext4][fixtures]") {
    require_fixtures();
    auto device = io::open_image(fixture_image("ext4_basic.img"), io::OpenOptions{});
    REQUIRE(device.has_value());
    std::shared_ptr<io::BlockDevice> shared(std::move(*device));
    auto scanner = fsys::detect_and_open(shared);
    REQUIRE(scanner.has_value());
    CHECK((*scanner)->kind() == fsys::FsKind::Ext4);
    CHECK((*scanner)->geometry().bytes_per_cluster == 1024);

    // The allocation map the reuse check runs on describes both block groups.
    auto map = (*scanner)->allocation_map();
    REQUIRE(map.has_value());
    CHECK((*map)->is_cluster_allocated(20));       // a live file's block
    CHECK_FALSE((*map)->is_cluster_allocated(22));  // a deleted file's, still free
    CHECK((*map)->cluster_count() == 256);
}

TEST_CASE("a bare ext4 volume is listed as a superfloppy", "[ext4][partition]") {
    require_fixtures();
    auto device = io::open_image(fixture_image("ext4_basic.img"), io::OpenOptions{});
    REQUIRE(device.has_value());
    auto partitions = partition::scan_partitions(**device);
    REQUIRE(partitions.has_value());
    REQUIRE(partitions->size() == 1);
    CHECK(partitions->front().scheme == partition::PartitionScheme::Superfloppy);
    CHECK(partitions->front().start_byte == 0);
    CHECK(partitions->front().length_byte == device->get()->info().size_bytes);
}
