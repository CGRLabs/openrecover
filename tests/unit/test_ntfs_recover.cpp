#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "openrecover/common/hash.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/fs/ntfs.hpp"
#include "openrecover/fs/ntfs_record.hpp"
#include "openrecover/io/block_device.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using nlohmann::json;
namespace fsys = openrecover::fs;

constexpr uint32_t kBytesPerSector = 512;
constexpr uint32_t kBytesPerCluster = 4096;
constexpr uint64_t kVolumeBytes = 16u << 20;

std::filesystem::path fixture_image(const char* name) {
    return std::filesystem::path(OPENRECOVER_FIXTURE_DIR) / name;
}

void require_fixtures() {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("NTFS fixture images were not generated (Python3 unavailable)");
    if (!std::filesystem::exists(fixture_image("ntfs_basic.img")))
        SKIP("NTFS fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
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
        // The goldens keep flag names in alphabetical order, so the comparison sorts them rather
        // than depending on the order the flag table happens to list.
        std::vector<std::string> names = flag_names(file.flags);
        std::sort(names.begin(), names.end());
        item["flags"] = std::move(names);
        item["note"] = file.note;
        item["mtime_unix"] = file.mtime_unix ? json(*file.mtime_unix) : json(nullptr);
        // Only the files whose deletion time came from recycle-bin metadata carry this.
        if (file.deleted_unix) item["deleted_unix"] = *file.deleted_unix;
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

void check_hashes(fsys::IFileSystemScanner& scanner, const std::vector<RecoveredFile>& files,
                  const json& hashes) {
    size_t verified = 0;
    for (const RecoveredFile& file : files) {
        if (file.confidence == Confidence::Low) continue;
        INFO("path: " << file.path);
        const auto expected = hashes.find(file.path);
        REQUIRE(expected != hashes.end());
        CHECK(sha256_hex(read_all(scanner, file)) == expected.value().get<std::string>());
        ++verified;
    }
    CHECK(verified == hashes.size());
}

std::unique_ptr<fsys::NtfsScanner> open_ntfs(const std::shared_ptr<io::BlockDevice>& device) {
    auto scanner = fsys::NtfsScanner::open(device);
    REQUIRE(scanner.has_value());
    return std::move(*scanner);
}

}  // namespace

TEST_CASE("ntfs_basic matches the committed golden and preserves the image",
          "[M2][ntfs][fixture]") {
    require_fixtures();
    const json golden = load_golden("ntfs_basic.golden.json");
    const auto image_path = fixture_image("ntfs_basic.img");
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    auto device = open_fixture(image_path);
    auto scanner = fsys::detect_and_open(device);
    REQUIRE(scanner.has_value());
    CHECK((*scanner)->kind() == fsys::FsKind::Ntfs);
    CHECK((*scanner)->geometry().bytes_per_sector == kBytesPerSector);
    CHECK((*scanner)->geometry().bytes_per_cluster == kBytesPerCluster);
    CHECK((*scanner)->geometry().total_clusters == kVolumeBytes / kBytesPerCluster);

    auto files = (*scanner)->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());
    CHECK(actual_files_json(*files) == golden.at("files"));
    REQUIRE(files->size() == 11);

    check_hashes(**scanner, *files, golden.at("hashes"));

    const RecoveredFile* orphan = find_file(*files, "__orphans__/orphan.bin");
    REQUIRE(orphan != nullptr);
    CHECK((orphan->flags & file_flags::PathUncertain) != 0);

    const RecoveredFile* stale = find_file(*files, "stale_parent.txt");
    REQUIRE(stale != nullptr);
    CHECK((stale->flags & file_flags::PathUncertain) != 0);

    for (const RecoveredFile& file : *files) {
        if (file.path == "__orphans__/orphan.bin" || file.path == "stale_parent.txt") continue;
        INFO("path: " << file.path);
        CHECK((file.flags & file_flags::PathUncertain) == 0);
    }

    const RecoveredFile* reused = find_file(*files, "reused.bin");
    REQUIRE(reused != nullptr);
    CHECK(reused->confidence == Confidence::Low);
    CHECK((reused->flags & file_flags::ClustersReallocated) != 0);
    CHECK(reused->extents.size() == 1);

    const RecoveredFile* sparse = find_file(*files, "sparse.bin");
    REQUIRE(sparse != nullptr);
    CHECK(sparse->confidence == Confidence::High);
    CHECK(sparse->size_bytes == 3 * kBytesPerCluster);
    REQUIRE(sparse->extents.size() == 3);
    CHECK(sparse->extents[1].sparse);
    const std::vector<uint8_t> sparse_data = read_all(**scanner, *sparse);
    CHECK(std::all_of(sparse_data.begin() + kBytesPerCluster,
                      sparse_data.begin() + 2 * kBytesPerCluster,
                      [](uint8_t b) { return b == 0; }));

    const RecoveredFile* resident = find_file(*files, "resident deleted.txt");
    REQUIRE(resident != nullptr);
    CHECK(resident->extents.empty());
    CHECK(resident->size_bytes == 300);
    CHECK(sha256_hex(read_all(**scanner, *resident)) ==
          golden.at("hashes").at("resident deleted.txt").get<std::string>());

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("ntfs_fragmented_mft reassembles files from a fragmented $MFT",
          "[M2][ntfs][fixture]") {
    require_fixtures();
    const json golden = load_golden("ntfs_fragmented_mft.golden.json");
    const auto image_path = fixture_image("ntfs_fragmented_mft.img");
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    auto device = open_fixture(image_path);
    auto scanner = open_ntfs(device);
    CHECK(scanner->kind() == fsys::FsKind::Ntfs);
    CHECK(scanner->boot().record_size == 1024);
    CHECK(scanner->mft().record_count() == 4096);

    const std::vector<fsys::DataRun>& runs = scanner->mft().mft_runs();
    REQUIRE(runs.size() == 3);
    CHECK(runs[0].length_clusters == 200);
    CHECK(runs[0].lcn == 8);
    CHECK(runs[1].length_clusters == 400);
    CHECK(runs[1].lcn == 800);
    CHECK(runs[2].length_clusters == 424);
    CHECK(runs[2].lcn == 1600);
    CHECK(runs[2].lcn != runs[1].lcn + static_cast<int64_t>(runs[1].length_clusters));

    auto files = scanner->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());
    CHECK(actual_files_json(*files) == golden.at("files"));
    REQUIRE(files->size() == 4);

    check_hashes(*scanner, *files, golden.at("hashes"));

    const RecoveredFile* fragmented = find_file(*files, "probe-fragmented.bin");
    REQUIRE(fragmented != nullptr);
    REQUIRE(fragmented->extents.size() == 2);
    CHECK(sha256_hex(read_all(*scanner, *fragmented)) ==
          golden.at("hashes").at("probe-fragmented.bin").get<std::string>());

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("ntfs_compressed expands LZNT1 units into readable content", "[M2][ntfs][fixture]") {
    require_fixtures();
    const json golden = load_golden("ntfs_compressed.golden.json");
    const auto image_path = fixture_image("ntfs_compressed.img");
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    auto device = open_fixture(image_path);
    auto scanner = open_ntfs(device);
    CHECK(scanner->boot().bytes_per_cluster == kBytesPerCluster);

    auto files = scanner->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());
    CHECK(actual_files_json(*files) == golden.at("files"));
    REQUIRE(files->size() == 5);

    const RecoveredFile* mixed = find_file(*files, "compressed mixed.bin");
    REQUIRE(mixed != nullptr);
    CHECK(mixed->confidence == Confidence::High);
    CHECK((mixed->flags & file_flags::Unsupported) == 0);
    // The content was expanded while the record was read, so there are no extents to carve by.
    CHECK(mixed->extents.empty());
    // Every unit shape is in this file and reads happen in 777-byte pieces, so a chunk never
    // starts at a cluster boundary.
    check_hashes(*scanner, *files, golden.at("hashes"));

    const RecoveredFile* hollow = find_file(*files, "compressed sparse.bin");
    REQUIRE(hollow != nullptr);
    CHECK(hollow->confidence == Confidence::High);
    const std::vector<uint8_t> zeros = read_all(*scanner, *hollow);
    REQUIRE(zeros.size() == hollow->size_bytes);
    CHECK(std::all_of(zeros.begin(), zeros.end(), [](uint8_t byte) { return byte == 0; }));

    const RecoveredFile* plain = find_file(*files, "plain deleted.txt");
    REQUIRE(plain != nullptr);
    const std::vector<uint8_t> mixed_all = read_all(*scanner, *mixed);
    REQUIRE(mixed_all.size() == mixed->size_bytes);
    std::vector<uint8_t> head(64, 0);
    auto got = scanner->read_file(*mixed, 100000, head.data(), head.size());
    REQUIRE(got.has_value());
    CHECK(*got == head.size());
    CHECK(std::equal(head.begin(), head.end(), mixed_all.begin() + 100000));
    CHECK(sha256_hex(read_all(*scanner, *plain)) ==
          golden.at("hashes").at("plain deleted.txt").get<std::string>());

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("ntfs_compressed reports what it cannot expand instead of guessing",
          "[M2][ntfs][fixture]") {
    require_fixtures();
    const auto image_path = fixture_image("ntfs_compressed.img");

    auto device = open_fixture(image_path);
    auto scanner = open_ntfs(device);
    auto files = scanner->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());

    const RecoveredFile* truncated = find_file(*files, "compressed truncated.bin");
    REQUIRE(truncated != nullptr);
    CHECK(truncated->confidence == Confidence::Low);
    CHECK((truncated->flags & file_flags::Unsupported) != 0);
    CHECK(truncated->extents.empty());
    // The runlist lost the cluster a chunk straddles, so the stream ends inside its own header.
    // The exact text is in the golden, which the other case compares.
    CHECK(truncated->note.rfind("ntfs_compressed_corrupt", 0) == 0);

    const RecoveredFile* encrypted = find_file(*files, "encrypted secret.bin");
    REQUIRE(encrypted != nullptr);
    CHECK(encrypted->confidence == Confidence::Low);
    CHECK((encrypted->flags & file_flags::Unsupported) != 0);
    CHECK(encrypted->note == "ntfs_encrypted");

    uint8_t byte = 0;
    auto got = scanner->read_file(*truncated, 0, &byte, 1);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error().code == ErrorCode::Unsupported);
    auto secret = scanner->read_file(*encrypted, 0, &byte, 1);
    REQUIRE_FALSE(secret.has_value());
    CHECK(secret.error().code == ErrorCode::Unsupported);
}

TEST_CASE("ntfs_4k_sector uses 4096-byte sectors and records", "[M2][ntfs][fixture]") {
    require_fixtures();
    const json golden = load_golden("ntfs_4k_sector.golden.json");
    const auto image_path = fixture_image("ntfs_4k_sector.img");
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    auto device = open_fixture(image_path);
    auto scanner = fsys::detect_and_open(device);
    REQUIRE(scanner.has_value());
    CHECK((*scanner)->kind() == fsys::FsKind::Ntfs);
    CHECK((*scanner)->geometry().bytes_per_sector == 4096);
    CHECK((*scanner)->geometry().bytes_per_cluster == 4096);

    auto* ntfs = dynamic_cast<fsys::NtfsScanner*>(scanner->get());
    REQUIRE(ntfs != nullptr);
    CHECK(ntfs->boot().record_size == 4096);
    CHECK(ntfs->mft().record_size() == 4096);

    auto files = (*scanner)->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());
    CHECK(actual_files_json(*files) == golden.at("files"));
    REQUIRE(files->size() == 2);

    check_hashes(**scanner, *files, golden.at("hashes"));

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("ntfs_recyclebin restores the recorded path of a soft-deleted file",
          "[M2][ntfs][fixture]") {
    require_fixtures();
    const json golden = load_golden("ntfs_recyclebin.golden.json");
    const auto image_path = fixture_image("ntfs_recyclebin.img");
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    constexpr const char* kBin =
        "$Recycle.Bin/S-1-5-21-1234567890-2345678901-3456789012-1001/";

    auto device = open_fixture(image_path);
    auto scanner = open_ntfs(device);
    auto files = scanner->scan_deleted(fsys::ScanOptions{}, {});
    REQUIRE(files.has_value());
    CHECK(actual_files_json(*files) == golden.at("files"));
    REQUIRE(files->size() == 14);

    const RecoveredFile* notes = find_file(*files, "Users/bob/Documents/notes.txt");
    REQUIRE(notes != nullptr);
    CHECK(notes->name == "notes.txt");
    CHECK(notes->confidence == Confidence::High);
    CHECK((notes->flags & file_flags::OriginalPathRestored) != 0);
    CHECK(notes->flags == static_cast<uint32_t>(file_flags::OriginalPathRestored));
    REQUIRE(notes->deleted_unix.has_value());
    CHECK(*notes->deleted_unix == 1704153600);
    CHECK(find_file(*files, std::string(kBin) + "$Rnotes.txt") == nullptr);

    // The metadata file is still what the MFT says it is: a file in the recycle bin.
    const RecoveredFile* record = find_file(*files, std::string(kBin) + "$Inotes.txt");
    REQUIRE(record != nullptr);
    CHECK(record->flags == 0);
    CHECK(record->note.empty());
    CHECK_FALSE(record->deleted_unix.has_value());

    // A photo whose bytes start with the signature the name promises stays high.
    const RecoveredFile* photo = find_file(*files, "Users/bob/Pictures/2024/photo.jpg");
    REQUIRE(photo != nullptr);
    CHECK(photo->confidence == Confidence::High);
    CHECK(photo->type_hint == "jpeg");

    // Metadata that disagrees about the size may describe a different file.
    const RecoveredFile* report = find_file(*files, "Users/bob/Desktop/report.docx");
    REQUIRE(report != nullptr);
    CHECK((report->flags & file_flags::PathUncertain) != 0);
    CHECK((report->flags & file_flags::OriginalPathRestored) != 0);

    // A recorded path that walks out of its own directory cannot be placed on this volume, so
    // only the deletion time is kept.
    const RecoveredFile* escaped = find_file(*files, std::string(kBin) + "$Rescaped.dll");
    REQUIRE(escaped != nullptr);
    CHECK((escaped->flags & file_flags::OriginalPathRestored) == 0);
    REQUIRE(escaped->deleted_unix.has_value());

    // Unreadable or absent metadata leaves the data file exactly where the directory tree puts it.
    for (const char* name : {"$Rbroken.txt", "$Rorphan.bin"}) {
        const RecoveredFile* file = find_file(*files, std::string(kBin) + name);
        REQUIRE(file != nullptr);
        INFO("name: " << name);
        CHECK(file->flags == 0);
        CHECK(file->note.empty());
        CHECK_FALSE(file->deleted_unix.has_value());
    }

    // An undated record still says where the file lived, just not when it left.
    const RecoveredFile* undated = find_file(*files, "Users/bob/Desktop/undated.txt");
    REQUIRE(undated != nullptr);
    CHECK((undated->flags & file_flags::OriginalPathRestored) != 0);
    CHECK_FALSE(undated->deleted_unix.has_value());

    check_hashes(*scanner, *files, golden.at("hashes"));

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("fuzz_ntfs_record seed corpus parses without crashing", "[M2][ntfs][fuzz]") {
    const std::filesystem::path seed_dir(OPENRECOVER_FUZZ_SEED_DIR);
    REQUIRE(std::filesystem::is_directory(seed_dir));

    std::vector<std::filesystem::path> seeds;
    for (const auto& entry : std::filesystem::directory_iterator(seed_dir)) {
        if (entry.is_regular_file()) seeds.push_back(entry.path());
    }
    std::sort(seeds.begin(), seeds.end());
    REQUIRE(seeds.size() == 9);

    size_t accepted = 0;
    size_t rejected = 0;
    for (const auto& path : seeds) {
        INFO("seed: " << path.filename().string());
        const std::vector<uint8_t> bytes = test::load_test_file(path);
        const bool should_parse = path.filename().string().rfind("record", 0) == 0;
        auto whole = fsys::parse_mft_record(std::span<const uint8_t>(bytes), 0);
        if (whole) {
            ++accepted;
        } else {
            ++rejected;
        }
        CHECK(whole.has_value() == should_parse);

        for (size_t offset = 0; offset < bytes.size(); offset += 37) {
            std::vector<uint8_t> mutated = bytes;
            mutated[offset] ^= 0xFF;
            auto parsed = fsys::parse_mft_record(std::span<const uint8_t>(mutated), 0);
            if (parsed) ++accepted; else ++rejected;
        }
        for (size_t size = 64; size < bytes.size(); size += 137) {
            auto parsed =
                fsys::parse_mft_record(std::span<const uint8_t>(bytes.data(), size), 0);
            if (parsed) ++accepted; else ++rejected;
        }
    }
    CHECK(accepted > 0);
    CHECK(rejected > 0);
}
