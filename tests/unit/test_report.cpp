#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <regex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "openrecover/io/output_sink.hpp"
#include "openrecover/report/report.hpp"
#include "openrecover/common/types.hpp"
#include "test_util.hpp"

using namespace openrecover;
using namespace openrecover::report;
namespace fs = std::filesystem;

namespace {

FileEntry make_file(FileOrigin origin, std::string path, uint64_t offset, uint64_t size) {
    FileEntry file;
    file.origin = origin;
    file.path = std::move(path);
    file.size = size;
    file.confidence = Confidence::High;
    file.extents.push_back(Extent{offset, size, false});
    return file;
}

}  // namespace

TEST_CASE("report finalize assigns stable ids and ordering", "[M5][report]") {
    Report report;
    report.files.push_back(make_file(FileOrigin::AndroidPull, "z.jpg", 0, 3));
    report.files.push_back(make_file(FileOrigin::FilesystemMetadata, "b.txt", 900, 10));
    report.files.push_back(make_file(FileOrigin::FilesystemMetadata, "a.txt", 200, 10));
    report.files.push_back(make_file(FileOrigin::FilesystemMetadata, "a.txt", 100, 10));
    report.carved.push_back(CarvedEntry{500, 10, "png", "", Confidence::High, "", ""});
    report.carved.push_back(CarvedEntry{100, 20, "jpeg", "", Confidence::High, "", ""});
    finalize(report);

    REQUIRE(report.files.size() == 4);
    CHECK(report.files[0].path == "a.txt");
    CHECK(report.files[0].extents[0].offset_bytes == 100);
    CHECK(report.files[0].id == 1);
    CHECK(report.files[1].id == 2);
    CHECK(report.files[1].extents[0].offset_bytes == 200);
    CHECK(report.files[2].path == "b.txt");
    CHECK(report.files[3].origin == FileOrigin::AndroidPull);
    CHECK(report.files[3].id == 4);

    REQUIRE(report.carved.size() == 2);
    CHECK(report.carved[0].offset == 100);
    CHECK(report.carved[1].offset == 500);
}

TEST_CASE("report JSON follows the schema and masks generated_at", "[M5][report]") {
    Report report;
    report.generated_at = "2026-01-02T03:04:05Z";
    report.source = SourceSummary{"disk.img", "vhd fixed", 4096, 512, true, {7, 9}};
    report.partitions.push_back(PartitionSummary{2, "gpt", 2048, 4096, "fat32"});
    FileEntry file = make_file(FileOrigin::FilesystemMetadata, "DOCS/quote\"d.txt", 512, 10);
    file.flags = file_flags::ClustersReallocated | file_flags::Truncated;
    file.mtime_unix = 1700000000;
    file.sha256 = "abc";
    file.exported_to = "files/DOCS/quote_d.txt";
    file.type = "txt";
    file.note = "n";
    report.files.push_back(file);
    report.carved.push_back(CarvedEntry{1024, 70, "png", "", Confidence::Medium, "def",
                                        "carved/png/x.png"});
    CarvedEntry joined{2048, 70, "jpeg", "", Confidence::Low, "ghi", "carved/jpeg/y.jpg"};
    joined.fragments = 2;
    joined.extents = {Extent{2048, 40, false}, Extent{8192, 30, false}};
    report.carved.push_back(joined);
    report.statistics = Statistics{1, 2, 3, 0, 0};
    report.warnings.push_back("w");
    finalize(report);

    const nlohmann::json json = nlohmann::json::parse(to_json(report));
    CHECK(json.at("tool") == "openrecover");
    CHECK(json.at("version") == "1.4.0");
    CHECK(json.at("generated_at") == "2026-01-02T03:04:05Z");
    CHECK(json.at("source").at("container") == "vhd fixed");
    CHECK(json.at("source").at("shared_write_fallback") == true);
    CHECK(json.at("source").at("bad_sectors") == nlohmann::json::array({7, 9}));
    CHECK(json.at("partitions").at(0).at("scheme") == "gpt");
    const nlohmann::json& f = json.at("files").at(0);
    CHECK(f.at("id") == 1);
    CHECK(f.at("origin") == "filesystem_metadata");
    CHECK(f.at("confidence") == "high");
    CHECK(f.at("flags") == nlohmann::json::array({"Truncated", "ClustersReallocated"}));
    CHECK(f.at("mtime") == 1700000000);
    CHECK(f.at("extents").at(0).at("offset") == 512);
    CHECK(f.at("sha256") == "abc");
    CHECK(f.at("exported_to") == "files/DOCS/quote_d.txt");
    CHECK(f.at("type") == "txt");
    const nlohmann::json& contiguous = json.at("carved").at(0);
    CHECK(contiguous.at("subtype") == "");
    CHECK_FALSE(contiguous.contains("fragments"));
    CHECK_FALSE(contiguous.contains("extents"));
    const nlohmann::json& reassembled = json.at("carved").at(1);
    CHECK(reassembled.at("fragments") == 2);
    CHECK(reassembled.at("extents").size() == 2);
    CHECK(reassembled.at("extents").at(0).at("offset") == 2048);
    CHECK(reassembled.at("extents").at(0).at("length") == 40);
    CHECK(reassembled.at("extents").at(1).at("offset") == 8192);
    CHECK(reassembled.at("extents").at(1).at("length") == 30);
    CHECK_FALSE(reassembled.at("extents").at(0).contains("sparse"));
    CHECK(json.at("android").is_null());
    CHECK(json.at("statistics").at("duplicates_skipped") == 0);
    CHECK(json.at("warnings").at(0) == "w");
}

TEST_CASE("manifest CSV mirrors the file table and escapes fields", "[M5][report]") {
    Report report;
    FileEntry file = make_file(FileOrigin::FilesystemMetadata, "a,\"b\".txt", 0, 5);
    file.mtime_unix = 12;
    file.note = "line1\nline2";
    file.flags = file_flags::PathUncertain;
    report.files.push_back(file);
    finalize(report);

    const std::string csv = manifest_csv(report);
    CHECK(csv.rfind("id,origin,path,size,confidence,flags,mtime,extents,sha256,exported_to,type,note\r\n",
                    0) == 0);
    CHECK(csv.find("\"a,\"\"b\"\".txt\"") != std::string::npos);
    CHECK(csv.find("\"line1\nline2\"") != std::string::npos);
    CHECK(csv.find("0:5:0") != std::string::npos);
    CHECK(csv.find("PathUncertain") != std::string::npos);
}

TEST_CASE("report writes both files through OutputSink", "[M5][report]") {
    test::TempDir tmp;
    Report report;
    report.generated_at = generated_at_utc();
    report.source.description = "disk.img";
    report.files.push_back(make_file(FileOrigin::FilesystemMetadata, "a.txt", 0, 1));

    auto sink = io::OutputSink::open(tmp.path(), io::SourceIdentity{});
    REQUIRE(sink.has_value());
    auto written = write_to_sink(**sink, report, "report.json", "manifest.csv");
    REQUIRE(written.has_value());

    const fs::path report_path = tmp.path() / "report.json";
    const fs::path manifest_path = tmp.path() / "manifest.csv";
    REQUIRE(fs::exists(report_path));
    REQUIRE(fs::exists(manifest_path));
    const auto bytes = test::load_test_file(report_path);
    const nlohmann::json json =
        nlohmann::json::parse(bytes.begin(), bytes.end());
    CHECK(json.at("source").at("description") == "disk.img");
    CHECK(test::sha256_of_file(manifest_path).size() == 64);

    const std::string stamp = json.at("generated_at").get<std::string>();
    CHECK(std::regex_match(stamp, std::regex(R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")));
}
