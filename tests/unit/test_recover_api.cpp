#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "openrecover/common/hash.hpp"
#include "openrecover/common/path_util.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/output_sink.hpp"
#include "openrecover/recover.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
namespace fs = openrecover::fs;
namespace stdfs = std::filesystem;

stdfs::path fixture_image(const std::string& name) {
    return stdfs::path(OPENRECOVER_FIXTURE_DIR) / name;
}

void require_fixtures() {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("fixture images were not generated (Python3 unavailable)");
    if (!stdfs::exists(fixture_image("fat32_basic.img")))
        SKIP("fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
}

SourceRequest image_request(const std::string& name) {
    SourceRequest request;
    request.source = fixture_image(name).string();
    return request;
}

io::OutputSink& opened_sink(test::TempDir& dir, const std::string& source,
                            std::unique_ptr<io::OutputSink>& holder) {
    auto sink = io::OutputSink::open(dir.path(), io::SourceIdentity::from_source_string(source));
    REQUIRE(sink.has_value());
    holder = std::move(*sink);
    return *holder;
}

// A report path is '/'-separated UTF-8, so read it with the decoder rather than as ANSI, and in the
// long-path form because a deep recovered tree passes the legacy 260-character limit.
stdfs::path native(const stdfs::path& p) {
#if defined(_WIN32)
    return win_long_path(p);
#else
    return p;
#endif
}

stdfs::path output_file(const stdfs::path& root, const std::string& relative) {
    return native(root / path_from_utf8(relative));
}

size_t count_files(const stdfs::path& root) {
    if (!stdfs::exists(native(root))) return 0;
    size_t n = 0;
    for (const auto& entry : stdfs::recursive_directory_iterator(native(root)))
        if (entry.is_regular_file()) ++n;
    return n;
}

// The CLI's default filter: every confidence, every type, no size cap, unallocated space first.
ExportFilter default_filter() {
    return ExportFilter{};
}

CarveRequest cli_carve_request() {
    CarveRequest request;
    request.options.scope = carve::CarveOptions::Scope::UnallocatedOnly;
    request.options.min_confidence = Confidence::Low;
    return request;
}

}  // namespace

TEST_CASE("open_volume pins the volume and names its filesystem") {
    require_fixtures();

    SECTION("a filesystem at offset 0 is the volume") {
        auto opened = open_volume(image_request("fat32_basic.img"), true);
        REQUIRE(opened.has_value());
        CHECK(opened->view_offset() == 0);
        CHECK(opened->view() == opened->root());
        REQUIRE(opened->scanner() != nullptr);
        CHECK(opened->scanner()->kind() == fs::FsKind::Fat32);
        REQUIRE(opened->partition_summaries().size() == 1);
        CHECK(opened->partition_summaries()[0].fs == "fat32");
        CHECK(opened->partition_summaries()[0].scheme == "superfloppy");
        CHECK(opened->warnings().empty());
        CHECK(opened->partitions_error().has_value() == false);
    }

    SECTION("an MBR image falls forward to the partition that has a volume") {
        auto opened = open_volume(image_request("fat32_in_mbr.img"), true);
        REQUIRE(opened.has_value());
        REQUIRE(opened->partitions().size() == 1);
        CHECK(opened->partitions()[0].index == 0);
        CHECK(opened->view_offset() == opened->partitions()[0].start_byte);
        CHECK(opened->view_offset() != 0);
        REQUIRE(opened->scanner() != nullptr);
        CHECK(opened->scanner()->kind() == fs::FsKind::Fat32);
        REQUIRE(opened->warnings().size() == 1);
        CHECK(opened->warnings()[0] == "no filesystem at offset 0; using partition 0 at byte 1048576");
    }

    SECTION("the source description is a file name, never a working directory") {
        auto opened = open_volume(image_request("fat32_basic.img"), true);
        REQUIRE(opened.has_value());
        const report::Report base = opened->base_report();
        CHECK(base.source.description == "fat32_basic.img");
        CHECK(base.source.size_bytes == opened->root()->info().size_bytes);
        CHECK_FALSE(base.generated_at.empty());
    }
}

TEST_CASE("open_volume rejects contradictory, out-of-range and wrong-filesystem requests") {
    require_fixtures();

    SECTION("a pinned partition and a pinned offset cannot be combined") {
        auto request = image_request("fat32_basic.img");
        request.partition = 0;
        request.offset = 512;
        auto opened = open_volume(request, false);
        REQUIRE_FALSE(opened.has_value());
        CHECK(opened.error().code == ErrorCode::InvalidArgument);
    }

    SECTION("an absent partition is an argument error") {
        auto request = image_request("fat32_basic.img");
        request.partition = 7;
        auto opened = open_volume(request, false);
        REQUIRE_FALSE(opened.has_value());
        CHECK(opened.error().code == ErrorCode::InvalidArgument);
    }

    SECTION("an offset past the end of the source is an argument error") {
        auto request = image_request("fat32_basic.img");
        request.offset = 1ull << 40;
        auto opened = open_volume(request, false);
        REQUIRE_FALSE(opened.has_value());
        CHECK(opened.error().code == ErrorCode::InvalidArgument);
    }

    SECTION("a forced filesystem that is not there fails instead of falling back") {
        auto request = image_request("fat32_basic.img");
        request.fs = fs::FsKind::Ntfs;
        auto opened = open_volume(request, false);
        REQUIRE_FALSE(opened.has_value());
        CHECK(opened.error().message.empty() == false);
    }

    SECTION("a forced filesystem that is there opens") {
        auto request = image_request("fat32_basic.img");
        request.fs = fs::FsKind::Fat32;
        auto opened = open_volume(request, true);
        REQUIRE(opened.has_value());
        CHECK(opened->scanner()->kind() == fs::FsKind::Fat32);
    }

    SECTION("a source with no filesystem needs a scanner only when asked") {
        auto with_scanner = open_volume(image_request("carve_mixed.img"), true);
        REQUIRE_FALSE(with_scanner.has_value());
        CHECK(with_scanner.error().code == ErrorCode::Unsupported);

        auto for_carving = open_volume(image_request("carve_mixed.img"), false);
        REQUIRE(for_carving.has_value());
        CHECK(for_carving->scanner() == nullptr);
        REQUIRE(for_carving->warnings().size() == 1);
        CHECK(for_carving->warnings()[0] == "no supported filesystem detected; carving the whole source");
    }

    SECTION("a missing source is an I/O error") {
        auto request = image_request("does_not_exist.img");
        auto opened = open_volume(request, false);
        REQUIRE_FALSE(opened.has_value());
        CHECK(opened.error().code != ErrorCode::InvalidArgument);
    }
}

TEST_CASE("export_metadata writes the files the directory still names") {
    require_fixtures();
    test::TempDir dir;
    std::unique_ptr<io::OutputSink> sink;
    io::OutputSink& out = opened_sink(dir, "fat32_basic.img", sink);

    auto opened = open_volume(image_request("fat32_basic.img"), true);
    REQUIRE(opened.has_value());
    report::Report result = opened->base_report();
    std::vector<RecoveredFile> accepted;

    auto exported = export_metadata(*opened, out, default_filter(), nullptr, result, &accepted);
    REQUIRE(exported.has_value());
    CHECK(*exported == 9);
    CHECK(result.statistics.deleted_entries_found == 9);
    CHECK(result.statistics.exported == 9);
    CHECK(result.files.size() == 9);
    CHECK(accepted.size() == 9);
    CHECK(count_files(dir.path() / "files") == 9);

    for (const report::FileEntry& entry : result.files) {
        CHECK_FALSE(entry.exported_to.empty());
        const stdfs::path written = output_file(dir.path(), entry.exported_to);
        INFO(entry.exported_to);
        CHECK(stdfs::exists(written));
        CHECK(entry.sha256 == test::sha256_of_file(written));
        CHECK(entry.size == stdfs::file_size(written));
    }
    // The extent offsets a scanner reports are volume-relative; the report has to place them in
    // the source the operator pointed at.
    for (const report::FileEntry& entry : result.files) {
        for (const Extent& extent : entry.extents) {
            CHECK(extent.offset_bytes >= opened->view_offset());
        }
    }
}

TEST_CASE("a progress callback that returns false cancels the work") {
    require_fixtures();
    test::TempDir dir;
    std::unique_ptr<io::OutputSink> sink;
    io::OutputSink& out = opened_sink(dir, "fat32_basic.img", sink);

    auto opened = open_volume(image_request("fat32_basic.img"), true);
    REQUIRE(opened.has_value());
    report::Report result = opened->base_report();

    const ProgressFn cancel = [](uint64_t, uint64_t) { return false; };
    auto exported = export_metadata(*opened, out, default_filter(), cancel, result);
    REQUIRE_FALSE(exported.has_value());
    CHECK(exported.error().code == ErrorCode::Cancelled);

    CarveRequest carving = cli_carve_request();
    carving.options.scope = carve::CarveOptions::Scope::All;
    auto carved = carve_and_export(*opened, out, carving, default_filter(), cancel, result, nullptr);
    REQUIRE_FALSE(carved.has_value());
    CHECK(carved.error().code == ErrorCode::Cancelled);
}

TEST_CASE("recover runs both phases and matches the CLI report") {
    require_fixtures();
    test::TempDir dir;
    std::unique_ptr<io::OutputSink> sink;
    io::OutputSink& out = opened_sink(dir, "fat32_basic.img", sink);

    RecoverRequest request;
    request.source = image_request("fat32_basic.img");
    request.sink = &out;
    request.metadata = true;
    request.carve = true;
    request.filter = default_filter();
    request.carving = cli_carve_request();

    auto document = recover(request);
    REQUIRE(document.has_value());
    // cli_fat32_basic.report.json: nine deleted entries, all nine exported, one carve that is a
    // duplicate of a file the metadata already returned.
    CHECK(document->statistics.deleted_entries_found == 9);
    CHECK(document->statistics.exported == 9);
    CHECK(document->statistics.carve_hits == 1);
    CHECK(document->statistics.duplicates_skipped == 1);
    CHECK(document->source.description == "fat32_basic.img");
    CHECK(document->partitions.size() == 1);
    REQUIRE(document->carved.size() == 1);
    CHECK(document->carved[0].exported_to.empty());

    auto written = report::write_to_sink(out, *document, "report.json", "manifest.csv");
    REQUIRE(written.has_value());
    CHECK(stdfs::exists(dir.path() / "report.json"));
    CHECK(stdfs::exists(dir.path() / "manifest.csv"));
    CHECK(count_files(dir.path() / "files") == 9);
}

TEST_CASE("recover carves a source whose filesystem is gone") {
    require_fixtures();
    test::TempDir dir;
    std::unique_ptr<io::OutputSink> sink;
    io::OutputSink& out = opened_sink(dir, "carve_mixed.img", sink);

    RecoverRequest request;
    request.source = image_request("carve_mixed.img");
    request.sink = &out;
    request.metadata = false;
    request.carve = true;
    request.filter = default_filter();
    request.carving = cli_carve_request();
    request.carving.options.scope = carve::CarveOptions::Scope::All;

    auto document = recover(request);
    REQUIRE(document.has_value());
    // cli_carve_mixed.report.json: twelve hits, no duplicates, all twelve exported.
    CHECK(document->statistics.deleted_entries_found == 0);
    CHECK(document->statistics.carve_hits == 12);
    CHECK(document->statistics.duplicates_skipped == 0);
    CHECK(document->statistics.exported == 12);
    CHECK(document->files.empty());
    CHECK(document->carved.size() == 12);
    CHECK(count_files(dir.path() / "carved") == 12);
    for (const report::CarvedEntry& entry : document->carved) {
        CHECK_FALSE(entry.exported_to.empty());
        INFO(entry.exported_to);
        CHECK(entry.sha256 == test::sha256_of_file(output_file(dir.path(), entry.exported_to)));
    }
}

TEST_CASE("recover validates its request before touching the source") {
    require_fixtures();
    test::TempDir dir;
    std::unique_ptr<io::OutputSink> sink;
    io::OutputSink& out = opened_sink(dir, "fat32_basic.img", sink);

    RecoverRequest no_sink;
    no_sink.source = image_request("fat32_basic.img");
    auto without = recover(no_sink);
    REQUIRE_FALSE(without.has_value());
    CHECK(without.error().code == ErrorCode::InvalidArgument);

    RecoverRequest no_phase;
    no_phase.source = image_request("fat32_basic.img");
    no_phase.sink = &out;
    no_phase.metadata = false;
    no_phase.carve = false;
    auto idle = recover(no_phase);
    REQUIRE_FALSE(idle.has_value());
    CHECK(idle.error().code == ErrorCode::InvalidArgument);

    RecoverRequest bad_type;
    bad_type.source = image_request("fat32_basic.img");
    bad_type.sink = &out;
    bad_type.metadata = false;
    bad_type.carving.options.types = {"not-a-format"};
    auto rejected = recover(bad_type);
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error().code == ErrorCode::InvalidArgument);
}

TEST_CASE("a size cap keeps oversized files out of the output") {
    require_fixtures();

    auto opened = open_volume(image_request("fat32_basic.img"), true);
    REQUIRE(opened.has_value());

    // First pass with no cap: it says what the volume holds and how big its largest file is.
    test::TempDir uncapped;
    std::unique_ptr<io::OutputSink> sink_a;
    io::OutputSink& out_a = opened_sink(uncapped, "fat32_basic.img", sink_a);
    report::Report all = opened->base_report();
    REQUIRE(export_metadata(*opened, out_a, default_filter(), nullptr, all).has_value());
    REQUIRE(all.statistics.exported == 9);

    uint64_t largest = 0;
    size_t at_largest = 0;
    std::set<std::string> types;
    for (const report::FileEntry& entry : all.files) {
        types.insert(entry.type);
        if (entry.size > largest) {
            largest = entry.size;
            at_largest = 1;
        } else if (entry.size == largest) {
            ++at_largest;
        }
    }
    REQUIRE(largest > 1);

    // Second pass with every type capped one byte below that: only the oversized files are refused,
    // while the report still names everything the metadata found.
    ExportFilter filter;
    for (const std::string& type : types) filter.max_sizes[type] = largest - 1;

    test::TempDir capped;
    std::unique_ptr<io::OutputSink> sink_b;
    io::OutputSink& out_b = opened_sink(capped, "fat32_basic.img", sink_b);
    report::Report limited = opened->base_report();
    auto exported = export_metadata(*opened, out_b, filter, nullptr, limited);
    REQUIRE(exported.has_value());
    CHECK(*exported == all.files.size() - at_largest);
    CHECK(limited.statistics.deleted_entries_found == 9);
    CHECK(limited.statistics.exported == *exported);
    CHECK(limited.files.size() == 9);
    CHECK(count_files(capped.path() / "files") == *exported);

    size_t named = 0;
    for (const report::FileEntry& entry : limited.files) {
        const bool fits = entry.size < largest;
        INFO(entry.path << " size=" << entry.size);
        CHECK(entry.exported_to.empty() == !fits);
        if (entry.exported_to.empty()) continue;
        ++named;
        CHECK(stdfs::exists(output_file(capped.path(), entry.exported_to)));
    }
    CHECK(named == *exported);
}
