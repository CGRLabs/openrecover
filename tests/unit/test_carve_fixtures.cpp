#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "openrecover/carve/carve_engine.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/output_sink.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;
using nlohmann::json;

std::filesystem::path fixture_image(const std::string& name) {
    return std::filesystem::path(OPENRECOVER_FIXTURE_DIR) / name;
}

void require_carve_fixtures() {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("carve fixture images were not generated (Python3 unavailable)");
    if (!std::filesystem::exists(fixture_image("carve_mixed.img")))
        SKIP("carve fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
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

json hits_json(const std::vector<CarveHit>& hits) {
    json out = json::array();
    for (const CarveHit& hit : hits) {
        out.push_back({{"offset", hit.offset},
                       {"length", hit.length},
                       {"type", hit.type},
                       {"confidence", confidence_name(hit.confidence)}});
    }
    return out;
}

json sorted_hits(json hits) {
    std::sort(hits.begin(), hits.end(), [](const json& a, const json& b) {
        return a.at("offset").get<uint64_t>() < b.at("offset").get<uint64_t>();
    });
    return hits;
}

CarveOptions all_scope_options() {
    CarveOptions options;
    options.scope = CarveOptions::Scope::All;
    return options;
}

class SyntheticAllocationMap final : public fs::IAllocationMap {
public:
    SyntheticAllocationMap(uint64_t cluster_size, uint64_t anchor_offset, uint64_t cluster_count,
                           std::set<uint64_t> allocated)
        : cluster_size_(cluster_size),
          anchor_(anchor_offset),
          count_(cluster_count),
          allocated_(std::move(allocated)) {}

    bool is_cluster_allocated(uint64_t cluster) const override {
        return allocated_.count(cluster) != 0;
    }
    uint64_t cluster_to_byte_offset(uint64_t cluster) const override {
        return anchor_ + (cluster - 2) * cluster_size_;
    }
    uint64_t cluster_count() const override { return count_; }

private:
    uint64_t cluster_size_;
    uint64_t anchor_;
    uint64_t count_;
    std::set<uint64_t> allocated_;
};

std::string expected_relative(const CarveHit& hit) {
    std::string extension;
    if (hit.type == "jpeg") extension = "jpg";
    else if (hit.type == "png") extension = "png";
    else if (hit.type == "pdf") extension = "pdf";
    else if (hit.type == "zip") extension = "zip";
    else extension = "bin";
    char offset[17]{};
    std::snprintf(offset, sizeof offset, "%016llx", static_cast<unsigned long long>(hit.offset));
    return "carved/" + hit.type + "/" + offset + "_" + std::to_string(hit.length) + "." +
           extension;
}

std::vector<uint8_t> read_recovered(fs::IFileSystemScanner& scanner,
                                    const RecoveredFile& file) {
    std::vector<uint8_t> data(static_cast<size_t>(file.size_bytes));
    uint64_t offset = 0;
    while (offset < file.size_bytes) {
        const size_t chunk =
            static_cast<size_t>(std::min<uint64_t>(555, file.size_bytes - offset));
        auto got = scanner.read_file(file, offset, data.data() + static_cast<size_t>(offset),
                                     chunk);
        REQUIRE(got.has_value());
        REQUIRE(*got == chunk);
        offset += chunk;
    }
    return data;
}

}  // namespace

TEST_CASE("carve_mixed matches the committed golden and leaves the image unchanged",
          "[M3][carve][fixture]") {
    require_carve_fixtures();
    const json golden = load_golden("carve_mixed.golden.json");
    const auto image_path = fixture_image(golden.at("image").get<std::string>());
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("image_sha256").get<std::string>());

    auto device = open_fixture(image_path);
    CHECK(device->info().size_bytes == golden.at("size_bytes").get<uint64_t>());

    auto hits = CarveEngine::run(*device, nullptr, all_scope_options(), {});
    REQUIRE(hits.has_value());
    CHECK(hits_json(*hits) == golden.at("hits"));

    std::set<uint64_t> decoy_offsets;
    for (const json& decoy : golden.at("decoys")) {
        decoy_offsets.insert(decoy.at("offset").get<uint64_t>());
    }
    for (const CarveHit& hit : *hits) CHECK(decoy_offsets.count(hit.offset) == 0);

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("carve_mixed exposes the nested JPEG only when nesting is enabled",
          "[M3][carve][fixture]") {
    require_carve_fixtures();
    const json golden = load_golden("carve_mixed.golden.json");
    auto device = open_fixture(fixture_image(golden.at("image").get<std::string>()));

    const json& nested = golden.at("nested");
    const uint64_t nested_offset = nested.at("offset").get<uint64_t>();

    auto aligned = CarveEngine::run(*device, nullptr, all_scope_options(), {});
    REQUIRE(aligned.has_value());
    for (const CarveHit& hit : *aligned) CHECK(hit.offset != nested_offset);

    CarveOptions options = all_scope_options();
    options.nested = true;
    auto nested_hits = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(nested_hits.has_value());

    json expected = golden.at("hits");
    json extra;
    extra["offset"] = nested.at("offset");
    extra["length"] = nested.at("length");
    extra["type"] = nested.at("type");
    extra["confidence"] = nested.at("confidence");
    expected.push_back(std::move(extra));

    CHECK(hits_json(*nested_hits) == sorted_hits(std::move(expected)));

    const auto contains = [&](uint64_t offset) {
        return std::any_of(nested_hits->begin(), nested_hits->end(),
                           [&](const CarveHit& hit) { return hit.offset == offset; });
    };
    CHECK(contains(nested.at("container_offset").get<uint64_t>()));
    CHECK(contains(nested_offset));
}

TEST_CASE("carve_mixed unaligned variant needs the unaligned scan", "[M3][carve][fixture]") {
    require_carve_fixtures();
    const json golden = load_golden("carve_mixed.golden.json");
    const auto image_path =
        fixture_image(golden.at("unaligned_image").get<std::string>());
    const std::string before = test::sha256_of_file(image_path);
    CHECK(before == golden.at("unaligned_image_sha256").get<std::string>());

    auto device = open_fixture(image_path);

    auto aligned = CarveEngine::run(*device, nullptr, all_scope_options(), {});
    REQUIRE(aligned.has_value());
    CHECK(aligned->empty());

    CarveOptions options = all_scope_options();
    options.unaligned = true;
    auto unaligned = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(unaligned.has_value());
    CHECK(hits_json(*unaligned) == golden.at("unaligned_hits"));

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("UnallocatedOnly carving skips files in allocated clusters", "[M3][carve][fixture]") {
    require_carve_fixtures();
    const json golden = load_golden("carve_mixed.golden.json");
    auto device = open_fixture(fixture_image(golden.at("image").get<std::string>()));

    const json& scope = golden.at("scope");
    std::set<uint64_t> allocated;
    for (const json& cluster : scope.at("allocated_clusters"))
        allocated.insert(cluster.get<uint64_t>());
    SyntheticAllocationMap map(scope.at("cluster_size").get<uint64_t>(),
                               scope.at("anchor_offset").get<uint64_t>(),
                               scope.at("cluster_count").get<uint64_t>(),
                               std::move(allocated));

    CarveOptions options = all_scope_options();
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    auto hits = CarveEngine::run(*device, &map, options, {});
    REQUIRE(hits.has_value());

    json expected = json::array();
    std::set<uint64_t> excluded;
    for (const json& offset : scope.at("excluded_offsets"))
        excluded.insert(offset.get<uint64_t>());
    for (const json& hit : golden.at("hits")) {
        if (excluded.count(hit.at("offset").get<uint64_t>()) == 0) expected.push_back(hit);
    }
    CHECK(hits_json(*hits) == expected);
    for (const CarveHit& hit : *hits) CHECK(excluded.count(hit.offset) == 0);

    options.scope = CarveOptions::Scope::All;
    auto everything = CarveEngine::run(*device, &map, options, {});
    REQUIRE(everything.has_value());
    CHECK(hits_json(*everything) == golden.at("hits"));
}

TEST_CASE("carve hits are marked as duplicates of FAT32-recovered files", "[M3][carve][fixture]") {
    require_carve_fixtures();
    const auto image_path = fixture_image("fat32_basic.img");
    if (!std::filesystem::exists(image_path))
        SKIP("FAT32 fixture image is missing from " << OPENRECOVER_FIXTURE_DIR);

    const std::string before = test::sha256_of_file(image_path);
    auto device = open_fixture(image_path);
    auto scanner = fs::detect_and_open(device);
    REQUIRE(scanner.has_value());
    auto files = (*scanner)->scan_deleted(fs::ScanOptions{}, {});
    REQUIRE(files.has_value());
    auto allocation = (*scanner)->allocation_map();
    REQUIRE(allocation.has_value());

    const auto recovered = std::find_if(
        files->begin(), files->end(),
        [](const RecoveredFile& file) { return file.path == "PICS/2024/summer holiday photo.jpg"; });
    REQUIRE(recovered != files->end());
    REQUIRE(recovered->confidence == Confidence::High);
    REQUIRE(recovered->extents.size() == 1);
    const Extent extent = recovered->extents.front();

    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.existing_files = &*files;
    auto hits = CarveEngine::run(*device, allocation->get(), options, {});
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    CHECK((*hits)[0].offset == extent.offset_bytes);
    CHECK((*hits)[0].length == extent.length_bytes);
    CHECK((*hits)[0].type == "jpeg");
    CHECK((*hits)[0].duplicate_of == recovered->path);

    const std::vector<uint8_t> original = read_recovered(**scanner, *recovered);
    CHECK(sha256_hex(original) == (*hits)[0].sha256);

    test::TempDir skipped_dir;
    auto skipped = io::OutputSink::open(skipped_dir.path(), io::SourceIdentity::image(image_path));
    REQUIRE(skipped.has_value());
    auto exported_skipped = export_hits(**skipped, *device, *hits, true);
    REQUIRE(exported_skipped.has_value());
    CHECK(exported_skipped->empty());

    test::TempDir all_dir;
    auto all = io::OutputSink::open(all_dir.path(), io::SourceIdentity::image(image_path));
    REQUIRE(all.has_value());
    auto exported_all = export_hits(**all, *device, *hits, false);
    REQUIRE(exported_all.has_value());
    REQUIRE(exported_all->size() == 1);
    CHECK((*exported_all)[0].relative == expected_relative((*hits)[0]));
    CHECK((*exported_all)[0].sha256 == (*hits)[0].sha256);
    CHECK(test::load_test_file((*exported_all)[0].path) == original);

    CHECK(before == test::sha256_of_file(image_path));
}

TEST_CASE("export_hits writes the carved fixtures with their hashes", "[M3][carve][fixture]") {
    require_carve_fixtures();
    const json golden = load_golden("carve_mixed.golden.json");
    const auto image_path = fixture_image(golden.at("image").get<std::string>());
    auto device = open_fixture(image_path);

    auto hits = CarveEngine::run(*device, nullptr, all_scope_options(), {});
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == golden.at("hits").size());

    test::TempDir out;
    auto sink = io::OutputSink::open(out.path(), io::SourceIdentity::image(image_path));
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, *device, *hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == hits->size());

    for (size_t i = 0; i < written->size(); ++i) {
        INFO("hit " << i << " type " << (*hits)[i].type << " offset " << (*hits)[i].offset);
        CHECK((*written)[i].relative == expected_relative((*hits)[i]));
        CHECK((*written)[i].size == (*hits)[i].length);
        CHECK((*written)[i].sha256 == (*hits)[i].sha256);
        CHECK(test::sha256_of_file((*written)[i].path) == (*hits)[i].sha256);
    }
}

TEST_CASE("carve_fragmented joins a JPEG that resumes after a discontinuity",
          "[M3][carve][fixture][fragment]") {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("carve fixture images were not generated (Python3 unavailable)");
    const auto image_path = fixture_image("carve_fragmented.img");
    if (!std::filesystem::exists(image_path))
        SKIP("carve_fragmented.img is missing from " << OPENRECOVER_FIXTURE_DIR);

    const json golden = load_golden("carve_fragmented.golden.json");
    CHECK(test::sha256_of_file(image_path) == golden.at("image_sha256").get<std::string>());
    auto device = open_fixture(image_path);

    const json& fragmented = golden.at("fragmented");
    const json& chained = golden.at("chained");
    const json& orphan = golden.at("orphan");

    CarveOptions options;
    options.scope = CarveOptions::Scope::All;
    options.reassemble = true;
    auto hits = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 3);

    const CarveHit& joined = (*hits)[0];
    CHECK(joined.offset == fragmented.at("offset").get<uint64_t>());
    CHECK(joined.length == fragmented.at("length").get<uint64_t>());
    CHECK(joined.type == fragmented.at("type").get<std::string>());
    CHECK(joined.sha256 == fragmented.at("sha256").get<std::string>());
    CHECK((joined.flags & file_flags::Fragmented) != 0);
    CHECK((joined.flags & file_flags::Truncated) == 0);
    REQUIRE(joined.fragments.size() == 2);
    CHECK(joined.fragments[0].offset == fragmented.at("offset").get<uint64_t>());
    CHECK(joined.fragments[0].length == fragmented.at("prefix_length").get<uint64_t>());
    CHECK(joined.fragments[1].offset == fragmented.at("tail_offset").get<uint64_t>());
    CHECK(joined.fragments[1].length == fragmented.at("tail_length").get<uint64_t>());

    // The twice-split JPEG is stitched across both cuts, piece by piece.
    const CarveHit& chain = (*hits)[1];
    CHECK(chain.offset == chained.at("offset").get<uint64_t>());
    CHECK(chain.length == chained.at("length").get<uint64_t>());
    CHECK(chain.type == chained.at("type").get<std::string>());
    CHECK(chain.sha256 == chained.at("sha256").get<std::string>());
    CHECK((chain.flags & file_flags::Fragmented) != 0);
    CHECK((chain.flags & file_flags::Truncated) == 0);
    REQUIRE(chain.fragments.size() == chained.at("pieces").size());
    for (size_t i = 0; i < chain.fragments.size(); ++i) {
        CHECK(chain.fragments[i].offset == chained.at("pieces")[i].at("offset").get<uint64_t>());
        CHECK(chain.fragments[i].length == chained.at("pieces")[i].at("length").get<uint64_t>());
    }

    const CarveHit& orphan_hit = (*hits)[2];
    CHECK(orphan_hit.offset == orphan.at("offset").get<uint64_t>());
    CHECK(orphan_hit.length == orphan.at("length").get<uint64_t>());
    CHECK(orphan_hit.fragments.empty());
    CHECK((orphan_hit.flags & file_flags::Truncated) != 0);

    // The exported file is the fragments concatenated, and nothing else.
    const std::vector<uint8_t> image = test::load_test_file(image_path);
    const auto concatenated = [&](const CarveHit& hit) {
        std::vector<uint8_t> bytes;
        for (const CarveFragment& fragment : hit.fragments) {
            bytes.insert(bytes.end(),
                         image.begin() + static_cast<std::ptrdiff_t>(fragment.offset),
                         image.begin() + static_cast<std::ptrdiff_t>(fragment.offset +
                                                                    fragment.length));
        }
        CHECK(bytes.size() == hit.length);
        CHECK(sha256_hex(bytes) == hit.sha256);
        return bytes;
    };
    const std::vector<uint8_t> expected = concatenated(joined);
    const std::vector<uint8_t> chain_bytes = concatenated(chain);

    test::TempDir out;
    auto sink = io::OutputSink::open(out.path(), io::SourceIdentity::image(image_path));
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, *device, *hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 3);
    CHECK(test::load_test_file((*written)[0].path) == expected);
    CHECK((*written)[0].relative == expected_relative(joined));
    CHECK(test::load_test_file((*written)[1].path) == chain_bytes);
    CHECK((*written)[1].relative == expected_relative(chain));

    // Without the join each head is all that can be claimed, and each stops at its first cut.
    options.reassemble = false;
    auto heads = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(heads.has_value());
    REQUIRE(heads->size() == 3);
    CHECK((*heads)[0].offset == joined.offset);
    CHECK((*heads)[0].length == fragmented.at("prefix_length").get<uint64_t>());
    CHECK((*heads)[0].fragments.empty());
    CHECK((*heads)[1].offset == chain.offset);
    CHECK((*heads)[1].length == chained.at("pieces")[0].at("length").get<uint64_t>());
    CHECK((*heads)[1].fragments.empty());
}

TEST_CASE("carve_fragmented_png resyncs a PNG onto its surviving chunk run",
          "[M3][carve][fixture][fragment]") {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("carve fixture images were not generated (Python3 unavailable)");
    const auto image_path = fixture_image("carve_fragmented_png.img");
    if (!std::filesystem::exists(image_path))
        SKIP("carve_fragmented_png.img is missing from " << OPENRECOVER_FIXTURE_DIR);

    const json golden = load_golden("carve_fragmented_png.golden.json");
    CHECK(test::sha256_of_file(image_path) == golden.at("image_sha256").get<std::string>());
    auto device = open_fixture(image_path);

    const json& joined_expected = golden.at("joined");
    const json& chained = golden.at("chained");
    const json& orphan = golden.at("orphan");

    CarveOptions options;
    options.scope = CarveOptions::Scope::All;
    options.reassemble = true;
    auto hits = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 3);

    const CarveHit& joined = (*hits)[0];
    CHECK(joined.offset == joined_expected.at("offset").get<uint64_t>());
    CHECK(joined.length == joined_expected.at("length").get<uint64_t>());
    CHECK(joined.type == joined_expected.at("type").get<std::string>());
    CHECK(joined.sha256 == joined_expected.at("sha256").get<std::string>());
    CHECK((joined.flags & file_flags::Fragmented) != 0);
    CHECK((joined.flags & file_flags::Truncated) == 0);
    REQUIRE(joined.fragments.size() == 2);
    CHECK(joined.fragments[0].offset == joined_expected.at("offset").get<uint64_t>());
    CHECK(joined.fragments[0].length == joined_expected.at("prefix_length").get<uint64_t>());
    CHECK(joined.fragments[1].offset == joined_expected.at("tail_offset").get<uint64_t>());
    CHECK(joined.fragments[1].length == joined_expected.at("tail_length").get<uint64_t>());

    // The orphan stops at the chunk that lost its bytes; the neighbouring PNG's signature is
    // not a tail, so its chunks are not absorbed into this head.
    const CarveHit& orphan_hit = (*hits)[1];
    CHECK(orphan_hit.offset == orphan.at("offset").get<uint64_t>());
    CHECK(orphan_hit.length == orphan.at("length").get<uint64_t>());
    CHECK(orphan_hit.type == orphan.at("type").get<std::string>());
    CHECK(orphan_hit.fragments.empty());
    CHECK((orphan_hit.flags & file_flags::Truncated) != 0);

    const CarveHit& chain = (*hits)[2];
    CHECK(chain.offset == chained.at("offset").get<uint64_t>());
    CHECK(chain.length == chained.at("length").get<uint64_t>());
    CHECK(chain.type == chained.at("type").get<std::string>());
    CHECK(chain.sha256 == chained.at("sha256").get<std::string>());
    CHECK((chain.flags & file_flags::Fragmented) != 0);
    CHECK((chain.flags & file_flags::Truncated) == 0);
    REQUIRE(chain.fragments.size() == chained.at("pieces").size());
    for (size_t i = 0; i < chain.fragments.size(); ++i) {
        CHECK(chain.fragments[i].offset == chained.at("pieces")[i].at("offset").get<uint64_t>());
        CHECK(chain.fragments[i].length == chained.at("pieces")[i].at("length").get<uint64_t>());
    }

    const std::vector<uint8_t> image = test::load_test_file(image_path);
    const auto concatenated = [&](const CarveHit& hit) {
        std::vector<uint8_t> bytes;
        for (const CarveFragment& fragment : hit.fragments) {
            bytes.insert(bytes.end(),
                         image.begin() + static_cast<std::ptrdiff_t>(fragment.offset),
                         image.begin() + static_cast<std::ptrdiff_t>(fragment.offset +
                                                                    fragment.length));
        }
        CHECK(bytes.size() == hit.length);
        CHECK(sha256_hex(bytes) == hit.sha256);
        return bytes;
    };
    const std::vector<uint8_t> joined_bytes = concatenated(joined);
    const std::vector<uint8_t> chain_bytes = concatenated(chain);

    test::TempDir out;
    auto sink = io::OutputSink::open(out.path(), io::SourceIdentity::image(image_path));
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, *device, *hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 3);
    CHECK(test::load_test_file((*written)[0].path) == joined_bytes);
    CHECK(test::load_test_file((*written)[2].path) == chain_bytes);

    options.reassemble = false;
    auto heads = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(heads.has_value());
    REQUIRE(heads->size() == 3);
    CHECK((*heads)[0].offset == joined.offset);
    CHECK((*heads)[0].length == joined_expected.at("prefix_length").get<uint64_t>());
    CHECK((*heads)[0].fragments.empty());
    CHECK((*heads)[1].offset == orphan_hit.offset);
    CHECK((*heads)[1].length == orphan_hit.length);
    CHECK((*heads)[1].fragments.empty());
    CHECK((*heads)[2].offset == chain.offset);
    CHECK((*heads)[2].length == chained.at("pieces")[0].at("length").get<uint64_t>());
    CHECK((*heads)[2].fragments.empty());
}

TEST_CASE("carve_fragmented_gif resyncs a GIF onto its surviving frames",
          "[M3][carve][fixture][fragment]") {
    if (std::string(OPENRECOVER_FIXTURE_DIR).empty())
        SKIP("carve fixture images were not generated (Python3 unavailable)");
    const auto image_path = fixture_image("carve_fragmented_gif.img");
    if (!std::filesystem::exists(image_path))
        SKIP("carve_fragmented_gif.img is missing from " << OPENRECOVER_FIXTURE_DIR);

    const json golden = load_golden("carve_fragmented_gif.golden.json");
    CHECK(test::sha256_of_file(image_path) == golden.at("image_sha256").get<std::string>());
    auto device = open_fixture(image_path);

    const json& joined_expected = golden.at("joined");
    const json& chained = golden.at("chained");
    const json& orphan = golden.at("orphan");

    CarveOptions options;
    options.scope = CarveOptions::Scope::All;
    options.reassemble = true;
    auto hits = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 3);

    const CarveHit& joined = (*hits)[0];
    CHECK(joined.offset == joined_expected.at("offset").get<uint64_t>());
    CHECK(joined.length == joined_expected.at("length").get<uint64_t>());
    CHECK(joined.type == joined_expected.at("type").get<std::string>());
    CHECK(joined.sha256 == joined_expected.at("sha256").get<std::string>());
    CHECK((joined.flags & file_flags::Fragmented) != 0);
    CHECK((joined.flags & file_flags::Truncated) == 0);
    REQUIRE(joined.fragments.size() == 2);
    CHECK(joined.fragments[0].offset == joined_expected.at("offset").get<uint64_t>());
    CHECK(joined.fragments[0].length == joined_expected.at("prefix_length").get<uint64_t>());
    CHECK(joined.fragments[1].offset == joined_expected.at("tail_offset").get<uint64_t>());
    CHECK(joined.fragments[1].length == joined_expected.at("tail_length").get<uint64_t>());

    // The orphan stops at the introducer in the fill; the chained GIF's signature is not a
    // tail, so its frames are not absorbed into this head.
    const CarveHit& orphan_hit = (*hits)[1];
    CHECK(orphan_hit.offset == orphan.at("offset").get<uint64_t>());
    CHECK(orphan_hit.length == orphan.at("length").get<uint64_t>());
    CHECK(orphan_hit.type == orphan.at("type").get<std::string>());
    CHECK(orphan_hit.fragments.empty());
    CHECK((orphan_hit.flags & file_flags::Truncated) != 0);

    const CarveHit& chain = (*hits)[2];
    CHECK(chain.offset == chained.at("offset").get<uint64_t>());
    CHECK(chain.length == chained.at("length").get<uint64_t>());
    CHECK(chain.type == chained.at("type").get<std::string>());
    CHECK(chain.sha256 == chained.at("sha256").get<std::string>());
    CHECK((chain.flags & file_flags::Fragmented) != 0);
    CHECK((chain.flags & file_flags::Truncated) == 0);
    REQUIRE(chain.fragments.size() == chained.at("pieces").size());
    for (size_t i = 0; i < chain.fragments.size(); ++i) {
        CHECK(chain.fragments[i].offset == chained.at("pieces")[i].at("offset").get<uint64_t>());
        CHECK(chain.fragments[i].length == chained.at("pieces")[i].at("length").get<uint64_t>());
    }

    const std::vector<uint8_t> image = test::load_test_file(image_path);
    const auto concatenated = [&](const CarveHit& hit) {
        std::vector<uint8_t> bytes;
        for (const CarveFragment& fragment : hit.fragments) {
            bytes.insert(bytes.end(),
                         image.begin() + static_cast<std::ptrdiff_t>(fragment.offset),
                         image.begin() + static_cast<std::ptrdiff_t>(fragment.offset +
                                                                    fragment.length));
        }
        CHECK(bytes.size() == hit.length);
        CHECK(sha256_hex(bytes) == hit.sha256);
        return bytes;
    };
    const std::vector<uint8_t> joined_bytes = concatenated(joined);
    const std::vector<uint8_t> chain_bytes = concatenated(chain);

    test::TempDir out;
    auto sink = io::OutputSink::open(out.path(), io::SourceIdentity::image(image_path));
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, *device, *hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 3);
    CHECK(test::load_test_file((*written)[0].path) == joined_bytes);
    CHECK(test::load_test_file((*written)[2].path) == chain_bytes);

    options.reassemble = false;
    auto heads = CarveEngine::run(*device, nullptr, options, {});
    REQUIRE(heads.has_value());
    REQUIRE(heads->size() == 3);
    CHECK((*heads)[0].offset == joined.offset);
    CHECK((*heads)[0].length == joined_expected.at("prefix_length").get<uint64_t>());
    CHECK((*heads)[0].fragments.empty());
    CHECK((*heads)[1].offset == orphan_hit.offset);
    CHECK((*heads)[1].length == orphan_hit.length);
    CHECK((*heads)[1].fragments.empty());
    CHECK((*heads)[2].offset == chain.offset);
    CHECK((*heads)[2].length == chained.at("pieces")[0].at("length").get<uint64_t>());
    CHECK((*heads)[2].fragments.empty());
}
