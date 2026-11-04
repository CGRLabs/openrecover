#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "jpeg_samples.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/carve_engine.hpp"
#include "openrecover/common/crc32.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/io/output_sink.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

class TestSignature final : public ISignature {
public:
    explicit TestSignature(Confidence confidence) : confidence_(confidence) {}

    std::string_view name() const override { return "test"; }

    std::span<const std::span<const uint8_t>> magics() const override {
        static const uint8_t magic[] = {'T', 'E', 'S', 'T'};
        static const std::span<const uint8_t> list[] = {magic};
        return list;
    }

    size_t min_header_bytes() const override { return 8; }
    uint64_t max_file_size() const override { return 1u << 20; }
    std::string_view default_extension() const override { return "tst"; }

    ValidationResult validate(BoundedReader& reader) const override {
        auto header = reader.read_vec(0, 8);
        if (!header || header->size() < 8) return ValidationResult::invalid();
        if (std::memcmp(header->data(), "TEST", 4) != 0) return ValidationResult::invalid();
        const uint32_t length = (static_cast<uint32_t>((*header)[4]) << 24) |
                                (static_cast<uint32_t>((*header)[5]) << 16) |
                                (static_cast<uint32_t>((*header)[6]) << 8) |
                                static_cast<uint32_t>((*header)[7]);
        if (length < 8 || length > reader.limit()) return ValidationResult::invalid();
        ValidationResult result;
        result.verdict = ValidationResult::Verdict::Valid;
        result.length_bytes = length;
        result.subtype = "unit";
        result.confidence = confidence_;
        return result;
    }

private:
    Confidence confidence_;
};

class FakeAllocationMap final : public fs::IAllocationMap {
public:
    FakeAllocationMap(uint64_t cluster_size, uint64_t anchor_offset, uint64_t cluster_count,
                      std::set<uint64_t> allocated)
        : cluster_size_(cluster_size),
          anchor_(anchor_offset),
          count_(cluster_count),
          allocated_(std::move(allocated)) {}

    bool is_cluster_allocated(uint64_t cluster) const override {
        return allocated_.find(cluster) != allocated_.end();
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

void place_candidate(std::vector<uint8_t>& image, uint64_t offset, uint32_t length) {
    image[offset] = 'T';
    image[offset + 1] = 'E';
    image[offset + 2] = 'S';
    image[offset + 3] = 'T';
    image[offset + 4] = static_cast<uint8_t>(length >> 24);
    image[offset + 5] = static_cast<uint8_t>(length >> 16);
    image[offset + 6] = static_cast<uint8_t>(length >> 8);
    image[offset + 7] = static_cast<uint8_t>(length);
    std::fill(image.begin() + static_cast<std::ptrdiff_t>(offset + 8),
              image.begin() + static_cast<std::ptrdiff_t>(offset + length), static_cast<uint8_t>(0x5A));
}

SignatureRegistry make_registry(const TestSignature& signature) {
    SignatureRegistry registry;
    registry.add(signature);
    return registry;
}

CarveOptions all_bytes_options() {
    CarveOptions options;
    options.scope = CarveOptions::Scope::All;
    options.alignment = 512;
    options.types = {"test"};
    return options;
}

}  // namespace

TEST_CASE("carve engine finds aligned candidates in order and hashes them", "[carve][m3]") {
    std::vector<uint8_t> image(64 * 1024, static_cast<uint8_t>(0xAA));
    place_candidate(image, 1024, 200);
    place_candidate(image, 4096, 96);

    test::MemoryDevice device(image);
    const TestSignature signature(Confidence::High);
    const SignatureRegistry registry = make_registry(signature);
    const CarveOptions options = all_bytes_options();

    auto hits = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 2);
    CHECK((*hits)[0].offset == 1024);
    CHECK((*hits)[0].length == 200);
    CHECK((*hits)[0].type == "test");
    CHECK((*hits)[0].subtype == "unit");
    CHECK((*hits)[0].confidence == Confidence::High);
    CHECK((*hits)[0].sha256 ==
          sha256_hex(std::span<const uint8_t>(image.data() + 1024, 200)));
    CHECK((*hits)[1].offset == 4096);
    CHECK((*hits)[1].length == 96);
}

TEST_CASE("carve engine only sees unaligned candidates in unaligned mode", "[carve][m3]") {
    std::vector<uint8_t> image(16 * 1024, static_cast<uint8_t>(0xAA));
    place_candidate(image, 1001, 128);

    test::MemoryDevice device(image);
    const TestSignature signature(Confidence::High);
    const SignatureRegistry registry = make_registry(signature);
    CarveOptions options = all_bytes_options();

    auto aligned = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(aligned.has_value());
    CHECK(aligned->empty());

    options.unaligned = true;
    auto unaligned = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(unaligned.has_value());
    REQUIRE(unaligned->size() == 1);
    CHECK((*unaligned)[0].offset == 1001);
    CHECK((*unaligned)[0].length == 128);
}

TEST_CASE("carve engine restricts UnallocatedOnly scans to free clusters", "[carve][m3]") {
    std::vector<uint8_t> image(32 * 1024, static_cast<uint8_t>(0xAA));
    place_candidate(image, 2048, 200);
    place_candidate(image, 5120, 200);

    test::MemoryDevice device(image);
    const TestSignature signature(Confidence::High);
    const SignatureRegistry registry = make_registry(signature);
    const FakeAllocationMap map(512, 1024, 64, {4});

    CarveOptions options = all_bytes_options();
    options.alignment = 0;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    auto restricted = CarveEngine::run(device, &map, options, {}, registry);
    REQUIRE(restricted.has_value());
    REQUIRE(restricted->size() == 1);
    CHECK((*restricted)[0].offset == 5120);

    options.scope = CarveOptions::Scope::All;
    auto everything = CarveEngine::run(device, &map, options, {}, registry);
    REQUIRE(everything.has_value());
    CHECK(everything->size() == 2);
}

TEST_CASE("carve engine nested mode reports candidates inside candidates", "[carve][m3]") {
    std::vector<uint8_t> image(16 * 1024, static_cast<uint8_t>(0xAA));
    place_candidate(image, 1024, 4096);
    place_candidate(image, 2048, 256);

    test::MemoryDevice device(image);
    const TestSignature signature(Confidence::High);
    const SignatureRegistry registry = make_registry(signature);
    CarveOptions options = all_bytes_options();

    auto outer_only = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(outer_only.has_value());
    REQUIRE(outer_only->size() == 1);
    CHECK((*outer_only)[0].offset == 1024);
    CHECK((*outer_only)[0].length == 4096);

    options.nested = true;
    auto nested = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(nested.has_value());
    REQUIRE(nested->size() == 2);
    CHECK((*nested)[0].offset == 1024);
    CHECK((*nested)[1].offset == 2048);
    CHECK((*nested)[1].length == 256);
}

TEST_CASE("carve engine marks hits already recovered from filesystem metadata", "[carve][m3]") {
    std::vector<uint8_t> image(16 * 1024, static_cast<uint8_t>(0xAA));
    place_candidate(image, 1024, 200);

    test::MemoryDevice device(image);
    const TestSignature signature(Confidence::High);
    const SignatureRegistry registry = make_registry(signature);
    CarveOptions options = all_bytes_options();

    RecoveredFile recovered;
    recovered.path = "DOCS/a.bin";
    recovered.confidence = Confidence::High;
    recovered.extents.push_back(Extent{1024, 200, false});
    std::vector<RecoveredFile> files{recovered};
    options.existing_files = &files;

    auto hits = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    CHECK((*hits)[0].duplicate_of == "DOCS/a.bin");

    files[0].confidence = Confidence::Medium;
    auto weak = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(weak.has_value());
    CHECK((*weak)[0].duplicate_of.empty());
}

TEST_CASE("carve engine honours the scan range and reports cancellation", "[carve][m3]") {
    std::vector<uint8_t> image(16 * 1024, static_cast<uint8_t>(0xAA));
    place_candidate(image, 1024, 200);
    place_candidate(image, 4096, 200);

    test::MemoryDevice device(image);
    const TestSignature signature(Confidence::High);
    const SignatureRegistry registry = make_registry(signature);
    CarveOptions options = all_bytes_options();
    options.start_byte = 2048;
    options.end_byte = 8192;

    auto ranged = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE(ranged.has_value());
    REQUIRE(ranged->size() == 1);
    CHECK((*ranged)[0].offset == 4096);

    options.start_byte = 0;
    options.end_byte = UINT64_MAX;
    auto cancelled = CarveEngine::run(
        device, nullptr, options, [](uint64_t, uint64_t) { return false; }, registry);
    REQUIRE_FALSE(cancelled.has_value());
    CHECK(cancelled.error().code == ErrorCode::Cancelled);
}

TEST_CASE("carve engine rejects unknown types and propagates device errors", "[carve][m3]") {
    std::vector<uint8_t> image(16 * 1024, static_cast<uint8_t>(0xAA));
    test::MemoryDevice device(image);
    const TestSignature signature(Confidence::High);
    const SignatureRegistry registry = make_registry(signature);

    CarveOptions options = all_bytes_options();
    options.types = {"does-not-exist"};
    auto unknown = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE_FALSE(unknown.has_value());
    CHECK(unknown.error().code == ErrorCode::InvalidArgument);

    options.types = {"test"};
    device.fail_at(0);
    auto failed = CarveEngine::run(device, nullptr, options, {}, registry);
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().code == ErrorCode::IoError);
}

namespace {

void put_le16(std::vector<uint8_t>& out, size_t off, uint16_t v) {
    out[off] = static_cast<uint8_t>(v & 0xFF);
    out[off + 1] = static_cast<uint8_t>(v >> 8);
}

void put_le32(std::vector<uint8_t>& out, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) out[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

void put_be32(std::vector<uint8_t>& out, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) out[off + i] = static_cast<uint8_t>((v >> (8 * (3 - i))) & 0xFF);
}

void place_bytes(std::vector<uint8_t>& image, uint64_t offset, const std::vector<uint8_t>& bytes) {
    std::copy(bytes.begin(), bytes.end(), image.begin() + static_cast<std::ptrdiff_t>(offset));
}

std::vector<uint8_t> build_sqlite_bytes(uint32_t pages) {
    std::vector<uint8_t> out(4096ull * pages, 0);
    std::memcpy(out.data(), "SQLite format 3\0", 16);
    out[16] = 0x10;  // 4096-byte pages
    put_be32(out, 24, 7);
    put_be32(out, 28, pages);
    put_be32(out, 92, 7);
    return out;
}

std::vector<uint8_t> build_tiff_bytes() {
    std::vector<uint8_t> out(50, 0);
    out[0] = 'I';
    out[1] = 'I';
    out[2] = 42;
    put_le32(out, 4, 8);   // first IFD
    out[8] = 1;            // one entry
    put_le16(out, 10, 0x011A);
    put_le16(out, 12, 2);  // ASCII
    put_le32(out, 14, 20);
    put_le32(out, 18, 30);  // stored out of line, ending at byte 50
    put_le32(out, 22, 0);   // end of the IFD chain
    return out;
}

std::vector<uint8_t> build_wav_bytes() {
    std::vector<uint8_t> out(144, 0);
    std::memcpy(out.data(), "RIFF", 4);
    put_le32(out, 4, static_cast<uint32_t>(out.size() - 8));
    std::memcpy(out.data() + 8, "WAVE", 4);
    std::memcpy(out.data() + 12, "fmt ", 4);
    put_le32(out, 16, 16);
    std::memcpy(out.data() + 36, "data", 4);
    put_le32(out, 40, 100);
    return out;
}

CarveOptions builtin_options(std::set<std::string> types) {
    CarveOptions options;
    options.scope = CarveOptions::Scope::All;
    options.alignment = 512;
    options.types = std::move(types);
    return options;
}

std::vector<uint8_t> mp4_box(std::string_view type, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> out(8 + body.size(), 0);
    put_be32(out, 0, static_cast<uint32_t>(out.size()));
    std::memcpy(out.data() + 4, type.data(), 4);
    std::memcpy(out.data() + 8, body.data(), body.size());
    return out;
}

std::vector<uint8_t> mp4_filled_box(std::string_view type, size_t body_bytes, uint8_t seed) {
    std::vector<uint8_t> body(body_bytes);
    for (size_t i = 0; i < body_bytes; ++i) body[i] = static_cast<uint8_t>((i * seed) & 0xFF);
    return mp4_box(type, body);
}

void append(std::vector<uint8_t>& out, const std::vector<uint8_t>& part) {
    out.insert(out.end(), part.begin(), part.end());
}

// ftyp + moov + mdat, the layout every brand in the family shares.
std::vector<uint8_t> build_mp4_bytes(std::string_view major, std::string_view brand) {
    std::vector<uint8_t> ftyp_body(8 + (brand.empty() ? 0 : 4), 0);
    std::memcpy(ftyp_body.data(), major.data(), 4);
    put_be32(ftyp_body, 4, 0x200000);
    if (!brand.empty()) std::memcpy(ftyp_body.data() + 8, brand.data(), 4);
    std::vector<uint8_t> out = mp4_box("ftyp", ftyp_body);
    append(out, mp4_filled_box("moov", 16, 11));
    append(out, mp4_filled_box("mdat", 64, 7));
    return out;
}

// A RIFF AVI: the same opening magic as the wave above, a different form type at byte 8.
std::vector<uint8_t> riff_chunk(std::string_view id, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out(8 + payload.size(), 0);
    std::memcpy(out.data(), id.data(), 4);
    put_le32(out, 4, static_cast<uint32_t>(payload.size()));
    if (!payload.empty()) std::memcpy(out.data() + 8, payload.data(), payload.size());
    if (payload.size() % 2) out.push_back(0);  // chunks are word aligned
    return out;
}

std::vector<uint8_t> riff_list(std::string_view form, const std::vector<uint8_t>& inner) {
    std::vector<uint8_t> payload(form.begin(), form.end());
    payload.insert(payload.end(), inner.begin(), inner.end());
    return riff_chunk("LIST", payload);
}

std::vector<uint8_t> build_avi_bytes() {
    std::vector<uint8_t> avih(60, 0);
    put_le32(avih, 0, 33333);  // microseconds per frame
    put_le32(avih, 16, 3);     // frames
    std::vector<uint8_t> frames;
    for (size_t i = 0; i < 3; ++i) {
        const std::vector<uint8_t> one(128, static_cast<uint8_t>(0x30 + i));
        append(frames, riff_chunk("00dc", one));
    }
    std::vector<uint8_t> index(3 * 16, 0);
    for (size_t i = 0; i < 3; ++i) put_le32(index, i * 16, 128);

    std::vector<uint8_t> out(12, 0);
    std::memcpy(out.data(), "RIFF", 4);
    std::memcpy(out.data() + 8, "AVI ", 4);
    append(out, riff_list("hdrl", riff_chunk("avih", avih)));
    append(out, riff_list("movi", frames));
    append(out, riff_chunk("idx1", index));
    put_le32(out, 4, static_cast<uint32_t>(out.size() - 8));
    return out;
}

// MPEG audio is a run of frames that each say how long they are; 128 kbit/s at 44.1 kHz is 417
// bytes a frame, which is what lets a walk land on the next header.
std::vector<uint8_t> build_mp3_bytes(size_t frames) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < frames; ++i) {
        std::vector<uint8_t> frame(417, 0);
        frame[0] = 0xFF;
        frame[1] = 0xFB;  // MPEG 1, Layer III, no CRC
        frame[2] = 0x90;  // 128 kbit/s, 44.1 kHz
        frame[3] = 0x44;
        for (size_t b = 4; b < frame.size(); ++b) frame[b] = static_cast<uint8_t>((b * 7) & 0xFF);
        append(out, frame);
    }
    return out;
}

// A compound file carries no length of its own: the allocation table is what says where it ends.
std::vector<uint8_t> build_cfb_bytes(size_t stream_bytes, std::string_view stream_name) {
    const size_t data_sectors = (stream_bytes + 511) / 512;
    std::vector<uint8_t> out(512 + (2 + data_sectors) * 512, 0);
    std::memcpy(out.data(), "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8);
    out[0x18] = 0x3E;                    // minor version
    out[0x1A] = 0x03;                    // version 3, which stores 512-byte sectors
    out[0x1C] = 0xFE;                    // the byte-order mark every producer writes
    out[0x1D] = 0xFF;
    out[0x1E] = 0x09;
    out[0x20] = 0x06;
    put_le32(out, 0x2C, 1);              // one table sector covers the whole file
    put_le32(out, 0x30, 1);              // the directory is the sector after it
    put_le32(out, 0x38, 4096);           // the mini stream cutoff
    put_le32(out, 0x3C, 0xFFFFFFFEu);    // no mini stream: the document is larger than the cutoff
    put_le32(out, 0x44, 0xFFFFFFFEu);    // and one table sector needs no map of its own
    for (size_t i = 0; i < 109; ++i) put_le32(out, 0x4C + i * 4, i == 0 ? 0u : 0xFFFFFFFFu);

    for (size_t i = 0; i < 128; ++i) put_le32(out, 512 + i * 4, 0xFFFFFFFFu);
    put_le32(out, 512, 0xFFFFFFFDu);  // sector 0 is the table
    put_le32(out, 516, 0xFFFFFFFEu);  // sector 1 is the directory, and the only one
    for (size_t i = 0; i < data_sectors; ++i) {
        put_le32(out, 512 + (2 + i) * 4,
                 i + 1 < data_sectors ? static_cast<uint32_t>(3 + i) : 0xFFFFFFFEu);
    }

    const auto put_entry = [&](size_t at, std::string_view name, uint8_t type, uint32_t start,
                               uint32_t size, uint32_t child, uint32_t right) {
        for (size_t i = 0; i < name.size(); ++i) out[at + i * 2] = static_cast<uint8_t>(name[i]);
        out[at + 0x40] = static_cast<uint8_t>((name.size() + 1) * 2);
        out[at + 0x42] = type;
        out[at + 0x43] = 1;
        for (size_t i = 0; i < 4; ++i) out[at + 0x44 + i] = 0xFF;  // no left sibling
        put_le32(out, at + 0x48, right);
        put_le32(out, at + 0x4C, child);
        put_le32(out, at + 0x74, start);
        put_le32(out, at + 0x78, size);
    };
    const size_t dir = 1024;
    put_entry(dir, "Root Entry", 5, 0xFFFFFFFEu, 0, 1, 0xFFFFFFFFu);
    put_entry(dir + 128, stream_name, 2, 2, static_cast<uint32_t>(stream_bytes), 0xFFFFFFFFu,
              0xFFFFFFFFu);
    for (size_t i = 0; i < stream_bytes; ++i)
        out[dir + 512 + i] = static_cast<uint8_t>((i * 5) & 0xFF);
    return out;
}

}  // namespace

TEST_CASE("built-in signatures are sized by their own metadata, not by the scan window",
          "[carve][m3][signatures]") {
    constexpr uint64_t kSqliteOffset = 4096;
    constexpr uint64_t kTiffOffset = 20480;
    constexpr uint64_t kWavOffset = 24576;

    const auto database = build_sqlite_bytes(2);
    const auto tiff = build_tiff_bytes();
    const auto wav = build_wav_bytes();

    std::vector<uint8_t> image(128 * 1024, static_cast<uint8_t>(0xAA));
    place_bytes(image, kSqliteOffset, database);
    place_bytes(image, kTiffOffset, tiff);
    place_bytes(image, kWavOffset, wav);

    test::MemoryDevice device(image);
    CarveOptions options = builtin_options({"sqlite", "tiff", "wav"});
    // The scan stops 100 bytes past the last file, so the room left after the database is not
    // a whole number of pages. Window arithmetic used to make that file invisible.
    options.end_byte = kWavOffset + wav.size() + 100;

    auto hits = CarveEngine::run(device, nullptr, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 3);
    CHECK((*hits)[0].offset == kSqliteOffset);
    CHECK((*hits)[0].type == "sqlite");
    CHECK((*hits)[0].length == database.size());
    CHECK((*hits)[0].confidence == Confidence::High);
    CHECK((*hits)[1].offset == kTiffOffset);
    CHECK((*hits)[1].type == "tiff");
    CHECK((*hits)[1].length == tiff.size());
    CHECK((*hits)[2].offset == kWavOffset);
    CHECK((*hits)[2].type == "wav");
    CHECK((*hits)[2].length == wav.size());
    for (const CarveHit& hit : *hits) {
        CHECK((hit.flags & file_flags::Truncated) == 0);
        CHECK(hit.sha256 ==
              sha256_hex(std::span<const uint8_t>(image.data() + hit.offset, hit.length)));
    }
}

TEST_CASE("a built-in candidate running past the scan range is flagged truncated",
          "[carve][m3][signatures]") {
    const auto database = build_sqlite_bytes(4);  // declares 16 KiB
    std::vector<uint8_t> image(32 * 1024, static_cast<uint8_t>(0xAA));
    place_bytes(image, 4096, database);

    test::MemoryDevice device(image);
    CarveOptions options = builtin_options({"sqlite"});
    options.end_byte = 4096 + 8192 + 100;  // two pages and part of the third

    auto hits = CarveEngine::run(device, nullptr, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    CHECK((*hits)[0].length == 8192);
    CHECK((*hits)[0].confidence == Confidence::Low);
    CHECK((*hits)[0].flags & file_flags::Truncated);
}

TEST_CASE("the scan finds a magic that sits past the start of the file", "[carve][m3][signatures]") {
    constexpr uint64_t kClipOffset = 8192;
    constexpr uint64_t kMovieOffset = 20480;
    constexpr uint64_t kStrayOffset = 32768;

    const auto clip = build_mp4_bytes("isom", "mp42");
    const auto movie = build_mp4_bytes("qt  ", "");
    std::vector<uint8_t> image(128 * 1024, static_cast<uint8_t>(0xAA));
    place_bytes(image, kClipOffset, clip);
    place_bytes(image, kMovieOffset, movie);
    // A brand nobody recognises stays invisible, even though the header itself is well formed.
    place_bytes(image, kStrayOffset, build_mp4_bytes("WXYZ", "ABCD"));

    test::MemoryDevice device(image);
    CarveOptions options = builtin_options({"mp4"});
    auto hits = CarveEngine::run(device, nullptr, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 2);
    CHECK((*hits)[0].offset == kClipOffset);
    CHECK((*hits)[0].type == "mp4");
    CHECK((*hits)[0].subtype == "mp4");
    CHECK((*hits)[0].length == clip.size());
    CHECK((*hits)[1].offset == kMovieOffset);
    CHECK((*hits)[1].subtype == "mov");
    CHECK((*hits)[1].length == movie.size());
    for (const CarveHit& hit : *hits) {
        CHECK(hit.confidence == Confidence::High);
        CHECK((hit.flags & file_flags::Truncated) == 0);
        CHECK(hit.sha256 ==
              sha256_hex(std::span<const uint8_t>(image.data() + hit.offset, hit.length)));
    }

    // One signature, several families: the brand decides the extension the exporter writes.
    test::TempDir dir;
    auto sink = io::OutputSink::open(dir.path(), io::SourceIdentity{});
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, device, *hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 2);
    CHECK((*written)[0].relative == "carved/mp4/0000000000002000_" + std::to_string(clip.size()) + ".mp4");
    CHECK((*written)[1].relative == "carved/mp4/0000000000005000_" + std::to_string(movie.size()) + ".mov");
}

TEST_CASE("a wave and an AVI that share their magic are told apart", "[carve][m3][signatures]") {
    constexpr uint64_t kWavOffset = 4096;
    constexpr uint64_t kAviOffset = 12288;
    constexpr uint64_t kMp3Offset = 20480;

    const auto wav = build_wav_bytes();
    const auto avi = build_avi_bytes();
    const auto audio = build_mp3_bytes(24);
    std::vector<uint8_t> image(128 * 1024, static_cast<uint8_t>(0xAA));
    place_bytes(image, kWavOffset, wav);
    place_bytes(image, kAviOffset, avi);
    place_bytes(image, kMp3Offset, audio);

    test::MemoryDevice device(image);
    CarveOptions options = builtin_options({"wav", "avi", "mp3"});
    auto hits = CarveEngine::run(device, nullptr, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 3);
    CHECK((*hits)[0].type == "wav");
    CHECK((*hits)[0].length == wav.size());
    CHECK((*hits)[1].offset == kAviOffset);
    CHECK((*hits)[1].type == "avi");
    CHECK((*hits)[1].subtype == "avi");
    CHECK((*hits)[1].length == avi.size());
    CHECK((*hits)[2].offset == kMp3Offset);
    CHECK((*hits)[2].type == "mp3");
    // The frames are walked, not guessed at: the hit ends where the stream does.
    CHECK((*hits)[2].length == audio.size());
    for (const CarveHit& hit : *hits) {
        CHECK(hit.confidence == Confidence::High);
        CHECK((hit.flags & file_flags::Truncated) == 0);
        CHECK(hit.sha256 ==
              sha256_hex(std::span<const uint8_t>(image.data() + hit.offset, hit.length)));
    }

    test::TempDir dir;
    auto sink = io::OutputSink::open(dir.path(), io::SourceIdentity{});
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, device, *hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 3);
    CHECK((*written)[1].relative == "carved/avi/0000000000003000_" + std::to_string(avi.size()) + ".avi");
    CHECK((*written)[2].relative == "carved/mp3/0000000000005000_" + std::to_string(audio.size()) + ".mp3");
}

TEST_CASE("a compound document is sized by its sector table and named by its stream",
          "[carve][m3][signatures]") {
    constexpr uint64_t kDocOffset = 4096;
    constexpr uint64_t kGenericOffset = 20480;

    const auto document = build_cfb_bytes(8192, "WordDocument");
    const auto container = build_cfb_bytes(4096, "\x01" "CompObj");
    std::vector<uint8_t> image(128 * 1024, static_cast<uint8_t>(0xAA));
    place_bytes(image, kDocOffset, document);
    place_bytes(image, kGenericOffset, container);

    test::MemoryDevice device(image);
    CarveOptions options = builtin_options({"cfb"});
    auto hits = CarveEngine::run(device, nullptr, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 2);
    CHECK((*hits)[0].offset == kDocOffset);
    CHECK((*hits)[0].type == "cfb");
    CHECK((*hits)[0].subtype == "doc");
    // Nothing in the container stores its own length; the table's free sectors end the file.
    CHECK((*hits)[0].length == document.size());
    CHECK((*hits)[1].offset == kGenericOffset);
    CHECK((*hits)[1].subtype == "cfb");
    for (const CarveHit& hit : *hits) {
        CHECK((hit.flags & file_flags::Truncated) == 0);
        CHECK(hit.sha256 ==
              sha256_hex(std::span<const uint8_t>(image.data() + hit.offset, hit.length)));
    }
    CHECK((*hits)[0].confidence == Confidence::High);
    CHECK((*hits)[1].confidence == Confidence::Medium);

    // The stream the directory lists decides the extension, the same way the brand does for video.
    test::TempDir dir;
    auto sink = io::OutputSink::open(dir.path(), io::SourceIdentity{});
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, device, *hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 2);
    CHECK((*written)[0].relative ==
          "carved/cfb/0000000000001000_" + std::to_string(document.size()) + ".doc");
    CHECK((*written)[1].relative ==
          "carved/cfb/0000000000005000_" + std::to_string(container.size()) + ".cfb");
}

TEST_CASE("export_hits streams carved bytes through the OutputSink", "[carve][m3]") {
    std::vector<uint8_t> image(16 * 1024, static_cast<uint8_t>(0xAA));
    place_candidate(image, 1024, 200);
    place_candidate(image, 4096, 96);
    test::MemoryDevice device(image);

    std::vector<CarveHit> hits(2);
    hits[0].offset = 1024;
    hits[0].length = 200;
    hits[0].type = "test";
    hits[0].subtype = "unit";
    hits[1].offset = 4096;
    hits[1].length = 96;
    hits[1].type = "test";
    hits[1].duplicate_of = "DOCS/b.bin";

    test::TempDir dir;
    auto sink = io::OutputSink::open(dir.path(), io::SourceIdentity{});
    REQUIRE(sink.has_value());

    auto written = export_hits(**sink, device, hits, true);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 1);
    CHECK((*written)[0].relative == "carved/test/0000000000000400_200.bin");
    CHECK((*written)[0].size == 200);
    CHECK((*written)[0].sha256 == sha256_hex(std::span<const uint8_t>(image.data() + 1024, 200)));
    const std::vector<uint8_t> extracted = test::load_test_file((*written)[0].path);
    CHECK(extracted ==
          std::vector<uint8_t>(image.begin() + 1024, image.begin() + 1024 + 200));

    test::TempDir dir_all;
    auto sink_all = io::OutputSink::open(dir_all.path(), io::SourceIdentity{});
    REQUIRE(sink_all.has_value());
    auto all = export_hits(**sink_all, device, hits, false);
    REQUIRE(all.has_value());
    CHECK(all->size() == 2);
}

namespace {

std::vector<uint8_t> long_jpeg(size_t entropy_bytes) {
    std::vector<uint8_t> bytes = test::make_jpeg();
    bytes.insert(bytes.end() - 2, entropy_bytes, static_cast<uint8_t>(0x42));
    return bytes;
}

void append_png_chunk(std::vector<uint8_t>& png, const char type[5],
                      const std::vector<uint8_t>& data) {
    const uint32_t length = static_cast<uint32_t>(data.size());
    png.push_back(static_cast<uint8_t>(length >> 24));
    png.push_back(static_cast<uint8_t>(length >> 16));
    png.push_back(static_cast<uint8_t>(length >> 8));
    png.push_back(static_cast<uint8_t>(length));
    const size_t crc_at = png.size();
    png.insert(png.end(), type, type + 4);
    png.insert(png.end(), data.begin(), data.end());
    const uint32_t crc = crc32_update(0, png.data() + crc_at, 4 + data.size());
    png.push_back(static_cast<uint8_t>(crc >> 24));
    png.push_back(static_cast<uint8_t>(crc >> 16));
    png.push_back(static_cast<uint8_t>(crc >> 8));
    png.push_back(static_cast<uint8_t>(crc));
}

std::vector<uint8_t> zlib_stored(const std::vector<uint8_t>& raw) {
    std::vector<uint8_t> out{0x78, 0x01};
    size_t pos = 0;
    do {
        const size_t n = std::min<size_t>(65535, raw.size() - pos);
        const bool final_block = pos + n == raw.size();
        out.push_back(final_block ? 0x01 : 0x00);
        out.push_back(static_cast<uint8_t>(n));
        out.push_back(static_cast<uint8_t>(n >> 8));
        const uint16_t nlen = static_cast<uint16_t>(~static_cast<uint16_t>(n));
        out.push_back(static_cast<uint8_t>(nlen));
        out.push_back(static_cast<uint8_t>(nlen >> 8));
        out.insert(out.end(), raw.begin() + static_cast<std::ptrdiff_t>(pos),
                   raw.begin() + static_cast<std::ptrdiff_t>(pos + n));
        pos += n;
    } while (pos < raw.size());
    const uint32_t adler = adler32_update(1, raw.data(), raw.size());
    out.push_back(static_cast<uint8_t>(adler >> 24));
    out.push_back(static_cast<uint8_t>(adler >> 16));
    out.push_back(static_cast<uint8_t>(adler >> 8));
    out.push_back(static_cast<uint8_t>(adler));
    return out;
}

// A deterministic 512x8 RGBA PNG (~16 KiB of rows) split into 4 KiB IDAT chunks, so a cut has
// real chunk boundaries to resync onto on either side.
std::vector<uint8_t> long_png() {
    constexpr uint32_t kWidth = 512;
    constexpr uint32_t kHeight = 8;
    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(kHeight) * (1 + kWidth * 4));
    uint8_t value = 0;
    for (uint32_t y = 0; y < kHeight; ++y) {
        raw.push_back(0);
        for (uint32_t i = 0; i < kWidth * 4; ++i) raw.push_back(static_cast<uint8_t>(value++));
    }

    std::vector<uint8_t> png{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    std::vector<uint8_t> ihdr{static_cast<uint8_t>(kWidth >> 24), static_cast<uint8_t>(kWidth >> 16),
                              static_cast<uint8_t>(kWidth >> 8), static_cast<uint8_t>(kWidth),
                              static_cast<uint8_t>(kHeight >> 24),
                              static_cast<uint8_t>(kHeight >> 16),
                              static_cast<uint8_t>(kHeight >> 8), static_cast<uint8_t>(kHeight),
                              8, 6, 0, 0, 0};
    append_png_chunk(png, "IHDR", ihdr);
    const std::vector<uint8_t> stream = zlib_stored(raw);
    constexpr size_t kIdatBytes = 4096;
    for (size_t start = 0; start < stream.size(); start += kIdatBytes) {
        const size_t end = std::min(start + kIdatBytes, stream.size());
        append_png_chunk(png, "IDAT",
                         std::vector<uint8_t>(stream.begin() + static_cast<std::ptrdiff_t>(start),
                                              stream.begin() + static_cast<std::ptrdiff_t>(end)));
    }
    append_png_chunk(png, "IEND", {});
    return png;
}

uint32_t png_be32(const std::vector<uint8_t>& bytes, uint64_t at) {
    return (static_cast<uint32_t>(bytes[at]) << 24) |
           (static_cast<uint32_t>(bytes[at + 1]) << 16) |
           (static_cast<uint32_t>(bytes[at + 2]) << 8) | static_cast<uint32_t>(bytes[at + 3]);
}

void append_u16le(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>(value >> 8));
}

// GIF LZW packs codes least-significant bit first. The code width grows after a
// code is emitted, not when the dictionary entry is inserted, matching giflib.
std::vector<uint8_t> lzw_encode(const std::vector<uint8_t>& pixels, uint8_t min_code_size) {
    const int clear = 1 << min_code_size;
    const int end = clear + 1;
    int next = clear + 2;
    int code_size = static_cast<int>(min_code_size) + 1;
    uint32_t bit_buffer = 0;
    int bit_count = 0;
    std::vector<uint8_t> out;

    auto put = [&](int code) {
        bit_buffer |= static_cast<uint32_t>(code) << bit_count;
        bit_count += code_size;
        while (bit_count >= 8) {
            out.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));
            bit_buffer >>= 8;
            bit_count -= 8;
        }
        if (next >= (1 << code_size) && code_size < 12) ++code_size;
    };

    std::map<uint32_t, int> dictionary;
    auto key = [](int prefix, uint8_t suffix) {
        return (static_cast<uint32_t>(prefix) << 8) | suffix;
    };

    put(clear);
    int w = pixels.empty() ? 0 : pixels[0];
    for (size_t i = 1; i < pixels.size(); ++i) {
        const uint8_t k = pixels[i];
        const auto it = dictionary.find(key(w, k));
        if (it != dictionary.end()) {
            w = it->second;
            continue;
        }
        put(w);
        if (next < 4096) {
            dictionary[key(w, k)] = next++;
        } else {
            put(clear);
            dictionary.clear();
            next = clear + 2;
            code_size = static_cast<int>(min_code_size) + 1;
        }
        w = k;
    }
    put(w);
    put(end);
    if (bit_count > 0) out.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));
    return out;
}

void append_subblocks(std::vector<uint8_t>& out, const std::vector<uint8_t>& data) {
    size_t pos = 0;
    while (pos < data.size()) {
        const size_t n = std::min<size_t>(255, data.size() - pos);
        out.push_back(static_cast<uint8_t>(n));
        out.insert(out.end(), data.begin() + static_cast<std::ptrdiff_t>(pos),
                   data.begin() + static_cast<std::ptrdiff_t>(pos + n));
        pos += n;
    }
    out.push_back(0);
}

// A deterministic three-frame GIF whose frames are large enough that a cut leaves
// real block boundaries to resync onto on either side.
std::vector<uint8_t> long_gif() {
    constexpr uint16_t kWidth = 256;
    constexpr uint16_t kHeight = 64;
    std::vector<uint8_t> gif{'G', 'I', 'F', '8', '9', 'a'};
    append_u16le(gif, kWidth);
    append_u16le(gif, kHeight);
    gif.push_back(0x80);  // global color table, two entries
    gif.push_back(0);
    gif.push_back(0);
    const uint8_t palette[] = {0, 0, 0, 255, 255, 255};
    gif.insert(gif.end(), palette, palette + sizeof palette);

    for (int frame = 0; frame < 3; ++frame) {
        const uint8_t gce[] = {0x21, 0xF9, 0x04, 0x00, 0x0A, 0x00, 0x00, 0x00};
        gif.insert(gif.end(), gce, gce + sizeof gce);
        gif.push_back(0x2C);
        append_u16le(gif, 0);
        append_u16le(gif, 0);
        append_u16le(gif, kWidth);
        append_u16le(gif, kHeight);
        gif.push_back(0x00);
        gif.push_back(2);  // minimum code size
        // Quasi-random pixel values keep the LZW streams poor at compressing, so each
        // frame's data spans many sub-blocks and a cut has room to land mid-stream.
        uint32_t state = 0x1234567u * static_cast<uint32_t>(frame + 1);
        std::vector<uint8_t> pixels;
        pixels.reserve(static_cast<size_t>(kWidth) * kHeight);
        for (uint16_t y = 0; y < kHeight; ++y) {
            for (uint16_t x = 0; x < kWidth; ++x) {
                state = state * 1664525u + 1013904223u;
                pixels.push_back(static_cast<uint8_t>((state >> 16) & 3u));
            }
        }
        append_subblocks(gif, lzw_encode(pixels, 2));
    }
    gif.push_back(0x3B);
    return gif;
}

// Offsets of the top-level block introducers, for choosing cuts on block boundaries.
std::vector<uint64_t> gif_block_offsets(const std::vector<uint8_t>& gif) {
    std::vector<uint64_t> blocks;
    uint64_t pos = 13;
    if (gif[10] & 0x80) pos += 3ull * (2u << (gif[10] & 0x07));
    while (pos < gif.size()) {
        blocks.push_back(pos);
        const uint8_t type = gif[pos];
        ++pos;
        if (type == 0x3B) break;
        if (type == 0x2C) {
            const uint8_t packed = gif[pos + 8];
            pos += 9;
            if (packed & 0x80) pos += 3ull * (2u << (packed & 0x07));
            ++pos;  // minimum code size
            while (gif[pos] != 0) pos += 1 + gif[pos];
            ++pos;
        } else {  // extension: label, then a sub-block chain
            ++pos;
            while (gif[pos] != 0) pos += 1 + gif[pos];
            ++pos;
        }
    }
    return blocks;
}

}  // namespace

TEST_CASE("carve engine reassembles a JPEG whose scan resumes across a gap",
          "[carve][m3][fragment]") {
    const std::vector<uint8_t> full = long_jpeg(4096);
    const uint64_t cut = full.size() - 2 - 2000;
    constexpr uint64_t kCluster = 4096;
    const uint64_t prefix_at = 3 * kCluster;
    const uint64_t tail_at = ((prefix_at + cut + kCluster - 1) / kCluster) * kCluster;

    std::vector<uint8_t> image(256 * 1024, static_cast<uint8_t>(0x5A));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut),
              image.begin() + static_cast<std::ptrdiff_t>(prefix_at));
    image[prefix_at + cut] = 0xFF;
    image[prefix_at + cut + 1] = 0x02;
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(cut), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(tail_at));

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.alignment = 0;
    options.reassemble = true;
    options.types = {"jpeg"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    const CarveHit& hit = hits->front();
    CHECK(hit.offset == prefix_at);
    CHECK(hit.length == full.size());
    REQUIRE(hit.fragments.size() == 2);
    CHECK(hit.fragments[0].offset == prefix_at);
    CHECK(hit.fragments[0].length == cut);
    CHECK(hit.fragments[1].offset == tail_at);
    CHECK(hit.fragments[1].length == full.size() - cut);
    CHECK((hit.flags & file_flags::Fragmented) != 0);
    CHECK((hit.flags & file_flags::Truncated) == 0);
    CHECK(hit.sha256 == sha256_hex(full));

    test::TempDir out;
    auto sink = io::OutputSink::open(out.path(), io::SourceIdentity::image("reassembly-test.img"));
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, device, *hits, false);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 1);
    CHECK(test::load_test_file((*written)[0].path) == full);
}

TEST_CASE("carve engine stitches a JPEG split into several pieces", "[carve][m3][fragment]") {
    constexpr uint64_t kCluster = 4096;
    const std::vector<uint8_t> full = long_jpeg(20480);
    const uint64_t cuts[] = {3000, 9000, 14000};
    REQUIRE(full.size() > cuts[2] + kCluster);

    const uint64_t head_at = 3 * kCluster;
    std::vector<uint8_t> image(256 * 1024, static_cast<uint8_t>(0x5A));
    std::vector<CarveFragment> expected;
    uint64_t source = 0;
    uint64_t at = head_at;
    for (const uint64_t cut : cuts) {
        const uint64_t length = cut - source;
        std::copy(full.begin() + static_cast<std::ptrdiff_t>(source),
                  full.begin() + static_cast<std::ptrdiff_t>(cut),
                  image.begin() + static_cast<std::ptrdiff_t>(at));
        expected.push_back({at, length});
        image[at + length] = 0xFF;
        image[at + length + 1] = 0x02;
        at = ((at + length + 2 + kCluster - 1) / kCluster) * kCluster;
        source = cut;
    }
    const uint64_t tail_length = full.size() - source;
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(source), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(at));
    expected.push_back({at, tail_length});

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.reassemble = true;
    options.types = {"jpeg"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    const CarveHit& hit = hits->front();
    CHECK(hit.offset == head_at);
    CHECK(hit.length == full.size());
    REQUIRE(hit.fragments.size() == expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        CHECK(hit.fragments[i].offset == expected[i].offset);
        CHECK(hit.fragments[i].length == expected[i].length);
    }
    CHECK((hit.flags & file_flags::Fragmented) != 0);
    CHECK((hit.flags & file_flags::Truncated) == 0);
    CHECK(hit.sha256 == sha256_hex(full));

    test::TempDir out;
    auto sink = io::OutputSink::open(out.path(), io::SourceIdentity::image("chain-test.img"));
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, device, *hits, false);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 1);
    CHECK(test::load_test_file((*written)[0].path) == full);
}

TEST_CASE("carve engine drops a chain that never reaches its terminator",
          "[carve][m3][fragment]") {
    constexpr uint64_t kCluster = 4096;
    const std::vector<uint8_t> full = long_jpeg(8192);
    const uint64_t cut = 3000;
    const uint64_t second = 8000;
    const uint64_t head_at = 3 * kCluster;
    const uint64_t second_at = ((head_at + cut + 2 + kCluster - 1) / kCluster) * kCluster;

    std::vector<uint8_t> image(128 * 1024, static_cast<uint8_t>(0x5A));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut),
              image.begin() + static_cast<std::ptrdiff_t>(head_at));
    image[head_at + cut] = 0xFF;
    image[head_at + cut + 1] = 0x02;
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(cut),
              full.begin() + static_cast<std::ptrdiff_t>(second),
              image.begin() + static_cast<std::ptrdiff_t>(second_at));
    image[second_at + second - cut] = 0xFF;
    image[second_at + second - cut + 1] = 0x02;

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.reassemble = true;
    options.types = {"jpeg"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    CHECK(hits->front().offset == head_at);
    CHECK(hits->front().length == cut);
    CHECK(hits->front().fragments.empty());
    CHECK((hits->front().flags & file_flags::Truncated) != 0);
}

TEST_CASE("carve engine resyncs a PNG onto its surviving chunk run", "[carve][m3][fragment]") {
    constexpr uint64_t kCluster = 4096;
    const std::vector<uint8_t> full = long_png();
    uint64_t containing = 0;
    uint64_t data_start = 0;
    uint64_t data_length = 0;
    for (uint64_t pos = 8; pos + 12 <= full.size();) {
        const uint64_t length = png_be32(full, pos);
        if (full.size() / 2 >= pos && full.size() / 2 < pos + 12 + length) {
            containing = pos;
            data_start = pos + 8;
            data_length = length;
            break;
        }
        pos += 12 + length;
    }
    CAPTURE(full.size(), containing, data_start, data_length);
    REQUIRE(containing != 0);
    REQUIRE(data_length >= kCluster);

    uint64_t cut = data_start + data_length / 2;
    // A cut on the allocation grid would leave the declared chunk end exactly on its own header,
    // so the resync point and the head's own boundary would coincide; the cut is nudged so the
    // head really stops inside a chunk.
    if (cut % kCluster == 0) cut += 7;
    uint64_t next_chunk = containing + 12 + data_length;
    CAPTURE(cut, next_chunk);
    REQUIRE(next_chunk > cut);
    REQUIRE(next_chunk < full.size());

    const uint64_t head_at = 3 * kCluster;
    const uint64_t tail_at = ((head_at + cut + kCluster - 1) / kCluster) * kCluster;
    std::vector<uint8_t> image(512 * 1024, static_cast<uint8_t>(0x5A));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut),
              image.begin() + static_cast<std::ptrdiff_t>(head_at));
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(cut), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(tail_at));

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.reassemble = true;
    options.types = {"png"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    const CarveHit& hit = hits->front();
    CHECK(hit.offset == head_at);
    CHECK(hit.length == containing + (full.size() - next_chunk));
    REQUIRE(hit.fragments.size() == 2);
    CHECK(hit.fragments[0].offset == head_at);
    CHECK(hit.fragments[0].length == containing);
    CHECK(hit.fragments[1].offset == tail_at + (next_chunk - cut));
    CHECK(hit.fragments[1].length == full.size() - next_chunk);
    CHECK((hit.flags & file_flags::Fragmented) != 0);
    CHECK((hit.flags & file_flags::Truncated) == 0);

    std::vector<uint8_t> expected(full.begin(),
                                  full.begin() + static_cast<std::ptrdiff_t>(containing));
    expected.insert(expected.end(), full.begin() + static_cast<std::ptrdiff_t>(next_chunk),
                    full.end());
    CHECK(hit.sha256 == sha256_hex(expected));

    test::TempDir out;
    auto sink = io::OutputSink::open(out.path(), io::SourceIdentity::image("png-resync-test.img"));
    REQUIRE(sink.has_value());
    auto written = export_hits(**sink, device, *hits, false);
    REQUIRE(written.has_value());
    REQUIRE(written->size() == 1);
    CHECK(test::load_test_file((*written)[0].path) == expected);

    options.reassemble = false;
    auto head = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(head.has_value());
    REQUIRE(head->size() == 1);
    CHECK((*head)[0].length == containing);
    CHECK((*head)[0].fragments.empty());
}

TEST_CASE("carve engine resyncs a PNG cut exactly on a chunk boundary",
          "[carve][m3][fragment]") {
    // The head ends where a chunk ends, so by itself it is an intact chunk run. It is the fill
    // in the gap that decides whether the validator sees a cut: every byte zero fails the next
    // header's type, and the head then stops at the boundary and the walk resyncs onto the tail.
    constexpr uint64_t kCluster = 4096;
    const std::vector<uint8_t> full = long_png();
    uint64_t boundary = 0;
    for (uint64_t pos = 8; pos + 12 <= full.size();) {
        const uint64_t length = png_be32(full, pos);
        pos += 12 + length;
        if (pos > full.size() / 2) {
            boundary = pos;
            break;
        }
    }
    REQUIRE(boundary > 8);
    REQUIRE(boundary < full.size());
    CAPTURE(boundary);

    const uint64_t head_at = 3 * kCluster;
    const uint64_t tail_at = ((head_at + boundary + kCluster - 1) / kCluster) * kCluster + kCluster;
    REQUIRE(tail_at - (head_at + boundary) >= kCluster);

    std::vector<uint8_t> image(512 * 1024, static_cast<uint8_t>(0x00));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(boundary),
              image.begin() + static_cast<std::ptrdiff_t>(head_at));
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(boundary), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(tail_at));

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.reassemble = true;
    options.types = {"png"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    const CarveHit& hit = hits->front();
    CHECK(hit.offset == head_at);
    CHECK(hit.length == full.size());
    REQUIRE(hit.fragments.size() == 2);
    CHECK(hit.fragments[0].offset == head_at);
    CHECK(hit.fragments[0].length == boundary);
    CHECK(hit.fragments[1].offset == tail_at);
    CHECK(hit.fragments[1].length == full.size() - boundary);
    CHECK((hit.flags & file_flags::Fragmented) != 0);
    CHECK((hit.flags & file_flags::Truncated) == 0);
    CHECK(hit.sha256 == sha256_hex(full));
}

TEST_CASE("carve engine refuses a gap piece that sits in an allocated cluster",
          "[carve][m3][fragment]") {
    // The tail's chunks are valid, but the clusters holding them are marked in use: those bytes
    // belong to whatever file owns the cluster now, so an unallocated-only scan must not stitch
    // them onto the deleted head.
    constexpr uint64_t kCluster = 4096;
    const std::vector<uint8_t> full = long_png();
    uint64_t containing = 0;
    uint64_t data_start = 0;
    uint64_t data_length = 0;
    for (uint64_t pos = 8; pos + 12 <= full.size();) {
        const uint64_t length = png_be32(full, pos);
        if (full.size() / 2 >= pos && full.size() / 2 < pos + 12 + length) {
            containing = pos;
            data_start = pos + 8;
            data_length = length;
            break;
        }
        pos += 12 + length;
    }
    REQUIRE(containing != 0);
    uint64_t cut = data_start + data_length / 2;
    if (cut % kCluster == 0) cut += 7;

    const uint64_t head_at = 3 * kCluster;
    const uint64_t tail_at = ((head_at + cut + kCluster - 1) / kCluster) * kCluster;
    const uint64_t tail_cluster = 2 + (tail_at - kCluster) / kCluster;

    std::vector<uint8_t> image(512 * 1024, static_cast<uint8_t>(0x5A));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut),
              image.begin() + static_cast<std::ptrdiff_t>(head_at));
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(cut), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(tail_at));

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {tail_cluster});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.reassemble = true;
    options.types = {"png"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    CHECK(hits->front().offset == head_at);
    CHECK(hits->front().length == containing);
    CHECK(hits->front().fragments.empty());
    CHECK((hits->front().flags & file_flags::Truncated) != 0);
}

TEST_CASE("carve engine resyncs a GIF cut on a frame boundary", "[carve][m3][fragment]") {
    // The head ends where a frame ends, so it is an intact block run; the zero fill in the
    // gap fails the next introducer, the head stops at the boundary, and the walk proves
    // itself on the tail's graphic control extension and frames.
    constexpr uint64_t kCluster = 4096;
    const std::vector<uint8_t> full = long_gif();
    const std::vector<uint64_t> blocks = gif_block_offsets(full);
    REQUIRE(blocks.size() == 7);
    const uint64_t boundary = blocks[2];  // the second frame's graphic control extension
    CAPTURE(boundary);

    const uint64_t head_at = 3 * kCluster;
    const uint64_t tail_at = ((head_at + boundary + kCluster - 1) / kCluster) * kCluster + kCluster;
    REQUIRE(tail_at - (head_at + boundary) >= kCluster);

    std::vector<uint8_t> image(512 * 1024, static_cast<uint8_t>(0x00));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(boundary),
              image.begin() + static_cast<std::ptrdiff_t>(head_at));
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(boundary), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(tail_at));

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.reassemble = true;
    options.types = {"gif"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    const CarveHit& hit = hits->front();
    CHECK(hit.offset == head_at);
    CHECK(hit.length == full.size());
    REQUIRE(hit.fragments.size() == 2);
    CHECK(hit.fragments[0].offset == head_at);
    CHECK(hit.fragments[0].length == boundary);
    CHECK(hit.fragments[1].offset == tail_at);
    CHECK(hit.fragments[1].length == full.size() - boundary);
    CHECK((hit.flags & file_flags::Fragmented) != 0);
    CHECK((hit.flags & file_flags::Truncated) == 0);
    CHECK(hit.sha256 == sha256_hex(full));
}

TEST_CASE("carve engine joins a GIF tail at the next frame after a mid-stream cut",
          "[carve][m3][fragment]") {
    // The cut lands on the third sub-block of the first frame's LZW data. Those remaining
    // sub-blocks are in the gap and unprovable, so the tail joins at the second frame's
    // graphic control extension and the recovered file is missing the interrupted frame's
    // tail sub-blocks.
    constexpr uint64_t kCluster = 4096;
    const std::vector<uint8_t> full = long_gif();
    const std::vector<uint64_t> blocks = gif_block_offsets(full);
    REQUIRE(blocks.size() == 7);
    const uint64_t data_start = blocks[1] + 1 + 9 + 1;
    const uint64_t cut = data_start + 2 * 256;
    REQUIRE(cut < blocks[2]);
    CAPTURE(cut, blocks[2]);

    const uint64_t head_at = 3 * kCluster;
    const uint64_t tail_at = ((head_at + cut + kCluster - 1) / kCluster) * kCluster + kCluster;
    REQUIRE(tail_at - (head_at + cut) >= kCluster);

    std::vector<uint8_t> image(512 * 1024, static_cast<uint8_t>(0x00));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut),
              image.begin() + static_cast<std::ptrdiff_t>(head_at));
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(cut), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(tail_at));

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.reassemble = true;
    options.types = {"gif"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    const CarveHit& hit = hits->front();
    // The chain terminator that ends the interrupted frame lives in the gap, so the head
    // claims one zero byte past the cut, and the surviving frame data follows from there.
    const uint64_t head_length = cut + 1;
    CHECK(hit.offset == head_at);
    CHECK(hit.length == head_length + (full.size() - blocks[2]));
    REQUIRE(hit.fragments.size() == 2);
    CHECK(hit.fragments[0].offset == head_at);
    CHECK(hit.fragments[0].length == head_length);
    CHECK(hit.fragments[1].offset == tail_at + (blocks[2] - cut));
    CHECK(hit.fragments[1].length == full.size() - blocks[2]);
    CHECK((hit.flags & file_flags::Fragmented) != 0);
    CHECK((hit.flags & file_flags::Truncated) == 0);

    std::vector<uint8_t> expected(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut));
    expected.push_back(0x00);
    expected.insert(expected.end(), full.begin() + static_cast<std::ptrdiff_t>(blocks[2]),
                    full.end());
    CHECK(hit.sha256 == sha256_hex(expected));
}

TEST_CASE("carve engine leaves the head alone when reassembly is off", "[carve][m3][fragment]") {
    const std::vector<uint8_t> full = long_jpeg(4096);
    const uint64_t cut = full.size() - 2 - 2000;
    constexpr uint64_t kCluster = 4096;
    const uint64_t prefix_at = 3 * kCluster;
    const uint64_t tail_at = ((prefix_at + cut + kCluster - 1) / kCluster) * kCluster;

    std::vector<uint8_t> image(256 * 1024, static_cast<uint8_t>(0x5A));
    std::copy(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut),
              image.begin() + static_cast<std::ptrdiff_t>(prefix_at));
    image[prefix_at + cut] = 0xFF;
    image[prefix_at + cut + 1] = 0x02;
    std::copy(full.begin() + static_cast<std::ptrdiff_t>(cut), full.end(),
              image.begin() + static_cast<std::ptrdiff_t>(tail_at));

    test::MemoryDevice device(image);
    const FakeAllocationMap map(kCluster, kCluster, 128, {});
    CarveOptions options;
    options.scope = CarveOptions::Scope::UnallocatedOnly;
    options.alignment = 0;
    options.types = {"jpeg"};

    auto hits = CarveEngine::run(device, &map, options, {}, SignatureRegistry::builtins());
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    CHECK(hits->front().offset == prefix_at);
    CHECK(hits->front().length == cut);
    CHECK(hits->front().fragments.empty());
    CHECK((hits->front().flags & file_flags::Truncated) != 0);
}
