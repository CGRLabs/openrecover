#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_zip.hpp"
#include "openrecover/common/crc32.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

constexpr uint32_t kLocalSig = 0x04034b50;
constexpr uint32_t kCentralSig = 0x02014b50;
constexpr uint32_t kEocdSig = 0x06054b50;
constexpr uint32_t kZip64EocdSig = 0x06064b50;
constexpr uint32_t kZip64LocatorSig = 0x07064b50;
constexpr uint32_t kDataDescriptorSig = 0x08074b50;

ValidationResult validate(const std::vector<uint8_t>& bytes, bool deep = false) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    reader.set_deep_validate(deep);
    return ZipSignature{}.validate(reader);
}

void append_text(std::vector<uint8_t>& out, std::string_view text) {
    out.insert(out.end(), text.begin(), text.end());
}

void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
}

void put32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}

void put64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(value >> (i * 8)));
}

bool has_note_prefix(const ValidationResult& result, std::string_view prefix) {
    return std::any_of(result.notes.begin(), result.notes.end(), [&](const std::string& note) {
        return note.starts_with(prefix);
    });
}

// A valid raw-deflate stream of stored (uncompressed) blocks.
std::vector<uint8_t> raw_deflate_stored(const std::vector<uint8_t>& raw) {
    std::vector<uint8_t> out;
    size_t pos = 0;
    do {
        const size_t n = std::min<size_t>(65535, raw.size() - pos);
        const bool final = pos + n == raw.size();
        out.push_back(final ? 0x01 : 0x00);
        out.push_back(static_cast<uint8_t>(n & 0xFF));
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
        const uint16_t nlen = static_cast<uint16_t>(~static_cast<uint16_t>(n));
        out.push_back(static_cast<uint8_t>(nlen & 0xFF));
        out.push_back(static_cast<uint8_t>(nlen >> 8));
        out.insert(out.end(), raw.begin() + static_cast<std::ptrdiff_t>(pos),
                   raw.begin() + static_cast<std::ptrdiff_t>(pos + n));
        pos += n;
    } while (pos < raw.size());
    return out;
}

struct TestEntry {
    std::string name;
    std::string local_name;
    std::vector<uint8_t> payload;
    uint64_t uncomp = 0;
    uint32_t crc = 0;
    uint16_t method = 0;
    uint16_t flags = 0;
    bool descriptor = false;
    bool zip64_central = false;
    bool corrupt_crc = false;
    int64_t lho_override = -1;
};

TestEntry stored_entry(std::string name, std::vector<uint8_t> data) {
    TestEntry entry;
    entry.name = std::move(name);
    entry.payload = std::move(data);
    entry.uncomp = entry.payload.size();
    entry.crc = entry.payload.empty()
                    ? 0
                    : crc32_update(0, entry.payload.data(), entry.payload.size());
    return entry;
}

TestEntry deflated_entry(std::string name, const std::vector<uint8_t>& raw) {
    TestEntry entry;
    entry.name = std::move(name);
    entry.method = 8;
    entry.uncomp = raw.size();
    entry.crc = raw.empty() ? 0 : crc32_update(0, raw.data(), raw.size());
    entry.payload = raw_deflate_stored(raw);
    return entry;
}

struct BuiltZip {
    std::vector<uint8_t> bytes;
    uint64_t cd_offset = 0;
    uint64_t eocd_offset = 0;
    std::vector<uint64_t> local_offsets;
};

BuiltZip build_zip(const std::vector<TestEntry>& entries, std::vector<uint8_t> comment = {},
                   bool zip64_eocd = false) {
    BuiltZip built;
    std::vector<uint8_t>& out = built.bytes;

    for (const TestEntry& entry : entries) {
        built.local_offsets.push_back(out.size());
        const std::string& local_name =
            entry.local_name.empty() ? entry.name : entry.local_name;
        const uint16_t version = entry.zip64_central ? 45 : 20;
        const uint16_t flags = static_cast<uint16_t>(entry.flags | (entry.descriptor ? 8 : 0));
        const uint32_t crc = entry.corrupt_crc ? (entry.crc ^ 1u) : entry.crc;
        const uint32_t comp = static_cast<uint32_t>(entry.payload.size());
        const uint32_t uncomp = static_cast<uint32_t>(entry.uncomp);

        put32(out, kLocalSig);
        put16(out, version);
        put16(out, flags);
        put16(out, entry.method);
        put16(out, 0);
        put16(out, 0);
        put32(out, entry.descriptor ? 0 : crc);
        put32(out, entry.descriptor ? 0 : comp);
        put32(out, entry.descriptor ? 0 : uncomp);
        put16(out, static_cast<uint16_t>(local_name.size()));
        put16(out, 0);
        append_text(out, local_name);
        out.insert(out.end(), entry.payload.begin(), entry.payload.end());
        if (entry.descriptor) {
            put32(out, kDataDescriptorSig);
            put32(out, crc);
            if (entry.zip64_central) {
                put64(out, comp);
                put64(out, uncomp);
            } else {
                put32(out, comp);
                put32(out, uncomp);
            }
        }
    }

    built.cd_offset = out.size();
    for (size_t i = 0; i < entries.size(); ++i) {
        const TestEntry& entry = entries[i];
        const uint16_t version = entry.zip64_central ? 45 : 20;
        const uint16_t flags = static_cast<uint16_t>(entry.flags | (entry.descriptor ? 8 : 0));
        const uint32_t crc = entry.corrupt_crc ? (entry.crc ^ 1u) : entry.crc;
        const uint64_t comp = entry.payload.size();
        const uint64_t uncomp = entry.uncomp;
        const uint64_t lho = entry.lho_override >= 0
                                 ? static_cast<uint64_t>(entry.lho_override)
                                 : built.local_offsets[i];

        std::vector<uint8_t> extra;
        uint32_t comp_field = static_cast<uint32_t>(comp);
        uint32_t uncomp_field = static_cast<uint32_t>(uncomp);
        uint32_t lho_field = static_cast<uint32_t>(lho);
        if (entry.zip64_central) {
            comp_field = 0xFFFFFFFFu;
            uncomp_field = 0xFFFFFFFFu;
            lho_field = 0xFFFFFFFFu;
            put16(extra, 0x0001);
            put16(extra, 24);
            put64(extra, uncomp);
            put64(extra, comp);
            put64(extra, lho);
        }

        put32(out, kCentralSig);
        put16(out, version);
        put16(out, version);
        put16(out, flags);
        put16(out, entry.method);
        put16(out, 0);
        put16(out, 0);
        put32(out, crc);
        put32(out, comp_field);
        put32(out, uncomp_field);
        put16(out, static_cast<uint16_t>(entry.name.size()));
        put16(out, static_cast<uint16_t>(extra.size()));
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put32(out, 0);
        put32(out, lho_field);
        append_text(out, entry.name);
        out.insert(out.end(), extra.begin(), extra.end());
    }
    const uint64_t cd_size = out.size() - built.cd_offset;

    built.eocd_offset = out.size();
    if (zip64_eocd) {
        const uint64_t zip64_pos = out.size();
        put32(out, kZip64EocdSig);
        put64(out, 44);
        put16(out, 45);
        put16(out, 45);
        put32(out, 0);
        put32(out, 0);
        put64(out, entries.size());
        put64(out, entries.size());
        put64(out, cd_size);
        put64(out, built.cd_offset);
        put32(out, kZip64LocatorSig);
        put32(out, 0);
        put64(out, zip64_pos);
        put32(out, 1);
        put32(out, kEocdSig);
        put16(out, 0);
        put16(out, 0);
        put16(out, 0xFFFF);
        put16(out, 0xFFFF);
        put32(out, 0xFFFFFFFFu);
        put32(out, 0xFFFFFFFFu);
        put16(out, static_cast<uint16_t>(comment.size()));
    } else {
        put32(out, kEocdSig);
        put16(out, 0);
        put16(out, 0);
        put16(out, static_cast<uint16_t>(entries.size()));
        put16(out, static_cast<uint16_t>(entries.size()));
        put32(out, static_cast<uint32_t>(cd_size));
        put32(out, static_cast<uint32_t>(built.cd_offset));
        put16(out, static_cast<uint16_t>(comment.size()));
    }
    out.insert(out.end(), comment.begin(), comment.end());
    return built;
}

std::vector<uint8_t> bytes_of(std::string_view text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::vector<uint8_t> pattern(size_t n) {
    std::vector<uint8_t> out(n);
    for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>((i * 37) & 0xFF);
    return out;
}

}  // namespace

TEST_CASE("ZIP stored archive validates High with exact length", "[sig_zip]") {
    const BuiltZip zip = build_zip({stored_entry("hello.txt", bytes_of("hello zip"))});
    const ValidationResult result = validate(zip.bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == zip.bytes.size());
    CHECK(result.confidence == Confidence::High);
    CHECK(result.subtype == "zip");
}

TEST_CASE("ZIP deflate archive deep CRC verification", "[sig_zip]") {
    const std::vector<uint8_t> raw = pattern(5000);
    const BuiltZip ok = build_zip({deflated_entry("data.bin", raw)});
    const ValidationResult shallow = validate(ok.bytes);
    REQUIRE(shallow.verdict == ValidationResult::Verdict::Valid);
    CHECK(shallow.confidence == Confidence::High);

    const ValidationResult deep = validate(ok.bytes, true);
    REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
    CHECK(deep.confidence == Confidence::High);

    TestEntry bad_crc = deflated_entry("data.bin", raw);
    bad_crc.corrupt_crc = true;
    const BuiltZip crc_zip = build_zip({bad_crc});
    const ValidationResult crc_result = validate(crc_zip.bytes, true);
    REQUIRE(crc_result.verdict == ValidationResult::Verdict::Valid);
    CHECK(crc_result.confidence == Confidence::Medium);
    CHECK(has_note_prefix(crc_result, "entry_crc_mismatch:data.bin"));

    BuiltZip bad_data = build_zip({deflated_entry("data.bin", raw)});
    // Break the first deflate block header, leaving the CRC in the directory intact.
    bad_data.bytes[static_cast<size_t>(bad_data.local_offsets[0]) + 30 + 8] ^= 0x01;
    const ValidationResult data_result = validate(bad_data.bytes, true);
    REQUIRE(data_result.verdict == ValidationResult::Verdict::Valid);
    CHECK(data_result.confidence == Confidence::Medium);
    CHECK(has_note_prefix(data_result, "entry_crc_mismatch:"));
}

TEST_CASE("ZIP entries with data descriptors validate and deep-check", "[sig_zip]") {
    TestEntry stored = stored_entry("stored.txt", bytes_of("descriptor payload"));
    stored.descriptor = true;
    const BuiltZip stored_zip = build_zip({stored});
    const ValidationResult stored_result = validate(stored_zip.bytes, true);
    REQUIRE(stored_result.verdict == ValidationResult::Verdict::Valid);
    CHECK(stored_result.length_bytes == stored_zip.bytes.size());
    CHECK(stored_result.confidence == Confidence::High);

    TestEntry deflated = deflated_entry("stream.bin", pattern(2000));
    deflated.descriptor = true;
    const BuiltZip deflated_zip = build_zip({deflated});
    const ValidationResult deflated_result = validate(deflated_zip.bytes, true);
    REQUIRE(deflated_result.verdict == ValidationResult::Verdict::Valid);
    CHECK(deflated_result.confidence == Confidence::High);
}

TEST_CASE("ZIP comment containing an EOCD signature does not truncate", "[sig_zip]") {
    std::vector<uint8_t> comment = bytes_of("note");
    put32(comment, kEocdSig);
    for (int i = 0; i < 18; ++i) comment.push_back(0);
    comment.push_back(0x41);
    comment.push_back(0x42);
    const BuiltZip zip = build_zip({stored_entry("a.txt", bytes_of("alpha"))}, comment);
    const ValidationResult result = validate(zip.bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == zip.bytes.size());
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("ZIP64 EOCD and ZIP64 entry extra fields validate", "[sig_zip]") {
    const BuiltZip zip64_eocd =
        build_zip({stored_entry("small.txt", bytes_of("zip64 eocd"))}, {}, true);
    const ValidationResult eocd_result = validate(zip64_eocd.bytes, true);
    REQUIRE(eocd_result.verdict == ValidationResult::Verdict::Valid);
    CHECK(eocd_result.length_bytes == zip64_eocd.bytes.size());
    CHECK(eocd_result.confidence == Confidence::High);

    TestEntry wide = stored_entry("wide.txt", bytes_of("zip64 entry extra"));
    wide.zip64_central = true;
    const BuiltZip zip64_entry = build_zip({wide});
    const ValidationResult entry_result = validate(zip64_entry.bytes, true);
    REQUIRE(entry_result.verdict == ValidationResult::Verdict::Valid);
    CHECK(entry_result.confidence == Confidence::High);
}

TEST_CASE("ZIP invalid first local header is rejected", "[sig_zip]") {
    TestEntry unsupported = stored_entry("seven.bin", bytes_of("method"));
    unsupported.method = 7;
    CHECK_FALSE(validate(build_zip({unsupported}).bytes).is_valid());

    TestEntry controlled = stored_entry(std::string("bad\x01name"), bytes_of("x"));
    CHECK_FALSE(validate(build_zip({controlled}).bytes).is_valid());

    std::vector<uint8_t> oversized;
    put32(oversized, kLocalSig);
    put16(oversized, 20);
    put16(oversized, 0);
    put16(oversized, 0);
    put16(oversized, 0);
    put16(oversized, 0);
    put32(oversized, 0);
    put32(oversized, 0);
    put32(oversized, 0);
    put16(oversized, 100);
    put16(oversized, 0);
    CHECK_FALSE(validate(oversized).is_valid());
}

TEST_CASE("ZIP central directory inconsistencies fall back to truncated", "[sig_zip]") {
    TestEntry local_name_mismatch = stored_entry("central.txt", bytes_of("payload"));
    local_name_mismatch.local_name = "local.txt";
    const BuiltZip mismatch_zip = build_zip({local_name_mismatch});
    const ValidationResult mismatch = validate(mismatch_zip.bytes);
    REQUIRE(mismatch.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(mismatch.length_bytes == mismatch_zip.cd_offset);
    CHECK(mismatch.confidence == Confidence::Low);

    std::vector<TestEntry> overlapping;
    TestEntry first = stored_entry("same.txt", bytes_of("one"));
    TestEntry second = stored_entry("same.txt", bytes_of("two"));
    second.lho_override = 0;
    overlapping.push_back(first);
    overlapping.push_back(second);
    const BuiltZip overlap_zip = build_zip(overlapping);
    const ValidationResult overlap = validate(overlap_zip.bytes);
    REQUIRE(overlap.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(overlap.length_bytes == overlap_zip.cd_offset);

    BuiltZip wrong_cd = build_zip({stored_entry("a.txt", bytes_of("alpha"))});
    wrong_cd.bytes[static_cast<size_t>(wrong_cd.eocd_offset) + 16] ^= 0x01;
    const ValidationResult cd_result = validate(wrong_cd.bytes);
    REQUIRE(cd_result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(cd_result.length_bytes == wrong_cd.cd_offset);
}

TEST_CASE("ZIP truncated archive ends at last valid entry", "[sig_zip]") {
    const BuiltZip zip = build_zip(
        {stored_entry("one.txt", bytes_of("first")), stored_entry("two.txt", bytes_of("second"))});
    std::vector<uint8_t> cut(zip.bytes.begin(),
                             zip.bytes.begin() + static_cast<std::ptrdiff_t>(zip.cd_offset));
    const ValidationResult result = validate(cut);
    REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(result.length_bytes == zip.cd_offset);
    CHECK(result.confidence == Confidence::Low);
    CHECK(has_note_prefix(result, "truncated"));
}

TEST_CASE("ZIP subtype classification follows central names", "[sig_zip]") {
    SECTION("docx") {
        const BuiltZip zip = build_zip({stored_entry("[Content_Types].xml", bytes_of("<Types/>")),
                                        stored_entry("word/document.xml", bytes_of("<doc/>"))});
        CHECK(validate(zip.bytes).subtype == "docx");
    }
    SECTION("xlsx") {
        const BuiltZip zip = build_zip({stored_entry("[Content_Types].xml", bytes_of("<Types/>")),
                                        stored_entry("xl/workbook.xml", bytes_of("<wb/>"))});
        CHECK(validate(zip.bytes).subtype == "xlsx");
    }
    SECTION("pptx") {
        const BuiltZip zip = build_zip({stored_entry("[Content_Types].xml", bytes_of("<Types/>")),
                                        stored_entry("ppt/presentation.xml", bytes_of("<p/>"))});
        CHECK(validate(zip.bytes).subtype == "pptx");
    }
    SECTION("odt") {
        const BuiltZip zip =
            build_zip({stored_entry("mimetype", bytes_of("application/vnd.oasis.opendocument.text")),
                       stored_entry("content.xml", bytes_of("<office/>"))});
        CHECK(validate(zip.bytes).subtype == "odt");
    }
    SECTION("ods") {
        const BuiltZip zip = build_zip(
            {stored_entry("mimetype", bytes_of("application/vnd.oasis.opendocument.spreadsheet")),
             stored_entry("content.xml", bytes_of("<office/>"))});
        CHECK(validate(zip.bytes).subtype == "ods");
    }
    SECTION("apk wins over jar") {
        const BuiltZip zip = build_zip({stored_entry("AndroidManifest.xml", bytes_of("<m/>")),
                                        stored_entry("classes.dex", bytes_of("dex\n")),
                                        stored_entry("META-INF/MANIFEST.MF", bytes_of("M"))});
        CHECK(validate(zip.bytes).subtype == "apk");
    }
    SECTION("jar") {
        const BuiltZip zip =
            build_zip({stored_entry("META-INF/MANIFEST.MF", bytes_of("Manifest-Version: 1.0"))});
        CHECK(validate(zip.bytes).subtype == "jar");
    }
    SECTION("epub") {
        const BuiltZip zip =
            build_zip({stored_entry("mimetype", bytes_of("application/epub+zip")),
                       stored_entry("META-INF/container.xml", bytes_of("<c/>"))});
        CHECK(validate(zip.bytes).subtype == "epub");
    }
    SECTION("default") {
        const BuiltZip zip = build_zip({stored_entry("plain.txt", bytes_of("plain"))});
        CHECK(validate(zip.bytes).subtype == "zip");
    }
}
