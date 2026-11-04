#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include "fuzz_seeds.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_avi.hpp"

namespace {
using namespace openrecover;
using namespace openrecover::carve;

void put32le(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

// RIFF chunks are word aligned, so an odd payload is followed by one pad byte that no chunk owns.
void append_chunk(std::vector<uint8_t>& b, std::string_view id, const std::vector<uint8_t>& payload) {
    const size_t at = b.size();
    b.resize(at + 8 + payload.size());
    std::memcpy(b.data() + at, id.data(), 4);
    put32le(b, at + 4, static_cast<uint32_t>(payload.size()));
    if (!payload.empty()) std::memcpy(b.data() + at + 8, payload.data(), payload.size());
    if (payload.size() % 2) b.push_back(0);
}

void append_list(std::vector<uint8_t>& b, std::string_view form, const std::vector<uint8_t>& inner) {
    std::vector<uint8_t> payload(form.begin(), form.end());
    payload.insert(payload.end(), inner.begin(), inner.end());
    append_chunk(b, "LIST", payload);
}

std::vector<uint8_t> pattern(size_t bytes, uint8_t seed) {
    std::vector<uint8_t> out(bytes);
    for (size_t i = 0; i < bytes; ++i) out[i] = static_cast<uint8_t>((i * seed) & 0xFF);
    return out;
}

struct AviParts {
    size_t frames = 4;
    size_t frame_bytes = 96;
    bool include_frames = true;
    bool with_index = true;
    bool rec_lists = false;
    bool with_strl = true;
    uint32_t declared_riff_size = 0;  // zero means the length the file actually has
};

// The layout an encoder writes: a header list describing one video stream, a movie list of
// compressed frames, and an index that lets a player seek.
std::vector<uint8_t> build_avi(const AviParts& parts) {
    std::vector<uint8_t> avih(60, 0);
    put32le(avih, 0, 33333);   // microseconds per frame
    put32le(avih, 8, 4);       // padding granularity
    put32le(avih, 12, 0x10);   // has an index
    put32le(avih, 16, static_cast<uint32_t>(parts.frames));
    put32le(avih, 28, 1);      // stream count
    put32le(avih, 32, static_cast<uint32_t>(parts.frame_bytes));
    put32le(avih, 36, 64);     // width
    put32le(avih, 40, 48);     // height

    std::vector<uint8_t> hdrl_inner;
    append_chunk(hdrl_inner, "avih", avih);
    if (parts.with_strl) {
        std::vector<uint8_t> strl;
        std::vector<uint8_t> strh(48, 0);
        std::memcpy(strh.data(), "vids", 4);
        append_chunk(strl, "strh", strh);
        std::vector<uint8_t> strf(40, 0);
        put32le(strf, 0, 40);
        append_chunk(strl, "strf", strf);
        append_list(hdrl_inner, "strl", strl);
    }

    std::vector<uint8_t> out(12, 0);
    std::memcpy(out.data(), "RIFF", 4);
    std::memcpy(out.data() + 8, "AVI ", 4);
    append_list(out, "hdrl", hdrl_inner);

    if (parts.include_frames) {
        std::vector<uint8_t> movie;
        if (parts.rec_lists) {
            for (size_t start = 0; start < parts.frames; start += 2) {
                std::vector<uint8_t> group;
                for (size_t i = start; i < std::min(start + 2, parts.frames); ++i)
                    append_chunk(group, "00dc", pattern(parts.frame_bytes, static_cast<uint8_t>(i)));
                append_list(movie, "rec ", group);
            }
        } else {
            for (size_t i = 0; i < parts.frames; ++i)
                append_chunk(movie, "00dc", pattern(parts.frame_bytes, static_cast<uint8_t>(i)));
        }
        append_list(out, "movi", movie);
    }

    if (parts.with_index) {
        // idx1 holds one 16-byte record per frame, not a chunk per frame.
        std::vector<uint8_t> index(parts.frames * 16, 0);
        for (size_t i = 0; i < parts.frames; ++i) {
            put32le(index, i * 16, 0x10);  // a key frame of this stream
            put32le(index, i * 16 + 8, static_cast<uint32_t>(parts.frame_bytes));
        }
        append_chunk(out, "idx1", index);
    }

    const uint32_t size =
        parts.declared_riff_size != 0 ? parts.declared_riff_size
                                      : static_cast<uint32_t>(out.size() - 8);
    put32le(out, 4, size);
    return out;
}

ValidationResult validate(const std::vector<uint8_t>& bytes, uint64_t limit = 0) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, limit != 0 ? std::min(limit, bytes.size()) : bytes.size());
    return AviSignature{}.validate(reader);
}

size_t find_chunk(const std::vector<uint8_t>& bytes, std::string_view needle) {
    for (size_t i = 12; i + needle.size() <= bytes.size(); ++i) {
        if (std::memcmp(bytes.data() + i, needle.data(), needle.size()) == 0) return i;
    }
    REQUIRE_FALSE(needle.empty());  // the form type is not in the file
    return 0;
}
}  // namespace

TEST_CASE("avi: a header list, a movie list and an index make a video", "[avi][m3]") {
    const std::vector<uint8_t> bytes = build_avi({});
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.subtype == "avi");
    CHECK(res.confidence == Confidence::High);
    CHECK(res.notes.empty());
}

TEST_CASE("avi: frames grouped into rec lists are still a movie", "[avi][m3]") {
    AviParts parts;
    parts.frames = 5;  // an odd group size exercises the word alignment of the last group
    parts.rec_lists = true;
    const std::vector<uint8_t> bytes = build_avi(parts);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());
}

TEST_CASE("avi: a movie list with no index is a recording that never closed", "[avi][m3]") {
    AviParts parts;
    parts.with_index = false;
    const std::vector<uint8_t> bytes = build_avi(parts);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());
}

TEST_CASE("avi: an odd-sized top-level chunk does not desynchronise the walk", "[avi][m3]") {
    const std::vector<uint8_t> whole = build_avi({});
    const size_t movi_at = find_chunk(whole, "movi") - 8;
    std::vector<uint8_t> out(12, 0);
    std::memcpy(out.data(), "RIFF", 4);
    std::memcpy(out.data() + 8, "AVI ", 4);
    out.insert(out.end(), whole.begin() + 12, whole.begin() + movi_at);  // the whole header list
    append_chunk(out, "strh", std::vector<uint8_t>(5, 0x5A));  // a payload that is not word sized
    out.insert(out.end(), whole.begin() + movi_at, whole.end());
    put32le(out, 4, static_cast<uint32_t>(out.size() - 8));

    auto res = validate(out);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == out.size());
}

TEST_CASE("avi: a wave is a different family and is refused", "[avi][m3]") {
    std::vector<uint8_t> bytes(12, 0);
    std::memcpy(bytes.data(), "RIFF", 4);
    std::memcpy(bytes.data() + 8, "WAVE", 4);
    append_chunk(bytes, "fmt ", std::vector<uint8_t>(16, 0));
    append_chunk(bytes, "data", pattern(64, 3));
    put32le(bytes, 4, static_cast<uint32_t>(bytes.size() - 8));
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("avi: a header list with neither frames nor an index is a fragment", "[avi][m3]") {
    AviParts parts;
    parts.include_frames = false;
    parts.with_index = false;
    auto res = validate(build_avi(parts));
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.confidence == Confidence::Low);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "the declared file ends inside the header list");
}

TEST_CASE("avi: an index that lists frames the file does not carry is a fragment", "[avi][m3]") {
    AviParts parts;
    parts.include_frames = false;
    auto res = validate(build_avi(parts));
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes > 0);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "no frame list in the declared file");
}

TEST_CASE("avi: a RIFF size past the window is claimed as far as the scan reaches", "[avi][m3]") {
    AviParts parts;
    parts.declared_riff_size = 1u << 28;
    const std::vector<uint8_t> bytes = build_avi(parts);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.confidence == Confidence::Low);
    REQUIRE_FALSE(res.notes.empty());
    CHECK(res.notes[0] == "RIFF size extends past the scan window");
    CHECK(res.notes.size() == 1);  // the movie list was inside the window
}

TEST_CASE("avi: a cut file whose frames are out of reach says so", "[avi][m3]") {
    AviParts parts;
    parts.declared_riff_size = 1u << 28;
    const std::vector<uint8_t> whole = build_avi(parts);
    // Keep the header list and drop in on the movie list: the index and frames are not reachable.
    const size_t movi_at = find_chunk(whole, "movi") - 8;
    const size_t cut = movi_at + 6;
    std::vector<uint8_t> bytes(whole.begin(), whole.begin() + cut);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == cut);
    REQUIRE(res.notes.size() == 2);
    CHECK(res.notes[1] == "no frame list inside the window");
}

TEST_CASE("avi: a chunk that overruns the declared file is a size that lies", "[avi][m3]") {
    std::vector<uint8_t> bytes = build_avi({});
    const size_t movi_at = find_chunk(bytes, "movi") - 8;
    put32le(bytes, movi_at + 4, static_cast<uint32_t>(bytes.size()));  // past the end of the file
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("avi: a chunk larger than the format allows is refused", "[avi][m3]") {
    std::vector<uint8_t> bytes = build_avi({});
    const size_t movi_at = find_chunk(bytes, "movi") - 8;
    put32le(bytes, movi_at + 4, 1u << 30);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("avi: a declared file bigger than the signature allows is refused", "[avi][m3]") {
    AviParts parts;
    parts.declared_riff_size = 0xFFFFFFFFu;  // the largest value a 32-bit RIFF size can hold
    CHECK_FALSE(validate(build_avi(parts)).is_valid());
}

TEST_CASE("avi: a RIFF with no header list is not a video", "[avi][m3]") {
    std::vector<uint8_t> empty(12, 0);
    std::memcpy(empty.data(), "RIFF", 4);
    std::memcpy(empty.data() + 8, "AVI ", 4);
    put32le(empty, 4, 4);
    CHECK_FALSE(validate(empty).is_valid());

    // A header list under some other form type describes nothing this parser knows.
    AviParts parts;
    parts.include_frames = false;
    parts.with_index = false;
    parts.with_strl = false;
    std::vector<uint8_t> wrong = build_avi(parts);
    const size_t at = find_chunk(wrong, "hdrl");
    std::memcpy(wrong.data() + at, "VQMT", 4);
    CHECK_FALSE(validate(wrong).is_valid());
}

TEST_CASE("avi: a RIFF size below the form type is refused", "[avi][m3]") {
    std::vector<uint8_t> bytes = build_avi({});
    put32le(bytes, 4, 3);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("avi: a chunk list that never ends is stopped", "[avi][m3]") {
    std::vector<uint8_t> out(12, 0);
    std::memcpy(out.data(), "RIFF", 4);
    std::memcpy(out.data() + 8, "AVI ", 4);
    append_list(out, "hdrl", std::vector<uint8_t>());
    // Ten thousand zero chunks tile the declared file exactly; the walk stops at its own limit.
    out.resize(out.size() + 10000 * 8, 0);
    put32le(out, 4, static_cast<uint32_t>(out.size() - 8));
    CHECK_FALSE(validate(out).is_valid());
}

TEST_CASE("avi: a candidate too short to name its form is refused", "[avi][m3]") {
    std::vector<uint8_t> bytes(11, 0);
    std::memcpy(bytes.data(), "RIFF", 4);
    CHECK_FALSE(validate(bytes).is_valid());
    CHECK_FALSE(validate(std::vector<uint8_t>()).is_valid());
}

TEST_CASE("avi: name, magic and extension", "[avi][m3]") {
    AviSignature sig;
    CHECK(sig.name() == "avi");
    CHECK(sig.default_extension() == "avi");
    CHECK(sig.magic_offset() == 0);
    CHECK(sig.min_header_bytes() == 12);
    CHECK(sig.max_file_size() == (4ull << 30));
    REQUIRE(sig.magics().size() == 1);
    REQUIRE(sig.magics()[0].size() == 4);
    CHECK(std::memcmp(sig.magics()[0].data(), "RIFF", 4) == 0);
}

TEST_CASE("avi: every single-byte mutation is refused or stays inside the window",
          "[avi][m3][mutation]") {
    const std::vector<uint8_t> good = build_avi({});
    size_t accepted = 0;
    size_t refused = 0;
    for (size_t offset = 0; offset < good.size(); ++offset) {
        for (uint8_t value : {uint8_t{0x00}, uint8_t{0xFF}, uint8_t{0x20}, uint8_t{0x41}}) {
            std::vector<uint8_t> mutated = good;
            mutated[offset] = value;
            const ValidationResult res = validate(mutated);
            if (!res.is_valid()) {
                ++refused;
                continue;
            }
            ++accepted;
            CHECK(res.length_bytes > 0);
            CHECK(res.length_bytes <= mutated.size());
            CHECK(res.subtype == "avi");
            if (res.verdict == ValidationResult::Verdict::Valid) CHECK(res.notes.empty());
            if (res.verdict == ValidationResult::Verdict::ValidTruncated) {
                CHECK(res.length_bytes == mutated.size());
                CHECK(res.confidence == Confidence::Low);
            }
        }
    }
    CHECK(accepted > 0);
    CHECK(refused > 0);
}

TEST_CASE("avi: the committed fuzz seeds validate as named", "[avi][m3][fuzz]") {
    test::check_signature_seed_corpus(OPENRECOVER_FUZZ_SEED_DIR, AviSignature{});
}
