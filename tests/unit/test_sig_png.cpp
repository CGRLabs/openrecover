#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_png.hpp"
#include "openrecover/common/crc32.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

const std::vector<uint8_t> kPngSignature = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

void append_u32be(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void append_chunk(std::vector<uint8_t>& png, const std::string& type,
                  const std::vector<uint8_t>& data, bool corrupt_crc = false) {
    append_u32be(png, static_cast<uint32_t>(data.size()));
    const size_t crc_start = png.size();
    png.insert(png.end(), type.begin(), type.end());
    png.insert(png.end(), data.begin(), data.end());
    uint32_t crc = crc32_update(0, png.data() + crc_start, 4 + data.size());
    if (corrupt_crc) crc ^= 1u;
    append_u32be(png, crc);
}

std::vector<uint8_t> zlib_stored(const std::vector<uint8_t>& raw, bool corrupt_adler = false) {
    std::vector<uint8_t> out = {0x78, 0x01};
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
    uint32_t adler = adler32_update(1, raw.data(), raw.size());
    if (corrupt_adler) adler ^= 1u;
    append_u32be(out, adler);
    return out;
}

std::vector<uint8_t> ihdr_data(uint32_t width, uint32_t height, uint8_t depth = 8,
                               uint8_t color = 6, uint8_t interlace = 0,
                               uint8_t compression = 0, uint8_t filter = 0) {
    std::vector<uint8_t> data;
    append_u32be(data, width);
    append_u32be(data, height);
    data.push_back(depth);
    data.push_back(color);
    data.push_back(compression);
    data.push_back(filter);
    data.push_back(interlace);
    return data;
}

std::vector<uint8_t> begin_png(uint32_t width, uint32_t height, uint8_t depth = 8,
                               uint8_t color = 6, uint8_t interlace = 0) {
    std::vector<uint8_t> png = kPngSignature;
    append_chunk(png, "IHDR", ihdr_data(width, height, depth, color, interlace));
    return png;
}

std::vector<uint8_t> raw_noninterlaced(uint32_t width, uint32_t height, uint32_t channels,
                                       uint8_t depth) {
    const size_t stride =
        static_cast<size_t>((static_cast<uint64_t>(width) * channels * depth + 7) / 8);
    std::vector<uint8_t> raw;
    raw.reserve((stride + 1) * height);
    uint32_t value = 0;
    for (uint32_t y = 0; y < height; ++y) {
        raw.push_back(0);
        for (size_t i = 0; i < stride; ++i) {
            raw.push_back(static_cast<uint8_t>(++value & 0xFF));
        }
    }
    return raw;
}

std::vector<uint8_t> raw_adam7(uint32_t width, uint32_t height, uint32_t channels,
                               uint8_t depth) {
    static constexpr uint32_t starts_x[7] = {0, 4, 0, 2, 0, 1, 0};
    static constexpr uint32_t starts_y[7] = {0, 0, 4, 0, 2, 0, 1};
    static constexpr uint32_t steps_x[7] = {8, 8, 4, 4, 2, 2, 1};
    static constexpr uint32_t steps_y[7] = {8, 8, 8, 4, 4, 2, 2};

    std::vector<uint8_t> raw;
    uint32_t value = 0;
    for (int pass = 0; pass < 7; ++pass) {
        const uint32_t w =
            width > starts_x[pass] ? (width - starts_x[pass] + steps_x[pass] - 1) / steps_x[pass] : 0;
        const uint32_t h =
            height > starts_y[pass] ? (height - starts_y[pass] + steps_y[pass] - 1) / steps_y[pass] : 0;
        if (w == 0 || h == 0) continue;
        const size_t stride =
            static_cast<size_t>((static_cast<uint64_t>(w) * channels * depth + 7) / 8);
        for (uint32_t y = 0; y < h; ++y) {
            raw.push_back(0);
            for (size_t i = 0; i < stride; ++i) {
                raw.push_back(static_cast<uint8_t>(++value & 0xFF));
            }
        }
    }
    return raw;
}

std::vector<uint8_t> minimal_png(uint32_t width = 4, uint32_t height = 4, uint8_t depth = 8,
                                 uint8_t color = 6, uint8_t interlace = 0, bool with_iend = true,
                                 bool corrupt_idat_crc = false, bool corrupt_adler = false,
                                 bool mismatch_raw = false) {
    const uint32_t channels = color == 6 ? 4 : (color == 2 ? 3 : (color == 3 ? 1 : 1));
    const uint32_t raw_width = mismatch_raw ? width / 2 : width;
    const uint32_t raw_height = mismatch_raw ? height / 2 : height;
    std::vector<uint8_t> raw = interlace ? raw_adam7(raw_width, raw_height, channels, depth)
                                         : raw_noninterlaced(raw_width, raw_height, channels, depth);
    std::vector<uint8_t> png = begin_png(width, height, depth, color, interlace);
    append_chunk(png, "IDAT", zlib_stored(raw, corrupt_adler), corrupt_idat_crc);
    if (with_iend) append_chunk(png, "IEND", {});
    return png;
}

ValidationResult validate(const std::vector<uint8_t>& bytes, bool deep) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    reader.set_deep_validate(deep);
    PngSignature signature;
    return signature.validate(reader);
}

std::optional<Continuation> continuation_of(const std::vector<uint8_t>& bytes) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    PngSignature signature;
    return signature.find_continuation(reader);
}

}  // namespace

TEST_CASE("png: minimal RGBA is medium shallow and high with deep validation", "[png][m3]") {
    const std::vector<uint8_t> png = minimal_png();
    const ValidationResult shallow = validate(png, false);
    REQUIRE(shallow.verdict == ValidationResult::Verdict::Valid);
    CHECK(shallow.length_bytes == png.size());
    CHECK(shallow.confidence == Confidence::Medium);

    const ValidationResult deep = validate(png, true);
    REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
    CHECK(deep.length_bytes == png.size());
    CHECK(deep.confidence == Confidence::High);
}

TEST_CASE("png: consecutive split IDAT chunks reassemble into one zlib stream", "[png][m3]") {
    const std::vector<uint8_t> raw = raw_noninterlaced(4, 4, 4, 8);
    const std::vector<uint8_t> compressed = zlib_stored(raw);
    const size_t half = compressed.size() / 2;

    std::vector<uint8_t> png = begin_png(4, 4);
    append_chunk(png, "IDAT", std::vector<uint8_t>(compressed.begin(),
                                                   compressed.begin() + static_cast<std::ptrdiff_t>(half)));
    append_chunk(png, "IDAT", std::vector<uint8_t>(
                                  compressed.begin() + static_cast<std::ptrdiff_t>(half),
                                  compressed.end()));
    append_chunk(png, "IEND", {});

    const ValidationResult deep = validate(png, true);
    REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
    CHECK(deep.confidence == Confidence::High);
}

TEST_CASE("png: a bad chunk CRC is always rejected", "[png][m3]") {
    const std::vector<uint8_t> png = minimal_png(4, 4, 8, 6, 0, true, true);
    CHECK_FALSE(validate(png, false).is_valid());
}

TEST_CASE("png: palette images require a valid PLTE before IDAT", "[png][m3]") {
    SECTION("valid palette") {
        std::vector<uint8_t> png = begin_png(2, 2, 8, 3);
        std::vector<uint8_t> plte(12);
        for (size_t i = 0; i < plte.size(); ++i) plte[i] = static_cast<uint8_t>(i * 17);
        append_chunk(png, "PLTE", plte);
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 1, 8)));
        append_chunk(png, "IEND", {});
        const ValidationResult deep = validate(png, true);
        REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
        CHECK(deep.confidence == Confidence::High);
    }
    SECTION("missing palette") {
        std::vector<uint8_t> png = begin_png(2, 2, 8, 3);
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 1, 8)));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("palette length not a multiple of three") {
        std::vector<uint8_t> png = begin_png(2, 2, 8, 3);
        append_chunk(png, "PLTE", std::vector<uint8_t>(13, 0));
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 1, 8)));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("palette entries exceed the bit depth") {
        std::vector<uint8_t> png = begin_png(2, 2, 1, 3);
        append_chunk(png, "PLTE", std::vector<uint8_t>(9, 0));
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 1, 1)));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("palette on grayscale") {
        std::vector<uint8_t> png = begin_png(2, 2, 8, 0);
        append_chunk(png, "PLTE", std::vector<uint8_t>(6, 0));
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 1, 8)));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
}

TEST_CASE("png: Adam7 interlaced images deep-validate", "[png][m3]") {
    const std::vector<uint8_t> png = minimal_png(8, 8, 8, 6, 1);
    const ValidationResult shallow = validate(png, false);
    REQUIRE(shallow.verdict == ValidationResult::Verdict::Valid);
    CHECK(shallow.confidence == Confidence::Medium);
    const ValidationResult deep = validate(png, true);
    REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
    CHECK(deep.confidence == Confidence::High);
}

TEST_CASE("png: a chunk that runs into foreign bytes is a cut at that chunk",
          "[png][m3][fragment]") {
    std::vector<uint8_t> png = begin_png(4, 4);
    const size_t idat_at = png.size();
    append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(4, 4, 4, 8)));
    append_chunk(png, "IEND", {});
    // Overwrite the chunk's tail and the bytes where its successor should start: a later write
    // took the rest of the file, so the declared end no longer lands on a chunk boundary.
    std::fill(png.begin() + static_cast<std::ptrdiff_t>(png.size() - 80), png.end(),
              static_cast<uint8_t>(0x5A));

    const ValidationResult result = validate(png, false);
    REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(result.length_bytes == idat_at);
    CHECK(result.confidence == Confidence::Low);
}

TEST_CASE("png: a cut exactly on a chunk boundary depends on what the next write left",
          "[png][m3][fragment]") {
    // The head ends where its second IDAT ends, so by itself it is an intact PNG with no IEND.
    // The validator has to read on: zero fill fails the header's type, which is a cut at the
    // boundary that the engine can resync from; letter fill (0x5A) is a plausible chunk type
    // whose declared length runs past the source, so the hit is a truncation that claims the
    // rest as one unverifiable chunk and the tail is never joined.
    std::vector<uint8_t> png = begin_png(4, 4);
    append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(4, 4, 4, 8)));
    append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(4, 4, 4, 8)));
    const size_t boundary = png.size();

    std::vector<uint8_t> zero_fill = png;
    zero_fill.resize(boundary + 512, 0x00);
    const ValidationResult cut = validate(zero_fill, false);
    REQUIRE(cut.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(cut.length_bytes == boundary);

    std::vector<uint8_t> letter_fill = png;
    letter_fill.resize(boundary + 512, 0x5A);
    const ValidationResult at_limit = validate(letter_fill, false);
    REQUIRE(at_limit.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(at_limit.length_bytes == letter_fill.size());
}

TEST_CASE("png: find_continuation resyncs onto a chunk run that reaches IEND",
          "[png][fragment]") {
    std::vector<uint8_t> tail;
    append_chunk(tail, "IDAT", zlib_stored(raw_noninterlaced(4, 4, 4, 8)));
    append_chunk(tail, "IEND", {});

    std::vector<uint8_t> bytes(64, 0x5A);
    bytes.insert(bytes.end(), tail.begin(), tail.end());

    const auto result = continuation_of(bytes);
    REQUIRE(result.has_value());
    CHECK(result->start == 64);
    CHECK(result->length == tail.size());
    CHECK(result->complete);
}

TEST_CASE("png: a continuation stops at the first chunk that fails", "[png][fragment]") {
    std::vector<uint8_t> first;
    append_chunk(first, "IDAT", zlib_stored(raw_noninterlaced(4, 4, 4, 8)));

    std::vector<uint8_t> bytes(64, 0x5A);
    bytes.insert(bytes.end(), first.begin(), first.end());
    // The next chunk header is intact but its data is not: the run stops at its start.
    append_chunk(bytes, "IDAT", zlib_stored(raw_noninterlaced(4, 4, 4, 8)), true);
    append_chunk(bytes, "IEND", {});

    const auto result = continuation_of(bytes);
    REQUIRE(result.has_value());
    CHECK(result->start == 64);
    CHECK(result->length == first.size());
    CHECK_FALSE(result->complete);
}

TEST_CASE("png: a continuation refuses another image and a lone terminator",
          "[png][fragment]") {
    const std::vector<uint8_t> other = minimal_png(4, 4);
    std::vector<uint8_t> bytes(64, 0x5A);
    bytes.insert(bytes.end(), other.begin(), other.end());
    CHECK_FALSE(continuation_of(bytes).has_value());

    std::vector<uint8_t> lone(64, 0x5A);
    append_chunk(lone, "IEND", {});
    CHECK_FALSE(continuation_of(lone).has_value());
}

TEST_CASE("png: a missing IEND after validated IDAT is a truncation", "[png][m3]") {
    const std::vector<uint8_t> png = minimal_png(4, 4, 8, 6, 0, false);
    const ValidationResult result = validate(png, false);
    REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(result.length_bytes == png.size());
    CHECK(result.confidence == Confidence::Low);
}

TEST_CASE("png: IDAT chunks must be consecutive", "[png][m3]") {
    std::vector<uint8_t> png = begin_png(2, 2);
    const std::vector<uint8_t> compressed = zlib_stored(raw_noninterlaced(2, 2, 4, 8));
    append_chunk(png, "IDAT", compressed);
    append_chunk(png, "tEXt", {'a', 0, 'b'});
    append_chunk(png, "IDAT", compressed);
    append_chunk(png, "IEND", {});
    CHECK_FALSE(validate(png, false).is_valid());
}

TEST_CASE("png: unknown critical chunks are rejected and unknown ancillary chunks are not",
          "[png][m3]") {
    SECTION("unknown critical") {
        std::vector<uint8_t> png = begin_png(2, 2);
        append_chunk(png, "ABCD", {});
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 4, 8)));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("unknown ancillary") {
        std::vector<uint8_t> png = begin_png(2, 2);
        append_chunk(png, "abcd", {1, 2, 3});
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 4, 8)));
        append_chunk(png, "IEND", {});
        const ValidationResult deep = validate(png, true);
        REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
        CHECK(deep.confidence == Confidence::High);
    }
}

TEST_CASE("png: duplicate and misordered ancillary chunks downgrade to medium", "[png][m3]") {
    SECTION("duplicate gAMA") {
        std::vector<uint8_t> png = begin_png(2, 2);
        const std::vector<uint8_t> gama = {0x00, 0x00, 0xB1, 0x8F};
        append_chunk(png, "gAMA", gama);
        append_chunk(png, "gAMA", gama);
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 4, 8)));
        append_chunk(png, "IEND", {});
        const ValidationResult deep = validate(png, true);
        REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
        CHECK(deep.confidence == Confidence::Medium);
        CHECK(std::find(deep.notes.begin(), deep.notes.end(), "duplicate_chunk:gAMA") !=
              deep.notes.end());
    }
    SECTION("gAMA after IDAT") {
        std::vector<uint8_t> png = begin_png(2, 2);
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 4, 8)));
        append_chunk(png, "gAMA", {0x00, 0x00, 0xB1, 0x8F});
        append_chunk(png, "IEND", {});
        const ValidationResult deep = validate(png, true);
        REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
        CHECK(deep.confidence == Confidence::Medium);
    }
}

TEST_CASE("png: invalid IHDR fields are rejected", "[png][m3]") {
    SECTION("zero width") {
        const std::vector<uint8_t> png = minimal_png(0, 4);
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("invalid depth for truecolor") {
        const std::vector<uint8_t> png = minimal_png(4, 4, 4, 2);
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("too many pixels") {
        std::vector<uint8_t> png = kPngSignature;
        append_chunk(png, "IHDR", ihdr_data(0x7FFFFFFFu, 2));
        append_chunk(png, "IDAT", zlib_stored({0}));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("nonzero compression method") {
        std::vector<uint8_t> png = kPngSignature;
        append_chunk(png, "IHDR", ihdr_data(2, 2, 8, 6, 0, 1, 0));
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 4, 8)));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
}

TEST_CASE("png: malformed chunk types and IEND are rejected", "[png][m3]") {
    SECTION("non-letter chunk type") {
        std::vector<uint8_t> png = begin_png(2, 2);
        append_chunk(png, "ID4T", zlib_stored(raw_noninterlaced(2, 2, 4, 8)));
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("IEND with data") {
        std::vector<uint8_t> png = begin_png(2, 2);
        append_chunk(png, "IDAT", zlib_stored(raw_noninterlaced(2, 2, 4, 8)));
        append_chunk(png, "IEND", {0});
        CHECK_FALSE(validate(png, false).is_valid());
    }
    SECTION("IEND without IDAT") {
        std::vector<uint8_t> png = begin_png(2, 2);
        append_chunk(png, "IEND", {});
        CHECK_FALSE(validate(png, false).is_valid());
    }
}

TEST_CASE("png: deep validation catches wrong decompressed sizes and bad Adler-32",
          "[png][m3]") {
    SECTION("wrong raw size") {
        const std::vector<uint8_t> png = minimal_png(8, 8, 8, 6, 0, true, false, false, true);
        REQUIRE(validate(png, false).is_valid());
        CHECK_FALSE(validate(png, true).is_valid());
    }
    SECTION("bad adler") {
        const std::vector<uint8_t> png = minimal_png(4, 4, 8, 6, 0, true, false, true);
        REQUIRE(validate(png, false).is_valid());
        CHECK_FALSE(validate(png, true).is_valid());
    }
}
