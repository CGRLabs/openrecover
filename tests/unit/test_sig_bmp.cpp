#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_bmp.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

void append_u16le(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>(value >> 8));
}

void append_u32le(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>(value >> 24));
}

void put_u16(std::vector<uint8_t>& out, size_t off, uint16_t value) {
    if (off + 2 > out.size()) return;
    out[off] = static_cast<uint8_t>(value & 0xFF);
    out[off + 1] = static_cast<uint8_t>(value >> 8);
}

void put_u32(std::vector<uint8_t>& out, size_t off, uint32_t value) {
    if (off + 4 > out.size()) return;
    for (size_t i = 0; i < 4; ++i)
        out[off + i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
}

struct BmpSpec {
    uint32_t dib_size = 40;
    int32_t width = 4;
    int32_t height = 4;
    uint16_t planes = 1;
    uint16_t bpp = 24;
    uint32_t compression = 0;
    uint32_t size_image = 0;
    uint32_t clr_used = 0;
    std::array<uint32_t, 4> masks{0x00FF0000u, 0x0000FF00u, 0x000000FFu, 0xFF000000u};
    std::vector<uint8_t> rle;
    std::vector<uint8_t> embedded;
    uint32_t reserved = 0;
    bool override_file_size = false;
    uint32_t file_size = 0;
    bool override_off_bits = false;
    uint32_t off_bits = 0;
    bool add_pixels = true;
    std::vector<uint8_t> trailing;
};

std::vector<uint8_t> build_bmp(const BmpSpec& spec) {
    const bool core = spec.dib_size == 12;
    const bool masks_in_file =
        spec.dib_size == 40 && (spec.compression == 3 || spec.compression == 6);
    const size_t mask_bytes = masks_in_file ? (spec.compression == 6 ? 16u : 12u) : 0;

    const uint64_t entries = spec.bpp <= 8
                                 ? (spec.clr_used != 0 ? spec.clr_used : (1u << spec.bpp))
                                 : spec.clr_used;
    const size_t palette_bytes = static_cast<size_t>(entries) * (core ? 3 : 4);
    const uint32_t off =
        14 + spec.dib_size + static_cast<uint32_t>(mask_bytes + palette_bytes);

    std::vector<uint8_t> dib(spec.dib_size, 0);
    put_u32(dib, 0, spec.dib_size);
    if (core) {
        put_u16(dib, 4, static_cast<uint16_t>(spec.width));
        put_u16(dib, 6, static_cast<uint16_t>(spec.height));
        put_u16(dib, 8, spec.planes);
        put_u16(dib, 10, spec.bpp);
    } else {
        put_u32(dib, 4, static_cast<uint32_t>(spec.width));
        put_u32(dib, 8, static_cast<uint32_t>(spec.height));
        put_u16(dib, 12, spec.planes);
        put_u16(dib, 14, spec.bpp);
        put_u32(dib, 16, spec.compression);
        put_u32(dib, 20, spec.size_image);
        put_u32(dib, 32, spec.clr_used);
        if (spec.dib_size >= 52 && (spec.compression == 3 || spec.compression == 6)) {
            put_u32(dib, 40, spec.masks[0]);
            put_u32(dib, 44, spec.masks[1]);
            put_u32(dib, 48, spec.masks[2]);
            if (spec.dib_size >= 56) put_u32(dib, 52, spec.masks[3]);
        }
    }

    std::vector<uint8_t> pixels;
    if (spec.compression == 1 || spec.compression == 2) {
        pixels = spec.rle;
    } else if (spec.compression == 4 || spec.compression == 5) {
        if (!spec.embedded.empty()) {
            pixels = spec.embedded;
        } else if (spec.compression == 4) {
            pixels = {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00};
        } else {
            pixels = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00};
        }
    } else if (spec.add_pixels) {
        const uint64_t abs_height =
            spec.height < 0 ? static_cast<uint64_t>(-static_cast<int64_t>(spec.height))
                            : static_cast<uint64_t>(spec.height);
        const uint64_t row_bits = static_cast<uint64_t>(spec.width) * spec.bpp;
        const uint64_t stride = ((row_bits + 31) / 32) * 4;
        pixels.assign(static_cast<size_t>(stride * abs_height), 0x5A);
    }

    const uint64_t declared_size = static_cast<uint64_t>(off) + pixels.size();
    const uint32_t file_size =
        spec.override_file_size ? spec.file_size : static_cast<uint32_t>(declared_size);
    const uint32_t off_bits = spec.override_off_bits ? spec.off_bits : off;

    std::vector<uint8_t> out;
    out.push_back('B');
    out.push_back('M');
    append_u32le(out, file_size);
    append_u16le(out, static_cast<uint16_t>(spec.reserved & 0xFFFF));
    append_u16le(out, static_cast<uint16_t>(spec.reserved >> 16));
    append_u32le(out, off_bits);
    out.insert(out.end(), dib.begin(), dib.end());
    if (masks_in_file) {
        append_u32le(out, spec.masks[0]);
        append_u32le(out, spec.masks[1]);
        append_u32le(out, spec.masks[2]);
        if (spec.compression == 6) append_u32le(out, spec.masks[3]);
    }
    out.insert(out.end(), palette_bytes, uint8_t{0});
    out.insert(out.end(), pixels.begin(), pixels.end());
    out.insert(out.end(), spec.trailing.begin(), spec.trailing.end());
    return out;
}

ValidationResult validate(const std::vector<uint8_t>& bytes, bool deep) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    reader.set_deep_validate(deep);
    BmpSignature signature;
    return signature.validate(reader);
}

bool has_note(const ValidationResult& result, const std::string& note) {
    return std::find(result.notes.begin(), result.notes.end(), note) != result.notes.end();
}

}  // namespace

TEST_CASE("bmp: a 24-bit image is medium shallow and high with deep validation", "[bmp][m3]") {
    BmpSpec spec;
    spec.trailing = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<uint8_t> bmp = build_bmp(spec);
    const uint64_t declared = bmp.size() - spec.trailing.size();

    const ValidationResult shallow = validate(bmp, false);
    REQUIRE(shallow.verdict == ValidationResult::Verdict::Valid);
    CHECK(shallow.length_bytes == declared);
    CHECK(shallow.confidence == Confidence::Medium);
    CHECK(shallow.subtype == "bmp");
    CHECK(shallow.notes.empty());

    const ValidationResult deep = validate(bmp, true);
    REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
    CHECK(deep.length_bytes == declared);
    CHECK(deep.confidence == Confidence::High);
    CHECK(deep.subtype == "bmp");
}

TEST_CASE("bmp: palette layouts and header variants are accepted", "[bmp][m3]") {
    SECTION("8-bit with an explicit 16-entry palette") {
        BmpSpec spec;
        spec.bpp = 8;
        spec.clr_used = 16;
        spec.width = 5;
        spec.height = 3;
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.confidence == Confidence::High);
        CHECK(result.subtype == "bmp");
    }
    SECTION("8-bit with the default 256-entry palette") {
        BmpSpec spec;
        spec.bpp = 8;
        spec.width = 5;
        spec.height = 3;
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("2-bit with the default 4-entry palette") {
        BmpSpec spec;
        spec.bpp = 2;
        spec.width = 4;
        spec.height = 2;
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("1-bit with the default 2-entry palette") {
        BmpSpec spec;
        spec.bpp = 1;
        spec.width = 8;
        spec.height = 2;
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("BITMAPCOREHEADER uses three-byte palette entries") {
        BmpSpec spec;
        spec.dib_size = 12;
        spec.bpp = 8;
        spec.width = 5;
        spec.height = 3;
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "os2");
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("OS/2 2.x 64-byte header") {
        BmpSpec spec;
        spec.dib_size = 64;
        spec.bpp = 8;
        spec.clr_used = 16;
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "os2");
    }
}

TEST_CASE("bmp: every accepted DIB header size parses", "[bmp][m3]") {
    for (const uint32_t size : {52u, 56u, 108u, 124u}) {
        BmpSpec spec;
        spec.dib_size = size;
        CAPTURE(size);
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "bmp");
    }
}

TEST_CASE("bmp: a negative height marks a top-down bitmap", "[bmp][m3]") {
    BmpSpec spec;
    spec.height = -4;
    const ValidationResult result = validate(build_bmp(spec), true);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(has_note(result, "top_down"));
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("bmp: malformed headers are rejected", "[bmp][m3]") {
    SECTION("nonzero reserved fields") {
        BmpSpec spec;
        spec.reserved = 1;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("unknown DIB header size") {
        BmpSpec spec;
        spec.dib_size = 41;
        spec.add_pixels = false;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("wrong plane count") {
        BmpSpec spec;
        spec.planes = 2;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("zero or negative dimensions") {
        BmpSpec spec;
        spec.width = 0;
        spec.add_pixels = false;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
        spec = BmpSpec{};
        spec.height = 0;
        spec.add_pixels = false;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
        spec = BmpSpec{};
        spec.width = -4;
        spec.add_pixels = false;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
        spec = BmpSpec{};
        spec.height = std::numeric_limits<int32_t>::min();
        spec.add_pixels = false;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("pixel count above the sanity cap") {
        BmpSpec spec;
        spec.width = 20000;
        spec.height = 20000;
        spec.add_pixels = false;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("unsupported bit depths and compressions") {
        BmpSpec spec;
        spec.bpp = 7;
        spec.add_pixels = false;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
        for (const uint32_t compression : {7u, 8u, 123u}) {
            CAPTURE(compression);
            spec = BmpSpec{};
            spec.compression = compression;
            spec.add_pixels = false;
            CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
        }
        spec = BmpSpec{};
        spec.compression = 1;
        spec.bpp = 4;
        spec.rle = {};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("palette size inconsistent with the bit depth") {
        BmpSpec spec;
        spec.bpp = 8;
        spec.clr_used = 257;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("bfSize shorter than the DIB header") {
        BmpSpec spec;
        spec.override_file_size = true;
        spec.file_size = 53;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("bfSize shorter than the pixel array") {
        BmpSpec spec;
        spec.override_file_size = true;
        spec.file_size = 101;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("bfOffBits pointing into the palette") {
        BmpSpec spec;
        spec.bpp = 8;
        spec.clr_used = 16;
        spec.override_off_bits = true;
        spec.off_bits = 54;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("bfOffBits beyond the declared file size") {
        BmpSpec spec;
        spec.override_off_bits = true;
        spec.off_bits = 1000;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("biSizeImage inconsistent with the pixel array") {
        BmpSpec spec;
        spec.size_image = 1;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
        spec = BmpSpec{};
        spec.size_image = 1000;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
}

TEST_CASE("bmp: RLE8 packet framing is validated", "[bmp][m3]") {
    auto rle_spec = [] {
        BmpSpec spec;
        spec.width = 4;
        spec.height = 4;
        spec.bpp = 8;
        spec.clr_used = 16;
        spec.compression = 1;
        return spec;
    };

    SECTION("encoded runs and end of bitmap") {
        BmpSpec spec = rle_spec();
        spec.rle = {4, 1, 0, 0, 4, 2, 0, 0, 0, 1};
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "rle8");
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("absolute mode with word padding") {
        BmpSpec spec = rle_spec();
        spec.rle = {0, 3, 0x11, 0x22, 0x33, 0x00, 0, 0, 0, 1};
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("delta moves the cursor") {
        BmpSpec spec = rle_spec();
        spec.rle = {0, 2, 2, 1, 2, 9, 0, 0, 0, 1};
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("a run wider than the row") {
        BmpSpec spec = rle_spec();
        spec.rle = {5, 1, 0, 1};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("an absolute run wider than the row") {
        BmpSpec spec = rle_spec();
        spec.rle = {0, 5, 1, 2, 3, 4, 5, 0, 0, 0, 0, 1};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("a delta beyond the bitmap") {
        BmpSpec spec = rle_spec();
        spec.rle = {0, 2, 5, 0, 0, 1};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("a missing end-of-bitmap marker") {
        BmpSpec spec = rle_spec();
        spec.rle = {4, 1, 0, 0};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("biSizeImage smaller than the stream") {
        BmpSpec spec = rle_spec();
        spec.rle = {4, 1, 0, 0, 0, 1};
        spec.size_image = static_cast<uint32_t>(spec.rle.size()) - 1;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("top-down RLE is not a defined layout") {
        BmpSpec spec = rle_spec();
        spec.height = -4;
        spec.rle = {4, 1, 0, 0, 0, 1};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("a stream cut before its marker is a truncation") {
        BmpSpec spec = rle_spec();
        spec.rle = {4, 1, 0, 0, 0, 1};
        const std::vector<uint8_t> bmp = build_bmp(spec);
        const std::vector<uint8_t> cut(bmp.begin(), bmp.end() - 1);
        const ValidationResult result = validate(cut, false);
        REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(result.length_bytes == cut.size());
        CHECK(result.confidence == Confidence::Low);
        CHECK(result.subtype == "rle8");
    }
}

TEST_CASE("bmp: RLE4 packet framing is validated", "[bmp][m3]") {
    auto rle_spec = [] {
        BmpSpec spec;
        spec.width = 4;
        spec.height = 4;
        spec.bpp = 4;
        spec.clr_used = 16;
        spec.compression = 2;
        return spec;
    };

    SECTION("encoded runs and end of bitmap") {
        BmpSpec spec = rle_spec();
        spec.rle = {4, 0x12, 0, 0, 4, 0x34, 0, 0, 0, 1};
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "rle4");
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("absolute mode packs two pixels per byte") {
        BmpSpec spec = rle_spec();
        spec.rle = {0, 3, 0x12, 0x30, 0, 0, 0, 1};
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("absolute mode pads odd data to a word") {
        BmpSpec spec = rle_spec();
        spec.rle = {0, 1, 0x70, 0x00, 0, 1};
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("a run wider than the row") {
        BmpSpec spec = rle_spec();
        spec.rle = {5, 0x12, 0, 1};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("a stream cut before its marker is a truncation") {
        BmpSpec spec = rle_spec();
        spec.rle = {4, 0x12, 0, 0, 0, 1};
        const std::vector<uint8_t> bmp = build_bmp(spec);
        const std::vector<uint8_t> cut(bmp.begin(), bmp.end() - 1);
        const ValidationResult result = validate(cut, false);
        REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(result.length_bytes == cut.size());
        CHECK(result.subtype == "rle4");
    }
}

TEST_CASE("bmp: bitfield masks must be disjoint and fit the depth", "[bmp][m3]") {
    SECTION("16-bit masks stored after a 40-byte header") {
        BmpSpec spec;
        spec.bpp = 16;
        spec.compression = 3;
        spec.masks = {0x7C00u, 0x03E0u, 0x001Fu, 0};
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "bitfields");
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("32-bit masks stored inside a 52-byte header") {
        BmpSpec spec;
        spec.bpp = 32;
        spec.dib_size = 52;
        spec.compression = 3;
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("32-bit alpha masks inside a 56-byte header") {
        BmpSpec spec;
        spec.bpp = 32;
        spec.dib_size = 56;
        spec.compression = 6;
        REQUIRE(validate(build_bmp(spec), true).verdict == ValidationResult::Verdict::Valid);
    }
    SECTION("overlapping color channels") {
        BmpSpec spec;
        spec.bpp = 32;
        spec.dib_size = 52;
        spec.compression = 3;
        spec.masks = {0x00FF0000u, 0x00FF0000u, 0x000000FFu, 0};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("a zero color channel") {
        BmpSpec spec;
        spec.bpp = 32;
        spec.dib_size = 52;
        spec.compression = 3;
        spec.masks = {0x00FF0000u, 0x0000FF00u, 0x00000000u, 0};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("16-bit masks wider than the pixel") {
        BmpSpec spec;
        spec.bpp = 16;
        spec.compression = 3;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("alpha channel overlapping red") {
        BmpSpec spec;
        spec.bpp = 32;
        spec.dib_size = 56;
        spec.compression = 6;
        spec.masks = {0x00FF0000u, 0x0000FF00u, 0x000000FFu, 0x00FF0000u};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("alpha masks in a header too short to hold them") {
        BmpSpec spec;
        spec.bpp = 32;
        spec.dib_size = 52;
        spec.compression = 6;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
}

TEST_CASE("bmp: embedded JPEG and PNG payloads are recognized", "[bmp][m3]") {
    SECTION("BI_JPEG") {
        BmpSpec spec;
        spec.compression = 4;
        spec.embedded = {0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43};
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "jpeg");
        CHECK(result.confidence == Confidence::Medium);
        CHECK(has_note(result, "embedded_image_unverified"));
    }
    SECTION("BI_PNG") {
        BmpSpec spec;
        spec.bpp = 32;
        spec.compression = 5;
        const ValidationResult result = validate(build_bmp(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.subtype == "png");
        CHECK(result.confidence == Confidence::Medium);
    }
    SECTION("wrong embedded magic") {
        BmpSpec spec;
        spec.compression = 4;
        spec.embedded = {0x00, 0x00, 0x00, 0x00};
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("bit depth not allowed for an embedded image") {
        BmpSpec spec;
        spec.bpp = 8;
        spec.compression = 4;
        CHECK_FALSE(validate(build_bmp(spec), false).is_valid());
    }
    SECTION("payload cut before the magic completes") {
        BmpSpec spec;
        spec.compression = 4;
        const std::vector<uint8_t> bmp = build_bmp(spec);
        const std::vector<uint8_t> cut(bmp.begin(), bmp.begin() + 56);
        const ValidationResult result = validate(cut, false);
        REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(result.length_bytes == cut.size());
        CHECK(result.confidence == Confidence::Low);
        CHECK(result.subtype == "jpeg");
    }
    SECTION("candidate cut exactly at the payload offset") {
        BmpSpec spec;
        spec.compression = 4;
        const std::vector<uint8_t> bmp = build_bmp(spec);
        const std::vector<uint8_t> cut(bmp.begin(), bmp.begin() + 54);
        const ValidationResult result = validate(cut, false);
        REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(result.length_bytes == cut.size());
    }
}

TEST_CASE("bmp: truncation yields a bounded low-confidence candidate", "[bmp][m3]") {
    SECTION("cut inside the pixel array") {
        BmpSpec spec;
        const std::vector<uint8_t> bmp = build_bmp(spec);
        const std::vector<uint8_t> cut(bmp.begin(), bmp.end() - 1);
        const ValidationResult result = validate(cut, false);
        REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(result.length_bytes == cut.size());
        CHECK(result.confidence == Confidence::Low);
        CHECK(result.subtype == "bmp");

        const ValidationResult deep = validate(cut, true);
        REQUIRE(deep.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(deep.length_bytes == cut.size());
    }
    SECTION("cut inside the DIB header is not a candidate") {
        BmpSpec spec;
        const std::vector<uint8_t> bmp = build_bmp(spec);
        const std::vector<uint8_t> cut(bmp.begin(), bmp.begin() + 30);
        CHECK_FALSE(validate(cut, false).is_valid());
    }
    SECTION("empty and tiny buffers") {
        CHECK_FALSE(validate({}, false).is_valid());
        CHECK_FALSE(validate({'B', 'M'}, false).is_valid());
    }
}
