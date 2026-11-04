#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_gif.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

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

std::vector<uint8_t> checkerboard(uint16_t width, uint16_t height, uint8_t colors = 2) {
    std::vector<uint8_t> pixels;
    pixels.reserve(static_cast<size_t>(width) * height);
    for (uint16_t y = 0; y < height; ++y)
        for (uint16_t x = 0; x < width; ++x)
            pixels.push_back(static_cast<uint8_t>((x + y) % colors));
    return pixels;
}

struct GifSpec {
    bool version89 = true;
    uint16_t canvas_width = 8;
    uint16_t canvas_height = 8;
    uint16_t frame_width = 8;
    uint16_t frame_height = 8;
    std::vector<uint8_t> pixels = checkerboard(8, 8);
    uint8_t min_code_size = 2;
    bool global_ct = true;
    bool local_ct = false;
    bool with_gce = true;
    bool with_comment = false;
    bool with_application = false;
    bool with_trailer = true;
    bool truncate_stream = false;
    bool empty_stream = false;
    bool custom_stream = false;
    std::vector<uint8_t> stream;
    uint8_t frame_packed_extra = 0;
    uint8_t gce_block_size = 4;
};

void append_image(std::vector<uint8_t>& out, const GifSpec& spec) {
    out.push_back(0x2C);
    append_u16le(out, 0);
    append_u16le(out, 0);
    append_u16le(out, spec.frame_width);
    append_u16le(out, spec.frame_height);
    out.push_back(static_cast<uint8_t>((spec.local_ct ? 0x80 : 0x00) | spec.frame_packed_extra));
    if (spec.local_ct) {
        const uint8_t palette[] = {0, 0, 0, 255, 255, 255};
        out.insert(out.end(), palette, palette + sizeof palette);
    }

    out.push_back(spec.min_code_size);
    std::vector<uint8_t> stream =
        spec.custom_stream ? spec.stream : lzw_encode(spec.pixels, spec.min_code_size);
    if (spec.truncate_stream) stream.resize(stream.size() / 2);
    if (spec.empty_stream) stream.clear();
    append_subblocks(out, stream);
}

std::vector<uint8_t> build_gif(const GifSpec& spec) {
    std::vector<uint8_t> out;
    const char* magic = spec.version89 ? "GIF89a" : "GIF87a";
    out.insert(out.end(), magic, magic + 6);
    append_u16le(out, spec.canvas_width);
    append_u16le(out, spec.canvas_height);
    out.push_back(spec.global_ct ? 0x80 : 0x00);  // two-entry global color table
    out.push_back(0);
    out.push_back(0);
    if (spec.global_ct) {
        const uint8_t palette[] = {0, 0, 0, 255, 255, 255};
        out.insert(out.end(), palette, palette + sizeof palette);
    }

    if (spec.with_gce) {
        const uint8_t gce[] = {0x21, 0xF9, spec.gce_block_size, 0, 0, 0, 0, 0};
        out.insert(out.end(), gce, gce + sizeof gce);
    }
    if (spec.with_comment) {
        out.push_back(0x21);
        out.push_back(0xFE);
        append_subblocks(out, {'h', 'e', 'l', 'l', 'o'});
    }
    if (spec.with_application) {
        out.push_back(0x21);
        out.push_back(0xFF);
        out.push_back(11);
        const char app[] = {'N', 'E', 'T', 'S', 'C', 'A', 'P', 'E', '2', '.', '0'};
        out.insert(out.end(), app, app + sizeof app);
        append_subblocks(out, {1, 0, 0});
    }

    append_image(out, spec);
    if (spec.with_trailer) out.push_back(0x3B);
    return out;
}

ValidationResult validate(const std::vector<uint8_t>& bytes, bool deep) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    reader.set_deep_validate(deep);
    GifSignature signature;
    return signature.validate(reader);
}

std::optional<Continuation> find_continuation(const std::vector<uint8_t>& bytes) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    GifSignature signature;
    return signature.find_continuation(reader);
}

}  // namespace

TEST_CASE("gif: a minimal image is medium shallow and high with deep validation", "[gif][m3]") {
    const std::vector<uint8_t> gif = build_gif(GifSpec{});
    const ValidationResult shallow = validate(gif, false);
    REQUIRE(shallow.verdict == ValidationResult::Verdict::Valid);
    CHECK(shallow.length_bytes == gif.size());
    CHECK(shallow.confidence == Confidence::Medium);
    CHECK(shallow.subtype == "gif89a");

    const ValidationResult deep = validate(gif, true);
    REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
    CHECK(deep.length_bytes == gif.size());
    CHECK(deep.confidence == Confidence::High);
    CHECK(deep.subtype == "gif89a");
}

TEST_CASE("gif: the 87a version is reported as a distinct subtype", "[gif][m3]") {
    GifSpec spec;
    spec.version89 = false;
    const std::vector<uint8_t> gif = build_gif(spec);
    const ValidationResult result = validate(gif, true);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.subtype == "gif87a");
}

TEST_CASE("gif: extensions and a local color table do not disturb the block chain",
          "[gif][m3]") {
    SECTION("comment extension") {
        GifSpec spec;
        spec.with_comment = true;
        const ValidationResult result = validate(build_gif(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("application extension") {
        GifSpec spec;
        spec.with_application = true;
        const ValidationResult result = validate(build_gif(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("both extensions") {
        GifSpec spec;
        spec.with_comment = true;
        spec.with_application = true;
        const ValidationResult result = validate(build_gif(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.confidence == Confidence::High);
    }
    SECTION("local color table only") {
        GifSpec spec;
        spec.global_ct = false;
        spec.local_ct = true;
        spec.with_gce = false;
        const ValidationResult result = validate(build_gif(spec), true);
        REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
        CHECK(result.confidence == Confidence::High);
    }
}

TEST_CASE("gif: larger palettes and multi-byte code sizes decode", "[gif][m3]") {
    GifSpec spec;
    spec.canvas_width = 64;
    spec.canvas_height = 64;
    spec.frame_width = 64;
    spec.frame_height = 64;
    spec.min_code_size = 8;
    spec.pixels = checkerboard(64, 64, 200);
    spec.global_ct = true;
    std::vector<uint8_t> gif = build_gif(spec);
    // Replace the two-entry table with 256 entries and update the size code.
    gif[10] = 0x87;
    std::vector<uint8_t> palette(768);
    for (size_t i = 0; i < palette.size(); ++i) palette[i] = static_cast<uint8_t>(i);
    gif.erase(gif.begin() + 13, gif.begin() + 19);
    gif.insert(gif.begin() + 13, palette.begin(), palette.end());

    const ValidationResult result = validate(gif, true);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.confidence == Confidence::High);
    CHECK(result.length_bytes == gif.size());
}

TEST_CASE("gif: a missing trailer after a complete image is a truncation", "[gif][m3]") {
    GifSpec spec;
    spec.with_trailer = false;
    const std::vector<uint8_t> gif = build_gif(spec);
    const ValidationResult result = validate(gif, false);
    REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(result.length_bytes == gif.size());
    CHECK(result.confidence == Confidence::Low);
    CHECK(result.subtype == "gif89a");
}

TEST_CASE("gif: truncation before any complete image is rejected", "[gif][m3]") {
    const std::vector<uint8_t> gif = build_gif(GifSpec{});
    // Cut inside the image data sub-block chain, before its terminator.
    const std::vector<uint8_t> cut(gif.begin(), gif.begin() + 40);
    REQUIRE(cut.size() < gif.size());
    CHECK_FALSE(validate(cut, false).is_valid());
    CHECK_FALSE(validate(cut, true).is_valid());
}

TEST_CASE("gif: an image without any color table is rejected", "[gif][m3]") {
    GifSpec spec;
    spec.global_ct = false;
    const std::vector<uint8_t> gif = build_gif(spec);
    CHECK_FALSE(validate(gif, false).is_valid());
}

TEST_CASE("gif: malformed headers and block introducers are rejected", "[gif][m3]") {
    SECTION("empty image data") {
        GifSpec spec;
        spec.empty_stream = true;
        CHECK_FALSE(validate(build_gif(spec), false).is_valid());
    }
    SECTION("invalid minimum code size") {
        GifSpec spec;
        spec.min_code_size = 1;
        CHECK_FALSE(validate(build_gif(spec), false).is_valid());
        spec.min_code_size = 9;
        CHECK_FALSE(validate(build_gif(spec), false).is_valid());
    }
    SECTION("zero frame dimensions") {
        GifSpec spec;
        spec.frame_width = 0;
        CHECK_FALSE(validate(build_gif(spec), false).is_valid());
    }
    SECTION("reserved frame descriptor bits") {
        GifSpec spec;
        spec.frame_packed_extra = 0x10;
        CHECK_FALSE(validate(build_gif(spec), false).is_valid());
    }
    SECTION("graphic control block with the wrong size") {
        GifSpec spec;
        spec.gce_block_size = 3;
        CHECK_FALSE(validate(build_gif(spec), false).is_valid());
    }
    SECTION("trailer without any image") {
        std::vector<uint8_t> gif;
        const char* magic = "GIF89a";
        gif.insert(gif.end(), magic, magic + 6);
        append_u16le(gif, 1);
        append_u16le(gif, 1);
        gif.push_back(0);
        gif.push_back(0);
        gif.push_back(0);
        gif.push_back(0x3B);
        CHECK_FALSE(validate(gif, false).is_valid());
    }
}

TEST_CASE("gif: deep validation rejects streams whose code count is wrong", "[gif][m3]") {
    SECTION("declared frame larger than the encoded pixels") {
        GifSpec spec;
        spec.frame_width = 9;
        spec.frame_height = 9;
        const std::vector<uint8_t> gif = build_gif(spec);
        REQUIRE(validate(gif, false).is_valid());
        CHECK_FALSE(validate(gif, true).is_valid());
    }
    SECTION("declared frame smaller than the encoded pixels") {
        GifSpec spec;
        spec.frame_width = 7;
        spec.frame_height = 7;
        const std::vector<uint8_t> gif = build_gif(spec);
        REQUIRE(validate(gif, false).is_valid());
        CHECK_FALSE(validate(gif, true).is_valid());
    }
}

TEST_CASE("gif: deep validation requires an initial clear code", "[gif][m3]") {
    std::vector<uint8_t> hand;
    uint32_t bits = 0;
    int count = 0;
    auto put3 = [&](int code) {
        bits |= static_cast<uint32_t>(code) << count;
        count += 3;
        while (count >= 8) {
            hand.push_back(static_cast<uint8_t>(bits & 0xFF));
            bits >>= 8;
            count -= 8;
        }
    };
    put3(0);  // literal without a preceding clear code
    put3(5);  // end code
    if (count > 0) hand.push_back(static_cast<uint8_t>(bits & 0xFF));

    GifSpec spec;
    spec.custom_stream = true;
    spec.stream = hand;
    const std::vector<uint8_t> gif = build_gif(spec);
    REQUIRE(validate(gif, false).is_valid());
    CHECK_FALSE(validate(gif, true).is_valid());
}

TEST_CASE("gif: a multi-frame stream completes each image", "[gif][m3]") {
    GifSpec first;
    std::vector<uint8_t> gif = build_gif(first);
    gif.pop_back();  // drop the trailer

    GifSpec second;
    second.global_ct = false;
    second.local_ct = true;
    second.with_gce = false;
    append_image(gif, second);
    gif.push_back(0x3B);

    const ValidationResult deep = validate(gif, true);
    REQUIRE(deep.verdict == ValidationResult::Verdict::Valid);
    CHECK(deep.confidence == Confidence::High);
    CHECK(deep.length_bytes == gif.size());

    std::vector<uint8_t> no_trailer(gif.begin(), gif.end() - 1);
    const ValidationResult truncated = validate(no_trailer, false);
    REQUIRE(truncated.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(truncated.length_bytes == no_trailer.size());
}

TEST_CASE("gif: the reported length stops at the trailer", "[gif][m3]") {
    std::vector<uint8_t> gif = build_gif(GifSpec{});
    const size_t gif_size = gif.size();
    gif.insert(gif.end(), {0xDE, 0xAD, 0xBE, 0xEF});
    const ValidationResult result = validate(gif, true);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == gif_size);
}

std::vector<uint8_t> two_frame_gif(uint64_t& second_at) {
    std::vector<uint8_t> gif = build_gif(GifSpec{});
    gif.pop_back();  // drop the trailer; the second frame follows
    second_at = gif.size();
    GifSpec second;
    second.global_ct = false;
    second.local_ct = true;
    second.with_gce = false;
    append_image(gif, second);
    gif.push_back(0x3B);
    return gif;
}

TEST_CASE("gif: a structurally broken block after a frame is a cut", "[gif][m3][fragment]") {
    SECTION("an unknown introducer where the trailer stood") {
        std::vector<uint8_t> gif = build_gif(GifSpec{});
        gif.back() = 0x00;
        const ValidationResult shallow = validate(gif, false);
        REQUIRE(shallow.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(shallow.length_bytes == gif.size() - 1);
        CHECK(shallow.confidence == Confidence::Low);
        REQUIRE(shallow.notes.size() == 1);
        CHECK(shallow.notes.front() == "discontinuity");

        const ValidationResult deep = validate(gif, true);
        REQUIRE(deep.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(deep.length_bytes == gif.size() - 1);
    }
    SECTION("a broken introducer between frames cuts at that block") {
        uint64_t second_at = 0;
        std::vector<uint8_t> gif = two_frame_gif(second_at);
        gif[second_at] = 0x7F;

        const ValidationResult result = validate(gif, true);
        REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
        CHECK(result.length_bytes == second_at);
        REQUIRE(result.notes.size() == 1);
        CHECK(result.notes.front() == "discontinuity");
    }
    SECTION("bytes that fail the deep decode are corruption, not a cut") {
        GifSpec first;
        first.canvas_width = 32;
        first.canvas_height = 32;
        first.frame_width = 32;
        first.frame_height = 32;
        first.pixels = checkerboard(32, 32);
        std::vector<uint8_t> gif = build_gif(first);
        gif.pop_back();
        const uint64_t second_at = gif.size();
        GifSpec second;
        second.global_ct = false;
        second.local_ct = true;
        second.with_gce = false;
        append_image(gif, second);
        gif.push_back(0x3B);
        // Flip a byte inside the first frame's LZW data: the sub-block chain still parses,
        // so shallow validation sees nothing, but the decode is this format's proof.
        gif[second_at - 2] ^= 0xFF;

        CHECK(validate(gif, false).is_valid());
        CHECK_FALSE(validate(gif, true).is_valid());
    }
}

TEST_CASE("gif: find_continuation joins a tail that proves itself",
          "[gif][m3][fragment]") {
    SECTION("a tail that opens on an image block") {
        uint64_t second_at = 0;
        const std::vector<uint8_t> gif = two_frame_gif(second_at);
        const std::vector<uint8_t> tail(gif.begin() + static_cast<std::ptrdiff_t>(second_at),
                                        gif.end());
        const auto cont = find_continuation(tail);
        REQUIRE(cont.has_value());
        CHECK(cont->start == 0);
        CHECK(cont->length == tail.size());
        CHECK(cont->complete);
    }
    SECTION("a tail resuming mid-stream joins at the next introducer") {
        std::vector<uint8_t> tail(37, 0x07);
        tail.push_back(0x00);  // the interrupted frame's chain ends here
        const uint64_t join_at = tail.size();
        GifSpec second;
        second.global_ct = false;
        second.local_ct = true;
        second.with_gce = false;
        append_image(tail, second);
        tail.push_back(0x3B);

        const auto cont = find_continuation(tail);
        REQUIRE(cont.has_value());
        CHECK(cont->start == join_at);
        CHECK(cont->length == tail.size() - join_at);
        CHECK(cont->complete);
    }
    SECTION("a run ends at the first block that fails") {
        std::vector<uint8_t> tail;
        GifSpec second;
        second.global_ct = false;
        second.local_ct = true;
        second.with_gce = false;
        append_image(tail, second);
        const uint64_t run_end = tail.size();
        tail.push_back(0x7F);  // a broken introducer ends the run
        GifSpec third;
        third.global_ct = false;
        third.local_ct = true;
        third.with_gce = false;
        append_image(tail, third);
        tail.push_back(0x3B);

        const auto cont = find_continuation(tail);
        REQUIRE(cont.has_value());
        CHECK(cont->start == 0);
        CHECK(cont->length == run_end);
        CHECK_FALSE(cont->complete);
    }
    SECTION("a frame cut inside its own data proves nothing") {
        std::vector<uint8_t> tail;
        tail.push_back(0x2C);
        append_u16le(tail, 0);
        append_u16le(tail, 0);
        append_u16le(tail, 8);
        append_u16le(tail, 8);
        tail.push_back(0x00);  // borrows the global table the head carries
        tail.push_back(2);
        append_subblocks(tail, {0x07, 0x07, 0x07});
        CHECK_FALSE(find_continuation(tail).has_value());
    }
}

TEST_CASE("gif: find_continuation refuses weak starts", "[gif][m3][fragment]") {
    SECTION("bare sub-block bytes are never claimed") {
        std::vector<uint8_t> tail;
        tail.push_back(0x09);
        tail.insert(tail.end(), 40, 0x07);
        tail.push_back(0x00);  // a well-formed chain, but no block opened it
        tail.push_back(0x3B);  // even a trailer does not make it a continuation
        CHECK_FALSE(find_continuation(tail).has_value());
    }
    SECTION("another GIF's header ends the search") {
        std::vector<uint8_t> tail(16, 0x07);
        const std::vector<uint8_t> next = build_gif(GifSpec{});
        tail.insert(tail.end(), next.begin(), next.end());
        CHECK_FALSE(find_continuation(tail).has_value());
    }
    SECTION("comment extensions are too weak to start a run") {
        std::vector<uint8_t> tail;
        tail.push_back(0x21);
        tail.push_back(0xFE);
        append_subblocks(tail, {'h', 'i'});
        tail.insert(tail.end(), 16, 0x07);
        CHECK_FALSE(find_continuation(tail).has_value());
    }
    SECTION("a lone trailer is not a continuation") {
        std::vector<uint8_t> tail(8, 0x07);
        tail.push_back(0x3B);
        CHECK_FALSE(find_continuation(tail).has_value());
    }
}
