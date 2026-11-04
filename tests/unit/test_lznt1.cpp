#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/error.hpp"
#include "openrecover/fs/lznt1.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::fs;

// [MS-XCA] publishes a worked example: a 142-byte ANSI string, terminal NUL included, that the
// standard compression engine writes as a single 59-byte chunk. Nothing pins the bit layout better.
const char* kDocumentedHex =
    "38 b0 88 46 23 20 00 20 47 20 41 00 10 a2 47 01 a0 45 20 44 00 08 45 01 "
    "50 79 00 c0 45 20 05 24 13 88 05 b4 02 4a 44 ef 03 58 02 8c 09 16 01 48 "
    "45 00 be 00 9e 00 04 01 18 90 00";

const char* kDocumentedText =
    "F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E "
    "F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D";

std::vector<uint8_t> from_hex(std::string_view text) {
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        return static_cast<uint8_t>(c - 'A' + 10);
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == ' ') continue;
        const uint8_t high = nibble(text[i]);
        const uint8_t low = nibble(text[++i]);
        out.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return out;
}

std::string text_of(const std::vector<uint8_t>& bytes, size_t length) {
    std::string out;
    out.reserve(length);
    for (size_t i = 0; i < length; ++i) out.push_back(static_cast<char>(bytes[i]));
    return out;
}

// Writes entries in the shape the format reads them back in: up to eight entries behind one flag
// byte, each entry a single literal byte or a two-byte back-reference, and the next flag byte
// following immediately. A back-reference splits its sixteen bits by how much the chunk has
// produced so far, so the builder has to track that count exactly like the decoder does.
class GroupBuilder {
public:
    void literal(uint8_t byte) {
        pending_.push_back(byte);
        ++produced_;
        complete_entry(false);
    }

    void match(size_t displacement, size_t length) {
        const size_t shift = offset_shift();
        const uint16_t mask = length_mask();
        REQUIRE(displacement >= 1);
        REQUIRE(displacement <= (size_t{1} << (16 - shift)));
        REQUIRE(length >= 3);
        REQUIRE(length - 3 <= static_cast<size_t>(mask));
        const uint16_t tuple = static_cast<uint16_t>(((displacement - 1) << shift) | (length - 3));
        pending_.push_back(static_cast<uint8_t>(tuple & 0xFF));
        pending_.push_back(static_cast<uint8_t>(tuple >> 8));
        produced_ += length;
        complete_entry(true);
    }

    // A compressed chunk of the 4096-byte shape. The on-disk count is the number of bytes after
    // the header, minus one.
    std::vector<uint8_t> chunk() {
        flush();
        REQUIRE(body_.size() >= 1);
        const uint16_t header = static_cast<uint16_t>(0x8000 | (3 << 12) | (body_.size() - 1));
        std::vector<uint8_t> out = {static_cast<uint8_t>(header & 0xFF),
                                    static_cast<uint8_t>(header >> 8)};
        out.insert(out.end(), body_.begin(), body_.end());
        return out;
    }

    size_t produced() const { return produced_; }

private:
    size_t offset_shift() const {
        size_t shift = 12;
        for (size_t probe = produced_ == 0 ? 0 : produced_ - 1; probe >= 16; probe >>= 1) --shift;
        return shift;
    }

    uint16_t length_mask() const {
        uint16_t mask = 0x0FFF;
        for (size_t probe = produced_ == 0 ? 0 : produced_ - 1; probe >= 16; probe >>= 1)
            mask = static_cast<uint16_t>(mask >> 1);
        return mask;
    }

    void complete_entry(bool is_match) {
        if (is_match) flags_ = static_cast<uint8_t>(flags_ | (1u << bits_));
        ++bits_;
        if (bits_ == 8) flush();
    }

    void flush() {
        if (bits_ == 0) return;
        body_.push_back(flags_);
        body_.insert(body_.end(), pending_.begin(), pending_.end());
        pending_.clear();
        flags_ = 0;
        bits_ = 0;
    }

    std::vector<uint8_t> body_;
    std::vector<uint8_t> pending_;
    uint8_t flags_ = 0;
    size_t bits_ = 0;
    size_t produced_ = 0;
};

std::vector<uint8_t> raw_chunk(std::string_view text) {
    const uint16_t header = static_cast<uint16_t>(text.size() - 1);
    std::vector<uint8_t> out = {static_cast<uint8_t>(header & 0xFF),
                                static_cast<uint8_t>(header >> 8)};
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

Result<Lznt1Chunk> decode(const std::vector<uint8_t>& src, std::span<uint8_t> dst) {
    return decompress_lznt1_chunk(std::span<const uint8_t>(src), dst);
}

bool guarded(const std::vector<uint8_t>& buffer, size_t limit) {
    return std::all_of(buffer.begin() + static_cast<std::ptrdiff_t>(limit), buffer.end(),
                       [](uint8_t byte) { return byte == 0xCC; });
}

}  // namespace

TEST_CASE("the documented MS-XCA chunk decompresses byte for byte", "[lznt1]") {
    const std::vector<uint8_t> src = from_hex(kDocumentedHex);
    REQUIRE(src.size() == 59);

    std::vector<uint8_t> dst(4096, 0);
    auto chunk = decode(src, std::span<uint8_t>(dst));
    REQUIRE(chunk.has_value());
    CHECK(chunk->consumed == 59);
    CHECK(chunk->produced == 142);
    CHECK_FALSE(chunk->end_of_stream);

    const std::string expected(kDocumentedText);
    CHECK(text_of(dst, expected.size()) == expected);
    // The document counts a terminal NUL in its 142 bytes, and that byte is the last entry.
    CHECK(dst[expected.size()] == 0);

    auto whole = decompress_lznt1(std::span<const uint8_t>(src), std::span<uint8_t>(dst));
    REQUIRE(whole.has_value());
    CHECK(*whole == 142);
}

TEST_CASE("a raw chunk is copied through unchanged", "[lznt1]") {
    const std::vector<uint8_t> src = raw_chunk("hello world abcde");
    std::vector<uint8_t> dst(4096, 0);
    auto chunk = decode(src, std::span<uint8_t>(dst));
    REQUIRE(chunk.has_value());
    CHECK(chunk->consumed == src.size());
    CHECK(chunk->produced == 17);
    CHECK(text_of(dst, 17) == "hello world abcde");
}

TEST_CASE("an empty chunk count ends the unit", "[lznt1]") {
    const std::vector<uint8_t> src = {0x00, 0x30, 'u', 'n', 'u', 's', 'e', 'd'};
    std::vector<uint8_t> dst(4096, 0);
    auto chunk = decode(src, std::span<uint8_t>(dst));
    REQUIRE(chunk.has_value());
    CHECK(chunk->end_of_stream);
    CHECK(chunk->consumed == 2);
    CHECK(chunk->produced == 0);

    auto whole = decompress_lznt1(std::span<const uint8_t>(src), std::span<uint8_t>(dst));
    REQUIRE(whole.has_value());
    CHECK(*whole == 0);
}

TEST_CASE("the 512-byte chunk shape is refused rather than guessed at", "[lznt1]") {
    GroupBuilder builder;
    builder.literal('x');
    std::vector<uint8_t> src = builder.chunk();
    // Keep the count and the compressed flag, flip the signature from 3 to 2.
    const uint16_t header = static_cast<uint16_t>(src[0] | (src[1] << 8));
    const uint16_t altered = static_cast<uint16_t>((header & 0x8FFFu) | (2u << 12));
    src[0] = static_cast<uint8_t>(altered & 0xFF);
    src[1] = static_cast<uint8_t>(altered >> 8);

    std::vector<uint8_t> dst(4096, 0);
    auto chunk = decode(src, std::span<uint8_t>(dst));
    REQUIRE_FALSE(chunk.has_value());
    CHECK(chunk.error().code == ErrorCode::Unsupported);
}

TEST_CASE("a back-reference that overlaps itself repeats the pattern it starts", "[lznt1]") {
    GroupBuilder builder;
    builder.literal('A');
    builder.match(1, 8);
    const std::vector<uint8_t> src = builder.chunk();

    std::vector<uint8_t> dst(4096, 0);
    auto chunk = decode(src, std::span<uint8_t>(dst));
    REQUIRE(chunk.has_value());
    CHECK(chunk->produced == 9);
    CHECK(text_of(dst, 9) == "AAAAAAAAA");
}

TEST_CASE("the displacement field widens exactly when the chunk outgrows four bits", "[lznt1]") {
    const std::string prefix = "0123456789abcdef";  // sixteen literals, the last reachable offset

    // With sixteen bytes produced, four displacement bits still reach the start of the chunk; a
    // decoder that widened the field one entry too early would read this as an out-of-range match.
    {
        GroupBuilder builder;
        for (char c : prefix) builder.literal(static_cast<uint8_t>(c));
        CHECK(builder.produced() == 16);
        builder.match(16, 3);
        const std::vector<uint8_t> src = builder.chunk();
        CHECK(src[src.size() - 2] == 0x00);
        CHECK(src[src.size() - 1] == 0xF0);

        std::vector<uint8_t> dst(4096, 0);
        auto chunk = decode(src, std::span<uint8_t>(dst));
        REQUIRE(chunk.has_value());
        CHECK(chunk->produced == 19);
        CHECK(text_of(dst, 19) == prefix + "012");
    }

    // With seventeen bytes produced four bits are no longer enough, so a bit moves over.
    {
        GroupBuilder builder;
        for (char c : prefix) builder.literal(static_cast<uint8_t>(c));
        builder.literal('g');
        CHECK(builder.produced() == 17);
        builder.match(17, 3);
        const std::vector<uint8_t> src = builder.chunk();

        std::vector<uint8_t> dst(4096, 0);
        auto chunk = decode(src, std::span<uint8_t>(dst));
        REQUIRE(chunk.has_value());
        CHECK(chunk->produced == 20);
        CHECK(text_of(dst, 20) == prefix + "g012");
    }
}

TEST_CASE("several chunks of one unit are walked in order", "[lznt1]") {
    GroupBuilder builder;
    for (char c : std::string("a short chunk")) builder.literal(static_cast<uint8_t>(c));
    std::vector<uint8_t> src = raw_chunk("01234");
    const std::vector<uint8_t> second = builder.chunk();
    src.insert(src.end(), second.begin(), second.end());

    std::vector<uint8_t> dst(4096, 0);
    auto whole = decompress_lznt1(std::span<const uint8_t>(src), std::span<uint8_t>(dst));
    REQUIRE(whole.has_value());
    CHECK(*whole == 18);
    CHECK(text_of(dst, 18) == "01234a short chunk");
}

TEST_CASE("a destination shorter than a chunk takes its own bytes and ignores the rest",
          "[lznt1]") {
    GroupBuilder builder;
    for (char c : std::string("a short chunk")) builder.literal(static_cast<uint8_t>(c));
    std::vector<uint8_t> src = raw_chunk("01234");
    const std::vector<uint8_t> second = builder.chunk();
    src.insert(src.end(), second.begin(), second.end());
    // Bytes past the stream are the padding of the last cluster of a unit. A reader that stops when
    // it has what it needs never parses them, so they cannot turn a good file into a corrupt one.
    src.push_back(0xFF);
    src.push_back(0xFF);

    std::vector<uint8_t> dst(3, 0);
    auto part = decompress_lznt1(std::span<const uint8_t>(src), std::span<uint8_t>(dst));
    REQUIRE(part.has_value());
    CHECK(*part == 3);
    CHECK(text_of(dst, 3) == "012");
}

TEST_CASE("a truncated or self-contradictory chunk is an error, not a write", "[lznt1]") {
    std::vector<uint8_t> dst(4096, 0);

    SECTION("header cut short") {
        const std::vector<uint8_t> src = {0x38};
        auto chunk = decode(src, std::span<uint8_t>(dst));
        REQUIRE_FALSE(chunk.has_value());
        CHECK(chunk.error().code == ErrorCode::CorruptStructure);
    }

    SECTION("count claims more bytes than the unit holds") {
        const std::vector<uint8_t> pristine = from_hex(kDocumentedHex);
        const std::vector<uint8_t> short_src(pristine.begin(), pristine.end() - 1);
        auto chunk = decode(short_src, std::span<uint8_t>(dst));
        REQUIRE_FALSE(chunk.has_value());
        CHECK(chunk.error().code == ErrorCode::CorruptStructure);
    }

    SECTION("the first entry is a match, so there is nothing to copy from") {
        const std::vector<uint8_t> src = {0x02, 0xB0, 0x01, 0x00, 0x00};
        auto chunk = decode(src, std::span<uint8_t>(dst));
        REQUIRE_FALSE(chunk.has_value());
        CHECK(chunk.error().code == ErrorCode::CorruptStructure);
    }

    SECTION("a match is cut off by the end of the chunk") {
        GroupBuilder builder;
        // Eight entries fill a group, so the bytes appended below really are a second group; a
        // short first group would just have read them as more of its own literals.
        for (char c : std::string("ABCDEFGH")) builder.literal(static_cast<uint8_t>(c));
        std::vector<uint8_t> src = builder.chunk();
        // A flag byte claiming a match, followed by only one of the two bytes it needs.
        src.push_back(0x01);
        src.push_back(0x00);
        const uint16_t header = static_cast<uint16_t>(src[0] | (src[1] << 8));
        const uint16_t grown = static_cast<uint16_t>(header + 2);
        src[0] = static_cast<uint8_t>(grown & 0xFF);
        src[1] = static_cast<uint8_t>(grown >> 8);
        auto chunk = decode(src, std::span<uint8_t>(dst));
        REQUIRE_FALSE(chunk.has_value());
        CHECK(chunk.error().code == ErrorCode::CorruptStructure);
    }

    SECTION("the chunk expands past the room left") {
        GroupBuilder builder;
        for (int i = 0; i < 40; ++i) builder.literal(static_cast<uint8_t>('a' + i % 26));
        builder.match(26, 20);
        const std::vector<uint8_t> src = builder.chunk();
        std::vector<uint8_t> tiny(30, 0);
        auto chunk = decode(src, std::span<uint8_t>(tiny));
        REQUIRE_FALSE(chunk.has_value());
        CHECK(chunk.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("hostile bytes stay inside the destination", "[lznt1][fuzz-shape]") {
    const std::vector<uint8_t> pristine = from_hex(kDocumentedHex);
    constexpr size_t kGuardBytes = 32;
    size_t failures = 0;
    size_t decoded = 0;

    for (size_t index = 0; index < pristine.size(); ++index) {
        for (const uint8_t mutation : {uint8_t{0x00}, uint8_t{0xFF}, uint8_t{0x01}, uint8_t{0x80}}) {
            std::vector<uint8_t> src = pristine;
            src[index] = static_cast<uint8_t>(src[index] + mutation);

            std::vector<uint8_t> buffer(4096 + kGuardBytes, 0xCC);
            const auto chunk = decompress_lznt1_chunk(std::span<const uint8_t>(src),
                                                      std::span<uint8_t>(buffer.data(), 4096));
            if (chunk) {
                ++decoded;
                if (chunk->produced > 4096 || chunk->consumed > src.size()) ++failures;
            }
            if (!guarded(buffer, 4096)) ++failures;

            std::vector<uint8_t> big(65536 + kGuardBytes, 0xCC);
            const auto whole = decompress_lznt1(std::span<const uint8_t>(src),
                                                std::span<uint8_t>(big.data(), 65536));
            if (whole && *whole > 65536) ++failures;
            if (!guarded(big, 65536)) ++failures;
        }
    }

    CHECK(failures == 0);
    // A sweep that only ever returned errors would prove nothing, so some mutants still decode.
    CHECK(decoded > 0);
}
