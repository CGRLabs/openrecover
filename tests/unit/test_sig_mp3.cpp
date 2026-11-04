#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_seeds.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_mp3.hpp"

namespace {
using namespace openrecover;
using namespace openrecover::carve;

constexpr uint8_t kMpeg1 = 3;
constexpr uint8_t kMpeg2 = 2;
constexpr uint8_t kMpeg25 = 0;
constexpr uint8_t kLayerI = 1;
constexpr uint8_t kLayerII = 2;
constexpr uint8_t kLayerIII = 3;
constexpr uint8_t kRate44100 = 0;
constexpr uint8_t kRate48000 = 1;
constexpr uint8_t kBitrate128 = 9;  // 128 kbit/s in the MPEG 1 Layer III row
constexpr size_t kFrame128 = 417;   // 144000 * 128 / 44100, the length every player agrees on
constexpr size_t kFrame128Padded = 418;
constexpr size_t kFrame48000 = 384;
constexpr size_t kLayerI448 = 487;  // 48000 * 448 / 44100
constexpr size_t kMpeg2_64 = 208;   // 72000 * 64 / 22050, rounded down as the format does
constexpr size_t kMpeg25_32 = 288;  // 72000 * 32 / 8000
constexpr size_t kMpeg2Layer2_32 = 104;  // 72000 * 32 / 22050
constexpr size_t kId3v1Bytes = 128;

void append(std::vector<uint8_t>& out, const std::vector<uint8_t>& add) {
    out.insert(out.end(), add.begin(), add.end());
}

// A frame whose length is the one the caller supplies: a validator that reads the bitrate or the
// sample-rate table differently stops on a different byte and fails the reported length.
std::vector<uint8_t> make_frame(uint8_t version, uint8_t layer, uint8_t bitrate_index,
                                 uint8_t rate_index, size_t total, bool padding = false) {
    std::vector<uint8_t> out(4);
    out[0] = 0xFF;
    out[1] = static_cast<uint8_t>(0xE0 | (version << 3) | ((4 - layer) << 1));
    out[2] = static_cast<uint8_t>((bitrate_index << 4) | (rate_index << 2) | (padding ? 2 : 0));
    out[3] = 0x44;  // single channel, original
    for (size_t i = 4; i < total; ++i) out.push_back(static_cast<uint8_t>((i * 7) & 0xFF));
    return out;
}

std::vector<uint8_t> make_audio(uint8_t version, uint8_t layer, uint8_t bitrate_index,
                                 uint8_t rate_index, size_t frames, size_t frame_total,
                                 bool padding = false) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < frames; ++i)
        append(out, make_frame(version, layer, bitrate_index, rate_index, frame_total, padding));
    return out;
}

std::vector<uint8_t> default_audio(size_t frames) {
    return make_audio(kMpeg1, kLayerIII, kBitrate128, kRate44100, frames, kFrame128);
}

// An ID3v2 header, which is the only part of a tag that says where its own bytes end. A 2.2 tag is
// nine bytes with a three-byte size; later tags are ten bytes with a four-byte synchsafe size.
std::vector<uint8_t> make_tag_header(uint8_t major, uint32_t size, uint8_t flags = 0) {
    std::vector<uint8_t> out{'I', 'D', '3', major, 0x00, flags};
    if (major == 2) {
        out.push_back(static_cast<uint8_t>((size >> 16) & 0x7F));
        out.push_back(static_cast<uint8_t>((size >> 8) & 0x7F));
        out.push_back(static_cast<uint8_t>(size & 0x7F));
        return out;
    }
    out.push_back(static_cast<uint8_t>((size >> 21) & 0x7F));
    out.push_back(static_cast<uint8_t>((size >> 14) & 0x7F));
    out.push_back(static_cast<uint8_t>((size >> 7) & 0x7F));
    out.push_back(static_cast<uint8_t>(size & 0x7F));
    return out;
}

std::vector<uint8_t> id3v1() {
    std::vector<uint8_t> out(128, 0);
    std::memcpy(out.data(), "TAG", 3);
    std::memcpy(out.data() + 3, "Recording", 9);
    std::memcpy(out.data() + 93, "2026", 4);
    return out;
}

// A recording as a scan finds it: tag, audio, optional trailer, then the bytes of whatever was
// freed next to it. `claimed` is the length a validator may report.
struct Recording {
    std::vector<uint8_t> bytes;
    size_t claimed = 0;
    size_t audio_at = 0;
};

Recording make_recording(size_t frames, uint8_t tag_major = 3, size_t tag_body = 32,
                         size_t padding = 0, uint8_t flags = 0, size_t footer_bytes = 0,
                         bool trailer = false) {
    Recording file;
    if (tag_major != 0) {
        append(file.bytes, make_tag_header(tag_major, static_cast<uint32_t>(tag_body), flags));
        file.bytes.insert(file.bytes.end(), tag_body, 0);
        file.bytes.insert(file.bytes.end(), padding, 0);
        if (footer_bytes != 0) {
            const size_t at = file.bytes.size();
            file.bytes.insert(file.bytes.end(), footer_bytes, 0);
            std::memcpy(file.bytes.data() + at, "3DI", 3);  // the v2.4 footer, outside the size
        }
    }
    file.audio_at = file.bytes.size();
    append(file.bytes, default_audio(frames));
    file.claimed = file.bytes.size();
    if (trailer) {
        append(file.bytes, id3v1());
        file.claimed += kId3v1Bytes;
    }
    file.bytes.insert(file.bytes.end(), 64, 0xAA);  // dead air
    return file;
}

ValidationResult validate(const std::vector<uint8_t>& bytes) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    return Mp3Signature{}.validate(reader);
}

// Frames that tile the buffer exactly, so the scanner cannot tell the file from its own window.
std::vector<uint8_t> with_dead_air(const std::vector<uint8_t>& bytes, size_t filler = 256) {
    std::vector<uint8_t> out = bytes;
    out.insert(out.end(), filler, 0xAA);
    return out;
}
}  // namespace

TEST_CASE("mp3: a run of frames that ends on a byte that is not a header is a file", "[mp3][m3]") {
    const Recording file = make_recording(20, 0);
    auto res = validate(file.bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == 20 * kFrame128);
    CHECK(res.subtype == "mp3");
    CHECK(res.confidence == Confidence::High);
    CHECK(res.notes.empty());
}

TEST_CASE("mp3: sixteen frames are a recording, four are a claim", "[mp3][m3]") {
    auto res = validate(with_dead_air(default_audio(16)));
    REQUIRE(res.is_valid());
    CHECK(res.confidence == Confidence::High);
    CHECK(res.notes.empty());

    res = validate(with_dead_air(default_audio(4)));
    REQUIRE(res.is_valid());
    CHECK(res.confidence == Confidence::Medium);
    CHECK(res.length_bytes == 4 * kFrame128);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "4 audio frames validated");

    CHECK_FALSE(validate(with_dead_air(default_audio(2))).is_valid());
}

TEST_CASE("mp3: the frame length follows the tables a player uses", "[mp3][m3]") {
    struct Expected {
        uint8_t version;
        uint8_t layer;
        uint8_t bitrate;
        uint8_t rate;
        size_t bytes;
        bool padding = false;
    };
    // MPEG 2 and 2.5 index their own sample-rate table, where 0 is 22050 and 2 is 16000 or 8000.
    const Expected cases[] = {
        {kMpeg1, kLayerIII, kBitrate128, kRate44100, kFrame128},
        {kMpeg1, kLayerIII, kBitrate128, kRate44100, kFrame128Padded, true},
        {kMpeg1, kLayerIII, kBitrate128, kRate48000, kFrame48000},
        {kMpeg1, kLayerI, 14, kRate44100, kLayerI448},
        {kMpeg2, kLayerIII, 8, 0, kMpeg2_64},
        {kMpeg2, kLayerII, 4, 0, kMpeg2Layer2_32},
        {kMpeg25, kLayerIII, 4, 2, kMpeg25_32},
    };
    for (const Expected& e : cases) {
        INFO("version " << unsigned(e.version) << " layer " << unsigned(e.layer) << " index "
                        << unsigned(e.bitrate));
        const std::vector<uint8_t> bytes =
            with_dead_air(make_audio(e.version, e.layer, e.bitrate, e.rate, 3, e.bytes, e.padding));
        const ValidationResult res = validate(bytes);
        REQUIRE(res.is_valid());
        CHECK(res.verdict == ValidationResult::Verdict::Valid);
        CHECK(res.length_bytes == 3 * e.bytes);
    }
}

TEST_CASE("mp3: an ID3v2 tag is part of the file it opens", "[mp3][m3]") {
    const Recording file = make_recording(20);
    auto res = validate(file.bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == file.claimed);
    CHECK(file.audio_at == 10 + 32);
    CHECK(res.confidence == Confidence::High);
}

TEST_CASE("mp3: a tag and an ID3v1 trailer are both claimed", "[mp3][m3]") {
    const Recording file = make_recording(18, 3, 32, 0, 0, 0, true);
    auto res = validate(file.bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == file.claimed);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "ID3v2 tag and ID3v1 trailer");

    // An untagged recording with a trailer is the same file with one fewer note.
    const Recording plain = make_recording(18, 0, 0, 0, 0, 0, true);
    res = validate(plain.bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == plain.claimed);
    CHECK(res.notes.empty());
}

TEST_CASE("mp3: a trailer the window cannot cover is left out", "[mp3][m3]") {
    const Recording file = make_recording(6, 3, 24, 0, 0, 0, true);
    const size_t audio_end = file.claimed - kId3v1Bytes;
    // Keep the "TAG" marker but lose the back half of the trailer: there is no 128-byte tag here.
    std::vector<uint8_t> bytes(file.bytes.begin(), file.bytes.begin() + audio_end + 88);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == audio_end);
}

TEST_CASE("mp3: padding between the tag and the audio is crossed", "[mp3][m3]") {
    const Recording file = make_recording(12, 3, 16, 512);
    auto res = validate(file.bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == file.claimed);
    CHECK(res.confidence == Confidence::Medium);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "12 audio frames validated");
}

TEST_CASE("mp3: a version 2.2 tag has a shorter header and a three-byte size", "[mp3][m3]") {
    const Recording file = make_recording(12, 2, 24);
    REQUIRE(file.audio_at == 9 + 24);
    auto res = validate(file.bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == file.claimed);
}

TEST_CASE("mp3: a version 2.4 footer sits outside the size the tag declares", "[mp3][m3]") {
    const Recording file = make_recording(12, 4, 20, 0, 0x10, 10);
    REQUIRE(file.audio_at == 10 + 20 + 10);
    auto res = validate(file.bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == file.claimed);
}

TEST_CASE("mp3: a tag whose bytes cannot be counted is refused", "[mp3][m3]") {
    SECTION("unsynchronisation rewrites the frame bytes") {
        CHECK_FALSE(validate(make_recording(12, 3, 16, 0, 0x80).bytes).is_valid());
    }
    SECTION("an extended header is not counted in the tag size") {
        CHECK_FALSE(validate(make_recording(12, 3, 16, 0, 0x40).bytes).is_valid());
    }
    SECTION("a size field that is not synchsafe") {
        Recording file = make_recording(12);
        file.bytes[6] = 0x80;  // a v2.3 size byte with its top bit set
        CHECK_FALSE(validate(file.bytes).is_valid());
    }
    SECTION("a tag that runs past the window") {
        Recording file = make_recording(12);
        file.bytes = make_tag_header(3, 100000);
        append(file.bytes, default_audio(12));
        file.bytes.insert(file.bytes.end(), 64, 0xAA);
        CHECK_FALSE(validate(file.bytes).is_valid());
    }
    SECTION("a version the format never defined") {
        CHECK_FALSE(validate(make_recording(12, 1, 16).bytes).is_valid());
        CHECK_FALSE(validate(make_recording(12, 5, 16).bytes).is_valid());
    }
    SECTION("a tag with no audio behind it") {
        Recording file = make_recording(0);
        file.bytes.insert(file.bytes.end(), 600, 0x20);
        CHECK_FALSE(validate(file.bytes).is_valid());
    }
}

TEST_CASE("mp3: a change of stream parameters ends the recording", "[mp3][m3]") {
    std::vector<uint8_t> bytes = default_audio(5);
    const size_t audio_end = bytes.size();
    append(bytes, make_audio(kMpeg1, kLayerIII, kBitrate128, kRate48000, 4, kFrame48000));
    bytes.insert(bytes.end(), 256, 0xAA);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == audio_end);
    CHECK(res.confidence == Confidence::Medium);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "5 audio frames validated");

    // A change of layer says the same thing: two streams, not one recording.
    bytes = default_audio(4);
    const size_t first = bytes.size();
    append(bytes, make_audio(kMpeg1, kLayerII, kBitrate128, kRate44100, 4, 576));
    bytes.insert(bytes.end(), 256, 0xAA);
    res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == first);
}

TEST_CASE("mp3: audio that continues past the window is claimed as a fragment", "[mp3][m3]") {
    const std::vector<uint8_t> whole = default_audio(10);
    const size_t cut = 4 * kFrame128 + 200;  // four frames and part of the fifth
    std::vector<uint8_t> bytes(whole.begin(), whole.begin() + cut);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == cut);
    CHECK(res.confidence == Confidence::Low);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "audio continues past the scan window");

    // Frames that tile the scan exactly leave the same doubt.
    const std::vector<uint8_t> tiled = default_audio(6);
    res = validate(tiled);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == tiled.size());
    CHECK(res.confidence == Confidence::Low);
}

TEST_CASE("mp3: a header the format does not define is not audio", "[mp3][m3]") {
    struct Bad {
        uint8_t version;
        uint8_t layer;
        uint8_t bitrate;
        uint8_t rate;
    };
    // The reserved version, the reserved layer index, the free and reserved bitrate indices and
    // the reserved sample-rate index. Layer index 4 is the value the header bits do not name.
    const Bad cases[] = {
        {1, kLayerIII, kBitrate128, kRate44100},
        {kMpeg1, 4, kBitrate128, kRate44100},
        {kMpeg1, kLayerIII, 0, kRate44100},
        {kMpeg1, kLayerIII, 15, kRate44100},
        {kMpeg1, kLayerIII, kBitrate128, 3},
    };
    for (const Bad& b : cases) {
        INFO("version " << unsigned(b.version) << " layer " << unsigned(b.layer) << " bitrate "
                        << unsigned(b.bitrate) << " rate " << unsigned(b.rate));
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < 6; ++i)
            append(bytes, make_frame(b.version, b.layer, b.bitrate, b.rate, kFrame128));
        bytes.insert(bytes.end(), 128, 0xAA);
        CHECK_FALSE(validate(bytes).is_valid());
    }

    // A sync word with nothing behind it is not a recording either.
    std::vector<uint8_t> lone = make_frame(kMpeg1, kLayerIII, kBitrate128, kRate44100, kFrame128);
    CHECK_FALSE(validate(lone).is_valid());
    CHECK_FALSE(validate(std::vector<uint8_t>{0xFF, 0xFB, 0x90, 0x44}).is_valid());
}

TEST_CASE("mp3: bytes that only look like a sync word are refused", "[mp3][m3]") {
    CHECK_FALSE(validate(std::vector<uint8_t>(64, 0xFF)).is_valid());

    std::vector<uint8_t> bytes(256, 0x00);
    bytes[0] = 0xFF;
    bytes[1] = 0xE0;
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("mp3: name, magics and the size the signature allows", "[mp3][m3]") {
    Mp3Signature sig;
    CHECK(sig.name() == "mp3");
    CHECK(sig.default_extension() == "mp3");
    CHECK(sig.magic_offset() == 0);
    CHECK(sig.min_header_bytes() == 4);
    CHECK(sig.max_file_size() == (1ull << 31));

    const auto magics = sig.magics();
    REQUIRE(magics.size() == 32);
    REQUIRE(magics[0].size() == 3);
    CHECK(std::memcmp(magics[0].data(), "ID3", 3) == 0);
    REQUIRE(magics[1].size() == 2);
    CHECK(magics[1][0] == 0xFF);
    CHECK(magics[1][1] == 0xE0);
    CHECK(magics.back()[0] == 0xFF);
    CHECK(magics.back()[1] == 0xFE);
    for (size_t i = 1; i < magics.size(); ++i) {
        REQUIRE(magics[i].size() == 2);
        CHECK(magics[i][0] == 0xFF);
        CHECK((magics[i][1] & 0xE0) == 0xE0);
    }
}

TEST_CASE("mp3: a candidate too short to hold a frame header is refused", "[mp3][m3]") {
    CHECK_FALSE(validate(std::vector<uint8_t>()).is_valid());
    CHECK_FALSE(validate(std::vector<uint8_t>{0xFF, 0xFB, 0x90}).is_valid());
    CHECK_FALSE(validate(std::vector<uint8_t>{'I', 'D', '3'}).is_valid());
}

TEST_CASE("mp3: every single-byte mutation is refused or stays inside the window",
          "[mp3][m3][mutation]") {
    const std::vector<uint8_t> good = make_recording(6, 3, 24, 0, 0, 0, true).bytes;
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
            CHECK(res.subtype == "mp3");
            if (res.verdict == ValidationResult::Verdict::Valid) {
                // A whole file may say how short it is, but never that something is missing.
                for (const std::string& note : res.notes)
                    CHECK(note.find("scan window") == std::string::npos);
            }
            if (res.verdict == ValidationResult::Verdict::ValidTruncated) {
                CHECK(res.length_bytes == mutated.size());
                CHECK(res.confidence == Confidence::Low);
            }
        }
    }
    CHECK(accepted > 0);
    CHECK(refused > 0);
}

TEST_CASE("mp3: the committed fuzz seeds validate as named", "[mp3][m3][fuzz]") {
    test::check_signature_seed_corpus(OPENRECOVER_FUZZ_SEED_DIR, Mp3Signature{});
}
