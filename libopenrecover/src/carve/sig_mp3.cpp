#include "openrecover/carve/sig_mp3.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"

namespace openrecover::carve {

namespace {

// A frame walk this long is stopped and reported as a fragment; 1M frames is around seven hours at
// 128 kbit/s, which is longer than any recording a scan is expected to hand back.
constexpr uint64_t kMaxFrames = 1ull << 20;
// Fewer validated frames than this is not evidence of a recording. A frame only counts when the
// next one starts exactly where this one said it would end, so a chain this short is hard to hit by
// chance and still catches a file whose tail was overwritten.
constexpr uint64_t kMinFrames = 3;
constexpr uint64_t kConfidentFrames = 16;
// Padding between an ID3v2 tag and the first frame is part of the file, so the search for the
// audio start may cross this many bytes.
constexpr uint64_t kMaxTagPadding = 4096;
constexpr uint64_t kId3v1Bytes = 128;
constexpr size_t kSyncMagics = 31;

struct FrameHeader {
    uint64_t bytes = 0;
    uint8_t version = 0;   // 0 = MPEG 2.5, 2 = MPEG 2, 3 = MPEG 1
    uint8_t layer = 0;     // 1 = I, 2 = II, 3 = III
    uint16_t sample_rate = 0;
};

// Bitrate tables in kbit/s, indexed by [layer - 1][is_mpeg1 ? 0 : 1][bitrate index]. A zero entry
// is not a bitrate the format defines, which includes the "free" index and the reserved 15.
constexpr uint16_t kBitrates[3][2][16] = {
    /* Layer I */
    {{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},
     {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 0}},
    /* Layer II */
    {{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
     {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}},
    /* Layer III */
    {{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},
     {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}},
};

constexpr uint16_t kSampleRates[4][3] = {
    {11025, 12000, 8000},  // MPEG 2.5
    {0, 0, 0},             // reserved version
    {22050, 24000, 16000}, // MPEG 2
    {44100, 48000, 32000}, // MPEG 1
};

bool is_frame_sync(std::span<const uint8_t> bytes) {
    return bytes.size() >= 2 && bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0;
}

// Decodes a four-byte MPEG frame header. A frame that cannot be decoded -- a reserved version, an
// undefined layer, the free or reserved bitrate index -- is the end of the audio, not an error.
std::optional<FrameHeader> parse_frame(std::span<const uint8_t> bytes) {
    if (bytes.size() < 4) return std::nullopt;
    if (!is_frame_sync(bytes)) return std::nullopt;
    const uint8_t second = bytes[1];
    const uint8_t version = (second >> 3) & 3;  // 0 = 2.5, 2 = 2, 3 = 1
    const uint8_t layer_bits = (second >> 1) & 3;
    if (version == 1 || layer_bits == 0) return std::nullopt;
    const uint8_t layer = static_cast<uint8_t>(4 - layer_bits);  // 3 -> I, 2 -> II, 1 -> III

    const uint8_t third = bytes[2];
    const uint8_t bitrate_index = third >> 4;
    const uint8_t rate_index = (third >> 2) & 3;
    const uint8_t padding = (third >> 1) & 1;
    if (rate_index == 3) return std::nullopt;
    if (bitrate_index == 0 || bitrate_index == 15) return std::nullopt;

    const bool mpeg1 = version == 3;
    const uint16_t bitrate = kBitrates[layer - 1][mpeg1 ? 0 : 1][bitrate_index];
    const uint16_t sample_rate = kSampleRates[version][rate_index];
    if (bitrate == 0 || sample_rate == 0) return std::nullopt;

    FrameHeader frame;
    frame.version = version;
    frame.layer = layer;
    frame.sample_rate = sample_rate;
    // A frame carries 384 samples on Layer I and 1152 on Layers II and III, so the same bitrate
    // gives a third of the bytes per frame on Layer I; MPEG 2 and 2.5 halve the rates again.
    if (layer == 1)
        frame.bytes = (mpeg1 ? 48000ull : 24000ull) * bitrate / sample_rate + padding;
    else
        frame.bytes = (mpeg1 ? 144000ull : 72000ull) * bitrate / sample_rate + padding;
    if (frame.bytes < 4) return std::nullopt;
    return frame;
}

struct FrameRun {
    uint64_t end = 0;
    uint64_t frames = 0;
    // The frames stopped because the scan window ran out, which is different from stopping because
    // the bytes there are not the next frame of this stream.
    bool stopped_at_window = false;
    bool stopped_at_cap = false;
};

FrameRun walk_frames(BoundedReader& reader, uint64_t start, uint64_t limit) {
    FrameRun run;
    uint64_t pos = start;
    std::optional<FrameHeader> previous;
    while (true) {
        if (run.frames == kMaxFrames) {
            run.stopped_at_cap = true;
            break;
        }
        if (pos + 4 > limit) {
            run.stopped_at_window = true;
            break;
        }
        auto header = reader.read_vec(pos, 4);
        if (!header || header->size() < 4) {
            run.stopped_at_window = true;
            break;
        }
        const std::optional<FrameHeader> frame = parse_frame(*header);
        if (!frame) break;
        // A recording keeps its version, layer and sample rate; a change of any of those is the
        // end of the stream rather than a new track, which is what stops the walk running on into
        // the bytes of whatever file followed this one.
        if (previous && (previous->version != frame->version || previous->layer != frame->layer ||
                         previous->sample_rate != frame->sample_rate))
            break;
        previous = frame;
        if (frame->bytes > limit - pos) {
            run.stopped_at_window = true;
            break;
        }
        pos += frame->bytes;
        ++run.frames;
    }
    run.end = pos;
    return run;
}

// A synchsafe integer stores seven bits per byte; the top bit of every byte is required to be zero,
// so a set top bit is not a size this parser can trust.
std::optional<uint64_t> synchsafe(std::span<const uint8_t> bytes) {
    uint64_t value = 0;
    for (const uint8_t byte : bytes) {
        if (byte & 0x80) return std::nullopt;
        value = (value << 7) | byte;
    }
    return value;
}

// Where the audio starts after an ID3v2 tag: the tag says its own size, padding may follow it, and
// a v2.4 footer is not counted in that size. The first frame header within the padding window wins.
std::optional<uint64_t> audio_start_after_tag(BoundedReader& reader, uint64_t limit) {
    auto head = reader.read_vec(0, 6);
    if (!head || head->size() < 6) return std::nullopt;
    const uint8_t* t = head->data();
    const uint8_t major = t[3];
    if (major < 2 || major > 4) return std::nullopt;
    // Unsynchronisation rewrites the frame bytes and an extended header sits between the tag header
    // and the body, so neither is a tag whose end can be found by adding a size to a fixed offset.
    if (t[5] & 0xC0) return std::nullopt;

    uint64_t body = 0;
    uint64_t size = 0;
    if (major == 2) {
        // v2.2 has a six-byte header followed by a three-byte size, so the body starts at 9.
        auto field = reader.read_vec(6, 3);
        if (!field || field->size() < 3) return std::nullopt;
        const std::optional<uint64_t> parsed = synchsafe(*field);
        if (!parsed) return std::nullopt;
        size = *parsed;
        body = 9;
    } else {
        auto field = reader.read_vec(6, 4);
        if (!field || field->size() < 4) return std::nullopt;
        const std::optional<uint64_t> parsed = synchsafe(*field);
        if (!parsed) return std::nullopt;
        size = *parsed;
        body = 10;
        if (major == 4 && (t[5] & 0x10) != 0) size += 10;  // the footer sits outside the size
    }

    const uint64_t tag_end = body + size;
    if (tag_end > limit) return std::nullopt;
    const uint64_t search_end = std::min(limit, tag_end + kMaxTagPadding);
    for (uint64_t pos = tag_end; pos + 4 <= search_end; ++pos) {
        auto candidate = reader.read_vec(pos, 4);
        if (!candidate || candidate->size() < 4) return std::nullopt;
        if (parse_frame(*candidate)) return pos;
    }
    return std::nullopt;
}

}  // namespace

std::span<const std::span<const uint8_t>> Mp3Signature::magics() const {
    // "ID3" for a tagged file; 0xFF followed by any byte whose top three bits are set is the
    // eleven-bit frame sync, which is how an untagged file opens. 0xFF 0xFF is left out because a
    // run of 0xFF bytes is what silence and padding look like, not what a header looks like.
    static constexpr std::array<std::array<uint8_t, 2>, kSyncMagics> sync = [] {
        std::array<std::array<uint8_t, 2>, kSyncMagics> out{};
        for (size_t i = 0; i < kSyncMagics; ++i)
            out[i] = {0xFF, static_cast<uint8_t>(0xE0 + i)};
        return out;
    }();
    static constexpr std::array<uint8_t, 3> id3{'I', 'D', '3'};
    static const std::vector<std::span<const uint8_t>> vec = [] {
        std::vector<std::span<const uint8_t>> out;
        out.push_back(std::span<const uint8_t>(id3.data(), id3.size()));
        for (const auto& pair : sync)
            out.push_back(std::span<const uint8_t>(pair.data(), pair.size()));
        return out;
    }();
    static const std::span<const std::span<const uint8_t>> sp(vec.data(), vec.size());
    return sp;
}

ValidationResult Mp3Signature::validate(BoundedReader& reader) const {
    const uint64_t limit = reader.limit();
    if (limit < 4) return ValidationResult::invalid();

    auto head = reader.read_vec(0, 4);
    if (!head || head->size() < 4) return ValidationResult::invalid();

    uint64_t start = 0;
    bool tagged = false;
    if (std::memcmp(head->data(), "ID3", 3) == 0) {
        const std::optional<uint64_t> audio = audio_start_after_tag(reader, limit);
        if (!audio) return ValidationResult::invalid();
        start = *audio;
        tagged = true;
    } else if (!parse_frame(*head)) {
        return ValidationResult::invalid();
    }

    const FrameRun run = walk_frames(reader, start, limit);
    if (run.frames < kMinFrames) return ValidationResult::invalid();

    // An ID3v1 tag is the last 128 bytes of the file, so it only counts when it follows the frames
    // the walk stopped on rather than the end of the window.
    uint64_t end = run.end;
    bool has_v1 = false;
    if (!run.stopped_at_window && !run.stopped_at_cap && end + kId3v1Bytes <= limit) {
        auto trailer = reader.read_vec(end, 3);
        if (trailer && trailer->size() == 3 && std::memcmp(trailer->data(), "TAG", 3) == 0) {
            end += kId3v1Bytes;
            has_v1 = true;
        }
    }

    ValidationResult result;
    result.subtype = "mp3";
    if (run.stopped_at_window || run.stopped_at_cap) {
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = limit;
        result.confidence = Confidence::Low;
        result.notes.push_back(run.stopped_at_cap ? "the frame walk stopped at its own limit"
                                                 : "audio continues past the scan window");
        return result;
    }

    result.verdict = ValidationResult::Verdict::Valid;
    result.length_bytes = end;
    result.confidence = run.frames >= kConfidentFrames ? Confidence::High : Confidence::Medium;
    if (result.confidence == Confidence::Medium)
        result.notes.push_back(std::to_string(run.frames) + " audio frames validated");
    if (tagged && has_v1) result.notes.push_back("ID3v2 tag and ID3v1 trailer");
    return result;
}

}  // namespace openrecover::carve
