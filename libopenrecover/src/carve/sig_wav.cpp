#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_wav.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace openrecover::carve {

namespace {
constexpr uint64_t kMaxChunks = 1024;
constexpr uint64_t kMaxChunkSize = 256ull << 20;

uint32_t rd32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

struct ChunkWalk {
    bool malformed = false;
    bool has_fmt = false;
    bool has_data = false;
};

// Walks the RIFF chunk list in [12, end). With `allow_final_overrun`, a chunk that runs
// past `end` is taken for the file being cut off rather than for a corrupt size field.
ChunkWalk walk_chunks(BoundedReader& reader, uint64_t end, bool allow_final_overrun) {
    ChunkWalk walk;
    uint64_t pos = 12;
    uint64_t chunks = 0;
    while (pos + 8 <= end) {
        if (++chunks > kMaxChunks) {
            walk.malformed = true;
            return walk;
        }
        auto ch = reader.read_vec(pos, 8);
        if (!ch || ch->size() < 8) {
            walk.malformed = true;
            return walk;
        }
        const uint8_t* id = ch->data();
        const uint32_t csize = rd32le(id + 4);
        if (csize > kMaxChunkSize) {
            walk.malformed = true;
            return walk;
        }
        if (std::memcmp(id, "fmt ", 4) == 0) walk.has_fmt = true;
        if (std::memcmp(id, "data", 4) == 0) walk.has_data = true;
        if (pos + 8 + static_cast<uint64_t>(csize) > end) {
            if (!allow_final_overrun) walk.malformed = true;
            return walk;
        }
        uint64_t step = 8 + static_cast<uint64_t>(csize);
        if (step % 2) step++;  // word alignment
        pos += step;
    }
    return walk;
}
}  // namespace

std::span<const std::span<const uint8_t>> WavSignature::magics() const {
    static std::array<uint8_t, 12> m{ 'R','I','F','F',0,0,0,0,'W','A','V','E' };
    static std::array<std::span<const uint8_t>, 1> arr{ std::span<const uint8_t>(m.data(), 4) };
    // The magic is only "RIFF" at offset 0; full validation checks "WAVE" at offset 8.
    return arr;
}

ValidationResult WavSignature::validate(BoundedReader& reader) const {
    auto hdr = reader.read_vec(0, 12);
    if (!hdr || hdr->size() < 12) return ValidationResult::invalid();
    const uint8_t* h = hdr->data();
    if (std::memcmp(h, "RIFF", 4) != 0 || std::memcmp(h + 8, "WAVE", 4) != 0)
        return ValidationResult::invalid();

    const uint32_t riff_size = rd32le(h + 4);
    if (riff_size < 4) return ValidationResult::invalid();
    const uint64_t total = static_cast<uint64_t>(riff_size) + 8;
    if (total > max_file_size()) return ValidationResult::invalid();

    const uint64_t limit = reader.limit();
    if (total > limit) {
        // The window cuts the candidate off; a format chunk is still required so that a
        // stray "RIFF....WAVE" in slack space does not become a window-sized hit.
        const ChunkWalk partial = walk_chunks(reader, limit, true);
        if (partial.malformed || !partial.has_fmt) return ValidationResult::invalid();
        ValidationResult r;
        r.verdict = ValidationResult::Verdict::ValidTruncated;
        r.length_bytes = limit;
        r.subtype = "wav";
        r.confidence = Confidence::Low;
        r.notes.push_back("RIFF size extends past the scan window");
        return r;
    }

    const ChunkWalk full = walk_chunks(reader, total, false);
    if (full.malformed || !full.has_fmt || !full.has_data) return ValidationResult::invalid();

    ValidationResult r;
    r.verdict = ValidationResult::Verdict::Valid;
    r.length_bytes = total;
    r.subtype = "wav";
    r.confidence = Confidence::High;
    return r;
}

}  // namespace openrecover::carve