#include "openrecover/carve/sig_avi.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"

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
    // A file is an AVI when its header list is there; a movie list or an index is what says the
    // frames came with it.
    bool has_hdrl = false;
    bool has_movi = false;
    bool has_idx1 = false;
};

// Reads the form type that follows a LIST chunk's header, so a LIST of 'hdrl' can be told from a
// LIST of 'movi' without walking the frames inside either of them.
bool list_type_is(BoundedReader& reader, uint64_t payload, uint64_t limit, std::string_view want) {
    if (payload + 4 > limit) return false;
    auto fourcc = reader.read_vec(payload, 4);
    return fourcc && fourcc->size() == 4 && std::memcmp(fourcc->data(), want.data(), 4) == 0;
}

// Walks the top-level chunk list in [12, end). A chunk that runs past `end` is the shape a cut
// file makes when `allow_final_overrun` is set, and a size field that does not tile the file when
// it is not; the difference is what lets a truncated recording be claimed without claiming a
// corrupt one.
ChunkWalk walk_chunks(BoundedReader& reader, uint64_t end, bool allow_final_overrun) {
    ChunkWalk walk;
    uint64_t pos = 12;
    uint64_t chunks = 0;
    while (pos + 8 <= end) {
        if (++chunks > kMaxChunks) {
            walk.malformed = true;
            return walk;
        }
        auto header = reader.read_vec(pos, 8);
        if (!header || header->size() < 8) {
            walk.malformed = true;
            return walk;
        }
        const uint8_t* id = header->data();
        const uint32_t size = rd32le(id + 4);
        if (size > kMaxChunkSize) {
            walk.malformed = true;
            return walk;
        }
        const uint64_t payload = pos + 8;
        if (std::memcmp(id, "LIST", 4) == 0) {
            if (list_type_is(reader, payload, end, "hdrl")) walk.has_hdrl = true;
            if (list_type_is(reader, payload, end, "movi")) walk.has_movi = true;
            if (list_type_is(reader, payload, end, "rec ")) walk.has_movi = true;
        }
        if (std::memcmp(id, "idx1", 4) == 0) walk.has_idx1 = true;

        if (payload + static_cast<uint64_t>(size) > end) {
            if (!allow_final_overrun) walk.malformed = true;
            return walk;
        }
        uint64_t step = 8 + static_cast<uint64_t>(size);
        if (step % 2) step++;  // chunks are word aligned
        pos += step;
    }
    return walk;
}

}  // namespace

std::span<const std::span<const uint8_t>> AviSignature::magics() const {
    static std::array<uint8_t, 4> m{'R', 'I', 'F', 'F'};
    static std::array<std::span<const uint8_t>, 1> arr{std::span<const uint8_t>(m.data(), 4)};
    // The magic is only "RIFF" at offset 0; the form type "AVI " at offset 8 is checked in validate.
    return arr;
}

ValidationResult AviSignature::validate(BoundedReader& reader) const {
    auto hdr = reader.read_vec(0, 12);
    if (!hdr || hdr->size() < 12) return ValidationResult::invalid();
    const uint8_t* h = hdr->data();
    if (std::memcmp(h, "RIFF", 4) != 0 || std::memcmp(h + 8, "AVI ", 4) != 0)
        return ValidationResult::invalid();

    const uint32_t riff_size = rd32le(h + 4);
    if (riff_size < 4) return ValidationResult::invalid();
    const uint64_t total = static_cast<uint64_t>(riff_size) + 8;
    if (total > max_file_size()) return ValidationResult::invalid();

    const uint64_t limit = reader.limit();
    ValidationResult result;
    if (total > limit) {
        // The declared length runs past the window, so only what the walk can still read counts.
        const ChunkWalk partial = walk_chunks(reader, limit, true);
        if (partial.malformed || !partial.has_hdrl) return ValidationResult::invalid();
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = limit;
        result.subtype = "avi";
        result.confidence = Confidence::Low;
        result.notes.push_back("RIFF size extends past the scan window");
        if (!partial.has_movi) result.notes.push_back("no frame list inside the window");
        return result;
    }

    const ChunkWalk full = walk_chunks(reader, total, false);
    if (full.malformed || !full.has_hdrl) return ValidationResult::invalid();

    result.subtype = "avi";
    result.length_bytes = total;
    if (!full.has_movi) {
        // The header list fills the declared file, so the frames it describes are not here. An
        // idx1 index that lists frames the movie list does not contain says the same thing: the
        // bytes claimed are the header of a recording, not the recording.
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.confidence = Confidence::Low;
        result.notes.push_back(full.has_idx1 ? "no frame list in the declared file"
                                             : "the declared file ends inside the header list");
        return result;
    }

    result.verdict = ValidationResult::Verdict::Valid;
    result.confidence = Confidence::High;
    return result;
}

}  // namespace openrecover::carve
