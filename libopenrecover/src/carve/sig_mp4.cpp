#include "openrecover/carve/sig_mp4.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"

namespace openrecover::carve {

namespace {

constexpr size_t kBoxHeaderBytes = 8;
constexpr size_t kFtypMinBytes = 16;    // size, fourcc, major brand, minor version
constexpr size_t kFtypMaxBytes = 4096;  // a brand list longer than this is not a media file
constexpr uint64_t kMaxTopBoxes = 1u << 16;

uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint64_t be64(const uint8_t* p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

bool is_fourcc(const uint8_t* p) noexcept {
    for (size_t i = 0; i < 4; ++i)
        if (p[i] < 0x20 || p[i] > 0x7E) return false;
    return true;
}

bool fourcc_equals(const uint8_t* p, std::string_view id) {
    return std::memcmp(p, id.data(), 4) == 0;
}

// The brands this library names a recovered file by. The major brand decides the extension when it
// is known; otherwise the compatible-brand list is asked, in the order the table lists brands so
// that a camera file stays "mp4" and a phone picture stays "heic".
constexpr std::pair<std::string_view, std::string_view> kBrands[] = {
    {"qt  ", "mov"},
    {"M4A ", "m4a"},
    {"M4P ", "m4a"},
    {"m4a ", "m4a"},
    {"3gp4", "3gp"},
    {"3gp5", "3gp"},
    {"3gp6", "3gp"},
    {"3gp7", "3gp"},
    {"3g2a", "3gp"},
    {"3g2b", "3gp"},
    {"3ge6", "3gp"},
    {"3ge7", "3gp"},
    {"mif1", "heic"},
    {"heic", "heic"},
    {"heix", "heic"},
    {"heim", "heic"},
    {"heis", "heic"},
    {"isom", "mp4"},
    {"iso2", "mp4"},
    {"iso4", "mp4"},
    {"iso5", "mp4"},
    {"mp41", "mp4"},
    {"mp42", "mp4"},
    {"mp71", "mp4"},
    {"mp4v", "mp4"},
    {"avc1", "mp4"},
    {"hvc1", "mp4"},
    {"hev1", "mp4"},
    {"M4V ", "mp4"},
    {"dash", "mp4"},
};

std::optional<std::string_view> brand_subtype(const uint8_t* ftyp, size_t ftyp_size) {
    for (const auto& brand : kBrands)
        if (fourcc_equals(ftyp + 8, brand.first)) return brand.second;
    if (ftyp_size < kFtypMinBytes + 4) return std::nullopt;
    const size_t listed = ftyp_size - kFtypMinBytes;
    for (size_t offset = 0; offset + 4 <= listed; offset += 4) {
        const uint8_t* code = ftyp + kFtypMinBytes + offset;
        if (!is_fourcc(code)) continue;
        for (const auto& brand : kBrands)
            if (fourcc_equals(code, brand.first)) return brand.second;
    }
    return std::nullopt;
}

// The top-level boxes of the family. Anything else ends the file: a deleted clip is followed by
// whatever occupied those clusters before it, and a box name outside this list says the walk has
// run off the end rather than that the media continues.
bool known_top_level(const uint8_t* type) {
    static constexpr std::string_view names[] = {
        "moov", "mdat", "moof", "mfra", "meta", "free", "skip",
        "wide", "pdin", "styp", "sidx", "uuid", "junk",
    };
    for (std::string_view name : names)
        if (fourcc_equals(type, name)) return true;
    return false;
}

struct Walk {
    bool has_mdat = false;
    // A moov describes the media in an MP4, a meta box describes the items in a HEIF image; either
    // one makes the candidate a file rather than a header followed by unrelated bytes.
    bool has_descriptor = false;
    // True when a box's own bytes run past the scan window, so part of the file is provably
    // missing. A window that ends where the boxes end is not a cut: there is nothing left to
    // claim, and every byte the result reports then belongs to a box that was read.
    bool cut_by_window = false;
    uint64_t end = 0;
};

Walk walk_boxes(BoundedReader& reader, uint64_t start, uint64_t limit) {
    Walk walk;
    uint64_t pos = start;
    uint64_t boxes = 0;
    while (true) {
        if (++boxes > kMaxTopBoxes) {
            walk.cut_by_window = true;
            break;
        }
        if (pos + kBoxHeaderBytes > limit) break;
        auto header = reader.read_vec(pos, kBoxHeaderBytes);
        if (!header || header->size() < kBoxHeaderBytes) {
            walk.cut_by_window = true;
            break;
        }
        const uint8_t* box = header->data();
        if (!is_fourcc(box + 4) || !known_top_level(box + 4)) break;

        // The box is counted before its size is judged: a media box that runs past the window is
        // still evidence that the file had media, which is what the truncated verdict reports.
        if (fourcc_equals(box + 4, "mdat")) walk.has_mdat = true;
        if (fourcc_equals(box + 4, "moov") || fourcc_equals(box + 4, "meta"))
            walk.has_descriptor = true;

        uint64_t size = be32(box);
        if (size == 1) {
            if (pos + 16 > limit) {
                walk.cut_by_window = true;
                break;
            }
            auto extended = reader.read_vec(pos + 8, 8);
            if (!extended || extended->size() < 8) {
                walk.cut_by_window = true;
                break;
            }
            size = be64(extended->data());
            if (size < 16) break;
        } else if (size == 0) {
            // A zero size means "to the end of the file", which a scan cannot see.
            walk.cut_by_window = true;
            break;
        } else if (size < kBoxHeaderBytes) {
            break;
        }

        if (size > limit - pos) {
            walk.cut_by_window = true;
            break;
        }
        pos += size;
    }
    walk.end = pos;
    return walk;
}

ValidationResult truncated_result(std::string_view subtype, uint64_t limit, std::string note) {
    ValidationResult result;
    result.verdict = ValidationResult::Verdict::ValidTruncated;
    result.length_bytes = limit;
    result.subtype = std::string(subtype);
    result.confidence = Confidence::Low;
    result.notes.push_back(std::move(note));
    return result;
}

}  // namespace

std::span<const std::span<const uint8_t>> Mp4Signature::magics() const {
    static const uint8_t m[] = {'f', 't', 'y', 'p'};
    static std::vector<std::span<const uint8_t>> vec{std::span<const uint8_t>(m, 4)};
    static std::span<const std::span<const uint8_t>> sp(vec.data(), vec.size());
    return sp;
}

ValidationResult Mp4Signature::validate(BoundedReader& reader) const {
    ValidationResult result;
    const uint64_t limit = reader.limit();
    // The candidate starts at the box header, four bytes before the magic the scan matched on.
    if (limit < kFtypMinBytes + 4) return result;

    auto head = reader.read_vec(0, kFtypMinBytes);
    if (!head || head->size() < kFtypMinBytes) return result;
    const uint8_t* h = head->data();
    if (!fourcc_equals(h + 4, "ftyp")) return result;

    const uint64_t declared = be32(h);
    if (declared < kFtypMinBytes || declared > kFtypMaxBytes) return result;
    // Without the whole brand list there is nothing to check the file against.
    if (declared > limit) return result;

    auto ftyp = reader.read_vec(0, static_cast<size_t>(declared));
    if (!ftyp || ftyp->size() != declared) return result;
    const std::optional<std::string_view> subtype = brand_subtype(ftyp->data(), declared);
    if (!subtype) return result;

    const Walk walk = walk_boxes(reader, declared, limit);
    const bool complete = walk.has_mdat && walk.has_descriptor;
    if (walk.cut_by_window) {
        // A fragment is only worth exporting once both halves of a playable file have appeared;
        // a header followed by nothing but the end of the window is not evidence of media.
        if (!walk.has_mdat && !walk.has_descriptor) return result;
        ValidationResult partial = truncated_result(
            *subtype, limit,
            complete ? "the file continues past the scan window"
                     : "metadata or media data runs past the scan window");
        if (!complete)
            partial.notes.push_back(walk.has_descriptor ? "no media data inside the window"
                                                       : "no moov or meta box inside the window");
        return partial;
    }
    if (!complete) return result;

    result.verdict = ValidationResult::Verdict::Valid;
    result.length_bytes = walk.end;
    result.subtype = std::string(*subtype);
    result.confidence = Confidence::High;
    return result;
}

}  // namespace openrecover::carve
