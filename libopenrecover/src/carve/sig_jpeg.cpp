#include "openrecover/carve/sig_jpeg.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"

namespace openrecover::carve {

namespace {

constexpr size_t kMaxSegments = 65536;
// A tail shorter than this is more likely a stray EOI in unrelated bytes than the rest of a
// scan, so it is not joined to a prefix.
constexpr uint64_t kMinTailBytes = 16;

ValidationResult truncated(std::vector<std::string> notes) {
    ValidationResult result;
    result.verdict = ValidationResult::Verdict::ValidTruncated;
    result.confidence = Confidence::Low;
    result.notes = std::move(notes);
    return result;
}

// The run stopped where the bytes stopped being JPEG: junk (another deleted file, a zeroed
// cluster) sits between this prefix and the rest of the image. `at` is the position of the
// marker sequence that failed to parse.
ValidationResult discontinuity(std::vector<std::string> notes, uint64_t at) {
    ValidationResult result = truncated(std::move(notes));
    result.length_bytes = at;
    result.notes.push_back("discontinuity");
    return result;
}

bool is_sof(uint8_t marker) {
    switch (marker) {
        case 0xC0:
        case 0xC1:
        case 0xC2:
        case 0xC3:
        case 0xC5:
        case 0xC6:
        case 0xC7:
        case 0xC9:
        case 0xCA:
        case 0xCB:
        case 0xCD:
        case 0xCE:
        case 0xCF:
            return true;
        default:
            return false;
    }
}

uint16_t be16(const std::vector<uint8_t>& data, size_t off) {
    return static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
}

bool parse_dqt(const std::vector<uint8_t>& p) {
    size_t i = 0;
    while (i < p.size()) {
        const uint8_t pq_tq = p[i++];
        const uint8_t pq = pq_tq >> 4;
        const uint8_t tq = pq_tq & 0x0F;
        if (pq > 1 || tq > 3) return false;
        const size_t need = 64 * (pq == 0 ? 1 : 2);
        if (need > p.size() - i) return false;
        i += need;
    }
    return true;
}

bool parse_dht(const std::vector<uint8_t>& p) {
    size_t i = 0;
    while (i < p.size()) {
        const uint8_t tc_th = p[i++];
        const uint8_t tc = tc_th >> 4;
        const uint8_t th = tc_th & 0x0F;
        if (tc > 1 || th > 3) return false;
        if (p.size() - i < 16) return false;
        size_t symbols = 0;
        for (size_t k = 0; k < 16; ++k) symbols += p[i + k];
        i += 16;
        if (symbols > 256 || symbols > p.size() - i) return false;
        i += symbols;
    }
    return true;
}

struct SofInfo {
    uint16_t width = 0;
    uint16_t height = 0;
    uint8_t components = 0;
};

bool parse_sof(uint8_t marker, const std::vector<uint8_t>& p, SofInfo& out) {
    if (p.size() < 6) return false;
    const uint8_t precision = p[0];
    out.height = be16(p, 1);
    out.width = be16(p, 3);
    out.components = p[5];
    if (precision != 8 && !(precision == 12 && (marker == 0xC1 || marker == 0xC2)))
        return false;
    if (out.width == 0 || out.height == 0) return false;
    if (out.components != 1 && out.components != 3 && out.components != 4) return false;
    if (p.size() != 6 + static_cast<size_t>(out.components) * 3) return false;
    for (size_t i = 0; i < out.components; ++i) {
        const uint8_t hv = p[6 + i * 3 + 1];
        const uint8_t h = hv >> 4;
        const uint8_t v = hv & 0x0F;
        if (h < 1 || h > 4 || v < 1 || v > 4) return false;
        if ((p[6 + i * 3 + 2] & 0x0F) > 3) return false;
    }
    return true;
}

bool parse_sos(const std::vector<uint8_t>& p, uint8_t total_components) {
    if (p.empty()) return false;
    const size_t ns = p[0];
    if (ns < 1 || ns > 4 || ns > total_components) return false;
    if (p.size() != 4 + 2 * ns) return false;
    for (size_t i = 0; i < ns; ++i) {
        const uint8_t tables = p[1 + i * 2 + 1];
        if ((tables >> 4) > 3 || (tables & 0x0F) > 3) return false;
    }
    const uint8_t ss = p[1 + 2 * ns];
    const uint8_t se = p[2 + 2 * ns];
    const uint8_t ah_al = p[3 + 2 * ns];
    if (ss > se || se > 63) return false;
    if ((ah_al >> 4) > 13 || (ah_al & 0x0F) > 13) return false;
    return true;
}

// Returns the offset of the next real marker's 0xFF byte, or limit when the
// entropy-coded stream is cut off. Fills `entropy_end` with the marker offset.
uint64_t find_entropy_end(BoundedReader& r, uint64_t start, bool& found) {
    constexpr size_t kChunk = 64u << 10;
    std::array<uint8_t, kChunk> buffer{};
    const uint64_t limit = r.limit();
    uint64_t i = start;
    found = false;
    while (i + 1 < limit) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(kChunk, limit - i));
        auto got = r.read_at(i, buffer.data(), want);
        if (!got) return limit;
        if (*got < 2) return limit;
        size_t j = 0;
        while (j + 1 < *got) {
            const void* hit = std::memchr(buffer.data() + j, 0xFF, *got - 1 - j);
            if (!hit) break;
            const size_t idx = static_cast<size_t>(static_cast<const uint8_t*>(hit) - buffer.data());
            if (idx + 1 >= *got) break;
            const uint8_t next = buffer[idx + 1];
            if (next == 0x00) {
                j = idx + 2;
                continue;
            }
            if (next >= 0xD0 && next <= 0xD7) {
                j = idx + 2;
                continue;
            }
            if (next == 0xFF) {
                j = idx + 1;
                continue;
            }
            found = true;
            return i + idx;
        }
        if (*got < want) return limit;
        if (buffer[*got - 1] == 0xFF) {
            i += *got - 1;
        } else {
            i += *got;
        }
    }
    return limit;
}

}  // namespace

std::span<const std::span<const uint8_t>> JpegSignature::magics() const {
    static const uint8_t m0[] = {0xFF, 0xD8, 0xFF, 0xE0};
    static const uint8_t m1[] = {0xFF, 0xD8, 0xFF, 0xE1};
    static const uint8_t m2[] = {0xFF, 0xD8, 0xFF, 0xE2};
    static const uint8_t m3[] = {0xFF, 0xD8, 0xFF, 0xE8};
    static const uint8_t m4[] = {0xFF, 0xD8, 0xFF, 0xDB};
    static const uint8_t m5[] = {0xFF, 0xD8, 0xFF, 0xC0};
    static const uint8_t m6[] = {0xFF, 0xD8, 0xFF, 0xC2};
    static const uint8_t m7[] = {0xFF, 0xD8, 0xFF, 0xEE};
    static const uint8_t m8[] = {0xFF, 0xD8, 0xFF, 0xFE};
    static const std::span<const uint8_t> list[] = {m0, m1, m2, m3, m4, m5, m6, m7, m8};
    return list;
}

ValidationResult JpegSignature::validate(BoundedReader& r) const {
    const uint64_t limit = r.limit();
    if (limit < 4) return ValidationResult::invalid();

    auto b0 = r.u8(0);
    auto b1 = r.u8(1);
    auto b2 = r.u8(2);
    auto b3 = r.u8(3);
    if (!b0 || !b1 || !b2 || !b3) return ValidationResult::invalid();
    if (*b0 != 0xFF || *b1 != 0xD8 || *b2 != 0xFF) return ValidationResult::invalid();

    bool saw_sof = false;
    bool saw_dqt = false;
    bool saw_dht = false;
    bool has_app = false;
    bool exif_bad = false;
    int scans = 0;
    uint8_t components = 0;
    std::string subtype;
    std::vector<std::string> notes;

    uint64_t pos = 2;
    // Before the first scan with a valid frame header, a parse failure means the bytes are not
    // a JPEG at all. After it, a failure means the file's bytes ran out and something else
    // follows: report where, so the engine can try to join the rest.
    const auto cut_at = [&](uint64_t at) {
        if (scans < 1 || !saw_sof) return ValidationResult::invalid();
        return discontinuity(notes, at);
    };

    for (size_t segments = 0;; ++segments) {
        if (segments >= kMaxSegments) return ValidationResult::invalid();
        if (pos + 1 >= limit) {
            if (scans >= 1 && saw_sof) {
                ValidationResult out = truncated(notes);
                out.length_bytes = limit;
                return out;
            }
            return ValidationResult::invalid();
        }

        while (true) {
            auto a = r.u8(pos);
            auto b = r.u8(pos + 1);
            if (!a || !b) return cut_at(pos);
            if (*a != 0xFF) return cut_at(pos);
            if (*b != 0xFF) break;
            ++pos;
        }

        auto marker_opt = r.u8(pos + 1);
        if (!marker_opt) return cut_at(pos);
        const uint8_t marker = *marker_opt;
        const uint64_t marker_pos = pos;
        pos += 2;

        if (marker == 0x00) return cut_at(marker_pos);
        if (marker == 0x01) continue;
        if (marker >= 0xD0 && marker <= 0xD7) return cut_at(marker_pos);
        if (marker == 0xD8) return cut_at(marker_pos);

        if (marker == 0xD9) {
            if (scans < 1 || !saw_sof) return ValidationResult::invalid();
            ValidationResult out;
            out.verdict = ValidationResult::Verdict::Valid;
            out.length_bytes = pos;
            out.subtype = subtype;
            out.notes = std::move(notes);
            if (exif_bad || !has_app) {
                out.confidence = Confidence::Medium;
            } else {
                out.confidence = Confidence::High;
            }
            return out;
        }

        if (pos + 2 > limit) return cut_at(marker_pos);
        auto seg_len_opt = r.u16be(pos);
        if (!seg_len_opt) return cut_at(marker_pos);
        const uint16_t seg_len = *seg_len_opt;
        if (seg_len < 2) return cut_at(marker_pos);
        if (static_cast<uint64_t>(seg_len) > limit - pos) return cut_at(marker_pos);

        std::vector<uint8_t> payload;
        if (seg_len > 2) {
            auto bytes = r.read_vec(pos + 2, static_cast<size_t>(seg_len - 2));
            if (!bytes) return cut_at(marker_pos);
            payload = std::move(*bytes);
        }
        const uint64_t next_pos = pos + seg_len;

        switch (marker) {
            case 0xDB:
                if (payload.empty() || !parse_dqt(payload)) return cut_at(marker_pos);
                saw_dqt = true;
                break;
            case 0xC4:
                if (payload.empty() || !parse_dht(payload)) return cut_at(marker_pos);
                saw_dht = true;
                break;
            case 0xDA: {
                if (!saw_sof || !saw_dqt || !saw_dht) return cut_at(marker_pos);
                if (!parse_sos(payload, components)) return cut_at(marker_pos);
                ++scans;
                bool found = false;
                const uint64_t entropy_end = find_entropy_end(r, next_pos, found);
                if (r.error()) return ValidationResult::invalid();
                if (!found) {
                    ValidationResult out = truncated(notes);
                    out.length_bytes = limit;
                    return out;
                }
                if (r.deep_validate() && entropy_end <= next_pos + 1)
                    return ValidationResult::invalid();
                pos = entropy_end;
                continue;
            }
            case 0xDD:
                if (payload.size() != 2) return cut_at(marker_pos);
                break;
            case 0xE0:
                if (payload.size() >= 5 && std::memcmp(payload.data(), "JFIF\0", 5) == 0) {
                    has_app = true;
                    if (subtype.empty()) subtype = "jfif";
                }
                break;
            case 0xE1:
                if (payload.size() >= 6 && std::memcmp(payload.data(), "Exif\0\0", 6) == 0) {
                    has_app = true;
                    const bool tiff_ok =
                        payload.size() >= 14 &&
                        (std::memcmp(payload.data() + 6, "II*\0", 4) == 0 ||
                         std::memcmp(payload.data() + 6, "MM\0*", 4) == 0);
                    if (tiff_ok) {
                        subtype = "exif";
                    } else {
                        exif_bad = true;
                        notes.push_back("exif_tiff_header_invalid");
                    }
                }
                break;
            case 0xE2:
                if (payload.size() >= 4 && std::memcmp(payload.data(), "MPF\0", 4) == 0)
                    notes.push_back("mpo_may_contain_additional_images");
                break;
            case 0xC8:
            case 0xDC:
            case 0xFE:
                break;
            default:
                if (marker >= 0xF0 && marker <= 0xFD) break;
                if (marker >= 0xE3 && marker <= 0xEF) break;
                if (!is_sof(marker)) return cut_at(marker_pos);
                if (saw_sof) return cut_at(marker_pos);
                {
                    SofInfo info;
                    if (!parse_sof(marker, payload, info)) return cut_at(marker_pos);
                    saw_sof = true;
                    components = info.components;
                }
                break;
        }
        pos = next_pos;
    }
}

// The remainder of an interrupted scan is entropy-coded data that ends at a marker. It is walked
// with the same rules the header walk applies: stuffing, restart markers and fill bytes are data.
// EOI ends the file; any other marker cuts the run there, because a progressive image can put
// another segment between two scans, and the engine resumes searching past the cut. A run that
// starts on a marker itself holds no bytes of the file, so nothing is claimed for it, and SOI is
// refused outright: these bytes open another image, not this one's next fragment.
std::optional<Continuation> JpegSignature::find_continuation(BoundedReader& r) const {
    constexpr size_t kChunk = 64u << 10;
    const uint64_t limit = r.limit();
    std::array<uint8_t, kChunk> buffer{};
    uint64_t i = 0;
    while (i + 1 < limit) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(kChunk, limit - i));
        auto got = r.read_at(i, buffer.data(), want);
        if (!got || *got < 2) return std::nullopt;
        size_t j = 0;
        while (j + 1 < *got) {
            const void* hit = std::memchr(buffer.data() + j, 0xFF, *got - 1 - j);
            if (!hit) break;
            const size_t idx =
                static_cast<size_t>(static_cast<const uint8_t*>(hit) - buffer.data());
            if (idx + 1 >= *got) break;
            const uint8_t next = buffer[idx + 1];
            if (next == 0xFF) {
                j = idx + 1;
                continue;
            }
            if (next == 0x00 || (next >= 0xD0 && next <= 0xD7)) {
                j = idx + 2;
                continue;
            }
            if (next == 0xD8) return std::nullopt;
            const uint64_t at = i + idx;
            if (at == 0) return std::nullopt;
            const uint64_t end = at + 2;
            // An EOI this close to the cut is a stray in unrelated bytes, not the rest of a scan;
            // treat it as a cut so the walk continues past it.
            if (next == 0xD9 && end >= kMinTailBytes) return Continuation{0, end, true};
            return Continuation{0, at, false};
        }
        if (*got < want) return std::nullopt;
        if (buffer[*got - 1] == 0xFF) {
            i += *got - 1;
        } else {
            i += *got;
        }
    }
    return std::nullopt;
}

}  // namespace openrecover::carve
