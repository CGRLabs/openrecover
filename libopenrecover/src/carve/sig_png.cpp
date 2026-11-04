#include "openrecover/carve/sig_png.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "inflate.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/common/bytes.hpp"
#include "openrecover/common/crc32.hpp"

namespace openrecover::carve {

namespace {

constexpr uint64_t kMaxChunkLength = 0x7FFFFFFFull;
constexpr size_t kIoChunk = 64u << 10;
constexpr uint64_t kMaxPixels = 1ull << 31;

using ChunkType = std::array<uint8_t, 4>;

bool type_is(const ChunkType& type, const char* name) {
    return std::memcmp(type.data(), name, 4) == 0;
}

std::string type_name(const ChunkType& type) {
    return std::string(type.begin(), type.end());
}

bool is_ascii_letter(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool is_critical(const ChunkType& type) { return (type[0] & 0x20) == 0; }

bool one_of(uint8_t value, std::initializer_list<uint8_t> allowed) {
    return std::find(allowed.begin(), allowed.end(), value) != allowed.end();
}

struct Header {
    uint32_t width = 0;
    uint32_t height = 0;
    uint8_t bit_depth = 0;
    uint8_t color_type = 0;
    uint8_t interlace = 0;
    uint8_t channels = 0;
};

bool parse_header(const std::vector<uint8_t>& p, Header& out) {
    if (p.size() != 13) return false;
    const uint32_t width = (static_cast<uint32_t>(p[0]) << 24) |
                           (static_cast<uint32_t>(p[1]) << 16) |
                           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
    const uint32_t height = (static_cast<uint32_t>(p[4]) << 24) |
                            (static_cast<uint32_t>(p[5]) << 16) |
                            (static_cast<uint32_t>(p[6]) << 8) | static_cast<uint32_t>(p[7]);
    if (width == 0 || height == 0 || width > 0x7FFFFFFFu || height > 0x7FFFFFFFu) return false;
    if (static_cast<uint64_t>(width) * height > kMaxPixels) return false;

    const uint8_t depth = p[8];
    const uint8_t color = p[9];
    const uint8_t compression = p[10];
    const uint8_t filter = p[11];
    const uint8_t interlace = p[12];
    if (compression != 0 || filter != 0 || interlace > 1) return false;

    uint8_t channels = 0;
    bool depth_ok = false;
    switch (color) {
        case 0:
            channels = 1;
            depth_ok = one_of(depth, {1, 2, 4, 8, 16});
            break;
        case 2:
            channels = 3;
            depth_ok = one_of(depth, {8, 16});
            break;
        case 3:
            channels = 1;
            depth_ok = one_of(depth, {1, 2, 4, 8});
            break;
        case 4:
            channels = 2;
            depth_ok = one_of(depth, {8, 16});
            break;
        case 6:
            channels = 4;
            depth_ok = one_of(depth, {8, 16});
            break;
        default:
            return false;
    }
    if (!depth_ok) return false;

    out.width = width;
    out.height = height;
    out.bit_depth = depth;
    out.color_type = color;
    out.interlace = interlace;
    out.channels = channels;
    return true;
}

uint64_t row_bytes(uint64_t width, const Header& header) {
    const uint64_t bits = static_cast<uint64_t>(header.channels) * header.bit_depth;
    return (width * bits + 7) / 8;
}

uint64_t expected_raw_size(const Header& header) {
    if (header.interlace == 0)
        return static_cast<uint64_t>(header.height) * (1 + row_bytes(header.width, header));

    static constexpr uint32_t starts_x[7] = {0, 4, 0, 2, 0, 1, 0};
    static constexpr uint32_t starts_y[7] = {0, 0, 4, 0, 2, 0, 1};
    static constexpr uint32_t steps_x[7] = {8, 8, 4, 4, 2, 2, 1};
    static constexpr uint32_t steps_y[7] = {8, 8, 8, 4, 4, 2, 2};

    uint64_t total = 0;
    for (int pass = 0; pass < 7; ++pass) {
        const uint32_t w =
            header.width > starts_x[pass]
                ? (header.width - starts_x[pass] + steps_x[pass] - 1) / steps_x[pass]
                : 0;
        const uint32_t h =
            header.height > starts_y[pass]
                ? (header.height - starts_y[pass] + steps_y[pass] - 1) / steps_y[pass]
                : 0;
        if (w == 0 || h == 0) continue;
        total += static_cast<uint64_t>(h) * (1 + row_bytes(w, header));
    }
    return total;
}

struct SingletonState {
    bool gama = false;
    bool chrm = false;
    bool srgb = false;
    bool iccp = false;
    bool sbit = false;
    bool bkgd = false;
    bool hist = false;
    bool trns = false;
    bool phys = false;
    bool time = false;

    bool* find(const ChunkType& type) {
        if (type_is(type, "gAMA")) return &gama;
        if (type_is(type, "cHRM")) return &chrm;
        if (type_is(type, "sRGB")) return &srgb;
        if (type_is(type, "iCCP")) return &iccp;
        if (type_is(type, "sBIT")) return &sbit;
        if (type_is(type, "bKGD")) return &bkgd;
        if (type_is(type, "hIST")) return &hist;
        if (type_is(type, "tRNS")) return &trns;
        if (type_is(type, "pHYs")) return &phys;
        if (type_is(type, "tIME")) return &time;
        return nullptr;
    }
};

bool must_precede_plte(const ChunkType& type) {
    return type_is(type, "gAMA") || type_is(type, "cHRM") || type_is(type, "sRGB") ||
           type_is(type, "iCCP") || type_is(type, "sBIT");
}

bool must_precede_idat(const ChunkType& type) {
    return type_is(type, "bKGD") || type_is(type, "hIST") || type_is(type, "tRNS") ||
           type_is(type, "pHYs");
}

ValidationResult truncated_result() {
    ValidationResult result;
    result.verdict = ValidationResult::Verdict::ValidTruncated;
    result.confidence = Confidence::Low;
    return result;
}

// Position just past a chunk that starts at `pos`, when its length field is sane. Used to ask
// whether a file whose chunk just failed still has an intact chunk boundary where that chunk
// says it ends.
bool declared_chunk_end(BoundedReader& r, uint64_t pos, uint64_t& end) {
    const uint64_t limit = r.limit();
    if (pos > limit || limit - pos < 12) return false;
    auto length = r.u32be(pos);
    if (!length || *length > kMaxChunkLength) return false;
    if (*length > limit - pos - 12) return false;
    end = pos + 12 + *length;
    return true;
}

// Verifies one whole chunk at `pos`: sane length, an all-letter type, and a CRC over type and
// data that matches. Outputs are optional. An I/O error is not reported here; callers check
// BoundedReader::error().
bool chunk_valid_at(BoundedReader& r, uint64_t pos, ChunkType* type_out, uint64_t* next_out,
                    uint64_t* length_out) {
    const uint64_t limit = r.limit();
    if (pos > limit || limit - pos < 12) return false;
    auto length_opt = r.u32be(pos);
    if (!length_opt || *length_opt > kMaxChunkLength) return false;
    const uint64_t length = *length_opt;
    if (length > limit - pos - 12) return false;

    auto type_opt = r.read_vec(pos + 4, 4);
    if (!type_opt || type_opt->size() != 4) return false;
    ChunkType type{};
    std::copy(type_opt->begin(), type_opt->end(), type.begin());
    for (uint8_t c : type) {
        if (!is_ascii_letter(c)) return false;
    }

    uint32_t crc = crc32_update(0, type.data(), 4);
    std::array<uint8_t, kIoChunk> io{};
    uint64_t offset = 0;
    while (offset < length) {
        const size_t take = static_cast<size_t>(std::min<uint64_t>(io.size(), length - offset));
        auto got = r.read_at(pos + 8 + offset, io.data(), take);
        if (!got || *got != take) return false;
        crc = crc32_update(crc, io.data(), take);
        offset += take;
    }
    auto stored = r.u32be(pos + 8 + length);
    if (!stored || *stored != crc) return false;

    if (type_out) *type_out = type;
    if (next_out) *next_out = pos + 12 + length;
    if (length_out) *length_out = length;
    return true;
}

uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}


}  // namespace

std::span<const std::span<const uint8_t>> PngSignature::magics() const {
    static const uint8_t magic[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    static const std::span<const uint8_t> list[] = {magic};
    return list;
}

ValidationResult PngSignature::validate(BoundedReader& reader) const {
    const uint64_t limit = reader.limit();
    auto signature = reader.read_vec(0, 8);
    if (!signature || signature->size() != 8) return ValidationResult::invalid();
    static const uint8_t expected[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (std::memcmp(signature->data(), expected, 8) != 0) return ValidationResult::invalid();

    Header header;
    bool seen_header = false;
    bool seen_plte = false;
    bool idat_started = false;
    bool idat_ended = false;
    uint64_t idat_total = 0;
    bool ordering_issue = false;
    bool duplicate_issue = false;
    std::vector<std::string> notes;
    SingletonState singletons;
    detail::Inflator inflator(true);
    const bool deep = reader.deep_validate();
    std::vector<uint8_t> io(kIoChunk);

    auto fail_at_limit = [&]() -> ValidationResult {
        if (seen_header && idat_total > 0) {
            ValidationResult result = truncated_result();
            result.length_bytes = limit;
            result.notes = notes;
            return result;
        }
        return ValidationResult::invalid();
    };

    // After a valid IHDR the bytes are a PNG, so a chunk that fails its own checks means either
    // the file resumes after overwritten bytes (a cut) or the chunk itself is corrupt while the
    // stream is intact. The two are told apart by what sits where the chunk says it ends: a valid
    // chunk boundary there means the structure survived and the candidate is rejected whole, as
    // before; anything else means the file's bytes stopped at this chunk.
    auto cut_or_invalid = [&](uint64_t at) -> ValidationResult {
        if (!seen_header) return ValidationResult::invalid();
        uint64_t end = 0;
        if (declared_chunk_end(reader, at, end) &&
            chunk_valid_at(reader, end, nullptr, nullptr, nullptr)) {
            return ValidationResult::invalid();
        }
        ValidationResult result = truncated_result();
        result.length_bytes = at;
        result.notes = notes;
        result.notes.push_back("discontinuity");
        return result;
    };

    uint64_t pos = 8;
    for (;;) {
        if (pos > limit || limit - pos < 12) return fail_at_limit();
        auto length_opt = reader.u32be(pos);
        if (!length_opt) return ValidationResult::invalid();
        const uint64_t length = *length_opt;
        if (length > kMaxChunkLength) return cut_or_invalid(pos);
        // A declared chunk that runs past the window is reported as a truncation at the limit,
        // which is what a file cut by the end of the source looks like. Checking the type first
        // would turn a header-only PNG followed by junk into a 33-byte "cut" instead, and the
        // truncated decoy in carve_mixed must stay rejected.
        if (length > limit - pos - 12) return fail_at_limit();

        auto type_opt = reader.read_vec(pos + 4, 4);
        if (!type_opt || type_opt->size() != 4) return ValidationResult::invalid();
        ChunkType type{};
        std::copy(type_opt->begin(), type_opt->end(), type.begin());
        for (uint8_t c : type) {
            if (!is_ascii_letter(c)) return cut_or_invalid(pos);
        }

        uint32_t crc = crc32_update(0, type.data(), 4);
        const uint64_t data_pos = pos + 8;
        uint64_t remaining = length;
        uint64_t offset = 0;
        while (remaining > 0) {
            const size_t take = static_cast<size_t>(std::min<uint64_t>(io.size(), remaining));
            auto got = reader.read_at(data_pos + offset, io.data(), take);
            if (!got) return ValidationResult::invalid();
            if (*got != take) return ValidationResult::invalid();
            crc = crc32_update(crc, io.data(), take);
            if (deep && type_is(type, "IDAT")) {
                if (!inflator.feed(io.data(), take)) return ValidationResult::invalid();
            }
            offset += take;
            remaining -= take;
        }
        auto stored_crc = reader.u32be(pos + 8 + length);
        if (!stored_crc) return ValidationResult::invalid();
        if (*stored_crc != crc) return cut_or_invalid(pos);

        if (!seen_header && !type_is(type, "IHDR")) return ValidationResult::invalid();

        if (type_is(type, "IHDR")) {
            if (seen_header) return ValidationResult::invalid();
            auto payload = reader.read_vec(pos + 8, 13);
            if (!payload || payload->size() != 13) return ValidationResult::invalid();
            if (!parse_header(*payload, header)) return ValidationResult::invalid();
            seen_header = true;
        } else if (type_is(type, "PLTE")) {
            if (seen_plte || idat_started) return ValidationResult::invalid();
            if (header.color_type == 0 || header.color_type == 4)
                return ValidationResult::invalid();
            if (length == 0 || length % 3 != 0 || length > 768)
                return ValidationResult::invalid();
            if (header.color_type == 3 && length / 3 > (1ull << header.bit_depth))
                return ValidationResult::invalid();
            seen_plte = true;
        } else if (type_is(type, "IDAT")) {
            if (header.color_type == 3 && !seen_plte) return ValidationResult::invalid();
            if (idat_ended) return ValidationResult::invalid();
            idat_started = true;
            uint64_t sum = 0;
            if (!checked_add(idat_total, length, sum)) return ValidationResult::invalid();
            idat_total = sum;
        } else if (type_is(type, "IEND")) {
            if (length != 0) return ValidationResult::invalid();
            if (!idat_started || idat_total == 0) return ValidationResult::invalid();
            if (header.color_type == 3 && !seen_plte) return ValidationResult::invalid();
            if (deep) {
                if (!inflator.finish()) return ValidationResult::invalid();
                if (inflator.output() != expected_raw_size(header))
                    return ValidationResult::invalid();
            }
            ValidationResult result;
            result.verdict = ValidationResult::Verdict::Valid;
            result.length_bytes = pos + 12 + length;
            result.confidence =
                deep && !ordering_issue && !duplicate_issue ? Confidence::High : Confidence::Medium;
            result.notes = std::move(notes);
            return result;
        } else {
            if (idat_started) idat_ended = true;
            if (is_critical(type)) return ValidationResult::invalid();

            if (bool* flag = singletons.find(type)) {
                if (*flag) {
                    duplicate_issue = true;
                    notes.push_back("duplicate_chunk:" + type_name(type));
                }
                *flag = true;
            }
            if (type_is(type, "tRNS")) {
                if (idat_started || (header.color_type == 3 && !seen_plte)) {
                    ordering_issue = true;
                    notes.push_back("chunk_order:tRNS");
                }
            } else if (must_precede_plte(type)) {
                if (seen_plte || idat_started) {
                    ordering_issue = true;
                    notes.push_back("chunk_order:" + type_name(type));
                }
            } else if (must_precede_idat(type)) {
                if (idat_started) {
                    ordering_issue = true;
                    notes.push_back("chunk_order:" + type_name(type));
                }
            }
        }

        pos += 12 + length;
    }
}

// A PNG that loses bytes to later writes keeps everything after the cut on a chunk grid the
// header walk cannot reach across the gap. The bytes are recognised by what proves them: a chunk
// whose type, length and CRC all check out, followed by chunks that reach IEND. The scan refuses
// to start after another image's signature, for the same reason a JPEG tail refuses SOI. A run
// that begins at IEND proves nothing -- the terminator alone carries no content -- so the first
// chunk must be something else, and the walk stops at the first chunk that fails, leaving the
// engine to resume past it.
std::optional<Continuation> PngSignature::find_continuation(BoundedReader& r) const {
    static constexpr uint8_t kSignature[8] = {0x89, 0x50, 0x4E, 0x47,
                                              0x0D, 0x0A, 0x1A, 0x0A};
    constexpr size_t kMaxCandidates = 4096;
    const uint64_t limit = r.limit();
    std::array<uint8_t, kIoChunk> buffer{};
    // A crafted run can otherwise make every offset look like a header; three halves of the
    // window is more than a real continuation needs to prove itself.
    uint64_t budget = limit + (limit >> 1);
    size_t candidates = 0;

    for (uint64_t base = 0; base < limit;) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(buffer.size(), limit - base));
        auto got = r.read_at(base, buffer.data(), want);
        if (!got || *got == 0) return std::nullopt;
        const size_t n = *got;
        for (size_t k = 0; k + 12 <= n; ++k) {
            const uint64_t s = base + k;
            if (std::memcmp(buffer.data() + k, kSignature, 8) == 0) return std::nullopt;

            const uint32_t length = be32(buffer.data() + k);
            if (length > kMaxChunkLength || length > limit - s - 12) continue;
            ChunkType first{};
            std::memcpy(first.data(), buffer.data() + k + 4, 4);
            bool letters = true;
            for (uint8_t c : first) {
                if (!is_ascii_letter(c)) letters = false;
            }
            if (!letters || type_is(first, "IEND")) continue;

            const uint64_t next = s + 12 + length;
            if (next + 12 > limit) continue;
            // The header after this chunk must also be plausible: that is what separates a real
            // boundary from random bytes that happen to look like one.
            auto next_length = r.u32be(next);
            auto next_type = r.read_vec(next + 4, 4);
            if (!next_length || *next_length > kMaxChunkLength ||
                *next_length > limit - next - 12 || !next_type || next_type->size() != 4)
                continue;
            bool next_letters = true;
            for (uint8_t c : *next_type) {
                if (!is_ascii_letter(c)) next_letters = false;
            }
            if (!next_letters) continue;

            if (candidates++ >= kMaxCandidates || length + 12 > budget) return std::nullopt;
            budget -= length + 12;
            if (!chunk_valid_at(r, s, nullptr, nullptr, nullptr)) continue;

            uint64_t cursor = next;
            uint64_t end = next;
            ChunkType type{};
            bool complete = false;
            for (;;) {
                if (!chunk_valid_at(r, cursor, &type, &end, nullptr)) break;
                if (type_is(type, "IEND")) {
                    complete = end - cursor == 12;
                    break;
                }
                cursor = end;
            }
            if (complete) return Continuation{s, end - s, true};
            return Continuation{s, cursor - s, false};
        }
        if (n < want || n <= 11) break;
        base += n - 11;  // overlap so the last eleven bytes are seen with a full header
    }
    return std::nullopt;
}

}  // namespace openrecover::carve
