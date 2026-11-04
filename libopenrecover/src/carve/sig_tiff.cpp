#include "openrecover/carve/sig_tiff.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/common/bytes.hpp"
#include "openrecover/common/types.hpp"

namespace openrecover::carve {

namespace {

constexpr uint64_t kMaxIfdEntries = 4096;
constexpr uint32_t kMaxIfds = 64;

uint16_t le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8)); }
uint32_t le32(const uint8_t* p) { return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24); }
uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]); }
uint32_t be32(const uint8_t* p) { return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]); }

enum class Endian { LE, BE };

struct Header { Endian endian; uint64_t first_ifd; };

bool parse_header(const uint8_t* p, Header& h) {
    if (p[0] == 'I' && p[1] == 'I' && p[2] == '*' && p[3] == 0) { h.endian = Endian::LE; }
    else if (p[0] == 'M' && p[1] == 'M' && p[2] == 0 && p[3] == '*') { h.endian = Endian::BE; }
    else return false;
    uint32_t off = (h.endian == Endian::LE) ? le32(p + 4) : be32(p + 4);
    if (off < 8) return false;
    h.first_ifd = off;
    return true;
}

uint16_t rd16(const uint8_t* p, Endian e) { return e == Endian::LE ? le16(p) : be16(p); }
uint32_t rd32(const uint8_t* p, Endian e) { return e == Endian::LE ? le32(p) : be32(p); }

}  // namespace

std::span<const std::span<const uint8_t>> TiffSignature::magics() const {
    static const uint8_t m1[] = {'I','I','*','\0'};
    static const uint8_t m2[] = {'M','M','\0','*'};
    static std::vector<std::span<const uint8_t>> vec{
        std::span<const uint8_t>(m1, 4),
        std::span<const uint8_t>(m2, 4)};
    static std::span<const std::span<const uint8_t>> sp(vec.data(), vec.size());
    return sp;
}

ValidationResult TiffSignature::validate(BoundedReader& reader) const {
    ValidationResult result;
    const uint64_t limit = reader.limit();
    if (limit < 8) return result;

    auto hdr_bytes = reader.read_vec(0, 8);
    if (!hdr_bytes || hdr_bytes->size() != 8) return result;

    Header h{};
    if (!parse_header(hdr_bytes->data(), h)) return result;

    uint64_t ifd_off = h.first_ifd;
    uint64_t max_referenced = 8;
    uint64_t num_ifds = 0;

    while (ifd_off != 0 && num_ifds < kMaxIfds) {
        if (ifd_off + 2 > limit) return result;
        auto cnt_bytes = reader.read_vec(ifd_off, 2);
        if (!cnt_bytes || cnt_bytes->size() != 2) return result;
        uint16_t nentries = rd16(cnt_bytes->data(), h.endian);
        if (nentries > kMaxIfdEntries) return result;

        uint64_t entry_base = ifd_off + 2;
        uint64_t ifd_end = entry_base + static_cast<uint64_t>(nentries) * 12;
        if (ifd_end + 4 > limit) return result;

        if (ifd_end + 4 > max_referenced) max_referenced = ifd_end + 4;

        for (uint32_t i = 0; i < nentries; ++i) {
            uint64_t eoff = entry_base + static_cast<uint64_t>(i) * 12;
            auto e = reader.read_vec(eoff, 12);
            if (!e || e->size() != 12) return result;
            uint16_t type = rd16(e->data() + 2, h.endian);
            uint32_t count = rd32(e->data() + 4, h.endian);
            uint32_t valoff = rd32(e->data() + 8, h.endian);

            size_t tsize = 0;
            switch (type) {
                case 1: case 2: case 6: case 7: tsize = 1; break;
                case 3: case 8: tsize = 2; break;
                case 4: case 9: case 11: tsize = 4; break;
                case 5: case 10: case 12: tsize = 8; break;
                default: return result;
            }
            if (count == 0) continue;
            uint64_t total = static_cast<uint64_t>(count) * tsize;
            bool inline_val = (total <= 4);
            if (!inline_val) {
                if (static_cast<uint64_t>(valoff) + total > limit) return result;
                uint64_t end = static_cast<uint64_t>(valoff) + total;
                if (end > max_referenced) max_referenced = end;
            }
        }

        auto nxt = reader.read_vec(ifd_end, 4);
        if (!nxt || nxt->size() != 4) return result;
        uint32_t next_off = rd32(nxt->data(), h.endian);
        if (next_off != 0) {
            if (next_off <= ifd_off) return result;  // backward or self-referencing chain
            ifd_off = next_off;
        } else {
            ifd_off = 0;
        }
        ++num_ifds;
    }

    if (num_ifds == 0) return result;

    // The highest byte any IFD entry references bounds the image. The scan window is not
    // part of the file, so trailing room after it says nothing about validity.
    if (max_referenced < 8 || max_referenced > limit) return result;

    result.verdict = ValidationResult::Verdict::Valid;
    result.length_bytes = max_referenced;
    result.subtype = "tiff";
    result.confidence = Confidence::Medium;
    return result;
}

}  // namespace openrecover::carve

