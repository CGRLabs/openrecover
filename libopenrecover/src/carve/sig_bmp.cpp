#include "openrecover/carve/sig_bmp.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/common/bytes.hpp"

namespace openrecover::carve {

namespace {

// "BM" is only two bytes, so every field below is part of the proof that this
// is a real bitmap rather than a chance match.
constexpr uint64_t kMaxPixels = 1ull << 28;
// Profiles and other ancillary blocks may follow the pixels; anything larger
// than this is treated as an inconsistent file size.
constexpr uint64_t kMaxExtraBytes = 64ull << 20;
constexpr uint64_t kMaxPaletteEntries = 65536;

enum class Status { Ok, Invalid, Truncated };

uint16_t le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

int32_t le32s(const uint8_t* p) {
    const uint32_t v = le32(p);
    return static_cast<int32_t>(v);
}

bool allowed_dib_size(uint32_t size) {
    switch (size) {
        case 12:
        case 40:
        case 52:
        case 56:
        case 64:
        case 108:
        case 124:
            return true;
        default:
            return false;
    }
}

bool bpp_is(uint16_t bpp, std::initializer_list<uint16_t> allowed) {
    return std::find(allowed.begin(), allowed.end(), bpp) != allowed.end();
}

bool masks_valid(uint32_t r, uint32_t g, uint32_t b, uint32_t a, bool alpha_used,
                 uint16_t bpp) {
    if (r == 0 || g == 0 || b == 0) return false;
    if (bpp == 16) {
        constexpr uint32_t kCap = 0xFFFFu;
        if ((r & ~kCap) != 0 || (g & ~kCap) != 0 || (b & ~kCap) != 0 || (a & ~kCap) != 0)
            return false;
    }
    if ((r & g) != 0 || (r & b) != 0 || (g & b) != 0) return false;
    if (alpha_used && a != 0 && ((a & r) != 0 || (a & g) != 0 || (a & b) != 0)) return false;
    return true;
}

struct Header {
    uint32_t dib_size = 0;
    uint64_t width = 0;
    uint64_t height = 0;
    bool top_down = false;
    uint16_t bpp = 0;
    uint32_t compression = 0;
    uint32_t size_image = 0;
    uint32_t clr_used = 0;
    uint64_t mask_bytes = 0;
    uint64_t palette_bytes = 0;
    std::string subtype = "bmp";
    std::vector<std::string> notes;
};

bool parse_masks_from_file(BoundedReader& reader, uint32_t mask_bytes, uint16_t bpp,
                           bool alpha_used) {
    constexpr uint64_t kMaskPos = 14 + 40;
    if (reader.limit() < kMaskPos + mask_bytes) return false;
    auto bytes = reader.read_vec(kMaskPos, mask_bytes);
    if (!bytes || bytes->size() != mask_bytes) return false;
    const uint32_t r = le32(bytes->data());
    const uint32_t g = le32(bytes->data() + 4);
    const uint32_t b = le32(bytes->data() + 8);
    const uint32_t a = mask_bytes >= 16 ? le32(bytes->data() + 12) : 0;
    return masks_valid(r, g, b, a, alpha_used, bpp);
}

bool parse_masks_from_header(const std::vector<uint8_t>& dib, uint16_t bpp, bool alpha_used) {
    const uint32_t r = le32(dib.data() + 40);
    const uint32_t g = le32(dib.data() + 44);
    const uint32_t b = le32(dib.data() + 48);
    const uint32_t a = dib.size() >= 56 ? le32(dib.data() + 52) : 0;
    return masks_valid(r, g, b, a, alpha_used, bpp);
}

bool bpp_allowed(uint32_t compression, uint16_t bpp, bool os2) {
    if (os2) {
        switch (compression) {
            case 0:
                return bpp_is(bpp, {1, 4, 8, 24});
            case 1:
                return bpp == 8;
            case 2:
                return bpp == 4;
            default:
                return false;
        }
    }
    switch (compression) {
        case 0:
            return bpp_is(bpp, {1, 2, 4, 8, 16, 24, 32});
        case 1:
            return bpp == 8;
        case 2:
            return bpp == 4;
        case 3:
        case 6:
            return bpp == 16 || bpp == 32;
        case 4:
        case 5:
            return bpp == 0 || bpp == 24 || bpp == 32;
        default:
            return false;
    }
}

bool parse_dib(BoundedReader& reader, const std::vector<uint8_t>& dib, Header& out) {
    if (out.dib_size == 12) {
        const uint16_t width = le16(dib.data() + 4);
        const uint16_t height = le16(dib.data() + 6);
        const uint16_t planes = le16(dib.data() + 8);
        const uint16_t bpp = le16(dib.data() + 10);
        if (width == 0 || height == 0 || planes != 1) return false;
        if (!bpp_is(bpp, {1, 4, 8, 24})) return false;
        out.width = width;
        out.height = height;
        out.bpp = bpp;
        out.compression = 0;
        out.subtype = "os2";
        if (bpp <= 8) out.palette_bytes = (uint64_t{1} << bpp) * 3;
        return true;
    }

    if (dib.size() < 40) return false;
    const int32_t width = le32s(dib.data() + 4);
    const int32_t height = le32s(dib.data() + 8);
    const uint16_t planes = le16(dib.data() + 12);
    const uint16_t bpp = le16(dib.data() + 14);
    const uint32_t compression = le32(dib.data() + 16);
    const uint32_t size_image = le32(dib.data() + 20);
    const uint32_t clr_used = le32(dib.data() + 32);

    if (width <= 0) return false;
    if (height == 0 || height == INT32_MIN) return false;
    const bool top_down = height < 0;
    const uint64_t abs_height =
        top_down ? static_cast<uint64_t>(-static_cast<int64_t>(height))
                 : static_cast<uint64_t>(height);
    if (static_cast<uint64_t>(width) * abs_height > kMaxPixels) return false;
    if (planes != 1) return false;

    const bool os2 = out.dib_size == 64;
    if (!bpp_allowed(compression, bpp, os2)) return false;
    if (bpp <= 8) {
        if (clr_used > (1u << bpp)) return false;
    } else if (clr_used > kMaxPaletteEntries) {
        return false;
    }

    out.width = static_cast<uint64_t>(width);
    out.height = abs_height;
    out.top_down = top_down;
    out.bpp = bpp;
    out.compression = compression;
    out.size_image = size_image;
    out.clr_used = clr_used;

    if (bpp <= 8) {
        const uint32_t entries = clr_used != 0 ? clr_used : (1u << bpp);
        out.palette_bytes = static_cast<uint64_t>(entries) * 4;
    } else {
        out.palette_bytes = static_cast<uint64_t>(clr_used) * 4;
    }

    if (out.dib_size == 40 && (compression == 3 || compression == 6)) {
        const uint32_t mask_bytes = compression == 6 ? 16 : 12;
        if (!parse_masks_from_file(reader, mask_bytes, bpp, compression == 6)) return false;
        out.mask_bytes = mask_bytes;
    } else if (out.dib_size >= 52 && (compression == 3 || compression == 6)) {
        if (compression == 6 && out.dib_size < 56) return false;
        if (!parse_masks_from_header(dib, bpp, compression == 6)) return false;
    }

    switch (compression) {
        case 1:
            out.subtype = "rle8";
            break;
        case 2:
            out.subtype = "rle4";
            break;
        case 3:
        case 6:
            out.subtype = "bitfields";
            break;
        case 4:
            out.subtype = "jpeg";
            out.notes.push_back("embedded_image_unverified");
            break;
        case 5:
            out.subtype = "png";
            out.notes.push_back("embedded_image_unverified");
            break;
        default:
            out.subtype = os2 ? "os2" : "bmp";
            break;
    }
    if (top_down) out.notes.push_back("top_down");
    return true;
}

// Validates RLE4/RLE8 packet framing, row placement and the end-of-bitmap
// marker. `end` receives the offset just past the marker.
Status parse_rle(BoundedReader& reader, uint64_t start, uint64_t file_size, uint64_t limit,
                 uint64_t width, uint64_t height, bool rle4, uint64_t& end) {
    uint64_t pos = start;
    uint64_t x = 0;
    uint64_t y = 0;

    auto next = [&](uint8_t& value) -> Status {
        if (pos >= limit) return file_size > limit ? Status::Truncated : Status::Invalid;
        if (pos >= file_size) return Status::Invalid;
        auto got = reader.u8(pos);
        if (!got) return Status::Invalid;
        value = *got;
        ++pos;
        return Status::Ok;
    };

    for (;;) {
        uint8_t count = 0;
        Status status = next(count);
        if (status != Status::Ok) return status;

        if (count != 0) {
            uint8_t value = 0;
            status = next(value);
            if (status != Status::Ok) return status;
            if (count > width - x) return Status::Invalid;
            x += count;
            continue;
        }

        uint8_t code = 0;
        status = next(code);
        if (status != Status::Ok) return status;

        if (code == 0) {  // end of line
            x = 0;
            ++y;
            if (y > height) return Status::Invalid;
            continue;
        }
        if (code == 1) {  // end of bitmap
            end = pos;
            return Status::Ok;
        }
        if (code == 2) {  // delta
            uint8_t dx = 0;
            uint8_t dy = 0;
            status = next(dx);
            if (status != Status::Ok) return status;
            status = next(dy);
            if (status != Status::Ok) return status;
            x += dx;
            y += dy;
            if (x > width || y > height) return Status::Invalid;
            continue;
        }

        const uint64_t pixels = code;
        if (pixels > width - x) return Status::Invalid;
        const uint64_t bytes = rle4 ? (pixels + 1) / 2 : pixels;
        const uint64_t padded = (bytes + 1) & ~uint64_t{1};
        for (uint64_t i = 0; i < padded; ++i) {
            uint8_t ignored = 0;
            status = next(ignored);
            if (status != Status::Ok) return status;
        }
        x += pixels;
    }
}

ValidationResult complete_result(const Header& header, uint64_t length, bool deep) {
    ValidationResult result;
    result.verdict = ValidationResult::Verdict::Valid;
    result.length_bytes = length;
    result.subtype = header.subtype;
    result.confidence = deep ? Confidence::High : Confidence::Medium;
    result.notes = header.notes;
    return result;
}

}  // namespace

std::span<const std::span<const uint8_t>> BmpSignature::magics() const {
    static const uint8_t magic[] = {'B', 'M'};
    static const std::span<const uint8_t> list[] = {magic};
    return list;
}

ValidationResult BmpSignature::validate(BoundedReader& reader) const {
    const uint64_t limit = reader.limit();
    if (limit < 18) return ValidationResult::invalid();

    auto file_header = reader.read_vec(0, 14);
    if (!file_header || file_header->size() != 14) return ValidationResult::invalid();
    const uint8_t* fh = file_header->data();
    if (fh[0] != 'B' || fh[1] != 'M') return ValidationResult::invalid();
    if (le16(fh + 6) != 0 || le16(fh + 8) != 0) return ValidationResult::invalid();

    const uint64_t file_size = le32(fh + 2);
    const uint64_t off_bits = le32(fh + 10);
    auto dib_size_bytes = reader.read_vec(14, 4);
    if (!dib_size_bytes || dib_size_bytes->size() != 4)
        return ValidationResult::invalid();
    const uint32_t dib_size = le32(dib_size_bytes->data());
    if (!allowed_dib_size(dib_size)) return ValidationResult::invalid();
    if (file_size < 14 + static_cast<uint64_t>(dib_size))
        return ValidationResult::invalid();
    if (limit < 14 + static_cast<uint64_t>(dib_size))
        return ValidationResult::invalid();

    auto dib = reader.read_vec(14, dib_size);
    if (!dib || dib->size() != dib_size) return ValidationResult::invalid();

    Header header;
    header.dib_size = dib_size;
    if (!parse_dib(reader, *dib, header)) return ValidationResult::invalid();

    uint64_t min_off = 0;
    if (!checked_add<uint64_t>(14 + static_cast<uint64_t>(dib_size), header.mask_bytes,
                               min_off))
        return ValidationResult::invalid();
    uint64_t with_palette = 0;
    if (!checked_add<uint64_t>(min_off, header.palette_bytes, with_palette))
        return ValidationResult::invalid();
    min_off = with_palette;
    if (file_size < min_off || off_bits < min_off || off_bits > file_size)
        return ValidationResult::invalid();

    auto truncated_result = [&]() {
        ValidationResult result;
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = limit;
        result.subtype = header.subtype;
        result.confidence = Confidence::Low;
        result.notes = header.notes;
        return result;
    };

    if (header.compression == 1 || header.compression == 2) {
        if (header.top_down) return ValidationResult::invalid();
        if (header.size_image != 0 &&
            off_bits + static_cast<uint64_t>(header.size_image) > file_size)
            return ValidationResult::invalid();

        uint64_t end = 0;
        const Status status =
            parse_rle(reader, off_bits, file_size, limit, header.width, header.height,
                      header.compression == 2, end);
        if (status == Status::Invalid) return ValidationResult::invalid();
        if (status == Status::Truncated) return truncated_result();
        if (header.size_image != 0 && end - off_bits > header.size_image)
            return ValidationResult::invalid();
        if (file_size - end > kMaxExtraBytes) return ValidationResult::invalid();
        if (file_size > limit) return truncated_result();
        return complete_result(header, file_size, reader.deep_validate());
    }

    if (header.compression == 4 || header.compression == 5) {
        const bool jpeg = header.compression == 4;
        if (off_bits >= file_size) return ValidationResult::invalid();
        if (header.size_image != 0 &&
            off_bits + static_cast<uint64_t>(header.size_image) > file_size)
            return ValidationResult::invalid();

        // A candidate cut before the embedded payload starts is still a truncation,
        // not a malformed bitmap; the subtraction below must not underflow.
        if (off_bits >= limit) return truncated_result();

        constexpr uint8_t kJpegMagic[] = {0xFF, 0xD8, 0xFF};
        constexpr uint8_t kPngMagic[] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        const size_t need = jpeg ? sizeof kJpegMagic : sizeof kPngMagic;
        const uint64_t available = std::min<uint64_t>(limit, file_size) - off_bits;
        if (available < need) {
            if (file_size > limit) return truncated_result();
            return ValidationResult::invalid();
        }
        auto magic = reader.read_vec(off_bits, need);
        if (!magic || magic->size() != need) return ValidationResult::invalid();
        const uint8_t* expected = jpeg ? kJpegMagic : kPngMagic;
        if (std::memcmp(magic->data(), expected, need) != 0)
            return ValidationResult::invalid();
        if (file_size > limit) return truncated_result();

        ValidationResult result;
        result.verdict = ValidationResult::Verdict::Valid;
        result.length_bytes = file_size;
        result.subtype = header.subtype;
        result.confidence = Confidence::Medium;
        result.notes = header.notes;
        return result;
    }

    uint64_t row_bits = 0;
    if (!checked_mul<uint64_t>(header.width, header.bpp, row_bits))
        return ValidationResult::invalid();
    const uint64_t stride = ((row_bits + 31) / 32) * 4;
    uint64_t data_bytes = 0;
    if (!checked_mul<uint64_t>(stride, header.height, data_bytes))
        return ValidationResult::invalid();
    uint64_t data_end = 0;
    if (!checked_add<uint64_t>(off_bits, data_bytes, data_end))
        return ValidationResult::invalid();
    if (data_end > file_size) return ValidationResult::invalid();
    if (header.size_image != 0) {
        if (header.size_image < data_bytes) return ValidationResult::invalid();
        if (off_bits + static_cast<uint64_t>(header.size_image) > file_size)
            return ValidationResult::invalid();
    }
    if (file_size - data_end > kMaxExtraBytes) return ValidationResult::invalid();
    if (file_size > limit) return truncated_result();
    return complete_result(header, file_size, reader.deep_validate());
}

}  // namespace openrecover::carve
