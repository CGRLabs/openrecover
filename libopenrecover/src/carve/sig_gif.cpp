#include "openrecover/carve/sig_gif.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"

namespace openrecover::carve {

namespace {

// A canvas or frame larger than this cannot plausibly belong to a file within
// the signature size cap, even at the best LZW compression ratios.
constexpr uint64_t kMaxPixels = 1ull << 28;
constexpr uint64_t kMaxBlocks = 1ull << 20;
constexpr size_t kIoChunk = 64u << 10;

constexpr uint8_t kTrailer = 0x3B;
constexpr uint8_t kImageSeparator = 0x2C;
constexpr uint8_t kExtensionIntroducer = 0x21;
constexpr uint8_t kGraphicControlLabel = 0xF9;
constexpr uint8_t kApplicationLabel = 0xFF;
constexpr uint8_t kPlainTextLabel = 0x01;

enum class Status { Ok, Invalid, Truncated, Corrupt };

uint16_t le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

struct Header {
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t gct_entries = 0;
    std::string subtype;
};

bool parse_header(const std::vector<uint8_t>& p, Header& out) {
    if (p.size() != 13) return false;
    if (std::memcmp(p.data(), "GIF87a", 6) == 0)
        out.subtype = "gif87a";
    else if (std::memcmp(p.data(), "GIF89a", 6) == 0)
        out.subtype = "gif89a";
    else
        return false;

    out.width = le16(p.data() + 6);
    out.height = le16(p.data() + 8);
    if (out.width == 0 || out.height == 0) return false;
    if (static_cast<uint64_t>(out.width) * out.height > kMaxPixels) return false;

    const uint8_t packed = p[10];
    if ((packed & 0x80) != 0)
        out.gct_entries = static_cast<uint16_t>(2u << (packed & 0x07u));
    return true;
}

// Walks a GIF data sub-block chain. Each block is at most 255 bytes; the chain
// ends with a zero-length block. `feed` sees every payload in order.
template <typename Feed>
Status walk_chain(BoundedReader& reader, uint64_t& pos, uint64_t limit, Feed&& feed) {
    std::array<uint8_t, 255> buffer{};
    uint64_t blocks = 0;
    for (;;) {
        if (++blocks > kMaxBlocks) return Status::Invalid;
        if (pos >= limit) return Status::Truncated;
        auto size_res = reader.read_at(pos, buffer.data(), 1);
        if (!size_res) return Status::Invalid;
        if (*size_res != 1) return Status::Truncated;
        const uint8_t size = buffer[0];
        ++pos;
        if (size == 0) return Status::Ok;

        if (size > limit - pos) return Status::Truncated;
        auto data_res = reader.read_at(pos, buffer.data(), size);
        if (!data_res) return Status::Invalid;
        if (*data_res != size) return Status::Truncated;
        if (!feed(buffer.data(), size)) return Status::Invalid;
        pos += size;
    }
}

// Decodes a GIF LZW stream far enough to verify its structure and exact pixel
// count. Strings are never materialised: per-code length and first byte are
// sufficient for both the output count and the KwKwK case.
class LzwDecoder {
public:
    LzwDecoder(uint8_t min_code_size, uint64_t expected_pixels)
        : min_code_size_(min_code_size),
          clear_code_(static_cast<uint16_t>(1u << min_code_size)),
          end_code_(static_cast<uint16_t>(clear_code_ + 1)),
          next_code_(static_cast<uint16_t>(clear_code_ + 2)),
          code_size_(static_cast<int>(min_code_size) + 1),
          expected_(expected_pixels) {
        for (uint32_t i = 0; i < clear_code_; ++i) {
            table_[i].length = 1;
            table_[i].first = static_cast<uint8_t>(i);
        }
    }

    bool feed(const uint8_t* data, size_t len) {
        if (ended_) return true;
        for (size_t i = 0; i < len; ++i) {
            bits_ |= static_cast<uint32_t>(data[i]) << bit_count_;
            bit_count_ += 8;
            while (bit_count_ >= code_size_) {
                const uint16_t code =
                    static_cast<uint16_t>(bits_ & ((1u << code_size_) - 1u));
                bits_ >>= code_size_;
                bit_count_ -= code_size_;
                if (!process(code)) return false;
                if (ended_) return true;
            }
        }
        return true;
    }

    bool finish() const { return ended_ && pixels_ == expected_; }

private:
    struct Entry {
        uint32_t length = 1;
        uint8_t first = 0;
    };

    bool process(uint16_t code) {
        if (code == clear_code_) {
            next_code_ = static_cast<uint16_t>(clear_code_ + 2);
            code_size_ = static_cast<int>(min_code_size_) + 1;
            have_prev_ = false;
            saw_clear_ = true;
            return true;
        }
        if (!saw_clear_) return false;
        if (code == end_code_) {
            ended_ = true;
            return true;
        }

        Entry current;
        if (code < next_code_) {
            current = table_[code];
        } else if (code == next_code_ && have_prev_) {
            current.length = table_[prev_].length + 1;
            current.first = table_[prev_].first;
        } else {
            return false;
        }

        pixels_ += current.length;
        if (pixels_ > expected_) return false;

        if (have_prev_ && next_code_ < 4096) {
            table_[next_code_].length = table_[prev_].length + 1;
            table_[next_code_].first = table_[prev_].first;
            ++next_code_;
            if (next_code_ == (1u << code_size_) && code_size_ < 12) ++code_size_;
        }
        prev_ = code;
        have_prev_ = true;
        return true;
    }

    uint8_t min_code_size_;
    uint16_t clear_code_;
    uint16_t end_code_;
    uint16_t next_code_;
    int code_size_;
    uint64_t expected_;
    uint64_t pixels_ = 0;
    uint32_t bits_ = 0;
    int bit_count_ = 0;
    bool saw_clear_ = false;
    bool have_prev_ = false;
    bool ended_ = false;
    uint16_t prev_ = 0;
    std::array<Entry, 4096> table_{};
};

// State shared by the block walk that both the header walk (`validate`) and the
// tail walk (`find_continuation`) use. `gct` is what the header walk knows about
// the global color table; a tail walk without the header assumes one exists, so
// a frame with a local table stays legal either way.
struct Walk {
    BoundedReader& reader;
    uint64_t limit;
    bool deep;
    bool gct;
    uint64_t frames = 0;
    // Set when a block fails structurally: the offset of that block's introducer.
    // The caller turns it into a cut at the block, so the failed block is dropped whole.
    uint64_t failed_at = 0;
};

// Walks one block -- an image descriptor with its LZW data, or an extension --
// starting at the introducer byte `pos`. On Ok, `pos` is just past the block and
// a completed image has bumped `frames`. On Truncated, the window ran out and
// `pos` is where the bytes stopped. On Invalid, the block is structurally broken
// and `failed_at` names it. On Corrupt, the block parsed but its image data
// failed the deep LZW decode -- proof of corruption, not of a cut.
Status walk_block(Walk& walk, uint64_t& pos) {
    BoundedReader& reader = walk.reader;
    const uint64_t limit = walk.limit;
    if (pos >= limit) {
        walk.failed_at = pos;
        return Status::Truncated;
    }
    auto type_res = reader.u8(pos);
    if (!type_res) return Status::Invalid;
    const uint8_t type = *type_res;
    const uint64_t block_at = pos;
    ++pos;

    if (type == kImageSeparator) {
        if (limit - pos < 9) {
            walk.failed_at = block_at;
            return Status::Truncated;
        }
        auto descriptor = reader.read_vec(pos, 9);
        if (!descriptor || descriptor->size() != 9) return Status::Invalid;
        const uint16_t frame_width = le16(descriptor->data() + 4);
        const uint16_t frame_height = le16(descriptor->data() + 6);
        const uint8_t packed = (*descriptor)[8];
        if (frame_width == 0 || frame_height == 0 ||
            static_cast<uint64_t>(frame_width) * frame_height > kMaxPixels ||
            (packed & 0x18u) != 0 || (walk.gct == false && (packed & 0x80u) == 0)) {
            walk.failed_at = block_at;
            return Status::Invalid;
        }
        pos += 9;

        if ((packed & 0x80u) != 0) {
            const uint64_t lct_bytes = 3ull * (2u << (packed & 0x07u));
            if (lct_bytes > limit - pos) {
                walk.failed_at = block_at;
                return Status::Truncated;
            }
            pos += lct_bytes;
        }

        if (pos >= limit) {
            walk.failed_at = block_at;
            return Status::Truncated;
        }
        auto min_code_res = reader.u8(pos);
        if (!min_code_res) return Status::Invalid;
        const uint8_t min_code_size = *min_code_res;
        ++pos;
        if (min_code_size < 2 || min_code_size > 8) {
            walk.failed_at = block_at;
            return Status::Invalid;
        }

        bool image_data_seen = false;
        bool content_failed = false;
        LzwDecoder decoder(min_code_size, static_cast<uint64_t>(frame_width) * frame_height);
        const Status chain =
            walk_chain(reader, pos, limit,
                       [&](const uint8_t* data, size_t len) {
                           image_data_seen = true;
                           if (!walk.deep) return true;
                           if (!decoder.feed(data, len)) {
                               content_failed = true;
                               return false;
                           }
                           return true;
                       });
        if (chain == Status::Invalid) return Status::Invalid;
        if (chain == Status::Truncated) {
            walk.failed_at = block_at;
            return Status::Truncated;
        }
        if (!image_data_seen) {
            walk.failed_at = block_at;
            return Status::Invalid;
        }
        if (content_failed || (walk.deep && !decoder.finish())) {
            walk.failed_at = block_at;
            return Status::Corrupt;
        }
        ++walk.frames;
        return Status::Ok;
    }

    if (type == kExtensionIntroducer) {
        if (pos >= limit) {
            walk.failed_at = block_at;
            return Status::Truncated;
        }
        auto label_res = reader.u8(pos);
        if (!label_res) return Status::Invalid;
        const uint8_t label = *label_res;
        ++pos;

        if (label == kGraphicControlLabel) {
            // Fixed four-byte block followed by a block terminator.
            if (limit - pos < 6) {
                walk.failed_at = block_at;
                return Status::Truncated;
            }
            auto block = reader.read_vec(pos, 6);
            if (!block || block->size() != 6) return Status::Invalid;
            if ((*block)[0] != 4 || ((*block)[1] & 0xE0u) != 0 || (*block)[5] != 0) {
                walk.failed_at = block_at;
                return Status::Invalid;
            }
            pos += 6;
            return Status::Ok;
        }

        if (limit - pos < 1) {
            walk.failed_at = block_at;
            return Status::Truncated;
        }
        auto size_res = reader.u8(pos);
        if (!size_res) return Status::Invalid;
        const uint8_t first_size = *size_res;
        ++pos;
        const uint16_t required =
            label == kApplicationLabel ? 11 : (label == kPlainTextLabel ? 12 : 0);
        if (required != 0 && first_size != required) {
            walk.failed_at = block_at;
            return Status::Invalid;
        }
        if (first_size == 0) {
            if (required != 0) {
                walk.failed_at = block_at;
                return Status::Invalid;
            }
            return Status::Ok;
        }
        if (first_size > limit - pos) {
            walk.failed_at = block_at;
            return Status::Truncated;
        }
        pos += first_size;

        const Status chain = walk_chain(
            reader, pos, limit, [](const uint8_t*, size_t) { return true; });
        if (chain == Status::Invalid) return Status::Invalid;
        if (chain == Status::Truncated) {
            walk.failed_at = block_at;
            return Status::Truncated;
        }
        return Status::Ok;
    }

    walk.failed_at = block_at;
    return Status::Invalid;
}

}  // namespace

std::span<const std::span<const uint8_t>> GifSignature::magics() const {
    static const uint8_t m0[] = {'G', 'I', 'F', '8', '7', 'a'};
    static const uint8_t m1[] = {'G', 'I', 'F', '8', '9', 'a'};
    static const std::span<const uint8_t> list[] = {m0, m1};
    return list;
}

ValidationResult GifSignature::validate(BoundedReader& reader) const {
    const uint64_t limit = reader.limit();
    if (limit < 13) return ValidationResult::invalid();

    auto header_bytes = reader.read_vec(0, 13);
    if (!header_bytes || header_bytes->size() != 13) return ValidationResult::invalid();
    Header header;
    if (!parse_header(*header_bytes, header)) return ValidationResult::invalid();

    uint64_t pos = 13;
    if (header.gct_entries != 0) {
        const uint64_t gct_bytes = 3ull * header.gct_entries;
        if (gct_bytes > limit - pos) return ValidationResult::invalid();
        pos += gct_bytes;
    }

    Walk walk{reader, limit, reader.deep_validate(), header.gct_entries != 0};
    uint64_t blocks = 0;

    auto truncated_or_invalid = [&]() -> ValidationResult {
        if (walk.frames == 0) return ValidationResult::invalid();
        ValidationResult result;
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = limit;
        result.subtype = header.subtype;
        result.confidence = Confidence::Low;
        return result;
    };

    for (;;) {
        if (++blocks > kMaxBlocks) return ValidationResult::invalid();
        if (pos >= limit) return truncated_or_invalid();

        auto type_res = reader.u8(pos);
        if (!type_res) return ValidationResult::invalid();
        if (*type_res == kTrailer) {
            if (walk.frames == 0) return ValidationResult::invalid();
            ValidationResult result;
            result.verdict = ValidationResult::Verdict::Valid;
            result.length_bytes = pos + 1;
            result.subtype = header.subtype;
            result.confidence = walk.deep ? Confidence::High : Confidence::Medium;
            return result;
        }

        const Status status = walk_block(walk, pos);
        if (reader.error()) return ValidationResult::invalid();
        if (status == Status::Ok) continue;
        if (status == Status::Truncated) return truncated_or_invalid();
        // Content corruption found by the deep decode stays invalid, as PNG treats
        // a failed inflate. A structurally broken block is different: a GIF carries
        // no checksums, so once a frame has completed there is nothing that tells
        // such a block from one whose bytes were overwritten -- both are reported as
        // the cut where parsing stopped, and the failed block is dropped whole.
        // Before any frame the bytes have not proven themselves, so the candidate is
        // rejected as before.
        if (status == Status::Corrupt) return ValidationResult::invalid();
        if (walk.frames == 0) return ValidationResult::invalid();
        ValidationResult result;
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = walk.failed_at;
        result.subtype = header.subtype;
        result.confidence = Confidence::Low;
        result.notes.push_back("discontinuity");
        return result;
    }
}

// A GIF tail has no checksum to offer, and a bare sub-block chain proves nothing:
// from almost any offset, junk parses as a chain of blocks for tens of kilobytes.
// What proves a tail is a block that is valid on its own terms -- an image whose LZW
// stream decodes to exactly the declared pixel count, or an extension whose fixed
// structure (graphic control, application, plain text) checks out. So the scan only
// starts a continuation at such a block, and it always decodes image data whether or
// not the head was validated deeply: the decode is this format's CRC. The walk then
// continues block by block to the trailer and stops at the first block that fails,
// dropping it whole, so the engine resumes past that cut exactly as it does for JPEG
// and PNG. The search refuses to start after another image's header, and bytes that
// merely parse as a sub-block chain are never claimed -- a tail resuming mid-stream
// is joined at the next introducer, and whatever sits before it is left out.
std::optional<Continuation> GifSignature::find_continuation(BoundedReader& r) const {
    constexpr size_t kMaxCandidates = 4096;
    constexpr size_t kOverlap = 13;
    const uint64_t limit = r.limit();
    if (limit < 4) return std::nullopt;
    // A crafted run can otherwise make every offset look like a block boundary;
    // three halves of the window is more than a real continuation needs.
    uint64_t budget = limit + (limit >> 1);
    size_t candidates = 0;

    std::vector<uint8_t> window(kIoChunk);
    for (uint64_t base = 0; base < limit;) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(window.size(), limit - base));
        auto got = r.read_at(base, window.data(), want);
        if (!got || *got == 0) return std::nullopt;
        const size_t n = *got;
        for (size_t k = 0; k + 2 <= n; ++k) {
            const uint64_t s = base + k;
            if (k + 13 <= n && (std::memcmp(window.data() + k, "GIF87a", 6) == 0 ||
                                std::memcmp(window.data() + k, "GIF89a", 6) == 0))
                return std::nullopt;

            const uint8_t introducer = window[k];
            if (introducer != kImageSeparator && introducer != kExtensionIntroducer) continue;
            if (introducer == kExtensionIntroducer) {
                // Only extensions whose structure is fixed are strong enough to start a
                // continuation; a comment block's free-form chain parses anywhere.
                if (k + 2 > n) continue;
                const uint8_t label = window[k + 1];
                if (label != kGraphicControlLabel && label != kApplicationLabel &&
                    label != kPlainTextLabel)
                    continue;
            }

            // The first block must complete on its own, decoded to its exact pixel
            // count when it is an image: that is the candidate's proof.
            Walk walk{r, limit, true, true};
            uint64_t cursor = s;
            if (walk_block(walk, cursor) != Status::Ok) continue;
            if (r.error()) return std::nullopt;
            if (budget < cursor - s) return std::nullopt;
            budget -= cursor - s;
            if (candidates++ >= kMaxCandidates) return std::nullopt;

            bool complete = false;
            uint64_t charged = cursor;
            for (;;) {
                if (cursor >= limit) break;
                auto type_res = r.u8(cursor);
                if (!type_res) return std::nullopt;
                if (*type_res == kTrailer) {
                    ++cursor;
                    complete = true;
                    break;
                }
                Walk next{r, limit, true, true};
                const uint64_t block_at = cursor;
                if (walk_block(next, cursor) != Status::Ok) {
                    cursor = block_at;
                    break;
                }
                if (r.error()) return std::nullopt;
                if (cursor - charged > budget) return std::nullopt;
                budget -= cursor - charged;
                charged = cursor;
            }
            return Continuation{s, cursor - s, complete};
        }
        if (n < want || base + n >= limit) break;
        base += n - kOverlap;
    }
    return std::nullopt;
}

}  // namespace openrecover::carve
