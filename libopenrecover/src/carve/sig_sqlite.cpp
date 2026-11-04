#include "openrecover/carve/sig_sqlite.hpp"

#include <cstring>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/common/bytes.hpp"
#include "openrecover/common/types.hpp"

namespace openrecover::carve {

namespace {
constexpr size_t kHeaderBytes = 100;
constexpr char kMagic[] = "SQLite format 3\0";

uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
}

std::span<const std::span<const uint8_t>> SqliteSignature::magics() const {
    static const uint8_t m[] = {'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3','\0'};
    static std::vector<std::span<const uint8_t>> vec{std::span<const uint8_t>(m, 16)};
    static std::span<const std::span<const uint8_t>> sp(vec.data(), vec.size());
    return sp;
}

ValidationResult SqliteSignature::validate(BoundedReader& reader) const {
    ValidationResult result;
    const uint64_t limit = reader.limit();
    if (limit < kHeaderBytes) return result;

    auto hdr = reader.read_vec(0, kHeaderBytes);
    if (!hdr || hdr->size() != kHeaderBytes) return result;
    const uint8_t* h = hdr->data();
    if (std::memcmp(h, kMagic, 16) != 0) return result;

    const uint16_t page_size_raw = static_cast<uint16_t>((h[16] << 8) | h[17]);
    const uint32_t page_size = (page_size_raw == 1) ? 65536u : page_size_raw;
    if (page_size < 512 || (page_size & (page_size - 1)) != 0) return result;

    // The page count is only authoritative while it agrees with the change counter; a
    // deleted database commonly leaves it one write behind.
    const bool size_is_current = be32(h + 24) == be32(h + 92);
    const uint32_t declared_pages = be32(h + 28);
    if (declared_pages == 0) return result;

    const uint64_t declared_bytes = static_cast<uint64_t>(declared_pages) * page_size;
    if (declared_bytes > max_file_size()) return result;

    // `limit` is the scan window, not the file: it ends wherever the device or the next
    // candidate does, so only whole pages inside it can be claimed.
    if (declared_bytes > limit) {
        const uint64_t visible = (limit / page_size) * page_size;
        if (visible < page_size) return result;
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = visible;
        result.subtype = "sqlite";
        result.confidence = Confidence::Low;
        result.notes.push_back("database extends past the scan window");
        return result;
    }

    result.verdict = ValidationResult::Verdict::Valid;
    result.length_bytes = declared_bytes;
    result.subtype = "sqlite";
    result.confidence = size_is_current ? Confidence::High : Confidence::Medium;
    if (!size_is_current)
        result.notes.push_back("change counter disagrees with the header page count");
    return result;
}

}  // namespace openrecover::carve