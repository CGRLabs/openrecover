#pragma once

// Builders for read-only VHD containers used by the tests and the fixture generator's
// equivalents inside unit tests. The library never writes, so this lives in the test tree.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace openrecover::test {

constexpr size_t kVhdSector = 512;
constexpr size_t kVhdFooter = 512;
constexpr size_t kVhdHeader = 1024;
constexpr uint32_t kVhdFixed = 2;
constexpr uint32_t kVhdDynamic = 3;
constexpr uint32_t kVhdDifferencing = 4;
constexpr uint32_t kVhdFormatVersion = 0x00010000;
constexpr uint32_t kVhdUnallocated = 0xFFFFFFFFu;

inline void put_be16(std::vector<uint8_t>& b, size_t at, uint16_t v) {
    b[at] = static_cast<uint8_t>(v >> 8);
    b[at + 1] = static_cast<uint8_t>(v);
}

inline void put_be32(std::vector<uint8_t>& b, size_t at, uint32_t v) {
    for (int i = 3; i >= 0; --i) b[at + static_cast<size_t>(3 - i)] = static_cast<uint8_t>(v >> (i * 8));
}

inline void put_be64(std::vector<uint8_t>& b, size_t at, uint64_t v) {
    for (int i = 7; i >= 0; --i) b[at + static_cast<size_t>(7 - i)] = static_cast<uint8_t>(v >> (i * 8));
}

// The header and footer checksums are the one-complement of the byte sum, skipping the
// four checksum bytes themselves.
inline uint32_t block_checksum(const std::vector<uint8_t>& b, size_t checksum_at) {
    uint32_t sum = 0;
    for (size_t i = 0; i < b.size(); ++i) {
        if (i >= checksum_at && i < checksum_at + 4) continue;
        sum += b[i];
    }
    return ~sum;
}

struct VhdFooterOptions {
    uint32_t type = kVhdFixed;
    uint64_t size = 0;
    uint64_t data_offset = 0xFFFFFFFFFFFFFFFFull;
};

inline std::vector<uint8_t> make_vhd_footer(const VhdFooterOptions& o) {
    std::vector<uint8_t> f(kVhdFooter, 0);
    std::memcpy(f.data(), "conectix", 8);
    put_be32(f, 8, 0);
    put_be32(f, 12, kVhdFormatVersion);
    put_be64(f, 16, o.data_offset);
    put_be32(f, 24, 0x65229A00);  // 2023-10-09, unused by the reader
    std::memcpy(f.data() + 28, "qemu", 4);
    put_be32(f, 32, 0x00050000);
    std::memcpy(f.data() + 36, "Wi2k", 4);
    put_be64(f, 40, o.size);
    put_be64(f, 48, o.size);
    // CHS geometry is advisory; the reader uses the footer size.
    uint64_t sectors = o.size / kVhdSector;
    put_be16(f, 56, static_cast<uint16_t>(sectors / 16 / 255 > 65535 ? 65535 : sectors / 16 / 255));
    f[58] = 16;
    f[59] = 255;
    put_be32(f, 60, o.type);
    put_be32(f, 64, block_checksum(f, 64));
    return f;
}

struct VhdDynamicHeaderOptions {
    uint64_t table_offset = 0;
    uint32_t max_entries = 0;
    uint32_t block_size = 2u << 20;
};

inline std::vector<uint8_t> make_vhd_dynamic_header(const VhdDynamicHeaderOptions& o) {
    std::vector<uint8_t> h(kVhdHeader, 0);
    std::memcpy(h.data(), "cxsparse", 8);
    put_be64(h, 8, 0xFFFFFFFFFFFFFFFFull);
    put_be64(h, 16, o.table_offset);
    put_be32(h, 24, kVhdFormatVersion);
    put_be32(h, 28, o.max_entries);
    put_be32(h, 32, o.block_size);
    put_be32(h, 36, block_checksum(h, 36));
    return h;
}

inline void set_sector_bits(std::vector<uint8_t>& bitmap, size_t first, size_t count) {
    for (size_t i = first; i < first + count; ++i) bitmap[i / 8] = static_cast<uint8_t>(bitmap[i / 8] | (1u << (i % 8)));
}

}  // namespace openrecover::test
