#include "openrecover/common/crc32c.hpp"

#include <array>

namespace openrecover {
namespace {

// Reflected Castagnoli polynomial: the bit-reversal of 0x1EDC6F41.
constexpr uint32_t kCrc32cPoly = 0x82F63B78u;

constexpr std::array<uint32_t, 256> build_table() {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) c = (c & 1u) ? ((c >> 1) ^ kCrc32cPoly) : (c >> 1);
        t[i] = c;
    }
    return t;
}

constexpr auto kTable = build_table();

}  // namespace

uint32_t crc32c_update(uint32_t crc, const uint8_t* data, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i)
        crc = kTable[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc;
}

uint32_t crc32c(const uint8_t* data, size_t len) noexcept {
    return crc32c_update(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

}  // namespace openrecover
