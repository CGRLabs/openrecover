#include "openrecover/fs/ext4/ext4_checksum.hpp"

#include <array>
#include <cstdint>

#include "openrecover/common/crc32c.hpp"

namespace openrecover::fs {
namespace {

constexpr std::array<uint8_t, 64> kZeros{};

}  // namespace

uint32_t crc32c_continue(uint32_t crc, const uint8_t* data, size_t len) noexcept {
    // The state goes in and comes out raw: no inversion on either side, which is the
    // convention ext4's chained metadata seeds use.
    return crc32c_update(crc, data, len);
}

uint32_t ext4_crc32c(const uint8_t* data, size_t len) noexcept { return openrecover::crc32c(data, len); }

uint32_t crc32c_zeros(uint32_t crc, size_t count) noexcept {
    // Same recurrence with the input byte fixed at zero.
    while (count > 0) {
        const size_t take = count < kZeros.size() ? count : kZeros.size();
        crc = crc32c_update(crc, kZeros.data(), take);
        count -= take;
    }
    return crc;
}

uint16_t crc16_continue(uint16_t crc, const uint8_t* data, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int b = 0; b < 8; ++b)
            crc = (crc & 0x8000u) ? static_cast<uint16_t>((crc << 1) ^ 0x1021u)
                                  : static_cast<uint16_t>(crc << 1);
    }
    return crc;
}

uint16_t ext4_crc16(const uint8_t* data, size_t len) noexcept {
    return crc16_continue(0xFFFFu, data, len);
}

}  // namespace openrecover::fs
