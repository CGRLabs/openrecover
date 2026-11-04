#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace openrecover {

// zlib/ISO-HDLC CRC-32 (poly 0xEDB88320); `crc` is the running value (start with 0).
uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) noexcept;
inline uint32_t crc32(std::span<const uint8_t> s) noexcept { return crc32_update(0, s.data(), s.size()); }

// Adler-32; start with 1.
uint32_t adler32_update(uint32_t adler, const uint8_t* data, size_t len) noexcept;

}  // namespace openrecover
