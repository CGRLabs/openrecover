#pragma once

#include <cstddef>
#include <cstdint>

namespace openrecover {

// The standard CRC-32c (Castagnoli): reflected polynomial 0x1EDC6F41, initial value
// 0xFFFFFFFF, final inversion. VHDX checksums are this flat form. ext4 needs the raw
// running state instead, because its metadata checksums are chained, so both are exposed.
uint32_t crc32c(const uint8_t* data, size_t len) noexcept;

// Continues a CRC32c from a raw, un-inverted running state (the value before the final
// inversion). Start a chain with 0xFFFFFFFF and finish it with `^ 0xFFFFFFFF`.
uint32_t crc32c_update(uint32_t state, const uint8_t* data, size_t len) noexcept;

}  // namespace openrecover
