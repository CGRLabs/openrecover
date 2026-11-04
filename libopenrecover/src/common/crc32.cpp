#include "openrecover/common/crc32.hpp"

#include <miniz.h>

namespace openrecover {

uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) noexcept {
    // mz_crc32 takes size_t, but process in bounded chunks to stay portable across mz_ulong widths.
    while (len > 0) {
        size_t chunk = len > (1u << 30) ? (1u << 30) : len;
        crc = static_cast<uint32_t>(mz_crc32(crc, data, chunk));
        data += chunk;
        len -= chunk;
    }
    return crc;
}

uint32_t adler32_update(uint32_t adler, const uint8_t* data, size_t len) noexcept {
    while (len > 0) {
        size_t chunk = len > (1u << 30) ? (1u << 30) : len;
        adler = static_cast<uint32_t>(mz_adler32(adler, data, chunk));
        data += chunk;
        len -= chunk;
    }
    return adler;
}

}  // namespace openrecover
