#pragma once

#include <cstddef>
#include <cstdint>

namespace openrecover::fs {

// The standard CRC-32c (Castagnoli): reflected polynomial 0x1EDC6F41, initial value
// 0xFFFFFFFF, final inversion. Not the CRC32 in common/crc32.hpp.
uint32_t ext4_crc32c(const uint8_t* data, size_t len) noexcept;

// Continues a CRC32c from a raw running state. ext4 checksums are not one flat CRC: an
// inode's checksum skips the 2 bytes at i_checksum_lo and, on a large inode, the 2 at
// i_checksum_hi; a group descriptor skips the 2 at bg_checksum. The kernel folds each
// skipped field away by running the state across zero bytes in its place, which is what
// crc32c_zeros does here -- so a fixture writer and this reader agree without either
// trusting a magic constant.
uint32_t crc32c_continue(uint32_t raw_state, const uint8_t* data, size_t len) noexcept;

// The raw (un-inverted) state a CRC32c of `data` would leave behind.
inline uint32_t crc32c_raw_state(const uint8_t* data, size_t len) noexcept {
    return crc32c_continue(0xFFFFFFFFu, data, len);
}

// A checksum seed extended across a run of zero bytes -- the shape both the inode and
// the group-descriptor checksum need.
uint32_t crc32c_zeros(uint32_t seed_state, size_t count) noexcept;

// CRC16-CCITT with the ext4 convention: initial value 0xFFFF, polynomial 0x1021, MSB-first,
// no final xor. Group descriptors use this on a volume with GDT_CSUM but without
// METADATA_CSUM, where the kernel chains it across the UUID, then the 4-byte group number,
// then the descriptor.
uint16_t ext4_crc16(const uint8_t* data, size_t len) noexcept;

// The chained form of the same CRC: the running value goes in and comes out unchanged in
// convention, so a caller can feed the three pieces separately.
uint16_t crc16_continue(uint16_t running, const uint8_t* data, size_t len) noexcept;

}  // namespace openrecover::fs
