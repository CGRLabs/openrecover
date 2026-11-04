#pragma once

// Builders for read-only VHDX containers used by unit tests and by the fixture generator's
// C++ equivalents. The library never writes, so this lives in the test tree.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "openrecover/common/crc32c.hpp"

namespace openrecover::test {

constexpr size_t kVhdxKiB = 1024;
constexpr size_t kVhdxMiB = 1024 * 1024;
constexpr size_t kVhdxHeader1 = 64 * kVhdxKiB;
constexpr size_t kVhdxHeader2 = 128 * kVhdxKiB;
constexpr size_t kVhdxHeaderBytes = 4 * kVhdxKiB;
constexpr size_t kVhdxRegion1 = 192 * kVhdxKiB;
constexpr size_t kVhdxRegion2 = 256 * kVhdxKiB;
constexpr size_t kVhdxRegionBytes = 64 * kVhdxKiB;
constexpr size_t kVhdxRegionEntries = 16;
constexpr size_t kVhdxBatOffset = 320 * kVhdxKiB;
constexpr size_t kVhdxBatBytes = 4 * kVhdxKiB;
constexpr size_t kVhdxMetadataOffset = 336 * kVhdxKiB;
constexpr size_t kVhdxMetadataBytes = 4 * kVhdxKiB;
constexpr size_t kVhdxPayloadStart = 1 * kVhdxMiB;
constexpr size_t kVhdxParamsAt = 0x100;
constexpr size_t kVhdxSizeAt = 0x108;
constexpr size_t kVhdxLogicalAt = 0x110;
constexpr size_t kVhdxPhysicalAt = 0x114;

inline void put_le16(std::vector<uint8_t>& b, size_t at, uint16_t v) {
    b[at] = static_cast<uint8_t>(v);
    b[at + 1] = static_cast<uint8_t>(v >> 8);
}

inline void put_le32(std::vector<uint8_t>& b, size_t at, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b[at + i] = static_cast<uint8_t>(v >> (i * 8));
}

inline void put_le64(std::vector<uint8_t>& b, size_t at, uint64_t v) {
    for (size_t i = 0; i < 8; ++i) b[at + i] = static_cast<uint8_t>(v >> (i * 8));
}

inline void put_guid(std::vector<uint8_t>& b, size_t at, const std::array<uint8_t, 16>& g) {
    std::copy(g.begin(), g.end(), b.begin() + static_cast<std::ptrdiff_t>(at));
}

// Recomputes a structure's CRC32c with the checksum field itself read as zeros.
inline void put_crc32c(std::vector<uint8_t>& b, size_t at, size_t length, size_t field) {
    std::fill(b.begin() + static_cast<std::ptrdiff_t>(at + field),
              b.begin() + static_cast<std::ptrdiff_t>(at + field + 4), uint8_t{0});
    put_le32(b, at + field, crc32c(b.data() + at, length));
}

inline const std::array<uint8_t, 16>& vhdx_bat_region_id() {
    static constexpr std::array<uint8_t, 16> kId = {0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42,
                                                    0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08};
    return kId;
}

inline const std::array<uint8_t, 16>& vhdx_metadata_region_id() {
    static constexpr std::array<uint8_t, 16> kId = {0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B,
                                                    0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E};
    return kId;
}

inline const std::array<uint8_t, 16>& vhdx_file_parameters_id() {
    static constexpr std::array<uint8_t, 16> kId = {0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D,
                                                    0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B};
    return kId;
}

inline const std::array<uint8_t, 16>& vhdx_virtual_disk_size_id() {
    static constexpr std::array<uint8_t, 16> kId = {0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48,
                                                    0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8};
    return kId;
}

inline const std::array<uint8_t, 16>& vhdx_logical_sector_id() {
    static constexpr std::array<uint8_t, 16> kId = {0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47,
                                                    0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F};
    return kId;
}

inline const std::array<uint8_t, 16>& vhdx_physical_sector_id() {
    static constexpr std::array<uint8_t, 16> kId = {0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44,
                                                    0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56};
    return kId;
}

inline const std::array<uint8_t, 16>& vhdx_parent_locator_id() {
    static constexpr std::array<uint8_t, 16> kId = {0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45,
                                                    0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C};
    return kId;
}

enum class VhdxBlockMode {
    kFull,
    kNotPresent,
    kUndefined,
    kZero,
    kPartial,
};

struct VhdxBuildOptions {
    uint64_t block_size = kVhdxMiB;
    uint32_t logical_sector = 512;
    uint32_t physical_sector = 512;
    bool has_parent = false;
    bool parent_locator = false;
    // Applied only to blocks the mode list does not name.
    VhdxBlockMode default_mode = VhdxBlockMode::kFull;
};

inline void write_header(std::vector<uint8_t>& b, size_t at, uint64_t sequence) {
    std::memcpy(b.data() + at, "head", 4);
    put_le64(b, at + 8, sequence);
    put_le16(b, at + 66, 1);  // version
    put_le16(b, at + 64, 0);  // log version
    put_crc32c(b, at, kVhdxHeaderBytes, 4);
}

inline void write_region_entry(std::vector<uint8_t>& b, size_t at,
                               const std::array<uint8_t, 16>& id, uint64_t offset, uint32_t length) {
    put_guid(b, at, id);
    put_le64(b, at + 16, offset);
    put_le32(b, at + 24, length);
    put_le32(b, at + 28, 1);  // required
}

// Wraps `volume` in a VHDX container. Blocks listed as partial keep one bit per sector that
// holds a non-zero byte, so the decoded volume equals the input; the omitted sectors read
// back as the zeros they already are.
inline std::vector<uint8_t> make_vhdx(const std::vector<uint8_t>& volume,
                                      const std::vector<VhdxBlockMode>& modes = {},
                                      const VhdxBuildOptions& opts = {}) {
    const uint64_t block_size = opts.block_size;
    const uint64_t sectors_per_block = block_size / opts.logical_sector;
    const uint64_t blocks = volume.empty() ? 1 : (volume.size() + block_size - 1) / block_size;
    const uint64_t bitmap_bytes = std::min<uint64_t>((sectors_per_block + 7) / 8, kVhdxMiB);

    std::vector<uint64_t> bat(static_cast<size_t>(blocks), 0);
    std::vector<uint64_t> payload_at(static_cast<size_t>(blocks), 0);
    std::vector<uint64_t> bitmap_at(static_cast<size_t>(blocks), 0);
    uint64_t cursor = kVhdxPayloadStart;
    for (uint64_t i = 0; i < blocks; ++i) {
        const VhdxBlockMode mode = i < modes.size() ? modes[static_cast<size_t>(i)] : opts.default_mode;
        if (mode == VhdxBlockMode::kFull) {
            payload_at[static_cast<size_t>(i)] = cursor;
            cursor += block_size;
        } else if (mode == VhdxBlockMode::kPartial) {
            bitmap_at[static_cast<size_t>(i)] = cursor;
            payload_at[static_cast<size_t>(i)] = cursor + kVhdxMiB;
            cursor += kVhdxMiB + block_size;
        }
    }

    std::vector<uint8_t> b(static_cast<size_t>(cursor), 0);
    std::memcpy(b.data(), "vhdxfile", 8);
    write_header(b, kVhdxHeader1, 1);
    write_header(b, kVhdxHeader2, 2);

    // Two identical region tables: BAT first, then metadata.
    for (size_t at : {kVhdxRegion1, kVhdxRegion2}) {
        std::memcpy(b.data() + at, "regi", 4);
        put_le32(b, at + 8, 2);
        write_region_entry(b, at + kVhdxRegionEntries, vhdx_bat_region_id(), kVhdxBatOffset,
                           static_cast<uint32_t>(kVhdxBatBytes));
        write_region_entry(b, at + kVhdxRegionEntries + 32, vhdx_metadata_region_id(),
                           kVhdxMetadataOffset, static_cast<uint32_t>(kVhdxMetadataBytes));
        put_crc32c(b, at, kVhdxRegionBytes, 4);
    }

    // Metadata table.
    const size_t meta = kVhdxMetadataOffset;
    std::memcpy(b.data() + meta, "metadata", 8);
    const uint16_t items = opts.parent_locator ? 5 : 4;
    put_le16(b, meta + 10, items);
    struct Item {
        const std::array<uint8_t, 16>& id;
        size_t offset;
        uint32_t length;
    };
    std::vector<Item> entries = {
        {vhdx_file_parameters_id(), kVhdxParamsAt, 8},
        {vhdx_virtual_disk_size_id(), kVhdxSizeAt, 8},
        {vhdx_logical_sector_id(), kVhdxLogicalAt, 4},
        {vhdx_physical_sector_id(), kVhdxPhysicalAt, 4},
    };
    if (opts.parent_locator) entries.push_back({vhdx_parent_locator_id(), 0x118, 8});
    for (size_t i = 0; i < entries.size(); ++i) {
        const size_t at = meta + 32 + i * 40;
        put_guid(b, at, entries[i].id);
        put_le32(b, at + 16, static_cast<uint32_t>(entries[i].offset));
        put_le32(b, at + 20, entries[i].length);
        put_le32(b, at + 28, 1);  // virtual disk metadata
        put_le32(b, at + 32, 1);  // required
    }
    put_le32(b, meta + kVhdxParamsAt, static_cast<uint32_t>(opts.block_size));
    put_le32(b, meta + kVhdxParamsAt + 4, opts.has_parent ? 2u : 0u);
    put_le64(b, meta + kVhdxSizeAt, volume.size());
    put_le32(b, meta + kVhdxLogicalAt, opts.logical_sector);
    put_le32(b, meta + kVhdxPhysicalAt, opts.physical_sector);

    // Payload blocks and block allocation table.
    for (uint64_t i = 0; i < blocks; ++i) {
        const VhdxBlockMode mode = i < modes.size() ? modes[static_cast<size_t>(i)] : opts.default_mode;
        const uint64_t start = i * block_size;
        if (mode == VhdxBlockMode::kNotPresent) bat[static_cast<size_t>(i)] = 0;
        else if (mode == VhdxBlockMode::kUndefined) bat[static_cast<size_t>(i)] = 1;
        else if (mode == VhdxBlockMode::kZero) bat[static_cast<size_t>(i)] = 2;
        else if (mode == VhdxBlockMode::kFull) {
            bat[static_cast<size_t>(i)] =
                4 | ((payload_at[static_cast<size_t>(i)] / kVhdxMiB) << 20);
            const uint64_t end = std::min<uint64_t>(start + block_size, volume.size());
            std::copy(volume.begin() + static_cast<std::ptrdiff_t>(start),
                      volume.begin() + static_cast<std::ptrdiff_t>(end),
                      b.begin() + static_cast<std::ptrdiff_t>(payload_at[static_cast<size_t>(i)]));
        } else {
            bat[static_cast<size_t>(i)] =
                5 | ((payload_at[static_cast<size_t>(i)] / kVhdxMiB) << 20);
            const uint64_t bitmap = bitmap_at[static_cast<size_t>(i)];
            for (uint64_t sector = 0; sector < sectors_per_block; ++sector) {
                const uint64_t sector_start = start + sector * opts.logical_sector;
                if (sector_start >= volume.size()) break;
                const uint64_t sector_end =
                    std::min<uint64_t>(sector_start + opts.logical_sector, volume.size());
                bool used = false;
                for (uint64_t p = sector_start; p < sector_end; ++p)
                    used = used || volume[static_cast<size_t>(p)] != 0;
                if (used && sector / 8 < bitmap_bytes)
                    b[static_cast<size_t>(bitmap + sector / 8)] |= static_cast<uint8_t>(1u << (sector % 8));
            }
            const uint64_t end = std::min<uint64_t>(start + block_size, volume.size());
            std::copy(volume.begin() + static_cast<std::ptrdiff_t>(start),
                      volume.begin() + static_cast<std::ptrdiff_t>(end),
                      b.begin() + static_cast<std::ptrdiff_t>(payload_at[static_cast<size_t>(i)]));
        }
    }
    for (size_t i = 0; i < bat.size(); ++i) put_le64(b, kVhdxBatOffset + i * 8, bat[i]);
    return b;
}

}  // namespace openrecover::test
