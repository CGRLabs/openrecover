#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/partition/partition_scanner.hpp"

namespace openrecover::partition {

struct MbrEntry {
    uint8_t status = 0;
    uint8_t type = 0;
    uint32_t start_lba = 0;
    uint32_t sector_count = 0;
};

// Decodes the four 16-byte entries at offset 0x1BE of an LBA-0 sector.
std::array<MbrEntry, 4> decode_mbr_entries(std::span<const uint8_t> sector);

}  // namespace openrecover::partition
