#pragma once

#include <cstdint>
#include <span>

#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

struct ExfatBoot {
    uint32_t bytes_per_sector = 0;
    uint32_t sectors_per_cluster = 0;
    uint32_t bytes_per_cluster = 0;
    uint32_t fat_offset_sectors = 0;
    uint32_t fat_length_sectors = 0;
    uint32_t cluster_heap_offset_sectors = 0;
    uint32_t cluster_count = 0;
    uint32_t first_cluster_of_root = 0;
    uint8_t number_of_fats = 0;
    uint16_t volume_flags = 0;
    uint32_t volume_serial = 0;
    uint16_t filesystem_revision = 0;
    uint64_t volume_length_sectors = 0;
    uint64_t partition_offset_sectors = 0;

    uint64_t fat_byte_offset() const {
        return static_cast<uint64_t>(fat_offset_sectors) * bytes_per_sector;
    }
    uint64_t cluster_heap_byte_offset() const {
        return static_cast<uint64_t>(cluster_heap_offset_sectors) * bytes_per_sector;
    }
    bool valid_cluster(uint32_t cluster) const {
        return cluster >= 2 && static_cast<uint64_t>(cluster) < static_cast<uint64_t>(cluster_count) + 2;
    }
    uint64_t cluster_to_byte(uint32_t cluster) const {
        if (cluster < 2) return 0;
        return cluster_heap_byte_offset() +
               static_cast<uint64_t>(cluster - 2) * bytes_per_cluster;
    }
};

Result<ExfatBoot> parse_exfat_boot(std::span<const uint8_t> boot_sector, uint64_t volume_size);
Result<ExfatBoot> read_exfat_boot(io::BlockDevice& dev);

}  // namespace openrecover::fs
