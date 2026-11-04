#pragma once

#include <cstdint>
#include <span>

#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

struct NtfsBoot {
    uint32_t bytes_per_sector = 0;
    uint32_t sectors_per_cluster = 0;
    uint32_t bytes_per_cluster = 0;
    uint64_t total_sectors = 0;
    uint64_t total_clusters = 0;
    uint64_t mft_lcn = 0;
    uint64_t mft_mirror_lcn = 0;
    int32_t clusters_per_record = 0;
    uint32_t record_size = 0;
    int32_t clusters_per_index_buffer = 0;
    uint32_t index_buffer_size = 0;
    uint64_t volume_serial = 0;

    uint64_t mft_byte_offset() const { return mft_lcn * bytes_per_cluster; }
    uint64_t mft_mirror_byte_offset() const { return mft_mirror_lcn * bytes_per_cluster; }
};

// Validates one NTFS boot sector against `volume_size` and derives the geometry.
Result<NtfsBoot> parse_ntfs_boot(std::span<const uint8_t> boot_sector, uint64_t volume_size);

// Reads and validates the primary boot sector, falling back to the backup copy in the
// last sector of the volume.
Result<NtfsBoot> read_ntfs_boot(io::BlockDevice& dev);

}  // namespace openrecover::fs
