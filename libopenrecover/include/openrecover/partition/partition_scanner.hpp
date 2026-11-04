#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::partition {

enum class PartitionScheme { Mbr, Gpt, Superfloppy };

struct PartitionInfo {
    uint32_t index = 0;
    uint64_t start_byte = 0;
    uint64_t length_byte = 0;
    std::string type_desc;
    PartitionScheme scheme = PartitionScheme::Mbr;
};

// Reads LBA 0, requires the 0x55AA signature, and returns primary and logical partitions.
// Extended containers (type 0x05/0x0F/0x85) are followed but are not emitted themselves.
Result<std::vector<PartitionInfo>> parse_mbr(io::BlockDevice& dev);

// Scans `dev` for a partition table. If LBA 0 is a FAT32, exFAT or NTFS boot sector, or the
// volume carries an ext4 superblock at byte 1024, and no MBR partitions exist, the whole
// device is returned as a single Superfloppy volume.
Result<std::vector<PartitionInfo>> scan_partitions(io::BlockDevice& dev);

}  // namespace openrecover::partition
