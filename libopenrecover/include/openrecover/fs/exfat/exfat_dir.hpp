#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

#include "openrecover/fs/exfat/exfat_boot.hpp"

namespace openrecover::fs {

struct ExfatFile {
    std::string name;
    uint64_t size = 0;
    uint64_t valid_size = 0;
    uint32_t first_cluster = 0;
    uint16_t attributes = 0;
    bool deleted = false;
    bool no_fat_chain = false;
    bool has_stream = false;
    std::optional<int64_t> mtime_unix;
    std::optional<int64_t> ctime_unix;
    std::optional<int64_t> atime_unix;

    bool is_directory() const { return (attributes & 0x10) != 0; }
};

struct ExfatDirListing {
    std::vector<ExfatFile> files;
    bool has_allocation_bitmap = false;
    uint32_t allocation_bitmap_cluster = 0;
    uint64_t allocation_bitmap_bytes = 0;
    bool has_upcase_table = false;
    uint32_t upcase_table_cluster = 0;
    uint64_t upcase_table_bytes = 0;
    bool chain_lost = false;
    bool truncated = false;
};

// Reads one directory. Root directories pass size_bytes = 0 and follow the FAT chain;
// subdirectories pass their stream size and NoFatChain flag. A deleted directory whose
// FAT chain was cleared is read contiguously and flagged chain_lost.
Result<ExfatDirListing> read_exfat_directory(io::BlockDevice& dev, const ExfatBoot& boot,
                                             uint32_t first_cluster, uint64_t size_bytes = 0,
                                             bool no_fat_chain = false);

}  // namespace openrecover::fs
