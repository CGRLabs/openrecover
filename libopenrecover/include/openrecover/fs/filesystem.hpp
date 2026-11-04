#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "openrecover/common/types.hpp"
#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

enum class FsKind { Fat32, Ntfs, ExFat, Ext4 };

struct FsGeometry {
    uint32_t bytes_per_sector = 0;
    uint32_t bytes_per_cluster = 0;
    uint64_t total_clusters = 0;
};

struct ScanOptions {
    uint32_t max_directory_depth = 255;
};

class IFileSystemScanner {
public:
    virtual ~IFileSystemScanner() = default;
    virtual FsKind kind() const = 0;
    virtual const FsGeometry& geometry() const = 0;
    virtual Result<std::vector<RecoveredFile>> scan_deleted(const ScanOptions&, ProgressFn) = 0;
    virtual Result<std::unique_ptr<IAllocationMap>> allocation_map() = 0;
    virtual Result<size_t> read_file(const RecoveredFile&, uint64_t file_offset, uint8_t* dst, size_t len) = 0;
};

// Opens the filesystem at the start of `dev` by signature: NTFS, then FAT32.
Result<std::unique_ptr<IFileSystemScanner>> detect_and_open(std::shared_ptr<io::BlockDevice> dev);

}  // namespace openrecover::fs
