#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/fs/exfat/exfat_boot.hpp"
#include "openrecover/fs/exfat/exfat_dir.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

// Cluster allocation state from the exFAT allocation bitmap, with a FAT fallback for
// volumes whose bitmap entry is missing or unreadable.
class ExfatAllocationMap final : public IAllocationMap {
public:
    ExfatAllocationMap(std::shared_ptr<io::BlockDevice> dev, ExfatBoot boot,
                       uint32_t bitmap_cluster, uint64_t bitmap_bytes);
    ExfatAllocationMap(const ExfatAllocationMap&) = delete;
    ExfatAllocationMap& operator=(const ExfatAllocationMap&) = delete;

    bool is_cluster_allocated(uint64_t cluster) const override;
    uint64_t cluster_to_byte_offset(uint64_t cluster) const override;
    uint64_t cluster_count() const override { return boot_.cluster_count; }

    // True when the bitmap was read successfully and cluster states are authoritative.
    bool bitmap_available() const;

private:
    bool load_bitmap() const;
    bool fat_entry_allocated(uint64_t cluster) const;

    std::shared_ptr<io::BlockDevice> dev_;
    ExfatBoot boot_;
    uint32_t bitmap_cluster_ = 0;
    uint64_t bitmap_bytes_ = 0;
    mutable std::mutex mutex_;
    mutable std::vector<uint8_t> bitmap_;
    mutable bool loaded_ = false;
    mutable bool bitmap_ok_ = false;
};

class ExfatScanner final : public IFileSystemScanner {
public:
    static Result<std::unique_ptr<ExfatScanner>> open(std::shared_ptr<io::BlockDevice> dev);

    FsKind kind() const override { return FsKind::ExFat; }
    const FsGeometry& geometry() const override { return geometry_; }
    Result<std::vector<RecoveredFile>> scan_deleted(const ScanOptions&, ProgressFn) override;
    Result<std::unique_ptr<IAllocationMap>> allocation_map() override;
    Result<size_t> read_file(const RecoveredFile&, uint64_t file_offset, uint8_t* dst,
                             size_t len) override;

    const ExfatBoot& boot() const noexcept { return boot_; }

private:
    ExfatScanner(std::shared_ptr<io::BlockDevice> dev, ExfatBoot boot);

    bool ensure_allocation();
    std::shared_ptr<ExfatAllocationMap> map_;
    uint32_t bitmap_cluster_ = 0;
    uint64_t bitmap_bytes_ = 0;

    std::shared_ptr<io::BlockDevice> dev_;
    ExfatBoot boot_;
    FsGeometry geometry_;
};

}  // namespace openrecover::fs
