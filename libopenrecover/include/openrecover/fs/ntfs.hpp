#pragma once

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/fs/ntfs_boot.hpp"
#include "openrecover/fs/ntfs_record.hpp"
#include "openrecover/fs/ntfs_runlist.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

// Random access to the $MFT, including a fragmented $MFT (runlist taken from record 0).
class NtfsMftReader {
public:
    static Result<std::unique_ptr<NtfsMftReader>> open(std::shared_ptr<io::BlockDevice> dev,
                                                       const NtfsBoot& boot);

    uint64_t record_count() const noexcept { return record_count_; }
    uint32_t record_size() const noexcept { return record_size_; }
    const std::vector<DataRun>& mft_runs() const noexcept { return runs_; }

    // Missing/unused/torn records are nullopt; I/O failures are errors.
    Result<std::optional<NtfsRecord>> load_record(uint64_t record_number);

private:
    NtfsMftReader(std::shared_ptr<io::BlockDevice> dev, NtfsBoot boot,
                  std::vector<DataRun> runs, uint64_t coverage_bytes, uint64_t record_count);
    Result<size_t> read_logical(uint64_t offset, uint8_t* dst, size_t len);

    std::shared_ptr<io::BlockDevice> dev_;
    NtfsBoot boot_;
    std::vector<DataRun> runs_;
    uint64_t coverage_bytes_ = 0;
    uint64_t record_count_ = 0;
    uint32_t record_size_ = 0;
};

class NtfsAllocationMap final : public IAllocationMap {
public:
    static Result<std::unique_ptr<NtfsAllocationMap>> open(std::shared_ptr<io::BlockDevice> dev,
                                                           const NtfsBoot& boot,
                                                           NtfsMftReader& mft);

    bool is_cluster_allocated(uint64_t cluster) const override;
    uint64_t cluster_to_byte_offset(uint64_t cluster) const override;
    uint64_t cluster_count() const override { return boot_.total_clusters; }

private:
    NtfsAllocationMap(std::shared_ptr<io::BlockDevice> dev, NtfsBoot boot) noexcept;

    Result<uint8_t> bitmap_byte(uint64_t index) const;
    Result<size_t> read_bitmap(uint64_t offset, uint8_t* dst, size_t len) const;

    std::shared_ptr<io::BlockDevice> dev_;
    NtfsBoot boot_;
    std::vector<uint8_t> resident_;
    std::vector<DataRun> runs_;
    uint64_t bitmap_size_ = 0;
    mutable std::vector<uint8_t> window_;
    mutable uint64_t window_start_ = 0;
    mutable size_t window_size_ = 0;
};

struct NtfsResolvedPath {
    std::string path;
    bool uncertain = false;
};

class NtfsPathResolver {
public:
    explicit NtfsPathResolver(NtfsMftReader& mft) : mft_(mft) {}

    Result<NtfsResolvedPath> resolve(uint64_t record_number);

private:
    struct CacheEntry {
        NtfsResolvedPath path;
        std::list<uint64_t>::iterator lru;
    };

    NtfsMftReader& mft_;
    std::unordered_map<uint64_t, CacheEntry> cache_;
    std::list<uint64_t> lru_;
    static constexpr size_t kMaxCacheEntries = 1u << 20;
};

class NtfsScanner final : public IFileSystemScanner {
public:
    static Result<std::unique_ptr<NtfsScanner>> open(std::shared_ptr<io::BlockDevice> dev);

    FsKind kind() const override { return FsKind::Ntfs; }
    const FsGeometry& geometry() const override { return geometry_; }
    Result<std::vector<RecoveredFile>> scan_deleted(const ScanOptions&, ProgressFn) override;
    Result<std::unique_ptr<IAllocationMap>> allocation_map() override;
    Result<size_t> read_file(const RecoveredFile&, uint64_t file_offset, uint8_t* dst,
                             size_t len) override;

    const NtfsBoot& boot() const noexcept { return boot_; }
    NtfsMftReader& mft() noexcept { return *mft_; }

private:
    NtfsScanner(std::shared_ptr<io::BlockDevice> dev, NtfsBoot boot,
                std::unique_ptr<NtfsMftReader> mft);

    Result<std::optional<RecoveredFile>> recover_record(const NtfsRecord& record,
                                                        NtfsPathResolver& resolver,
                                                        const IAllocationMap* allocation);

    std::shared_ptr<io::BlockDevice> dev_;
    NtfsBoot boot_;
    std::unique_ptr<NtfsMftReader> mft_;
    FsGeometry geometry_;
};

}  // namespace openrecover::fs
