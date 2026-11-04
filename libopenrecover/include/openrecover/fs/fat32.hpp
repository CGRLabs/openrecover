#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

inline constexpr uint32_t kFatFree = 0x00000000;
inline constexpr uint32_t kFatBad = 0x0FFFFFF7;
inline constexpr uint32_t kFatEndOfChain = 0x0FFFFFF8;
inline constexpr uint32_t kFatValueMask = 0x0FFFFFFF;

struct Fat32Bpb {
    uint16_t bytes_per_sector = 0;
    uint8_t sectors_per_cluster = 0;
    uint16_t reserved_sectors = 0;
    uint8_t num_fats = 0;
    uint32_t total_sectors = 0;
    uint32_t fat_size_sectors = 0;
    uint16_t ext_flags = 0;
    uint32_t root_cluster = 0;
    uint16_t fsinfo_sector = 0;
    uint16_t backup_boot_sector = 0;

    uint32_t bytes_per_cluster = 0;
    uint64_t fat_start_byte = 0;
    uint64_t data_start_byte = 0;
    uint64_t cluster_count = 0;
    uint32_t max_valid_cluster = 0;
    uint8_t active_fat = 0;
};

// Validates one FAT32 boot sector against `volume_size` and derives the geometry.
Result<Fat32Bpb> parse_fat32_bpb(std::span<const uint8_t> boot_sector, uint64_t volume_size);

// Reads and validates the primary BPB, falling back to the backup boot sector.
Result<Fat32Bpb> read_fat32_bpb(io::BlockDevice& dev);

// FAT table access with a 64 KiB window cache. Thread-safe.
class FatReader {
public:
    FatReader(std::shared_ptr<io::BlockDevice> dev, Fat32Bpb bpb);

    Result<uint32_t> entry(uint64_t cluster) const;
    // Follows a live chain, stopping at EOC, a free or bad cluster, an out-of-range link,
    // a cycle, or 2^24 clusters.
    Result<std::vector<uint32_t>> chain(uint32_t start) const;

    bool valid_cluster(uint64_t cluster) const { return cluster >= 2 && cluster <= bpb_.max_valid_cluster; }
    uint64_t cluster_to_byte(uint64_t cluster) const;
    const Fat32Bpb& bpb() const noexcept { return bpb_; }
    uint64_t fat_bytes() const noexcept { return fat_bytes_; }

private:
    std::shared_ptr<io::BlockDevice> dev_;
    Fat32Bpb bpb_;
    uint64_t fat_bytes_ = 0;
    mutable std::mutex mutex_;
    mutable std::vector<uint8_t> window_;
    mutable uint64_t window_offset_ = 0;
    mutable size_t window_size_ = 0;
    mutable bool window_valid_ = false;
};

class FatAllocationMap final : public IAllocationMap {
public:
    explicit FatAllocationMap(std::shared_ptr<FatReader> fat) : fat_(std::move(fat)) {}
    bool is_cluster_allocated(uint64_t cluster) const override;
    uint64_t cluster_to_byte_offset(uint64_t cluster) const override;
    uint64_t cluster_count() const override { return fat_->bpb().cluster_count; }

private:
    std::shared_ptr<FatReader> fat_;
};

struct FatShortEntry {
    std::array<uint8_t, 11> name{};
    uint8_t attr = 0;
    uint8_t nt_res = 0;
    uint8_t crt_time_tenth = 0;
    uint16_t crt_time = 0;
    uint16_t crt_date = 0;
    uint16_t lst_acc_date = 0;
    uint16_t wrt_time = 0;
    uint16_t wrt_date = 0;
    uint32_t first_cluster = 0;
    uint32_t file_size = 0;
    bool deleted = false;
    bool end_of_directory = false;

    bool is_directory() const { return (attr & 0x10) != 0; }
    bool is_volume_label() const { return (attr & 0x08) != 0; }
    bool is_lfn() const { return attr == 0x0F; }
};

FatShortEntry decode_short_entry(std::span<const uint8_t> raw);
// Decodes the 8.3 name (CP437, NTRes lowercase bits). If `first_char_lost`, the first
// character is replaced with '_' (the entry was deleted and carried no long name).
std::string decode_short_name(const FatShortEntry& e, bool first_char_lost = false);
uint8_t short_name_checksum(const std::array<uint8_t, 11>& name);

struct FatLfnEntry {
    uint8_t ord = 0;
    uint8_t checksum = 0;
    std::array<uint16_t, 13> name{};
    bool deleted = false;
};

FatLfnEntry decode_lfn_entry(std::span<const uint8_t> raw);
// `stack` is in physical order (last name part first). The short name's checksum must match
// every LFN entry; for a deleted short entry the lost first byte is brute-forced.
std::optional<std::string> assemble_lfn(std::span<const FatLfnEntry> stack,
                                        const std::array<uint8_t, 11>& short_name, bool short_name_deleted);

// FAT timestamp to Unix seconds, interpreted as UTC. Omitted (nullopt) if any field is invalid.
std::optional<int64_t> fat_datetime_to_unix(uint16_t date, uint16_t time);

class Fat32Scanner final : public IFileSystemScanner {
public:
    static Result<std::unique_ptr<Fat32Scanner>> open(std::shared_ptr<io::BlockDevice> dev);

    FsKind kind() const override { return FsKind::Fat32; }
    const FsGeometry& geometry() const override { return geometry_; }
    Result<std::vector<RecoveredFile>> scan_deleted(const ScanOptions&, ProgressFn) override;
    Result<std::unique_ptr<IAllocationMap>> allocation_map() override;
    Result<size_t> read_file(const RecoveredFile&, uint64_t file_offset, uint8_t* dst, size_t len) override;

    const Fat32Bpb& bpb() const noexcept { return bpb_; }

private:
    Fat32Scanner(std::shared_ptr<io::BlockDevice> dev, Fat32Bpb bpb);

    std::shared_ptr<io::BlockDevice> dev_;
    Fat32Bpb bpb_;
    FsGeometry geometry_;
    std::shared_ptr<FatReader> fat_;
};

}  // namespace openrecover::fs
