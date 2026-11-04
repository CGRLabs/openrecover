#include "openrecover/fs/exfat/exfat_scanner.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/fs/exfat/exfat_boot.hpp"
#include "openrecover/fs/exfat/exfat_dir.hpp"
#include "openrecover/fs/exfat/exfat_fat.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

namespace {

constexpr uint64_t kMaxBitmapBytes = 64ull << 20;
constexpr size_t kMaxChainClusters = size_t{1} << 24;

std::string join_path(const std::string& parent, const std::string& component) {
    if (parent.empty()) return component;
    return parent + "/" + component;
}

std::string build_note(const std::vector<std::string>& parts) {
    std::string note;
    for (const std::string& part : parts) {
        if (!note.empty()) note += "; ";
        note += part;
    }
    return note;
}

bool all_clusters_free(const ExfatAllocationMap& map, uint32_t first, uint64_t count) {
    for (uint64_t i = 0; i < count; ++i) {
        if (map.is_cluster_allocated(static_cast<uint64_t>(first) + i)) return false;
    }
    return true;
}

// A deleted directory whose clusters were reused now contains whatever the new owner
// wrote. exFAT directories have no self-referencing dot entries, so the first entry of
// an intact deleted directory is either an end marker or another deleted entry.
bool deleted_directory_looks_intact(io::BlockDevice& dev, const ExfatBoot& boot,
                                    const ExfatAllocationMap& map, const ExfatFile& entry) {
    if (!boot.valid_cluster(entry.first_cluster)) return false;
    const uint64_t clusters =
        (entry.size + boot.bytes_per_cluster - 1) / boot.bytes_per_cluster;
    if (clusters == 0 ||
        static_cast<uint64_t>(entry.first_cluster) - 2 + clusters > boot.cluster_count)
        return false;
    if (!all_clusters_free(map, entry.first_cluster, clusters)) return false;

    std::array<uint8_t, 32> first_entry{};
    auto got = io::read_fully(dev, boot.cluster_to_byte(entry.first_cluster), first_entry.data(),
                              first_entry.size());
    if (!got || *got != first_entry.size()) return false;
    return first_entry[0] == 0x00 || (first_entry[0] & 0x80) == 0;
}

std::vector<Extent> extents_from_clusters(const ExfatBoot& boot,
                                          const std::vector<uint32_t>& clusters,
                                          uint64_t file_size) {
    std::vector<Extent> extents;
    uint64_t remaining = file_size;
    size_t i = 0;
    while (i < clusters.size() && remaining > 0) {
        const uint32_t run_start = clusters[i];
        size_t run_length = 1;
        while (i + run_length < clusters.size() &&
               clusters[i + run_length] == clusters[i + run_length - 1] + 1)
            ++run_length;
        Extent extent{};
        extent.offset_bytes = boot.cluster_to_byte(run_start);
        extent.length_bytes =
            static_cast<uint64_t>(run_length) * boot.bytes_per_cluster;
        if (extent.length_bytes > remaining) extent.length_bytes = remaining;
        extent.sparse = false;
        extents.push_back(extent);
        remaining -= extent.length_bytes;
        i += run_length;
    }
    return extents;
}

bool extents_within_device(const std::vector<Extent>& extents, uint64_t device_bytes) {
    for (const Extent& extent : extents) {
        if (extent.offset_bytes > device_bytes ||
            extent.length_bytes > device_bytes - extent.offset_bytes)
            return false;
    }
    return true;
}

std::vector<uint32_t> contiguous_clusters(uint32_t first, uint64_t count) {
    std::vector<uint32_t> clusters;
    clusters.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i)
        clusters.push_back(static_cast<uint32_t>(first + i));
    return clusters;
}

}  // namespace

ExfatAllocationMap::ExfatAllocationMap(std::shared_ptr<io::BlockDevice> dev, ExfatBoot boot,
                                       uint32_t bitmap_cluster, uint64_t bitmap_bytes)
    : dev_(std::move(dev)),
      boot_(boot),
      bitmap_cluster_(bitmap_cluster),
      bitmap_bytes_(bitmap_bytes) {}

bool ExfatAllocationMap::load_bitmap() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (loaded_) return bitmap_ok_;
    loaded_ = true;
    if (bitmap_cluster_ < 2 || bitmap_bytes_ == 0 || bitmap_bytes_ > kMaxBitmapBytes ||
        !boot_.valid_cluster(bitmap_cluster_)) {
        bitmap_ok_ = false;
        return false;
    }
    const uint64_t needed = (static_cast<uint64_t>(boot_.cluster_count) + 7) / 8;
    const uint64_t bytes = std::min(bitmap_bytes_, needed);
    if (bytes == 0) {
        bitmap_ok_ = false;
        return false;
    }
    bitmap_.resize(static_cast<size_t>(bytes));
    const uint64_t offset = boot_.cluster_to_byte(bitmap_cluster_);
    uint64_t done = 0;
    while (done < bytes) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(bytes - done, 1u << 20));
        auto got = io::read_fully(*dev_, offset + done, bitmap_.data() + done, chunk);
        if (!got || *got != chunk) {
            bitmap_.clear();
            bitmap_ok_ = false;
            return false;
        }
        done += chunk;
    }
    bitmap_ok_ = true;
    return true;
}

bool ExfatAllocationMap::bitmap_available() const { return load_bitmap(); }

bool ExfatAllocationMap::fat_entry_allocated(uint64_t cluster) const {
    if (boot_.fat_length_sectors == 0 || cluster < 2 ||
        cluster >= static_cast<uint64_t>(boot_.cluster_count) + 2)
        return true;
    std::array<uint8_t, 4> buf{};
    const uint64_t offset = boot_.fat_byte_offset() + cluster * 4;
    auto got = io::read_fully(*dev_, offset, buf.data(), buf.size());
    if (!got || *got != buf.size()) return true;
    const uint32_t value = static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) |
                           (static_cast<uint32_t>(buf[2]) << 16) |
                           (static_cast<uint32_t>(buf[3]) << 24);
    return value != 0;
}

bool ExfatAllocationMap::is_cluster_allocated(uint64_t cluster) const {
    if (cluster < 2 || cluster >= static_cast<uint64_t>(boot_.cluster_count) + 2) return true;
    if (load_bitmap()) {
        const uint64_t index = cluster - 2;
        const uint64_t byte = index / 8;
        if (byte >= bitmap_.size()) return true;
        return (bitmap_[static_cast<size_t>(byte)] & (1u << (index % 8))) != 0;
    }
    return fat_entry_allocated(cluster);
}

uint64_t ExfatAllocationMap::cluster_to_byte_offset(uint64_t cluster) const {
    return boot_.cluster_to_byte(static_cast<uint32_t>(cluster));
}

ExfatScanner::ExfatScanner(std::shared_ptr<io::BlockDevice> dev, ExfatBoot boot)
    : dev_(std::move(dev)), boot_(boot) {
    geometry_.bytes_per_sector = boot.bytes_per_sector;
    geometry_.bytes_per_cluster = boot.bytes_per_cluster;
    geometry_.total_clusters = boot.cluster_count;
}

Result<std::unique_ptr<ExfatScanner>> ExfatScanner::open(std::shared_ptr<io::BlockDevice> dev) {
    if (!dev) return fail(ErrorCode::InvalidArgument, "null device");
    auto boot = read_exfat_boot(*dev);
    if (!boot) return fail(boot.error());
    return std::unique_ptr<ExfatScanner>(new ExfatScanner(std::move(dev), *boot));
}

bool ExfatScanner::ensure_allocation() {
    if (map_) return true;
    auto root = read_exfat_directory(*dev_, boot_, boot_.first_cluster_of_root);
    if (root && root->has_allocation_bitmap) {
        bitmap_cluster_ = root->allocation_bitmap_cluster;
        bitmap_bytes_ = root->allocation_bitmap_bytes;
    } else if (!root) {
        log::warn("cannot read exFAT root directory: " + root.error().message);
    }
    map_ = std::make_shared<ExfatAllocationMap>(dev_, boot_, bitmap_cluster_, bitmap_bytes_);
    return static_cast<bool>(root);
}

Result<std::vector<RecoveredFile>> ExfatScanner::scan_deleted(const ScanOptions& options,
                                                             ProgressFn progress) {
    struct DirectoryTask {
        uint32_t first_cluster;
        uint64_t size;
        bool no_fat_chain;
        std::string path;
        uint32_t depth;
    };

    std::vector<RecoveredFile> out;
    std::deque<DirectoryTask> queue;
    std::unordered_set<uint32_t> visited;
    queue.push_back(DirectoryTask{boot_.first_cluster_of_root, 0, false, "", 0});

    ensure_allocation();
    const uint64_t device_bytes = dev_->info().size_bytes;

    uint64_t done = 0;
    if (progress && !progress(0, 1)) return fail(ErrorCode::Cancelled, "scan cancelled");

    while (!queue.empty()) {
        DirectoryTask task = std::move(queue.front());
        queue.pop_front();
        if (!visited.insert(task.first_cluster).second) {
            ++done;
            continue;
        }

        auto listing =
            read_exfat_directory(*dev_, boot_, task.first_cluster, task.size, task.no_fat_chain);
        if (!listing) {
            log::warn("cannot read exFAT directory cluster " +
                      std::to_string(task.first_cluster) + ": " + listing.error().message);
            ++done;
            continue;
        }
        if (listing->truncated) {
            log::warn("exFAT directory at cluster " + std::to_string(task.first_cluster) +
                      " is truncated");
        }

        for (const ExfatFile& entry : listing->files) {
            const std::string component = sanitize_component(entry.name);
            if (component.empty()) continue;
            const std::string child_path = join_path(task.path, component);

            if (!entry.deleted) {
                if (entry.is_directory() && boot_.valid_cluster(entry.first_cluster)) {
                    if (task.depth + 1 > options.max_directory_depth) {
                        log::warn("directory depth limit reached at " + child_path);
                    } else if (visited.find(entry.first_cluster) == visited.end()) {
                        queue.push_back(DirectoryTask{entry.first_cluster, entry.size,
                                                      entry.no_fat_chain, child_path,
                                                      task.depth + 1});
                    }
                }
                continue;
            }

            if (entry.is_directory()) {
                if (task.depth + 1 > options.max_directory_depth) continue;
                if (!map_ || !deleted_directory_looks_intact(*dev_, boot_, *map_, entry)) continue;
                if (visited.find(entry.first_cluster) == visited.end()) {
                    queue.push_back(DirectoryTask{entry.first_cluster, entry.size,
                                                  entry.no_fat_chain, child_path,
                                                  task.depth + 1});
                }
                continue;
            }

            RecoveredFile file;
            file.path = child_path;
            file.name = component;
            file.size_bytes = entry.size;
            file.origin = FileOrigin::FilesystemMetadata;
            file.mtime_unix = entry.mtime_unix;
            file.ctime_unix = entry.ctime_unix;
            file.atime_unix = entry.atime_unix;

            std::vector<std::string> notes;
            if (file.mtime_unix || file.ctime_unix || file.atime_unix)
                notes.push_back("exfat_local_time_assumed_utc");

            if (entry.size == 0) {
                file.confidence = Confidence::High;
                file.note = build_note(notes);
                out.push_back(std::move(file));
                continue;
            }

            if (!boot_.valid_cluster(entry.first_cluster)) {
                log::warn("skipping deleted file " + child_path +
                          ": first cluster is outside the volume");
                continue;
            }
            if (entry.valid_size > entry.size) {
                notes.push_back("valid_data_length_exceeds_size");
            }

            const uint64_t clusters_needed =
                (entry.size + boot_.bytes_per_cluster - 1) / boot_.bytes_per_cluster;
            if (clusters_needed > kMaxChainClusters) {
                log::warn("skipping deleted file " + child_path + ": file is too large");
                continue;
            }
            if (static_cast<uint64_t>(entry.first_cluster) - 2 + clusters_needed >
                boot_.cluster_count) {
                log::warn("skipping deleted file " + child_path + ": extent beyond volume");
                continue;
            }

            std::vector<uint32_t> clusters;
            bool chain_lost = false;
            bool chain_truncated = false;
            if (entry.no_fat_chain) {
                clusters = contiguous_clusters(entry.first_cluster, clusters_needed);
            } else {
                auto chain = read_exfat_chain(*dev_, boot_, entry.first_cluster);
                if (!chain) {
                    chain_lost = true;
                    clusters = contiguous_clusters(entry.first_cluster, clusters_needed);
                } else {
                    clusters = *chain;
                    if (clusters.size() > clusters_needed) {
                        clusters.resize(static_cast<size_t>(clusters_needed));
                    } else if (clusters.size() < clusters_needed) {
                        chain_truncated = true;
                        notes.push_back("chain_truncated");
                    }
                }
            }
            if (chain_lost) notes.push_back("fat_chain_lost; contiguous_assumption");

            file.extents = extents_from_clusters(boot_, clusters, entry.size);
            if (file.extents.empty()) {
                log::warn("skipping deleted file " + child_path + ": no readable extent");
                continue;
            }
            if (!extents_within_device(file.extents, device_bytes)) {
                log::warn("skipping deleted file " + child_path + ": extent outside the device");
                continue;
            }

            bool reused = false;
            if (map_) {
                for (uint32_t cluster : clusters) {
                    if (map_->is_cluster_allocated(cluster)) {
                        reused = true;
                        break;
                    }
                }
            }
            if (reused) {
                file.confidence = Confidence::Low;
                file.flags |= file_flags::ClustersReallocated;
            } else if (chain_truncated) {
                file.confidence = Confidence::Low;
                file.flags |= file_flags::Truncated;
            } else {
                file.confidence = Confidence::High;
            }
            file.note = build_note(notes);
            out.push_back(std::move(file));
        }

        ++done;
        const uint64_t total = done + static_cast<uint64_t>(queue.size());
        if (progress && !progress(done, total)) return fail(ErrorCode::Cancelled, "scan cancelled");
    }

    if (progress && !progress(done, done)) return fail(ErrorCode::Cancelled, "scan cancelled");
    return out;
}

Result<std::unique_ptr<IAllocationMap>> ExfatScanner::allocation_map() {
    ensure_allocation();
    if (!map_)
        return fail(ErrorCode::CorruptStructure, "exFAT allocation map is unavailable");
    return std::unique_ptr<IAllocationMap>(
        new ExfatAllocationMap(dev_, boot_, bitmap_cluster_, bitmap_bytes_));
}

Result<size_t> ExfatScanner::read_file(const RecoveredFile& file, uint64_t file_offset,
                                       uint8_t* dst, size_t len) {
    if (file_offset >= file.size_bytes) return size_t{0};

    const uint64_t wanted = std::min<uint64_t>(len, file.size_bytes - file_offset);
    uint64_t logical = 0;
    uint64_t done = 0;
    for (const Extent& extent : file.extents) {
        if (done >= wanted) break;
        if (file_offset >= logical + extent.length_bytes) {
            logical += extent.length_bytes;
            continue;
        }
        const uint64_t within = file_offset > logical ? file_offset - logical : 0;
        const uint64_t take = std::min<uint64_t>(extent.length_bytes - within, wanted - done);
        if (extent.sparse) {
            std::memset(dst + done, 0, static_cast<size_t>(take));
        } else {
            auto got = io::read_fully(*dev_, extent.offset_bytes + within, dst + done,
                                      static_cast<size_t>(take));
            if (!got) return fail(got.error());
            if (*got != take) return fail(ErrorCode::IoError, "short exFAT extent read");
        }
        done += take;
        logical += extent.length_bytes;
    }
    return static_cast<size_t>(done);
}

}  // namespace openrecover::fs
