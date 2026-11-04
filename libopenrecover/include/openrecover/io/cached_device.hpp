#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

#include "openrecover/io/block_device.hpp"

namespace openrecover::io {

// LRU cache of 1 MiB aligned blocks with one-block read-ahead on sequential access.
class CachedDevice final : public BlockDevice {
public:
    static constexpr size_t kBlockSize = 1u << 20;

    CachedDevice(std::shared_ptr<BlockDevice> inner, uint64_t capacity_bytes);

    const DeviceInfo& info() const noexcept override { return inner_->info(); }
    Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override;
    std::vector<uint64_t> bad_sectors() const override { return inner_->bad_sectors(); }

    uint64_t inner_reads() const noexcept { return inner_reads_.load(); }

private:
    struct Block {
        std::vector<uint8_t> data;
        bool had_bad = false;
        std::atomic<uint64_t> last_used{0};
    };

    Result<std::shared_ptr<Block>> get_block(uint64_t index);
    bool range_has_bad_sector(uint64_t offset, size_t len) const;

    std::shared_ptr<BlockDevice> inner_;
    size_t capacity_blocks_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<Block>> blocks_;
    std::atomic<uint64_t> clock_{0};
    std::atomic<uint64_t> inner_reads_{0};

    std::mutex seq_mutex_;
    uint64_t last_end_ = UINT64_MAX;
    int sequential_run_ = 0;
};

}  // namespace openrecover::io
