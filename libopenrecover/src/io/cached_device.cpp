#include "openrecover/io/cached_device.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace openrecover::io {

CachedDevice::CachedDevice(std::shared_ptr<BlockDevice> inner, uint64_t capacity_bytes) : inner_(std::move(inner)) {
    if (!inner_) throw std::invalid_argument("CachedDevice: null inner device");
    uint64_t blocks = capacity_bytes / kBlockSize;
    capacity_blocks_ = static_cast<size_t>(std::max<uint64_t>(1, blocks));
}

Result<std::shared_ptr<CachedDevice::Block>> CachedDevice::get_block(uint64_t index) {
    {
        std::shared_lock lock(mutex_);
        auto it = blocks_.find(index);
        if (it != blocks_.end()) {
            it->second->last_used.store(clock_.fetch_add(1) + 1, std::memory_order_relaxed);
            return it->second;
        }
    }

    const uint64_t size = inner_->info().size_bytes;
    const uint64_t start = index * kBlockSize;
    auto block = std::make_shared<Block>();
    if (start < size) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(kBlockSize, size - start));
        block->data.resize(want);
        size_t got = 0;
        while (got < want) {
            auto r = inner_->read(start + got, block->data.data() + got, want - got);
            if (!r) return fail(r.error());
            if (r->had_bad_sectors) block->had_bad = true;
            if (r->bytes_read == 0) break;
            got += r->bytes_read;
        }
        block->data.resize(got);
        inner_reads_.fetch_add(1, std::memory_order_relaxed);
    }
    block->last_used.store(clock_.fetch_add(1) + 1, std::memory_order_relaxed);

    std::unique_lock lock(mutex_);
    auto it = blocks_.find(index);
    if (it != blocks_.end()) return it->second;
    while (blocks_.size() >= capacity_blocks_) {
        auto victim = blocks_.begin();
        for (auto cur = blocks_.begin(); cur != blocks_.end(); ++cur)
            if (cur->second->last_used.load(std::memory_order_relaxed) <
                victim->second->last_used.load(std::memory_order_relaxed))
                victim = cur;
        blocks_.erase(victim);
    }
    blocks_.emplace(index, block);
    return block;
}

bool CachedDevice::range_has_bad_sector(uint64_t offset, size_t len) const {
    const uint64_t s = inner_->info().logical_sector_size ? inner_->info().logical_sector_size : 512;
    const uint64_t end = offset + len;
    for (uint64_t sec : inner_->bad_sectors()) {
        uint64_t b = sec * s;
        if (b < end && b + s > offset) return true;
    }
    return false;
}

Result<ReadResult> CachedDevice::read(uint64_t offset, uint8_t* dst, size_t len) {
    const uint64_t size = inner_->info().size_bytes;
    if (len == 0 || offset >= size) return ReadResult{0, false};
    if (len > size - offset) len = static_cast<size_t>(size - offset);

    bool prefetch = false;
    {
        std::lock_guard lock(seq_mutex_);
        sequential_run_ = (offset == last_end_) ? sequential_run_ + 1 : 1;
        last_end_ = offset + len;
        prefetch = sequential_run_ >= 3;
    }

    size_t done = 0;
    bool any_bad = false;
    uint64_t last_index = 0;
    while (done < len) {
        const uint64_t pos = offset + done;
        const uint64_t index = pos / kBlockSize;
        last_index = index;
        auto block = get_block(index);
        if (!block) return fail(block.error());
        const size_t in_block = static_cast<size_t>(pos - index * kBlockSize);
        const auto& data = (*block)->data;
        if (in_block >= data.size()) break;
        size_t n = std::min(data.size() - in_block, len - done);
        std::memcpy(dst + done, data.data() + in_block, n);
        if ((*block)->had_bad) any_bad = true;
        done += n;
    }

    if (prefetch && (last_index + 1) * kBlockSize < size) (void)get_block(last_index + 1);

    ReadResult rr{done, false};
    if (any_bad) rr.had_bad_sectors = range_has_bad_sector(offset, done);
    return rr;
}

}  // namespace openrecover::io
