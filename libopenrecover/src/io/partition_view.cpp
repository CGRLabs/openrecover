#include "openrecover/io/partition_view.hpp"

#include <algorithm>
#include <stdexcept>

namespace openrecover::io {

PartitionView::PartitionView(std::shared_ptr<BlockDevice> parent, uint64_t offset, uint64_t length)
    : parent_(std::move(parent)), offset_(offset) {
    if (!parent_) throw std::invalid_argument("PartitionView: null parent");
    const DeviceInfo& pi = parent_->info();
    uint64_t avail = offset_ < pi.size_bytes ? pi.size_bytes - offset_ : 0;
    info_ = pi;
    info_.size_bytes = std::min(length, avail);
    info_.description = pi.description + "@" + std::to_string(offset_);
}

Result<ReadResult> PartitionView::read(uint64_t offset, uint8_t* dst, size_t len) {
    if (len == 0 || offset >= info_.size_bytes) return ReadResult{0, false};
    uint64_t max = info_.size_bytes - offset;
    if (len > max) len = static_cast<size_t>(max);
    return parent_->read(offset_ + offset, dst, len);
}

std::vector<uint64_t> PartitionView::bad_sectors() const {
    std::vector<uint64_t> out;
    const uint64_t s = info_.logical_sector_size ? info_.logical_sector_size : 512;
    for (uint64_t sec : parent_->bad_sectors()) {
        uint64_t byte = sec * s;
        if (byte + s > offset_ && byte < offset_ + info_.size_bytes) {
            uint64_t rel = byte >= offset_ ? byte - offset_ : 0;
            out.push_back(rel / s);
        }
    }
    return out;
}

}  // namespace openrecover::io
