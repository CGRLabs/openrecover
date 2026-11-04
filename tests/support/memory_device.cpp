#include "memory_device.hpp"

#include <algorithm>
#include <cstring>

namespace openrecover::test {

MemoryDevice::MemoryDevice(const std::vector<uint8_t>& data, uint32_t sector_size, std::string description)
    : data_(data) {
    info_.description = std::move(description);
    info_.size_bytes = data_.size();
    info_.logical_sector_size = sector_size;
    info_.physical_sector_size = sector_size;
    info_.is_image = true;
}

void MemoryDevice::fail_at(uint64_t offset) {
    std::lock_guard lock(mutex_);
    fail_offsets_.insert(offset);
}

void MemoryDevice::bad_sector(uint64_t n) {
    std::lock_guard lock(mutex_);
    bad_.insert(n);
}

std::vector<uint64_t> MemoryDevice::bad_sectors() const {
    std::lock_guard lock(mutex_);
    return {reported_bad_.begin(), reported_bad_.end()};
}

Result<io::ReadResult> MemoryDevice::read(uint64_t offset, uint8_t* dst, size_t len) {
    reads_.fetch_add(1);
    if (len == 0 || offset >= data_.size()) return io::ReadResult{0, false};
    len = static_cast<size_t>(std::min<uint64_t>(len, data_.size() - offset));
    const uint64_t end = offset + len;

    std::lock_guard lock(mutex_);
    auto f = fail_offsets_.lower_bound(offset);
    if (f != fail_offsets_.end() && *f < end) return fail(ErrorCode::IoError, "injected read failure", *f);

    std::memcpy(dst, data_.data() + offset, len);
    io::ReadResult rr{len, false};
    const uint64_t s = info_.logical_sector_size;
    for (uint64_t sec = offset / s; sec * s < end; ++sec) {
        if (!bad_.count(sec)) continue;
        const uint64_t a = std::max(sec * s, offset), b = std::min((sec + 1) * s, end);
        std::memset(dst + (a - offset), 0, static_cast<size_t>(b - a));
        reported_bad_.insert(sec);
        rr.had_bad_sectors = true;
    }
    return rr;
}

}  // namespace openrecover::test
