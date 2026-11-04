#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <set>
#include <vector>

#include "openrecover/io/block_device.hpp"

namespace openrecover::test {

// Test-only device over an immutable in-memory buffer. It cannot be mutated through any interface.
class MemoryDevice final : public io::BlockDevice {
public:
    explicit MemoryDevice(const std::vector<uint8_t>& data, uint32_t sector_size = 512,
                          std::string description = "memory");

    const io::DeviceInfo& info() const noexcept override { return info_; }
    Result<io::ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override;
    std::vector<uint64_t> bad_sectors() const override;

    // Any read whose range covers `offset` fails with IoError.
    void fail_at(uint64_t offset);
    // Sector `n` reads back as zeros and is reported as bad.
    void bad_sector(uint64_t n);

    uint64_t read_count() const noexcept { return reads_.load(); }
    const std::vector<uint8_t>& contents() const noexcept { return data_; }

private:
    const std::vector<uint8_t> data_;
    io::DeviceInfo info_;
    mutable std::mutex mutex_;
    std::set<uint64_t> fail_offsets_;
    std::set<uint64_t> bad_;
    std::set<uint64_t> reported_bad_;
    std::atomic<uint64_t> reads_{0};
};

}  // namespace openrecover::test
