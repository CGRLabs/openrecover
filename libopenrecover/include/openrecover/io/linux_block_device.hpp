#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "openrecover/io/block_device.hpp"

namespace openrecover::io {

#if defined(__linux__)

// Read-only POSIX fd device (block node or regular image file), read via pread.
class LinuxBlockDevice final : public BlockDevice {
public:
    LinuxBlockDevice(int fd, DeviceInfo info);
    ~LinuxBlockDevice() override;

    const DeviceInfo& info() const noexcept override { return info_; }
    Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override;
    std::vector<uint64_t> bad_sectors() const override;

private:
    int fd_;
    DeviceInfo info_;
    mutable std::mutex bad_mutex_;
    std::set<uint64_t> bad_;
};

Result<std::unique_ptr<LinuxBlockDevice>> open_linux_fd_device(const std::string& path, const OpenOptions& opts,
                                                                bool expect_block_node);

#endif

}  // namespace openrecover::io
