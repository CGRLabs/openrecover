#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <set>

#include "openrecover/io/block_device.hpp"

namespace openrecover::io {

// Presents [offset, offset+length) of a parent device as a device starting at 0.
class PartitionView final : public BlockDevice {
public:
    PartitionView(std::shared_ptr<BlockDevice> parent, uint64_t offset, uint64_t length);

    const DeviceInfo& info() const noexcept override { return info_; }
    Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override;
    std::vector<uint64_t> bad_sectors() const override;

    uint64_t parent_offset() const noexcept { return offset_; }

private:
    std::shared_ptr<BlockDevice> parent_;
    uint64_t offset_;
    DeviceInfo info_;
};

}  // namespace openrecover::io
