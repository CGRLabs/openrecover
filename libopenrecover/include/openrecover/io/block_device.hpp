#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"

namespace openrecover::io {

struct DeviceInfo {
    std::string description;
    uint64_t size_bytes = 0;
    uint32_t logical_sector_size = 512;
    uint32_t physical_sector_size = 512;
    bool is_image = false;
    bool shared_write_fallback = false;
    // Container format when this device translates an enclosing image, e.g. "vhd fixed" or
    // "vhdx". Empty when the bytes are read directly.
    std::string container;
};

struct ReadResult {
    size_t bytes_read = 0;
    bool had_bad_sectors = false;
};

struct OpenOptions {
    bool allow_shared_write_sharing = false;
    uint64_t cache_bytes = 64ull << 20;
    uint32_t sector_size = 0;  // images only; 0 = 512
};

// Read-only by construction. There is intentionally no mutating member of any kind.
class BlockDevice {
public:
    virtual ~BlockDevice() = default;
    virtual const DeviceInfo& info() const noexcept = 0;
    // Reads exactly `len` bytes at absolute byte `offset` unless EOF is reached.
    // Unaligned offset/len are supported. Thread-safe.
    virtual Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) = 0;
    // Bad sector indices (relative to this device, in logical sectors).
    virtual std::vector<uint64_t> bad_sectors() const = 0;

    BlockDevice(const BlockDevice&) = delete;
    BlockDevice& operator=(const BlockDevice&) = delete;

protected:
    BlockDevice() = default;
};

// Reads up to len bytes, looping until satisfied or EOF.
Result<size_t> read_fully(BlockDevice& dev, uint64_t offset, uint8_t* dst, size_t len);

Result<std::unique_ptr<BlockDevice>> open_physical_drive(uint32_t drive_number, const OpenOptions& opts);
Result<std::unique_ptr<BlockDevice>> open_block_node(const std::string& path, const OpenOptions& opts);
Result<std::unique_ptr<BlockDevice>> open_image(const std::filesystem::path& path, const OpenOptions& opts);

// Opens `source` as a Windows device path (\\.\PhysicalDriveN), a Linux block node, or an image file.
Result<std::unique_ptr<BlockDevice>> open_source(const std::string& source, const OpenOptions& opts);

// Wraps a raw device with the standard decorators (cache, guard).
std::unique_ptr<BlockDevice> wrap_standard(std::shared_ptr<BlockDevice> raw, const OpenOptions& opts);

}  // namespace openrecover::io
