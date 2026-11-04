#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "openrecover/common/readonly.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::io {

using ::openrecover::ReadOnlyViolation;

[[noreturn]] void fatal_write_attempt(const char* what, const char* file, int line);

#define OR_FATAL_WRITE(what) ::openrecover::io::fatal_write_attempt(what, __FILE__, __LINE__)

// Decorator applied to every device returned by the factories. It forwards reads only.
class GuardedDevice final : public BlockDevice {
public:
    explicit GuardedDevice(std::shared_ptr<BlockDevice> inner);

    const DeviceInfo& info() const noexcept override { return inner_->info(); }
    Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override;
    std::vector<uint64_t> bad_sectors() const override { return inner_->bad_sectors(); }

    uint64_t read_count() const noexcept { return reads_.load(); }
    static constexpr uint64_t bytes_written() noexcept { return 0; }

    // Re-hashes the full device content and throws ReadOnlyViolation if it differs from `sha256_before`.
    void assert_untouched(const std::string& sha256_before);

private:
    std::shared_ptr<BlockDevice> inner_;
    std::atomic<uint64_t> reads_{0};
};

// SHA-256 over the full logical content of a device (streamed in 1 MiB chunks).
Result<std::string> sha256_of_device(BlockDevice& dev);

}  // namespace openrecover::io
