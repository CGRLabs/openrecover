#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>

#include "openrecover/io/block_device.hpp"
#include "openrecover/io/win32_api.hpp"

namespace openrecover::io {

bool is_valid_physical_drive_path(std::string_view path);
bool is_valid_volume_path(std::string_view path);

// A read-only Win32 handle device (physical drive, volume, or image file).
class WinPhysicalDevice final : public BlockDevice {
public:
    WinPhysicalDevice(std::shared_ptr<win::IWin32Api> api, win::Handle h, DeviceInfo info);
    ~WinPhysicalDevice() override;

    const DeviceInfo& info() const noexcept override { return info_; }
    Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override;
    std::vector<uint64_t> bad_sectors() const override;

private:
    Result<size_t> read_aligned_chunk(uint64_t aligned_offset, uint8_t* buf, size_t len, bool& had_bad);

    std::shared_ptr<win::IWin32Api> api_;
    win::Handle handle_;
    DeviceInfo info_;
    std::mutex handle_mutex_;
    mutable std::mutex bad_mutex_;
    std::set<uint64_t> bad_;
};

// Opens a Windows device path (\\.\PhysicalDriveN or \\.\X:) through `api`. Returns the raw device.
Result<std::unique_ptr<WinPhysicalDevice>> open_win_device(std::string_view path, const OpenOptions& opts,
                                                           std::shared_ptr<win::IWin32Api> api);

// Opens an image file through `api` (GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING).
Result<std::unique_ptr<WinPhysicalDevice>> open_win_image(const std::wstring& path, std::string description,
                                                          const OpenOptions& opts,
                                                          std::shared_ptr<win::IWin32Api> api);

}  // namespace openrecover::io
