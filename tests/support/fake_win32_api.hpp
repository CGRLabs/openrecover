#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "openrecover/io/win32_api.hpp"

namespace openrecover::test {

// Records every Win32 call and serves reads from an in-memory "disk".
class FakeWin32Api final : public io::win::IWin32Api {
public:
    struct CreateCall {
        std::wstring path;
        uint32_t access;
        uint32_t share;
        uint32_t disposition;
        uint32_t flags;
    };
    struct IoctlCall {
        uint32_t code;
        uint32_t in_size;
        uint32_t out_size;
    };

    std::vector<uint8_t> disk;
    uint32_t sector_size = 512;
    uint32_t physical_sector_size = 4096;
    uint32_t device_number = 1;
    uint32_t file_type = io::win::kFileTypeDisk;
    bool geometry_ok = true;
    bool length_ok = true;
    bool device_number_ok = true;

    // Error codes returned by successive CreateFileW calls; an exhausted queue means success.
    std::deque<uint32_t> open_errors;
    // Sectors whose ReadFile fails with `bad_sector_error`.
    std::set<uint64_t> bad;
    uint32_t bad_sector_error = io::win::kErrorCrc;
    // When set, every ReadFile fails with this error.
    std::optional<uint32_t> read_error;
    std::optional<uint32_t> disk_number_for_path;
    // Volume GUID returned per queried path; a path that is absent means "unresolvable".
    std::map<std::wstring, std::wstring> volume_guid_by_path;

    std::vector<CreateCall> creates;
    std::vector<IoctlCall> ioctls;
    std::vector<std::wstring> disk_number_queries;
    std::vector<std::wstring> volume_guid_queries;
    uint64_t read_calls = 0;
    uint64_t close_calls = 0;

    io::win::Handle CreateFileW(const std::wstring& path, uint32_t access, uint32_t share, uint32_t disposition,
                                uint32_t flags) override;
    bool ReadFile(io::win::Handle h, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read) override;
    bool SetFilePointerEx(io::win::Handle h, int64_t distance, uint32_t move_method) override;
    bool IoControl(io::win::Handle h, uint32_t code, const void* in, uint32_t in_size, void* out,
                   uint32_t out_size, uint32_t* bytes_returned) override;
    bool CloseHandle(io::win::Handle h) override;
    uint32_t GetLastError() override { return last_error_; }
    bool GetFileSizeEx(io::win::Handle h, int64_t* size) override;
    uint32_t GetFileType(io::win::Handle h) override;
    std::string FormatErrorMessage(uint32_t code) override { return "fake error " + std::to_string(code); }
    std::optional<uint32_t> DiskNumberForPath(const std::wstring& path) override;
    std::optional<std::wstring> VolumeGuidForPath(const std::wstring& path) override;

    static io::win::Handle fake_handle() { return reinterpret_cast<io::win::Handle>(static_cast<intptr_t>(0x1234)); }

private:
    std::mutex mutex_;
    uint32_t last_error_ = 0;
    uint64_t pos_ = 0;
};

}  // namespace openrecover::test
