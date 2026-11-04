#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace openrecover::io::win {

// Portable mirror of the Win32 types/constants used by the device layer, so that the device
// logic (and the FakeWin32Api used in tests) compiles on every platform.
using Handle = void*;
inline Handle invalid_handle() noexcept { return reinterpret_cast<Handle>(static_cast<intptr_t>(-1)); }

inline constexpr uint32_t kGenericRead = 0x80000000u;
inline constexpr uint32_t kFileShareRead = 0x00000001u;
inline constexpr uint32_t kFileShareWrite = 0x00000002u;
inline constexpr uint32_t kOpenExisting = 3u;
inline constexpr uint32_t kFileAttributeNormal = 0x00000080u;
inline constexpr uint32_t kFileFlagRandomAccess = 0x10000000u;
inline constexpr uint32_t kFileBegin = 0u;
inline constexpr uint32_t kFileTypeDisk = 0x0001u;

inline constexpr uint32_t kErrorFileNotFound = 2;
inline constexpr uint32_t kErrorPathNotFound = 3;
inline constexpr uint32_t kErrorAccessDenied = 5;
inline constexpr uint32_t kErrorCrc = 23;
inline constexpr uint32_t kErrorSectorNotFound = 27;
inline constexpr uint32_t kErrorReadFault = 30;
inline constexpr uint32_t kErrorSharingViolation = 32;
inline constexpr uint32_t kErrorHandleEof = 38;
inline constexpr uint32_t kErrorIoDevice = 1117;

inline constexpr uint32_t kIoctlDiskGetDriveGeometryEx = 0x000700A0u;
inline constexpr uint32_t kIoctlDiskGetLengthInfo = 0x0007405Cu;
inline constexpr uint32_t kIoctlStorageQueryProperty = 0x002D1400u;
inline constexpr uint32_t kIoctlStorageGetDeviceNumber = 0x002D1080u;

inline constexpr uint32_t kAllowedIoctls[] = {
    kIoctlDiskGetDriveGeometryEx,
    kIoctlDiskGetLengthInfo,
    kIoctlStorageQueryProperty,
    kIoctlStorageGetDeviceNumber,
};

// Every Win32 call made by the I/O layer goes through this interface.
struct IWin32Api {
    virtual ~IWin32Api() = default;
    virtual Handle CreateFileW(const std::wstring& path, uint32_t desired_access, uint32_t share_mode,
                               uint32_t creation_disposition, uint32_t flags_and_attributes) = 0;
    virtual bool ReadFile(Handle h, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read) = 0;
    virtual bool SetFilePointerEx(Handle h, int64_t distance, uint32_t move_method) = 0;
    // Thin wrapper over the Win32 device-control call; only reached via safe_ioctl().
    virtual bool IoControl(Handle h, uint32_t code, const void* in, uint32_t in_size, void* out,
                           uint32_t out_size, uint32_t* bytes_returned) = 0;
    virtual bool CloseHandle(Handle h) = 0;
    virtual uint32_t GetLastError() = 0;
    virtual bool GetFileSizeEx(Handle h, int64_t* size) = 0;
    virtual uint32_t GetFileType(Handle h) = 0;
    virtual std::string FormatErrorMessage(uint32_t code) = 0;
    // Physical disk number backing the volume that contains `path` (query-only access).
    virtual std::optional<uint32_t> DiskNumberForPath(const std::wstring& path) = 0;
    // Unique volume GUID path (\\?\Volume{...}\) for the volume that contains `path`, so two
    // paths can be proven to name the same volume. nullopt when the volume cannot be resolved.
    virtual std::optional<std::wstring> VolumeGuidForPath(const std::wstring& path) = 0;
};

// The real implementation exists only on Windows.
std::shared_ptr<IWin32Api> real_api();

// Throws ReadOnlyViolation if `code` is not in kAllowedIoctls.
bool safe_ioctl(IWin32Api& api, Handle h, uint32_t code, const void* in, uint32_t in_size, void* out,
                uint32_t out_size, uint32_t* bytes_returned);

}  // namespace openrecover::io::win
