// The ONLY translation unit that calls real Win32 I/O functions for the device layer.
#include "openrecover/io/win32_api.hpp"

#include <windows.h>
#include <winioctl.h>

#include <string>
#include <vector>

namespace openrecover::io::win {

namespace {

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

class RealWin32Api final : public IWin32Api {
public:
    Handle CreateFileW(const std::wstring& path, uint32_t desired_access, uint32_t share_mode,
                       uint32_t creation_disposition, uint32_t flags_and_attributes) override {
        HANDLE h = ::CreateFileW(path.c_str(), desired_access, share_mode, nullptr, creation_disposition,
                                 flags_and_attributes, nullptr);
        return h == INVALID_HANDLE_VALUE ? invalid_handle() : static_cast<Handle>(h);
    }

    bool ReadFile(Handle h, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read) override {
        DWORD got = 0;
        BOOL ok = ::ReadFile(static_cast<HANDLE>(h), buffer, bytes_to_read, &got, nullptr);
        if (bytes_read) *bytes_read = got;
        return ok != FALSE;
    }

    bool SetFilePointerEx(Handle h, int64_t distance, uint32_t move_method) override {
        LARGE_INTEGER li;
        li.QuadPart = distance;
        return ::SetFilePointerEx(static_cast<HANDLE>(h), li, nullptr, move_method) != FALSE;
    }

    bool IoControl(Handle h, uint32_t code, const void* in, uint32_t in_size, void* out, uint32_t out_size,
                   uint32_t* bytes_returned) override {
        DWORD ret = 0;
        BOOL ok = ::DeviceIoControl(static_cast<HANDLE>(h), code, const_cast<void*>(in), in_size, out, out_size, &ret,
                                    nullptr);
        if (bytes_returned) *bytes_returned = ret;
        return ok != FALSE;
    }

    bool CloseHandle(Handle h) override { return ::CloseHandle(static_cast<HANDLE>(h)) != FALSE; }

    uint32_t GetLastError() override { return ::GetLastError(); }

    bool GetFileSizeEx(Handle h, int64_t* size) override {
        LARGE_INTEGER li{};
        if (!::GetFileSizeEx(static_cast<HANDLE>(h), &li)) return false;
        *size = li.QuadPart;
        return true;
    }

    uint32_t GetFileType(Handle h) override { return ::GetFileType(static_cast<HANDLE>(h)); }

    std::string FormatErrorMessage(uint32_t code) override {
        wchar_t* buf = nullptr;
        DWORD n = ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                       FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, code, 0, reinterpret_cast<wchar_t*>(&buf), 0, nullptr);
        std::wstring w = (n && buf) ? std::wstring(buf, n) : std::wstring();
        if (buf) ::LocalFree(buf);
        while (!w.empty() && (w.back() == L'\r' || w.back() == L'\n' || w.back() == L' ')) w.pop_back();
        return narrow(w);
    }

    std::optional<std::wstring> VolumeGuidForPath(const std::wstring& path) override {
        std::vector<wchar_t> mount(32768);
        if (!::GetVolumePathNameW(path.c_str(), mount.data(), static_cast<DWORD>(mount.size()))) return std::nullopt;
        std::vector<wchar_t> volume(64);
        if (!::GetVolumeNameForVolumeMountPointW(mount.data(), volume.data(), static_cast<DWORD>(volume.size())))
            return std::nullopt;
        return std::wstring(volume.data());
    }

    std::optional<uint32_t> DiskNumberForPath(const std::wstring& path) override {
        std::vector<wchar_t> mount(32768);
        if (!::GetVolumePathNameW(path.c_str(), mount.data(), static_cast<DWORD>(mount.size()))) return std::nullopt;
        std::vector<wchar_t> volume(64);
        if (!::GetVolumeNameForVolumeMountPointW(mount.data(), volume.data(), static_cast<DWORD>(volume.size())))
            return std::nullopt;
        std::wstring vol(volume.data());
        if (!vol.empty() && vol.back() == L'\\') vol.pop_back();
        // Query-only handle: zero access rights.
        HANDLE h = ::CreateFileW(vol.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                 nullptr);
        if (h == INVALID_HANDLE_VALUE) return std::nullopt;
        STORAGE_DEVICE_NUMBER sdn{};
        DWORD ret = 0;
        BOOL ok = ::DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &sdn, sizeof sdn, &ret, nullptr);
        ::CloseHandle(h);
        if (!ok) return std::nullopt;
        return static_cast<uint32_t>(sdn.DeviceNumber);
    }
};

}  // namespace

std::shared_ptr<IWin32Api> real_api() {
    static std::shared_ptr<IWin32Api> api = std::make_shared<RealWin32Api>();
    return api;
}

}  // namespace openrecover::io::win
