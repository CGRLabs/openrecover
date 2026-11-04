#include "openrecover/io/win_physical_device.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <new>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/io/readonly_guard.hpp"

namespace openrecover::io {

namespace win {

bool safe_ioctl(IWin32Api& api, Handle h, uint32_t code, const void* in, uint32_t in_size, void* out,
                uint32_t out_size, uint32_t* bytes_returned) {
    bool allowed = false;
    for (uint32_t c : kAllowedIoctls)
        if (c == code) allowed = true;
    if (!allowed) {
        char buf[64];
        std::snprintf(buf, sizeof buf, "device control code 0x%08X is not allowlisted", code);
        OR_FATAL_WRITE(buf);
    }
    return api.IoControl(h, code, in, in_size, out, out_size, bytes_returned);
}

}  // namespace win

namespace {

constexpr size_t kChunk = 1u << 20;
constexpr std::align_val_t kAlign{4096};

struct AlignedBuffer {
    explicit AlignedBuffer(size_t n) : p(static_cast<uint8_t*>(::operator new(n, kAlign))), size(n) {}
    ~AlignedBuffer() { ::operator delete(p, kAlign); }
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;
    uint8_t* p;
    size_t size;
};

bool is_bad_sector_error(uint32_t e) {
    return e == win::kErrorCrc || e == win::kErrorSectorNotFound || e == win::kErrorIoDevice ||
           e == win::kErrorReadFault;
}

std::wstring widen_ascii(std::string_view s) {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    return w;
}

Error map_open_error(win::IWin32Api& api, uint32_t err, const std::string& what) {
    switch (err) {
        case win::kErrorAccessDenied:
            return make_error(ErrorCode::PermissionDenied, what + ": access denied (Run as Administrator)");
        case win::kErrorFileNotFound:
        case win::kErrorPathNotFound:
            return make_error(ErrorCode::NotFound, what + ": not found");
        case win::kErrorSharingViolation:
            return make_error(ErrorCode::DeviceBusy,
                              what + ": another process holds this disk open for writing. Take the disk offline "
                                     "(Disk Management -> Offline) or attach it through a hardware write-blocker. "
                                     "As a last resort pass --allow-shared-write-sharing.");
        default:
            return make_error(ErrorCode::IoError,
                              what + ": Win32 error " + std::to_string(err) + ": " + api.FormatErrorMessage(err));
    }
}

// Opens with EXACTLY GENERIC_READ. The share-mode fallback only lets *others* write.
Result<win::Handle> open_readonly_handle(win::IWin32Api& api, const std::wstring& path, const std::string& what,
                                         const OpenOptions& opts, bool& shared_write_fallback) {
    constexpr uint32_t access = win::kGenericRead;
    static_assert(access == 0x80000000u, "device handles must be opened with GENERIC_READ only");
    constexpr uint32_t flags = win::kFileAttributeNormal | win::kFileFlagRandomAccess;
    shared_write_fallback = false;

    win::Handle h = api.CreateFileW(path, access, win::kFileShareRead, win::kOpenExisting, flags);
    if (h != win::invalid_handle()) return h;
    uint32_t err = api.GetLastError();
    if (err == win::kErrorSharingViolation && opts.allow_shared_write_sharing) {
        log::warn(what + ": sharing violation; retrying with FILE_SHARE_READ|FILE_SHARE_WRITE "
                         "(--allow-shared-write-sharing). Access remains GENERIC_READ.");
        h = api.CreateFileW(path, access, win::kFileShareRead | win::kFileShareWrite, win::kOpenExisting, flags);
        if (h != win::invalid_handle()) {
            shared_write_fallback = true;
            return h;
        }
        err = api.GetLastError();
    }
    return fail(map_open_error(api, err, what));
}

bool valid_sector_size(uint64_t s) { return s >= 512 && s <= 65536 && (s & (s - 1)) == 0; }

}  // namespace

bool is_valid_physical_drive_path(std::string_view path) {
    constexpr std::string_view prefix = "\\\\.\\PhysicalDrive";
    if (path.size() <= prefix.size() || path.substr(0, prefix.size()) != prefix) return false;
    std::string_view digits = path.substr(prefix.size());
    if (digits.empty() || digits.size() > 3) return false;
    return std::all_of(digits.begin(), digits.end(), [](char c) { return c >= '0' && c <= '9'; });
}

bool is_valid_volume_path(std::string_view path) {
    if (path.size() != 6 || path.substr(0, 4) != "\\\\.\\" || path[5] != ':') return false;
    char c = path[4];
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

WinPhysicalDevice::WinPhysicalDevice(std::shared_ptr<win::IWin32Api> api, win::Handle h, DeviceInfo info)
    : api_(std::move(api)), handle_(h), info_(std::move(info)) {}

WinPhysicalDevice::~WinPhysicalDevice() {
    if (handle_ != win::invalid_handle()) api_->CloseHandle(handle_);
}

std::vector<uint64_t> WinPhysicalDevice::bad_sectors() const {
    std::lock_guard lock(bad_mutex_);
    return {bad_.begin(), bad_.end()};
}

Result<size_t> WinPhysicalDevice::read_aligned_chunk(uint64_t aligned_offset, uint8_t* buf, size_t len,
                                                     bool& had_bad) {
    const uint32_t s = info_.logical_sector_size;
    std::lock_guard lock(handle_mutex_);
    if (!api_->SetFilePointerEx(handle_, static_cast<int64_t>(aligned_offset), win::kFileBegin)) {
        uint32_t e = api_->GetLastError();
        return fail(ErrorCode::IoError, "seek failed: Win32 error " + std::to_string(e), aligned_offset);
    }
    uint32_t got = 0;
    if (api_->ReadFile(handle_, buf, static_cast<uint32_t>(len), &got)) return static_cast<size_t>(got);

    uint32_t err = api_->GetLastError();
    if (err == win::kErrorHandleEof) return size_t{0};
    if (!is_bad_sector_error(err))
        return fail(ErrorCode::IoError,
                    "read failed: Win32 error " + std::to_string(err) + ": " + api_->FormatErrorMessage(err),
                    aligned_offset);

    size_t total = 0;
    for (size_t off = 0; off < len; off += s) {
        const uint64_t sector_pos = aligned_offset + off;
        if (!api_->SetFilePointerEx(handle_, static_cast<int64_t>(sector_pos), win::kFileBegin))
            return fail(ErrorCode::IoError, "seek failed during sector retry", sector_pos);
        uint32_t g = 0;
        if (api_->ReadFile(handle_, buf + off, s, &g)) {
            total = off + g;
            if (g < s) break;
            continue;
        }
        uint32_t e2 = api_->GetLastError();
        if (e2 == win::kErrorHandleEof) break;
        if (!is_bad_sector_error(e2))
            return fail(ErrorCode::IoError, "read failed during sector retry: Win32 error " + std::to_string(e2),
                        sector_pos);
        std::memset(buf + off, 0, s);
        {
            std::lock_guard bl(bad_mutex_);
            bad_.insert(sector_pos / s);
        }
        had_bad = true;
        total = off + s;
        log::warn("unreadable sector " + std::to_string(sector_pos / s) + " zero-filled");
    }
    return total;
}

Result<ReadResult> WinPhysicalDevice::read(uint64_t offset, uint8_t* dst, size_t len) {
    if (len == 0 || offset >= info_.size_bytes) return ReadResult{0, false};
    if (len > info_.size_bytes - offset) len = static_cast<size_t>(info_.size_bytes - offset);

    const uint64_t s = info_.logical_sector_size;
    const uint64_t end = offset + len;
    const uint64_t a_start = align_down(offset, s);
    uint64_t a_end = 0;
    if (!align_up(end, s, a_end)) return fail(ErrorCode::InvalidArgument, "read range overflow", offset);

    AlignedBuffer buf(static_cast<size_t>(std::min<uint64_t>(kChunk, a_end - a_start)));
    ReadResult rr{0, false};
    uint64_t pos = a_start;
    while (pos < a_end) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(buf.size, a_end - pos));
        bool bad = false;
        auto got = read_aligned_chunk(pos, buf.p, chunk, bad);
        if (!got) return fail(got.error());
        if (bad) rr.had_bad_sectors = true;
        const uint64_t chunk_end = pos + *got;
        const uint64_t copy_start = std::max(pos, offset);
        const uint64_t copy_end = std::min(chunk_end, end);
        if (copy_end > copy_start) {
            std::memcpy(dst + (copy_start - offset), buf.p + (copy_start - pos),
                        static_cast<size_t>(copy_end - copy_start));
            rr.bytes_read = static_cast<size_t>(copy_end - offset);
        }
        if (*got < chunk) break;
        pos += chunk;
    }
    return rr;
}

Result<std::unique_ptr<WinPhysicalDevice>> open_win_device(std::string_view path, const OpenOptions& opts,
                                                           std::shared_ptr<win::IWin32Api> api) {
    const bool is_drive = is_valid_physical_drive_path(path);
    if (!is_drive && !is_valid_volume_path(path))
        return fail(ErrorCode::InvalidArgument, "invalid Windows device path: " + std::string(path));
    if (!api) return fail(ErrorCode::Unsupported, "Win32 API unavailable on this platform");

    const std::string what(path);
    bool fallback = false;
    auto h = open_readonly_handle(*api, widen_ascii(path), what, opts, fallback);
    if (!h) return fail(h.error());

    auto close_and_fail = [&](ErrorCode code, std::string msg) -> Result<std::unique_ptr<WinPhysicalDevice>> {
        api->CloseHandle(*h);
        return fail(code, std::move(msg));
    };

    if (api->GetFileType(*h) != win::kFileTypeDisk)
        return close_and_fail(ErrorCode::Unsupported, what + ": not a disk device");

    DeviceInfo info;
    info.description = what;
    info.is_image = false;
    info.shared_write_fallback = fallback;

    uint64_t geometry_size = 0;
    uint32_t logical = 0;
    {
        uint8_t out[256] = {};
        uint32_t ret = 0;
        if (win::safe_ioctl(*api, *h, win::kIoctlDiskGetDriveGeometryEx, nullptr, 0, out, sizeof out, &ret) &&
            ret >= 32) {
            ByteView v(out, ret);
            logical = v.u32le(20);
            geometry_size = v.u64le(24);
        }
    }
    uint64_t length = 0;
    {
        uint8_t out[8] = {};
        uint32_t ret = 0;
        if (win::safe_ioctl(*api, *h, win::kIoctlDiskGetLengthInfo, nullptr, 0, out, sizeof out, &ret) && ret >= 8)
            length = ByteView(out, 8).u64le(0);
    }
    if (length == 0) length = geometry_size;
    if (length == 0) return close_and_fail(ErrorCode::IoError, what + ": cannot determine device length");
    info.size_bytes = length;

    if (!valid_sector_size(logical)) {
        if (logical != 0) log::warn(what + ": implausible logical sector size " + std::to_string(logical));
        logical = 512;
    }
    info.logical_sector_size = logical;
    info.physical_sector_size = logical;
    {
        uint8_t in[12] = {6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // StorageAccessAlignmentProperty, standard query
        uint8_t out[28] = {};
        uint32_t ret = 0;
        if (win::safe_ioctl(*api, *h, win::kIoctlStorageQueryProperty, in, sizeof in, out, sizeof out, &ret) &&
            ret >= 24) {
            uint32_t phys = ByteView(out, ret).u32le(20);
            if (valid_sector_size(phys) && phys >= logical) info.physical_sector_size = phys;
        }
    }
    if (is_drive) {
        uint8_t out[12] = {};
        uint32_t ret = 0;
        if (win::safe_ioctl(*api, *h, win::kIoctlStorageGetDeviceNumber, nullptr, 0, out, sizeof out, &ret) &&
            ret >= 8) {
            uint32_t number = ByteView(out, ret).u32le(4);
            uint32_t expected = static_cast<uint32_t>(std::stoul(std::string(path.substr(17))));
            if (number != expected)
                return close_and_fail(ErrorCode::IoError, what + ": device number mismatch (got " +
                                                              std::to_string(number) + ")");
        } else {
            log::debug(what + ": IOCTL_STORAGE_GET_DEVICE_NUMBER unavailable");
        }
    }
    return std::make_unique<WinPhysicalDevice>(std::move(api), *h, std::move(info));
}

Result<std::unique_ptr<WinPhysicalDevice>> open_win_image(const std::wstring& path, std::string description,
                                                          const OpenOptions& opts,
                                                          std::shared_ptr<win::IWin32Api> api) {
    if (!api) return fail(ErrorCode::Unsupported, "Win32 API unavailable on this platform");
    bool fallback = false;
    auto h = open_readonly_handle(*api, path, description, opts, fallback);
    if (!h) return fail(h.error());
    if (api->GetFileType(*h) != win::kFileTypeDisk) {
        api->CloseHandle(*h);
        return fail(ErrorCode::Unsupported, description + ": not a regular file");
    }
    int64_t size = 0;
    if (!api->GetFileSizeEx(*h, &size) || size < 0) {
        uint32_t e = api->GetLastError();
        api->CloseHandle(*h);
        return fail(ErrorCode::IoError, description + ": cannot get file size (Win32 error " + std::to_string(e) + ")");
    }
    const uint32_t sector = opts.sector_size ? opts.sector_size : 512;
    if (!valid_sector_size(sector)) {
        api->CloseHandle(*h);
        return fail(ErrorCode::InvalidArgument, "sector size must be a power of two in [512, 65536]");
    }
    DeviceInfo info;
    info.description = std::move(description);
    info.size_bytes = static_cast<uint64_t>(size);
    info.logical_sector_size = sector;
    info.physical_sector_size = sector;
    info.is_image = true;
    info.shared_write_fallback = fallback;
    return std::make_unique<WinPhysicalDevice>(std::move(api), *h, std::move(info));
}

}  // namespace openrecover::io
