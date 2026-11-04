#include "fake_win32_api.hpp"

#include <algorithm>
#include <cstring>

namespace openrecover::test {

namespace {
void put_u32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
void put_u64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
}  // namespace

io::win::Handle FakeWin32Api::CreateFileW(const std::wstring& path, uint32_t access, uint32_t share,
                                          uint32_t disposition, uint32_t flags) {
    std::lock_guard lock(mutex_);
    creates.push_back({path, access, share, disposition, flags});
    if (!open_errors.empty()) {
        last_error_ = open_errors.front();
        open_errors.pop_front();
        return io::win::invalid_handle();
    }
    last_error_ = 0;
    pos_ = 0;
    return fake_handle();
}

bool FakeWin32Api::SetFilePointerEx(io::win::Handle, int64_t distance, uint32_t move_method) {
    std::lock_guard lock(mutex_);
    if (move_method != io::win::kFileBegin || distance < 0) {
        last_error_ = 87;
        return false;
    }
    pos_ = static_cast<uint64_t>(distance);
    return true;
}

bool FakeWin32Api::ReadFile(io::win::Handle, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read) {
    std::lock_guard lock(mutex_);
    ++read_calls;
    *bytes_read = 0;
    if (read_error) {
        last_error_ = *read_error;
        return false;
    }
    const uint64_t end = pos_ + bytes_to_read;
    for (uint64_t sec = pos_ / sector_size; sec * sector_size < end; ++sec) {
        if (bad.count(sec)) {
            last_error_ = bad_sector_error;
            return false;
        }
    }
    uint64_t n = pos_ >= disk.size() ? 0 : std::min<uint64_t>(bytes_to_read, disk.size() - pos_);
    if (n) std::memcpy(buffer, disk.data() + pos_, static_cast<size_t>(n));
    pos_ += n;
    *bytes_read = static_cast<uint32_t>(n);
    last_error_ = 0;
    return true;
}

bool FakeWin32Api::IoControl(io::win::Handle, uint32_t code, const void*, uint32_t in_size, void* out,
                             uint32_t out_size, uint32_t* bytes_returned) {
    std::lock_guard lock(mutex_);
    ioctls.push_back({code, in_size, out_size});
    auto* o = static_cast<uint8_t*>(out);
    *bytes_returned = 0;
    switch (code) {
        case io::win::kIoctlDiskGetDriveGeometryEx:
            if (!geometry_ok || out_size < 32) break;
            std::memset(o, 0, out_size);
            put_u32(o + 20, sector_size);
            put_u64(o + 24, disk.size());
            *bytes_returned = 32;
            return true;
        case io::win::kIoctlDiskGetLengthInfo:
            if (!length_ok || out_size < 8) break;
            put_u64(o, disk.size());
            *bytes_returned = 8;
            return true;
        case io::win::kIoctlStorageQueryProperty:
            if (out_size < 28) break;
            std::memset(o, 0, out_size);
            put_u32(o + 0, 28);
            put_u32(o + 4, 28);
            put_u32(o + 16, sector_size);
            put_u32(o + 20, physical_sector_size);
            *bytes_returned = 28;
            return true;
        case io::win::kIoctlStorageGetDeviceNumber:
            if (!device_number_ok || out_size < 12) break;
            std::memset(o, 0, out_size);
            put_u32(o + 0, 7);
            put_u32(o + 4, device_number);
            put_u32(o + 8, 0xFFFFFFFFu);
            *bytes_returned = 12;
            return true;
        default: break;
    }
    last_error_ = 1;
    return false;
}

bool FakeWin32Api::CloseHandle(io::win::Handle) {
    std::lock_guard lock(mutex_);
    ++close_calls;
    return true;
}

bool FakeWin32Api::GetFileSizeEx(io::win::Handle, int64_t* size) {
    *size = static_cast<int64_t>(disk.size());
    return true;
}

uint32_t FakeWin32Api::GetFileType(io::win::Handle) { return file_type; }

std::optional<uint32_t> FakeWin32Api::DiskNumberForPath(const std::wstring& path) {
    std::lock_guard lock(mutex_);
    disk_number_queries.push_back(path);
    return disk_number_for_path;
}

std::optional<std::wstring> FakeWin32Api::VolumeGuidForPath(const std::wstring& path) {
    std::lock_guard lock(mutex_);
    volume_guid_queries.push_back(path);
    const auto it = volume_guid_by_path.find(path);
    if (it == volume_guid_by_path.end()) return std::nullopt;
    return it->second;
}

}  // namespace openrecover::test
