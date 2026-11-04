// POSIX block-node / image device. The only place (besides tests) allowed to call ioctl().
#include "openrecover/io/linux_block_device.hpp"

#if defined(__linux__)

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "openrecover/common/log.hpp"
#include "openrecover/io/readonly_guard.hpp"

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

namespace openrecover::io {

namespace {

constexpr unsigned long kAllowedLinuxIoctls[] = {BLKGETSIZE64, BLKSSZGET, BLKPBSZGET};

int safe_ioctl(int fd, unsigned long request, void* arg) {
    bool allowed = false;
    for (unsigned long r : kAllowedLinuxIoctls)
        if (r == request) allowed = true;
    if (!allowed) OR_FATAL_WRITE("ioctl request not allowlisted");
    return ::ioctl(fd, request, arg);
}

Error map_errno(int e, const std::string& what) {
    switch (e) {
        case EACCES:
        case EPERM: return make_error(ErrorCode::PermissionDenied, what + ": permission denied (try sudo)");
        case ENOENT: return make_error(ErrorCode::NotFound, what + ": not found");
        case EBUSY: return make_error(ErrorCode::DeviceBusy, what + ": device busy");
        default: return make_error(ErrorCode::IoError, what + ": " + std::strerror(e));
    }
}

bool valid_sector_size(uint64_t s) { return s >= 512 && s <= 65536 && (s & (s - 1)) == 0; }

}  // namespace

LinuxBlockDevice::LinuxBlockDevice(int fd, DeviceInfo info) : fd_(fd), info_(std::move(info)) {}

LinuxBlockDevice::~LinuxBlockDevice() {
    if (fd_ >= 0) ::close(fd_);
}

std::vector<uint64_t> LinuxBlockDevice::bad_sectors() const {
    std::lock_guard lock(bad_mutex_);
    return {bad_.begin(), bad_.end()};
}

Result<ReadResult> LinuxBlockDevice::read(uint64_t offset, uint8_t* dst, size_t len) {
    if (len == 0 || offset >= info_.size_bytes) return ReadResult{0, false};
    if (len > info_.size_bytes - offset) len = static_cast<size_t>(info_.size_bytes - offset);

    ReadResult rr{0, false};
    while (rr.bytes_read < len) {
        const uint64_t pos = offset + rr.bytes_read;
        ssize_t n = ::pread(fd_, dst + rr.bytes_read, len - rr.bytes_read, static_cast<off_t>(pos));
        if (n > 0) {
            rr.bytes_read += static_cast<size_t>(n);
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        if (errno != EIO) return fail(ErrorCode::IoError, std::string("pread: ") + std::strerror(errno), pos);

        // Sector-by-sector retry over the remainder of the request.
        const uint64_t s = info_.logical_sector_size;
        uint64_t cur = pos;
        const uint64_t end = offset + len;
        while (cur < end) {
            const uint64_t sector = cur / s;
            const uint64_t sector_end = std::min<uint64_t>((sector + 1) * s, end);
            const size_t want = static_cast<size_t>(sector_end - cur);
            uint8_t* out = dst + (cur - offset);
            ssize_t m;
            do {
                m = ::pread(fd_, out, want, static_cast<off_t>(cur));
            } while (m < 0 && errno == EINTR);
            if (m < 0 && errno != EIO)
                return fail(ErrorCode::IoError, std::string("pread retry: ") + std::strerror(errno), cur);
            if (m < 0) {
                std::memset(out, 0, want);
                {
                    std::lock_guard bl(bad_mutex_);
                    bad_.insert(sector);
                }
                rr.had_bad_sectors = true;
                log::warn("unreadable sector " + std::to_string(sector) + " zero-filled");
                cur = sector_end;
            } else if (m == 0) {
                rr.bytes_read = static_cast<size_t>(cur - offset);
                return rr;
            } else {
                cur += static_cast<uint64_t>(m);
            }
        }
        rr.bytes_read = len;
    }
    return rr;
}

Result<std::unique_ptr<LinuxBlockDevice>> open_linux_fd_device(const std::string& path, const OpenOptions& opts,
                                                                bool expect_block_node) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_LARGEFILE);
    if (fd < 0) return fail(map_errno(errno, path));

    int fl = ::fcntl(fd, F_GETFL);
    if (fl < 0 || (fl & O_ACCMODE) != O_RDONLY) {
        ::close(fd);
        OR_FATAL_WRITE("source descriptor is not O_RDONLY");
    }

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        int e = errno;
        ::close(fd);
        return fail(map_errno(e, path));
    }

    DeviceInfo info;
    info.description = path;
    if (S_ISBLK(st.st_mode)) {
        uint64_t size = 0;
        int lss = 0;
        unsigned int pss = 0;
        if (safe_ioctl(fd, BLKGETSIZE64, &size) != 0) {
            int e = errno;
            ::close(fd);
            return fail(map_errno(e, path + " (BLKGETSIZE64)"));
        }
        if (safe_ioctl(fd, BLKSSZGET, &lss) != 0 || !valid_sector_size(static_cast<uint64_t>(lss))) lss = 512;
        if (safe_ioctl(fd, BLKPBSZGET, &pss) != 0 || !valid_sector_size(pss) || pss < static_cast<unsigned>(lss))
            pss = static_cast<unsigned>(lss);
        info.size_bytes = size;
        info.logical_sector_size = static_cast<uint32_t>(lss);
        info.physical_sector_size = pss;
        info.is_image = false;
    } else if (S_ISREG(st.st_mode)) {
        if (expect_block_node) {
            ::close(fd);
            return fail(ErrorCode::InvalidArgument, path + ": not a block device");
        }
        const uint32_t sector = opts.sector_size ? opts.sector_size : 512;
        if (!valid_sector_size(sector)) {
            ::close(fd);
            return fail(ErrorCode::InvalidArgument, "sector size must be a power of two in [512, 65536]");
        }
        info.size_bytes = static_cast<uint64_t>(st.st_size);
        info.logical_sector_size = sector;
        info.physical_sector_size = sector;
        info.is_image = true;
    } else {
        ::close(fd);
        return fail(ErrorCode::Unsupported, path + ": neither a block device nor a regular file");
    }
    return std::make_unique<LinuxBlockDevice>(fd, std::move(info));
}

}  // namespace openrecover::io

#endif
