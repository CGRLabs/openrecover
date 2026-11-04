#include "openrecover/io/block_device.hpp"

#include <charconv>

#include "openrecover/common/path_util.hpp"
#include "openrecover/io/cached_device.hpp"
#include "openrecover/io/image_device.hpp"
#include "openrecover/io/linux_block_device.hpp"
#include "openrecover/io/readonly_guard.hpp"
#include "openrecover/io/win_physical_device.hpp"

namespace openrecover::io {

Result<size_t> read_fully(BlockDevice& dev, uint64_t offset, uint8_t* dst, size_t len) {
    size_t total = 0;
    while (total < len) {
        auto r = dev.read(offset + total, dst + total, len - total);
        if (!r) return fail(r.error());
        if (r->bytes_read == 0) break;
        total += r->bytes_read;
    }
    return total;
}

std::unique_ptr<BlockDevice> wrap_standard(std::shared_ptr<BlockDevice> raw, const OpenOptions& opts) {
    std::shared_ptr<BlockDevice> dev = std::move(raw);
    if (opts.cache_bytes > 0) dev = std::make_shared<CachedDevice>(std::move(dev), opts.cache_bytes);
    return std::make_unique<GuardedDevice>(std::move(dev));
}

Result<std::unique_ptr<BlockDevice>> open_physical_drive(uint32_t drive_number, const OpenOptions& opts) {
#if defined(_WIN32)
    if (drive_number > 999) return fail(ErrorCode::InvalidArgument, "drive number out of range");
    std::string path = "\\\\.\\PhysicalDrive" + std::to_string(drive_number);
    auto dev = open_win_device(path, opts, win::real_api());
    if (!dev) return fail(dev.error());
    return wrap_standard(std::shared_ptr<BlockDevice>(std::move(*dev)), opts);
#else
    (void)drive_number;
    (void)opts;
    return fail(ErrorCode::Unsupported, "physical drive numbers are only supported on Windows");
#endif
}

Result<std::unique_ptr<BlockDevice>> open_block_node(const std::string& path, const OpenOptions& opts) {
#if defined(__linux__)
    auto dev = open_linux_fd_device(path, opts, true);
    if (!dev) return fail(dev.error());
    return wrap_standard(std::shared_ptr<BlockDevice>(std::move(*dev)), opts);
#else
    (void)path;
    (void)opts;
    return fail(ErrorCode::Unsupported, "block device nodes are only supported on Linux");
#endif
}

Result<std::unique_ptr<BlockDevice>> open_image(const std::filesystem::path& path, const OpenOptions& opts) {
    auto dev = open_image_raw(path, opts);
    if (!dev) return fail(dev.error());
    return wrap_standard(std::shared_ptr<BlockDevice>(std::move(*dev)), opts);
}

Result<std::unique_ptr<BlockDevice>> open_source(const std::string& source, const OpenOptions& opts) {
    if (is_valid_physical_drive_path(source)) {
        const std::string digits = source.substr(17);
        uint32_t n = 0;
        std::from_chars(digits.data(), digits.data() + digits.size(), n);
        return open_physical_drive(n, opts);
    }
    if (source.rfind("\\\\.\\", 0) == 0) {
#if defined(_WIN32)
        if (!is_valid_volume_path(source))
            return fail(ErrorCode::InvalidArgument, "invalid Windows device path: " + source);
        auto dev = open_win_device(source, opts, win::real_api());
        if (!dev) return fail(dev.error());
        return wrap_standard(std::shared_ptr<BlockDevice>(std::move(*dev)), opts);
#else
        return fail(ErrorCode::Unsupported, "Windows device paths are only supported on Windows");
#endif
    }
#if defined(__linux__)
    std::error_code ec;
    if (source.rfind("/dev/", 0) == 0 && std::filesystem::is_block_file(source, ec)) return open_block_node(source, opts);
#endif
    return open_image(path_from_utf8(source), opts);
}

}  // namespace openrecover::io
