#include "openrecover/io/image_device.hpp"

#include <system_error>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/path_util.hpp"
#include "openrecover/io/linux_block_device.hpp"
#include "openrecover/io/vhd_device.hpp"
#include "openrecover/io/vhdx_device.hpp"
#include "openrecover/io/win_physical_device.hpp"

namespace openrecover::io {

namespace {

enum class ContainerKind { kFlat, kVhd, kVhdx };

// Classifies a file by its container signature, and fails for the formats that are still
// out of scope.
Result<ContainerKind> classify_container(BlockDevice& dev) {
    const uint64_t size = dev.info().size_bytes;
    uint8_t head[8] = {};
    auto n = read_fully(dev, 0, head, sizeof head);
    if (!n) return fail(n.error());
    ByteView h(head, *n);
    if (h.equals(0, std::string_view("EVF\x09\x0D\x0A\xFF\x00", 8)))
        return fail(ErrorCode::Unsupported, "EnCase E01 containers are not supported");
    if (h.equals(0, "KDMV")) return fail(ErrorCode::Unsupported, "VMDK sparse containers are not supported");
    if (h.equals(0, "vhdxfile")) return ContainerKind::kVhdx;
    if (h.equals(0, "conectix")) return ContainerKind::kVhd;
    if (size >= 512) {
        uint8_t foot[8] = {};
        auto m = read_fully(dev, size - 512, foot, sizeof foot);
        if (!m) return fail(m.error());
        if (ByteView(foot, *m).equals(0, "conectix")) return ContainerKind::kVhd;
    }
    return ContainerKind::kFlat;
}

}  // namespace

Result<std::unique_ptr<BlockDevice>> open_image_flat(const std::filesystem::path& path, const OpenOptions& opts) {
    const std::string desc = path_to_utf8(path);
    std::error_code ec;
    auto st = std::filesystem::status(path, ec);
    if (ec || !std::filesystem::exists(st)) return fail(ErrorCode::NotFound, desc + ": not found");
    if (std::filesystem::is_directory(st)) return fail(ErrorCode::InvalidArgument, desc + ": is a directory");

#if defined(_WIN32)
    auto d = open_win_image(win_long_path(path).wstring(), desc, opts, win::real_api());
    if (!d) return fail(d.error());
    return std::move(*d);
#elif defined(__linux__)
    auto d = open_linux_fd_device(path.string(), opts, false);
    if (!d) return fail(d.error());
    return std::move(*d);
#else
    (void)opts;
    return fail(ErrorCode::Unsupported, "image files are only supported on Windows and Linux");
#endif
}

Result<std::unique_ptr<BlockDevice>> open_image_raw(const std::filesystem::path& path, const OpenOptions& opts) {
    auto dev = open_image_flat(path, opts);
    if (!dev) return fail(dev.error());
    auto kind = classify_container(**dev);
    if (!kind) return fail(kind.error());
    if (*kind == ContainerKind::kVhd) return open_vhd(std::shared_ptr<BlockDevice>(std::move(*dev)));
    if (*kind == ContainerKind::kVhdx)
        return open_vhdx(std::shared_ptr<BlockDevice>(std::move(*dev)));
    return dev;
}

}  // namespace openrecover::io
