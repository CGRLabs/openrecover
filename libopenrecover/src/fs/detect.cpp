#include <array>
#include <cstdint>
#include <memory>
#include <utility>

#include "openrecover/common/bytes.hpp"
#include "openrecover/fs/fat32.hpp"
#include "openrecover/fs/exfat/exfat_boot.hpp"
#include "openrecover/fs/exfat/exfat_scanner.hpp"
#include "openrecover/fs/ext4/ext4_scanner.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/fs/ntfs.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

Result<std::unique_ptr<IFileSystemScanner>> detect_and_open(
    std::shared_ptr<io::BlockDevice> dev) {
    if (!dev) return fail(ErrorCode::InvalidArgument, "null device");

    std::array<uint8_t, 512> boot{};
    auto got = io::read_fully(*dev, 0, boot.data(), boot.size());
    if (!got) return fail(got.error());
    if (*got < boot.size())
        return fail(ErrorCode::NoFilesystem, "device is too small to hold a file system");

    if (ByteView(boot).equals(3, "NTFS    ")) {
        auto scanner = NtfsScanner::open(std::move(dev));
        if (!scanner) return fail(scanner.error());
        return std::unique_ptr<IFileSystemScanner>(std::move(*scanner));
    }

    if (ByteView(boot).equals(3, "EXFAT   ")) {
        auto scanner = ExfatScanner::open(std::move(dev));
        if (!scanner) return fail(scanner.error());
        return std::unique_ptr<IFileSystemScanner>(std::move(*scanner));
    }

    // ext4 has no boot-sector signature; its superblock starts at byte 1024. The scanner's own
    // magic check is what identifies it, so a volume without one is passed on rather than
    // rejected -- but a volume that has the magic and fails to open is an ext4 volume this
    // library cannot read, and saying so beats calling it FAT32.
    {
        auto scanner = Ext4Scanner::open(dev);
        if (scanner) return std::unique_ptr<IFileSystemScanner>(std::move(*scanner));
        if (scanner.error().code != ErrorCode::NoFilesystem) return fail(scanner.error());
    }

    auto scanner = Fat32Scanner::open(std::move(dev));
    if (!scanner) {
        if (scanner.error().code == ErrorCode::CorruptStructure ||
            scanner.error().code == ErrorCode::NoFilesystem)
            return fail(ErrorCode::Unsupported, "unknown filesystem");
        return fail(scanner.error());
    }
    return std::unique_ptr<IFileSystemScanner>(std::move(*scanner));
}

}  // namespace openrecover::fs
