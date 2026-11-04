#include "openrecover/fs/exfat/exfat_boot.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

namespace {

uint32_t u32le(std::span<const uint8_t> v, size_t off) {
    return static_cast<uint32_t>(v[off]) | (static_cast<uint32_t>(v[off + 1]) << 8) |
           (static_cast<uint32_t>(v[off + 2]) << 16) | (static_cast<uint32_t>(v[off + 3]) << 24);
}
uint64_t u64le(std::span<const uint8_t> v, size_t off) {
    uint64_t r = 0;
    for (int i = 0; i < 8; ++i) r |= static_cast<uint64_t>(v[off + i]) << (8 * i);
    return r;
}
uint16_t u16le(std::span<const uint8_t> v, size_t off) {
    return static_cast<uint16_t>(v[off] | (static_cast<uint16_t>(v[off + 1]) << 8));
}

constexpr uint32_t kMaxClusterCount = 0xFFFFFFF5u;
constexpr uint32_t kMaxClusterBytes = 32u * 1024 * 1024;

}  // namespace

Result<ExfatBoot> parse_exfat_boot(std::span<const uint8_t> boot_sector, uint64_t volume_size) {
    if (boot_sector.size() < 512)
        return fail(ErrorCode::CorruptStructure, "exFAT boot sector is truncated");
    if (boot_sector[3] != 'E' || boot_sector[4] != 'X' || boot_sector[5] != 'F' ||
        boot_sector[6] != 'A' || boot_sector[7] != 'T' || boot_sector[8] != ' ' ||
        boot_sector[9] != ' ' || boot_sector[10] != ' ')
        return fail(ErrorCode::CorruptStructure, "exFAT signature missing");
    if (boot_sector[510] != 0x55 || boot_sector[511] != 0xAA)
        return fail(ErrorCode::CorruptStructure, "exFAT boot signature 0x55AA missing");

    const bool jump_ok = (boot_sector[0] == 0xEB && boot_sector[2] == 0x90) ||
                         boot_sector[0] == 0xE9;
    if (!jump_ok) return fail(ErrorCode::CorruptStructure, "invalid exFAT jump instruction");

    ExfatBoot b;
    const uint8_t sector_shift = boot_sector[0x6C];
    const uint8_t cluster_shift = boot_sector[0x6D];
    if (sector_shift < 9 || sector_shift > 12)
        return fail(ErrorCode::CorruptStructure, "exFAT bytes-per-sector shift is invalid");
    if (cluster_shift > 25 - sector_shift)
        return fail(ErrorCode::CorruptStructure, "exFAT sectors-per-cluster shift is invalid");
    b.bytes_per_sector = 1u << sector_shift;
    b.sectors_per_cluster = 1u << cluster_shift;
    b.bytes_per_cluster = b.bytes_per_sector * b.sectors_per_cluster;
    if (b.bytes_per_cluster > kMaxClusterBytes)
        return fail(ErrorCode::CorruptStructure, "exFAT cluster size exceeds 32 MiB");

    b.fat_offset_sectors = u32le(boot_sector, 0x50);
    b.fat_length_sectors = u32le(boot_sector, 0x54);
    b.cluster_heap_offset_sectors = u32le(boot_sector, 0x58);
    b.cluster_count = u32le(boot_sector, 0x5C);
    b.first_cluster_of_root = u32le(boot_sector, 0x60);
    b.volume_serial = u32le(boot_sector, 0x64);
    b.filesystem_revision = u16le(boot_sector, 0x68);
    b.volume_flags = u16le(boot_sector, 0x6A);
    b.number_of_fats = boot_sector[0x6E];
    b.volume_length_sectors = u64le(boot_sector, 0x48);
    b.partition_offset_sectors = u64le(boot_sector, 0x40);

    if (b.fat_offset_sectors < 24)
        return fail(ErrorCode::CorruptStructure, "exFAT FAT offset overlaps the boot region");
    if (b.fat_length_sectors == 0)
        return fail(ErrorCode::CorruptStructure, "exFAT FAT length is zero");
    if (b.number_of_fats < 1 || b.number_of_fats > 2)
        return fail(ErrorCode::CorruptStructure, "exFAT number-of-FATs is invalid");
    if (b.cluster_count < 1 || b.cluster_count > kMaxClusterCount)
        return fail(ErrorCode::CorruptStructure, "exFAT cluster count is invalid");

    const uint64_t fats_end =
        static_cast<uint64_t>(b.fat_offset_sectors) +
        static_cast<uint64_t>(b.fat_length_sectors) * b.number_of_fats;
    if (b.cluster_heap_offset_sectors < fats_end)
        return fail(ErrorCode::CorruptStructure, "exFAT cluster heap overlaps the FATs");

    const uint64_t fat_bytes = static_cast<uint64_t>(b.fat_length_sectors) * b.bytes_per_sector;
    if (fat_bytes / 4 < static_cast<uint64_t>(b.cluster_count) + 2)
        return fail(ErrorCode::CorruptStructure, "exFAT FAT is too small for the cluster count");

    if (b.volume_length_sectors < b.cluster_heap_offset_sectors)
        return fail(ErrorCode::CorruptStructure, "exFAT volume length is below the heap offset");
    const uint64_t heap_end_sectors =
        static_cast<uint64_t>(b.cluster_heap_offset_sectors) +
        static_cast<uint64_t>(b.cluster_count) * b.sectors_per_cluster;
    if (heap_end_sectors > b.volume_length_sectors)
        return fail(ErrorCode::CorruptStructure, "exFAT cluster heap exceeds the volume length");
    if (volume_size != 0 && heap_end_sectors * b.bytes_per_sector > volume_size)
        return fail(ErrorCode::CorruptStructure, "exFAT cluster heap exceeds the device size");

    if (!b.valid_cluster(b.first_cluster_of_root))
        return fail(ErrorCode::CorruptStructure, "exFAT root cluster is out of range");

    return b;
}

Result<ExfatBoot> read_exfat_boot(io::BlockDevice& dev) {
    std::array<uint8_t, 512> buf{};
    auto got = io::read_fully(dev, 0, buf.data(), buf.size());
    if (!got || *got < buf.size())
        return fail(ErrorCode::IoError, "exFAT boot read failed");
    return parse_exfat_boot(std::span<const uint8_t>(buf.data(), buf.size()),
                            dev.info().size_bytes);
}

}  // namespace openrecover::fs
