#include "openrecover/fs/ntfs_boot.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "openrecover/common/bytes.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

namespace {

bool is_power_of_two(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

Result<uint64_t> decode_cluster_size(uint8_t raw, uint32_t bytes_per_sector) {
    uint64_t sectors = 0;
    if (raw == 0) return fail(ErrorCode::CorruptStructure, "NTFS sectors per cluster is zero");
    if (raw <= 0x80) {
        if (!is_power_of_two(raw))
            return fail(ErrorCode::CorruptStructure, "NTFS sectors per cluster is not a power of two");
        sectors = raw;
    } else {
        const unsigned shift = 256u - raw;
        if (shift >= 64)
            return fail(ErrorCode::CorruptStructure, "NTFS sectors per cluster is out of range");
        sectors = uint64_t{1} << shift;
    }
    uint64_t bytes = 0;
    if (!checked_mul<uint64_t>(sectors, bytes_per_sector, bytes) || bytes > (1ull << 30))
        return fail(ErrorCode::CorruptStructure, "NTFS cluster size is out of range");
    return bytes;
}

Result<uint64_t> decode_sized_field(int8_t raw, uint32_t bytes_per_cluster, const char* what) {
    if (raw > 0) {
        uint64_t size = 0;
        if (!checked_mul<uint64_t>(static_cast<uint64_t>(raw), bytes_per_cluster, size))
            return fail(ErrorCode::CorruptStructure, std::string("NTFS ") + what + " overflows");
        return size;
    }
    if (raw < 0) {
        const int shift = -static_cast<int>(raw);
        if (shift >= 64)
            return fail(ErrorCode::CorruptStructure, std::string("NTFS ") + what + " shift is out of range");
        return uint64_t{1} << shift;
    }
    return fail(ErrorCode::CorruptStructure, std::string("NTFS ") + what + " is zero");
}

}  // namespace

Result<NtfsBoot> parse_ntfs_boot(std::span<const uint8_t> boot_sector, uint64_t volume_size) {
    if (boot_sector.size() < 512)
        return fail(ErrorCode::CorruptStructure, "NTFS boot sector is truncated");
    if (volume_size < 512) return fail(ErrorCode::NoFilesystem, "volume is too small for an NTFS boot sector");

    const ByteView view(boot_sector);
    if (!view.equals(3, "NTFS    "))
        return fail(ErrorCode::NoFilesystem, "missing NTFS OEM identifier");
    if (view.u16le(0x1FE) != 0xAA55)
        return fail(ErrorCode::CorruptStructure, "invalid NTFS boot sector signature");

    const uint16_t bps = view.u16le(0x0B);
    if (bps != 512 && bps != 1024 && bps != 2048 && bps != 4096)
        return fail(ErrorCode::CorruptStructure, "invalid NTFS bytes per sector");

    auto cluster_size = decode_cluster_size(view.u8(0x0D), bps);
    if (!cluster_size) return fail(cluster_size.error());
    const uint32_t sectors_per_cluster = static_cast<uint32_t>(*cluster_size / bps);

    const uint64_t total_sectors = view.u64le(0x28);
    if (total_sectors == 0) return fail(ErrorCode::CorruptStructure, "NTFS total sector count is zero");
    uint64_t total_bytes = 0;
    if (!checked_mul<uint64_t>(total_sectors, bps, total_bytes) || total_bytes > volume_size)
        return fail(ErrorCode::CorruptStructure, "NTFS volume geometry exceeds the device size");

    const uint64_t total_clusters = total_sectors / sectors_per_cluster;
    if (total_clusters == 0)
        return fail(ErrorCode::CorruptStructure, "NTFS volume has no clusters");

    NtfsBoot boot;
    boot.bytes_per_sector = bps;
    boot.sectors_per_cluster = sectors_per_cluster;
    boot.bytes_per_cluster = static_cast<uint32_t>(*cluster_size);
    boot.total_sectors = total_sectors;
    boot.total_clusters = total_clusters;
    boot.mft_lcn = view.u64le(0x30);
    boot.mft_mirror_lcn = view.u64le(0x38);
    boot.volume_serial = view.u64le(0x48);
    if (boot.mft_lcn >= total_clusters)
        return fail(ErrorCode::CorruptStructure, "NTFS MFT location is outside the volume");
    if (boot.mft_mirror_lcn >= total_clusters)
        return fail(ErrorCode::CorruptStructure, "NTFS MFT mirror location is outside the volume");

    const int8_t record_encoding = static_cast<int8_t>(view.u8(0x40));
    auto record_size = decode_sized_field(record_encoding, boot.bytes_per_cluster, "MFT record size");
    if (!record_size) return fail(record_size.error());
    if (*record_size < 512 || *record_size > 65536 || !is_power_of_two(*record_size))
        return fail(ErrorCode::CorruptStructure, "NTFS MFT record size is not a power of two in [512, 65536]");

    const int8_t index_encoding = static_cast<int8_t>(view.u8(0x44));
    auto index_size = decode_sized_field(index_encoding, boot.bytes_per_cluster, "index buffer size");
    if (!index_size) return fail(index_size.error());
    if (*index_size < 512 || *index_size > (1ull << 30) || !is_power_of_two(*index_size))
        return fail(ErrorCode::CorruptStructure, "NTFS index buffer size is not a power of two in [512, 1 GiB]");

    boot.clusters_per_record = record_encoding;
    boot.record_size = static_cast<uint32_t>(*record_size);
    boot.clusters_per_index_buffer = index_encoding;
    boot.index_buffer_size = static_cast<uint32_t>(*index_size);

    if (boot.mft_byte_offset() >= total_bytes || boot.record_size > total_bytes - boot.mft_byte_offset())
        return fail(ErrorCode::CorruptStructure, "NTFS MFT record lies outside the volume");

    return boot;
}

Result<NtfsBoot> read_ntfs_boot(io::BlockDevice& dev) {
    const uint64_t volume_size = dev.info().size_bytes;
    if (volume_size < 512) return fail(ErrorCode::NoFilesystem, "device is too small for an NTFS boot sector");

    std::array<uint8_t, 512> primary{};
    auto got = io::read_fully(dev, 0, primary.data(), primary.size());
    if (!got) return fail(got.error());
    if (*got < primary.size())
        return fail(ErrorCode::NoFilesystem, "device is too small for an NTFS boot sector");

    auto primary_parse = parse_ntfs_boot(primary, volume_size);
    if (primary_parse) return primary_parse;

    if (volume_size > 512) {
        std::array<uint8_t, 512> backup{};
        auto backup_got = io::read_fully(dev, volume_size - backup.size(), backup.data(), backup.size());
        if (backup_got && *backup_got == backup.size()) {
            auto backup_parse = parse_ntfs_boot(backup, volume_size);
            if (backup_parse) return backup_parse;
        }
    }
    return fail(ErrorCode::CorruptStructure,
                "invalid NTFS boot sector and backup: " + primary_parse.error().message);
}

}  // namespace openrecover::fs
