#include "openrecover/partition/partition_scanner.hpp"

#include <array>
#include <cstddef>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/partition/gpt.hpp"
#include "openrecover/partition/mbr.hpp"

namespace openrecover::partition {

namespace {

bool is_power_of_two(uint32_t v) { return v != 0 && (v & (v - 1)) == 0; }

// Signature-level check used only to recognise a partitionless (superfloppy) image.
// Full BPB validation happens in the filesystem layer.
bool looks_like_fat32(const ByteView& s, uint64_t volume_size) {
    if (s.size() < 512) return false;
    const bool jump = (s.u8(0) == 0xEB && s.u8(2) == 0x90) || s.u8(0) == 0xE9;
    const uint32_t bytes_per_sector = s.u16le(0x0B);
    const uint32_t sectors_per_cluster = s.u8(0x0D);
    const uint32_t reserved = s.u16le(0x0E);
    const uint32_t fats = s.u8(0x10);
    const uint32_t total_sectors = s.u32le(0x20);
    const uint32_t fat_size = s.u32le(0x24);
    if (!jump || (bytes_per_sector != 512 && bytes_per_sector != 1024 && bytes_per_sector != 2048 &&
                  bytes_per_sector != 4096))
        return false;
    if (!is_power_of_two(sectors_per_cluster) || sectors_per_cluster > 128) return false;
    if (reserved < 1 || (fats != 1 && fats != 2)) return false;
    if (s.u16le(0x11) != 0 || s.u16le(0x13) != 0 || s.u16le(0x16) != 0) return false;
    if (total_sectors == 0 || fat_size == 0 || s.u32le(0x2C) < 2) return false;
    if (static_cast<uint64_t>(total_sectors) * bytes_per_sector > volume_size) return false;
    return s.u16le(0x1FE) == 0xAA55;
}

bool looks_like_ntfs(const ByteView& s) { return s.size() >= 512 && s.equals(3, "NTFS    "); }

bool looks_like_exfat(const ByteView& s) {
    return s.size() >= 512 && s.equals(3, "EXFAT   ") && s.u16le(0x1FE) == 0xAA55;
}

// ext4 has no boot sector: mkfs zeroes the first KiB and the superblock starts at byte 1024.
// The magic and a plausible block-size shift are enough to recognise a partitionless volume;
// read_superblock validates the rest once the filesystem layer opens it.
bool looks_like_ext4(io::BlockDevice& dev) {
    if (dev.info().size_bytes < 2048) return false;
    std::array<uint8_t, 2> magic{};
    auto got = read_fully(dev, 1024 + 56, magic.data(), magic.size());
    if (!got || *got != magic.size()) return false;
    if (magic[0] != 0x53 || magic[1] != 0xEF) return false;
    std::array<uint8_t, 2> log_block_size{};
    got = read_fully(dev, 1024 + 24, log_block_size.data(), log_block_size.size());
    if (!got || *got != log_block_size.size()) return false;
    return log_block_size[0] <= 6 && log_block_size[1] == 0;
}

}  // namespace

Result<std::vector<PartitionInfo>> scan_partitions(io::BlockDevice& dev) {
    std::array<uint8_t, 512> lba0{};
    auto got = read_fully(dev, 0, lba0.data(), lba0.size());
    if (!got) return fail(got.error());
    if (*got != lba0.size()) return fail(ErrorCode::CorruptStructure, "device is too small for a partition table");
    ByteView sector(lba0);
    if (sector.u16le(510) != 0xAA55 && !looks_like_ext4(dev))
        return fail(ErrorCode::NoFilesystem, "no 0x55AA signature at LBA 0 or ext4 superblock");
    if (sector.u16le(510) != 0xAA55)
        return std::vector<PartitionInfo>{
            PartitionInfo{0, 0, dev.info().size_bytes, "whole-device volume", PartitionScheme::Superfloppy}};

    uint64_t sector_size = dev.info().logical_sector_size;
    if (sector_size < 512) sector_size = 512;

    const auto entries = decode_mbr_entries(lba0);
    if (entries[0].type == 0xEE) {
        auto gpt = parse_gpt(dev);
        if (gpt) return gpt;
        log::warn("GPT is invalid (" + gpt.error().message + "); falling back to the protective MBR entry");
        const MbrEntry& protective = entries[0];
        if (protective.sector_count == 0 || protective.start_lba >= dev.info().size_bytes / sector_size)
            return fail(ErrorCode::CorruptStructure, "GPT is invalid and the protective MBR entry is unusable");
        uint64_t sectors = protective.sector_count;
        const uint64_t available = dev.info().size_bytes / sector_size - protective.start_lba;
        if (sectors > available) sectors = available;
        return std::vector<PartitionInfo>{PartitionInfo{0, protective.start_lba * sector_size,
                                                        sectors * sector_size,
                                                        "GPT protective (invalid GPT, MBR fallback)",
                                                        PartitionScheme::Mbr}};
    }

    auto mbr = parse_mbr(dev);
    if (!mbr) return fail(mbr.error());
    if (!mbr->empty()) return mbr;

    if (looks_like_ntfs(sector) || looks_like_fat32(sector, dev.info().size_bytes) ||
        looks_like_exfat(sector) || looks_like_ext4(dev)) {
        return std::vector<PartitionInfo>{
            PartitionInfo{0, 0, dev.info().size_bytes, "whole-device volume", PartitionScheme::Superfloppy}};
    }
    return mbr;
}

}  // namespace openrecover::partition
