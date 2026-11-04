#include "openrecover/partition/mbr.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <unordered_set>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"

namespace openrecover::partition {

namespace {

constexpr size_t kSector = 512;
constexpr size_t kEntryOffset = 0x1BE;
constexpr size_t kEntrySize = 16;

bool is_extended(uint8_t type) { return type == 0x05 || type == 0x0F || type == 0x85; }

std::string type_name(uint8_t type) {
    switch (type) {
        case 0x01: return "FAT12";
        case 0x04: return "FAT16 <32M";
        case 0x05: return "Extended";
        case 0x06: return "FAT16";
        case 0x07: return "NTFS/exFAT";
        case 0x0B: return "FAT32";
        case 0x0C: return "FAT32 (LBA)";
        case 0x0E: return "FAT16 (LBA)";
        case 0x0F: return "Extended (LBA)";
        case 0x82: return "Linux swap";
        case 0x83: return "Linux";
        case 0x85: return "Linux extended";
        case 0x8E: return "Linux LVM";
        case 0xEE: return "GPT protective";
        case 0xEF: return "EFI System";
        default: break;
    }
    static const char* hex = "0123456789abcdef";
    std::string s = "type 0x";
    s.push_back(hex[type >> 4]);
    s.push_back(hex[type & 15]);
    return s;
}

Result<std::array<uint8_t, kSector>> read_lba(io::BlockDevice& dev, uint64_t lba, uint64_t sector_size) {
    if (lba != 0 && (sector_size == 0 || lba >= dev.info().size_bytes / sector_size))
        return fail(ErrorCode::CorruptStructure, "partition LBA beyond device", lba * sector_size);
    std::array<uint8_t, kSector> buf{};
    auto got = read_fully(dev, lba * sector_size, buf.data(), buf.size());
    if (!got) return fail(got.error());
    if (*got != buf.size()) return fail(ErrorCode::CorruptStructure, "short read of partition sector", lba * sector_size);
    return buf;
}

bool has_signature(const std::array<uint8_t, kSector>& s) { return s[510] == 0x55 && s[511] == 0xAA; }

void append_bounded(std::vector<PartitionInfo>& out, uint64_t start_lba, uint64_t sectors, uint8_t type,
                    uint64_t sector_size, uint64_t device_sectors) {
    if (sectors == 0 || start_lba >= device_sectors) {
        log::warn("ignoring MBR partition outside the device (start LBA " + std::to_string(start_lba) + ")");
        return;
    }
    if (start_lba + sectors > device_sectors) {
        log::warn("clamping MBR partition that extends beyond the device");
        sectors = device_sectors - start_lba;
    }
    out.push_back(PartitionInfo{static_cast<uint32_t>(out.size()), start_lba * sector_size,
                                sectors * sector_size, type_name(type), PartitionScheme::Mbr});
}

// Follows an EBR chain starting at `extended_base`. Logical entry LBAs are relative to their
// own EBR; link entry LBAs are relative to the extended container.
void collect_extended(io::BlockDevice& dev, uint64_t extended_base, uint64_t sector_size,
                      uint64_t device_sectors, std::vector<PartitionInfo>& out) {
    constexpr size_t kMaxDepth = 128;
    std::unordered_set<uint64_t> visited;
    uint64_t ebr = extended_base;
    for (size_t depth = 0; depth < kMaxDepth; ++depth) {
        if (!visited.insert(ebr).second) {
            log::warn("EBR chain loop detected at LBA " + std::to_string(ebr));
            return;
        }
        auto sector = read_lba(dev, ebr, sector_size);
        if (!sector) {
            log::warn("cannot read EBR at LBA " + std::to_string(ebr) + ": " + sector.error().message);
            return;
        }
        if (!has_signature(*sector)) {
            log::warn("EBR at LBA " + std::to_string(ebr) + " has no 0x55AA signature");
            return;
        }
        auto entries = decode_mbr_entries(*sector);
        const MbrEntry& logical = entries[0];
        if (logical.type != 0 && !is_extended(logical.type))
            append_bounded(out, ebr + logical.start_lba, logical.sector_count, logical.type, sector_size,
                           device_sectors);
        const MbrEntry& link = entries[1];
        if (!is_extended(link.type) || link.sector_count == 0) return;
        ebr = extended_base + link.start_lba;
    }
    log::warn("EBR chain exceeded the maximum depth of 128");
}

}  // namespace

std::array<MbrEntry, 4> decode_mbr_entries(std::span<const uint8_t> sector) {
    std::array<MbrEntry, 4> entries{};
    if (sector.size() < kEntryOffset + 4 * kEntrySize) return entries;
    ByteView v(sector);
    for (size_t i = 0; i < entries.size(); ++i) {
        const size_t off = kEntryOffset + i * kEntrySize;
        entries[i].status = v.u8(off);
        entries[i].type = v.u8(off + 4);
        entries[i].start_lba = v.u32le(off + 8);
        entries[i].sector_count = v.u32le(off + 12);
    }
    return entries;
}

Result<std::vector<PartitionInfo>> parse_mbr(io::BlockDevice& dev) {
    uint64_t sector_size = dev.info().logical_sector_size;
    if (sector_size < 512) sector_size = 512;
    auto sector = read_lba(dev, 0, sector_size);
    if (!sector) return fail(sector.error());
    if (!has_signature(*sector)) return fail(ErrorCode::NoFilesystem, "no 0x55AA signature at LBA 0");

    const uint64_t device_sectors = dev.info().size_bytes / sector_size;
    const auto entries = decode_mbr_entries(*sector);
    std::vector<PartitionInfo> out;
    for (const auto& e : entries) {
        if (e.type == 0 || is_extended(e.type)) continue;
        append_bounded(out, e.start_lba, e.sector_count, e.type, sector_size, device_sectors);
    }
    for (const auto& e : entries) {
        if (!is_extended(e.type) || e.sector_count == 0) continue;
        collect_extended(dev, e.start_lba, sector_size, device_sectors, out);
    }
    return out;
}

}  // namespace openrecover::partition
