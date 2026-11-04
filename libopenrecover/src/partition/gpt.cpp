#include "openrecover/partition/gpt.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/crc32.hpp"
#include "openrecover/common/log.hpp"

namespace openrecover::partition {

namespace {

constexpr uint64_t kMaxEntryArrayBytes = 16ull << 20;
constexpr uint32_t kMinEntrySize = 128;

struct GptHeader {
    uint64_t entry_lba = 0;
    uint32_t entry_count = 0;
    uint32_t entry_size = 0;
    uint32_t entries_crc = 0;
};

using Guid = std::array<uint8_t, 16>;

constexpr Guid kEfiSystem = {0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                             0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B};
constexpr Guid kMicrosoftBasicData = {0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
                                      0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7};
constexpr Guid kMicrosoftReserved = {0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D,
                                     0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE};
constexpr Guid kWindowsRecovery = {0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D,
                                   0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC};
constexpr Guid kLinuxFilesystem = {0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                                   0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4};
constexpr Guid kLinuxSwap = {0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43,
                             0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F};
constexpr Guid kLinuxLvm = {0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44,
                            0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28};
constexpr Guid kBiosBoot = {0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E,
                            0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49};

bool guid_is_zero(const uint8_t* g) {
    for (size_t i = 0; i < 16; ++i)
        if (g[i] != 0) return false;
    return true;
}

std::string guid_to_string(const uint8_t* g) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(36);
    auto put = [&](uint64_t value, int digits) {
        for (int i = digits - 1; i >= 0; --i) s.push_back(hex[(value >> (4 * i)) & 0x0F]);
    };
    ByteView v(g, 16);
    put(v.u32le(0), 8);
    s.push_back('-');
    put(v.u16le(4), 4);
    s.push_back('-');
    put(v.u16le(6), 4);
    s.push_back('-');
    put(g[8], 2);
    put(g[9], 2);
    s.push_back('-');
    for (int i = 10; i < 16; ++i) put(g[i], 2);
    return s;
}

std::string guid_description(const uint8_t* g) {
    if (std::memcmp(g, kEfiSystem.data(), 16) == 0) return "EFI System";
    if (std::memcmp(g, kMicrosoftBasicData.data(), 16) == 0) return "Microsoft basic data";
    if (std::memcmp(g, kMicrosoftReserved.data(), 16) == 0) return "Microsoft reserved";
    if (std::memcmp(g, kWindowsRecovery.data(), 16) == 0) return "Windows recovery";
    if (std::memcmp(g, kLinuxFilesystem.data(), 16) == 0) return "Linux filesystem";
    if (std::memcmp(g, kLinuxSwap.data(), 16) == 0) return "Linux swap";
    if (std::memcmp(g, kLinuxLvm.data(), 16) == 0) return "Linux LVM";
    if (std::memcmp(g, kBiosBoot.data(), 16) == 0) return "BIOS boot";
    return "GUID " + guid_to_string(g);
}

std::string entry_name(const uint8_t* p, size_t bytes) {
    std::u16string units;
    units.reserve(bytes / 2);
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        uint16_t u = static_cast<uint16_t>(p[i] | (p[i + 1] << 8));
        if (u == 0) break;
        units.push_back(static_cast<char16_t>(u));
    }
    return utf16_to_utf8(units);
}

Result<GptHeader> read_header(io::BlockDevice& dev, uint64_t lba, uint32_t sector_size) {
    const uint64_t sectors = dev.info().size_bytes / sector_size;
    if (lba >= sectors) return fail(ErrorCode::CorruptStructure, "GPT header LBA beyond device");
    std::vector<uint8_t> raw(sector_size);
    auto got = read_fully(dev, lba * sector_size, raw.data(), raw.size());
    if (!got) return fail(got.error());
    if (*got != raw.size()) return fail(ErrorCode::CorruptStructure, "short GPT header read");

    ByteView v(raw);
    if (!v.equals(0, "EFI PART")) return fail(ErrorCode::CorruptStructure, "missing EFI PART signature");
    const uint32_t header_size = v.u32le(12);
    const uint32_t stored_crc = v.u32le(16);
    if (v.failed() || header_size < 92 || header_size > sector_size)
        return fail(ErrorCode::CorruptStructure, "invalid GPT header size");

    std::vector<uint8_t> for_crc(raw.begin(), raw.begin() + header_size);
    for (size_t i = 16; i < 20; ++i) for_crc[i] = 0;
    if (crc32(for_crc) != stored_crc) return fail(ErrorCode::CorruptStructure, "GPT header CRC mismatch");

    GptHeader h;
    h.entry_lba = v.u64le(72);
    h.entry_count = v.u32le(80);
    h.entry_size = v.u32le(84);
    h.entries_crc = v.u32le(88);
    if (v.failed()) return fail(ErrorCode::CorruptStructure, "truncated GPT header");
    if (h.entry_size < kMinEntrySize || h.entry_size % 8 != 0)
        return fail(ErrorCode::CorruptStructure, "invalid GPT partition entry size");
    if (h.entry_count == 0) return fail(ErrorCode::CorruptStructure, "GPT has no partition entries");

    uint64_t array_bytes = 0;
    if (!checked_mul<uint64_t>(h.entry_count, h.entry_size, array_bytes) || array_bytes > kMaxEntryArrayBytes)
        return fail(ErrorCode::CorruptStructure, "GPT partition entry array is implausibly large");
    const uint64_t array_sectors = (array_bytes + sector_size - 1) / sector_size;
    if (h.entry_lba >= sectors || array_sectors > sectors - h.entry_lba)
        return fail(ErrorCode::CorruptStructure, "GPT partition entry array is outside the device");
    return h;
}

Result<std::vector<PartitionInfo>> read_entries(io::BlockDevice& dev, const GptHeader& h, uint32_t sector_size) {
    const uint64_t array_bytes = static_cast<uint64_t>(h.entry_count) * h.entry_size;
    std::vector<uint8_t> array(static_cast<size_t>(array_bytes));
    auto got = read_fully(dev, h.entry_lba * sector_size, array.data(), array.size());
    if (!got) return fail(got.error());
    if (*got != array.size()) return fail(ErrorCode::CorruptStructure, "short GPT partition entry array read");
    if (crc32(array) != h.entries_crc)
        return fail(ErrorCode::CorruptStructure, "GPT partition entry array CRC mismatch");

    const uint64_t device_last_lba = dev.info().size_bytes / sector_size - 1;
    std::vector<PartitionInfo> out;
    for (uint32_t i = 0; i < h.entry_count; ++i) {
        const uint8_t* e = array.data() + static_cast<size_t>(i) * h.entry_size;
        if (guid_is_zero(e)) continue;
        ByteView v(e, h.entry_size);
        const uint64_t first = v.u64le(32);
        const uint64_t last = v.u64le(40);
        if (v.failed()) return fail(ErrorCode::CorruptStructure, "truncated GPT partition entry");
        if (first > last || last > device_last_lba) {
            log::warn("skipping GPT partition " + std::to_string(i) + " outside the device");
            continue;
        }
        std::string desc = guid_description(e);
        const std::string name = entry_name(e + 56, 72);
        if (!name.empty()) desc += " (" + name + ")";
        PartitionInfo p;
        p.index = static_cast<uint32_t>(out.size());
        p.start_byte = first * sector_size;
        p.length_byte = (last - first + 1) * sector_size;
        p.type_desc = std::move(desc);
        p.scheme = PartitionScheme::Gpt;
        out.push_back(std::move(p));
    }
    return out;
}

}  // namespace

Result<std::vector<PartitionInfo>> parse_gpt(io::BlockDevice& dev) {
    uint32_t sector_size = dev.info().logical_sector_size;
    if (sector_size < 512 || sector_size > 65536 || (sector_size & (sector_size - 1)) != 0) sector_size = 512;
    const uint64_t sectors = dev.info().size_bytes / sector_size;
    if (sectors < 3) return fail(ErrorCode::CorruptStructure, "device is too small for GPT");

    std::string primary_error;
    auto primary = read_header(dev, 1, sector_size);
    if (primary) {
        auto parts = read_entries(dev, *primary, sector_size);
        if (parts) return parts;
        primary_error = parts.error().message;
        log::warn("GPT primary unusable: " + primary_error);
    } else {
        primary_error = primary.error().message;
        log::warn("GPT primary header unusable: " + primary_error);
    }

    auto backup = read_header(dev, sectors - 1, sector_size);
    if (!backup) {
        return fail(ErrorCode::CorruptStructure, "GPT primary and backup are both invalid: " + primary_error + "; " +
                                                     backup.error().message);
    }
    auto parts = read_entries(dev, *backup, sector_size);
    if (!parts) return fail(parts.error());
    log::warn("using the backup GPT at the last LBA");
    return parts;
}

}  // namespace openrecover::partition
