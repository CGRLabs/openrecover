#include "openrecover/fs/fat32.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"

namespace openrecover::fs {

namespace {

constexpr uint64_t kFatWindowBytes = 64 * 1024;
constexpr size_t kMaxChainClusters = size_t{1} << 24;
constexpr size_t kDirEntryBytes = 32;
constexpr size_t kMaxLfnEntries = 20;

std::span<const uint8_t> span_of(const std::vector<uint8_t>& v, size_t count) {
    if (count > v.size()) count = v.size();
    return std::span<const uint8_t>(v.data(), count);
}

constexpr std::array<uint16_t, 128> kCp437 = {
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF,
    0x00EE, 0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA,
    0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4,
    0x221E, 0x03C6, 0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
};

void append_cp437(std::string& out, uint8_t b) {
    if (b < 0x20 || b == 0x7F) {
        out.push_back('_');
    } else if (b < 0x80) {
        out.push_back(static_cast<char>(b));
    } else {
        append_utf8(out, kCp437[static_cast<size_t>(b - 0x80)]);
    }
}

uint32_t entry_cluster(const FatShortEntry& e) {
    return ((static_cast<uint32_t>(e.first_cluster) >> 16) & 0x0FFF) << 16 |
           (static_cast<uint32_t>(e.first_cluster) & 0xFFFF);
}

bool is_all_zero(std::span<const uint8_t> raw) {
    for (uint8_t b : raw)
        if (b != 0) return false;
    return true;
}

std::string decode_name_bytes(const uint8_t* bytes, size_t count, bool lowercase) {
    std::string out;
    for (size_t i = 0; i < count; ++i) {
        uint8_t b = bytes[i];
        if (b == 0) break;
        if (lowercase && b >= 'A' && b <= 'Z') b = static_cast<uint8_t>(b + 32);
        append_cp437(out, b);
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

bool is_leap_year(unsigned year) {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

unsigned days_in_month(unsigned year, unsigned month) {
    constexpr std::array<unsigned, 12> days = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month == 2 && is_leap_year(year)) return 29;
    return days[month - 1];
}

std::string dir_component(const std::string& name) { return sanitize_component(name); }

std::string join_path(const std::string& parent, const std::string& component) {
    if (parent.empty()) return component;
    return parent + "/" + component;
}

bool looks_like_deleted_directory(FatReader& fat, io::BlockDevice& dev, uint32_t cluster) {
    uint8_t raw[64];
    auto got = io::read_fully(dev, fat.cluster_to_byte(cluster), raw, sizeof raw);
    if (!got || *got != sizeof raw) return false;
    auto dot_entry_ok = [](const uint8_t* e, size_t dots) {
        for (size_t i = 0; i < 11; ++i) {
            const uint8_t want = i < dots ? static_cast<uint8_t>('.') : static_cast<uint8_t>(' ');
            if (e[i] != want) return false;
        }
        return (e[11] & 0x10) != 0;
    };
    if (!dot_entry_ok(raw, 1) || !dot_entry_ok(raw + kDirEntryBytes, 2)) return false;
    ByteView v(raw, sizeof raw);
    const uint32_t self = ((v.u16le(20) & 0x0FFF) << 16) | v.u16le(26);
    return self == cluster;
}

}  // namespace

Result<Fat32Bpb> parse_fat32_bpb(std::span<const uint8_t> boot_sector, uint64_t volume_size) {
    if (boot_sector.size() < 512)
        return fail(ErrorCode::CorruptStructure, "FAT32 boot sector is truncated");

    ByteView v(boot_sector);
    const uint8_t j0 = v.u8(0);
    if (!((j0 == 0xEB && v.u8(2) == 0x90) || j0 == 0xE9))
        return fail(ErrorCode::CorruptStructure, "invalid FAT32 jump instruction");

    Fat32Bpb b;
    b.bytes_per_sector = v.u16le(0x0B);
    b.sectors_per_cluster = v.u8(0x0D);
    b.reserved_sectors = v.u16le(0x0E);
    b.num_fats = v.u8(0x10);
    const uint16_t root_entries = v.u16le(0x11);
    const uint16_t total16 = v.u16le(0x13);
    const uint16_t fat16 = v.u16le(0x16);
    b.total_sectors = v.u32le(0x20);
    b.fat_size_sectors = v.u32le(0x24);
    b.ext_flags = v.u16le(0x28);
    b.root_cluster = v.u32le(0x2C);
    b.fsinfo_sector = v.u16le(0x30);
    b.backup_boot_sector = v.u16le(0x32);
    const uint16_t signature = v.u16le(0x1FE);
    if (v.failed()) return fail(ErrorCode::CorruptStructure, "FAT32 boot sector is truncated");
    if (signature != 0xAA55)
        return fail(ErrorCode::CorruptStructure, "missing FAT32 boot sector signature 55 AA");

    if (b.bytes_per_sector != 512 && b.bytes_per_sector != 1024 && b.bytes_per_sector != 2048 &&
        b.bytes_per_sector != 4096)
        return fail(ErrorCode::CorruptStructure, "invalid FAT32 bytes-per-sector");
    if (b.sectors_per_cluster == 0 || b.sectors_per_cluster > 128 ||
        (b.sectors_per_cluster & (b.sectors_per_cluster - 1)) != 0)
        return fail(ErrorCode::CorruptStructure, "invalid FAT32 sectors-per-cluster");
    if (b.reserved_sectors < 1)
        return fail(ErrorCode::CorruptStructure, "FAT32 reserved sector count is zero");
    if (b.num_fats != 1 && b.num_fats != 2)
        return fail(ErrorCode::CorruptStructure, "invalid FAT32 number of FATs");
    if (root_entries != 0 || total16 != 0 || fat16 != 0)
        return fail(ErrorCode::CorruptStructure, "FAT12/16 fields are nonzero in a FAT32 BPB");
    if (b.total_sectors == 0)
        return fail(ErrorCode::CorruptStructure, "FAT32 total sector count is zero");
    if (b.fat_size_sectors == 0)
        return fail(ErrorCode::CorruptStructure, "FAT32 FAT size is zero");
    if (b.root_cluster < 2)
        return fail(ErrorCode::CorruptStructure, "FAT32 root cluster is invalid");

    uint64_t total_bytes = 0;
    if (!checked_mul<uint64_t>(b.total_sectors, b.bytes_per_sector, total_bytes))
        return fail(ErrorCode::CorruptStructure, "FAT32 volume size overflows");
    if (total_bytes > volume_size)
        return fail(ErrorCode::CorruptStructure, "FAT32 BPB claims more sectors than the volume has");

    uint64_t fat_sectors = 0;
    if (!checked_mul<uint64_t>(b.num_fats, b.fat_size_sectors, fat_sectors))
        return fail(ErrorCode::CorruptStructure, "FAT32 FAT size overflows");
    uint64_t data_start_sector = 0;
    if (!checked_add<uint64_t>(b.reserved_sectors, fat_sectors, data_start_sector) ||
        data_start_sector >= b.total_sectors)
        return fail(ErrorCode::CorruptStructure, "FAT32 data region is empty or outside the volume");

    const uint64_t data_sectors = static_cast<uint64_t>(b.total_sectors) - data_start_sector;
    const uint64_t cluster_count = data_sectors / b.sectors_per_cluster;
    if (cluster_count == 0)
        return fail(ErrorCode::CorruptStructure, "FAT32 volume has no data clusters");
    if (cluster_count < 65525)
        log::warn("FAT32 volume has only " + std::to_string(cluster_count) +
                  " clusters (FAT32 normally requires at least 65525)");

    uint64_t fat_bytes = 0;
    if (!checked_mul<uint64_t>(b.fat_size_sectors, b.bytes_per_sector, fat_bytes) || fat_bytes < 12)
        return fail(ErrorCode::CorruptStructure, "FAT32 FAT is too small");
    const uint64_t fat_entries = fat_bytes / 4;
    uint64_t max_valid_cluster = cluster_count + 1;
    max_valid_cluster = std::min(max_valid_cluster, fat_entries - 1);
    max_valid_cluster = std::min(max_valid_cluster, static_cast<uint64_t>(kFatBad) - 1);

    b.bytes_per_cluster = static_cast<uint32_t>(b.bytes_per_sector) * b.sectors_per_cluster;
    b.fat_start_byte = static_cast<uint64_t>(b.reserved_sectors) * b.bytes_per_sector;
    b.data_start_byte = data_start_sector * b.bytes_per_sector;
    b.cluster_count = cluster_count;
    b.max_valid_cluster = static_cast<uint32_t>(max_valid_cluster);

    if ((b.ext_flags & 0x80) != 0) {
        const uint8_t active = static_cast<uint8_t>(b.ext_flags & 0x0F);
        if (active >= b.num_fats)
            return fail(ErrorCode::CorruptStructure, "FAT32 ExtFlags selects an unavailable FAT");
        b.active_fat = active;
    }
    return b;
}

Result<Fat32Bpb> read_fat32_bpb(io::BlockDevice& dev) {
    const auto& info = dev.info();
    if (info.size_bytes < 512)
        return fail(ErrorCode::NoFilesystem, "device is smaller than a FAT32 boot sector");

    uint32_t io_sector = info.logical_sector_size;
    if (io_sector < 512 || io_sector > 65536 || (io_sector & (io_sector - 1)) != 0) io_sector = 512;

    std::vector<uint8_t> primary(io_sector);
    auto got = io::read_fully(dev, 0, primary.data(), primary.size());
    if (!got) return fail(got.error());
    if (*got < 512) return fail(ErrorCode::NoFilesystem, "device is too small for a FAT32 boot sector");

    auto parsed = parse_fat32_bpb(span_of(primary, primary.size()), info.size_bytes);
    if (parsed) return parsed;
    const Error primary_error = parsed.error();

    ByteView raw(primary);
    const uint16_t backup_sector = raw.u16le(0x32);
    const uint16_t reserved = raw.u16le(0x0E);
    if (backup_sector >= 1 && backup_sector < reserved) {
        const uint64_t offset = static_cast<uint64_t>(backup_sector) * io_sector;
        if (offset < info.size_bytes) {
            std::vector<uint8_t> backup(io_sector);
            auto backup_read = io::read_fully(dev, offset, backup.data(), backup.size());
            if (!backup_read) {
                log::warn("FAT32 backup boot sector read failed: " + backup_read.error().message);
            } else if (*backup_read < 512) {
                log::warn("FAT32 backup boot sector is truncated");
            } else {
                auto backup_parsed =
                    parse_fat32_bpb(span_of(backup, backup.size()), info.size_bytes);
                if (backup_parsed) {
                    log::warn("FAT32 primary boot sector invalid (" + primary_error.message +
                              "); using backup boot sector " + std::to_string(backup_sector));
                    return backup_parsed;
                }
                log::warn("FAT32 backup boot sector invalid: " + backup_parsed.error().message);
            }
        }
    }
    return fail(primary_error);
}

FatReader::FatReader(std::shared_ptr<io::BlockDevice> dev, Fat32Bpb bpb)
    : dev_(std::move(dev)), bpb_(bpb) {
    fat_bytes_ = static_cast<uint64_t>(bpb_.fat_size_sectors) * bpb_.bytes_per_sector;
}

Result<uint32_t> FatReader::entry(uint64_t cluster) const {
    if (!valid_cluster(cluster))
        return fail(ErrorCode::CorruptStructure, "FAT cluster " + std::to_string(cluster) +
                                                    " is outside the volume");
    const uint64_t index = cluster * 4;
    if (index + 4 > fat_bytes_)
        return fail(ErrorCode::CorruptStructure, "FAT entry is outside the active FAT");
    const uint64_t fat_base =
        bpb_.fat_start_byte + static_cast<uint64_t>(bpb_.active_fat) * fat_bytes_;
    const uint64_t offset = fat_base + index;

    uint8_t raw[4];
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool hit = window_valid_ && offset >= window_offset_ &&
                         offset - window_offset_ + 4 <= window_size_;
        if (!hit) {
            const uint64_t fat_end =
                bpb_.fat_start_byte + (static_cast<uint64_t>(bpb_.active_fat) + 1) * fat_bytes_;
            const uint64_t start = align_down(offset, kFatWindowBytes);
            const uint64_t take = std::min<uint64_t>(kFatWindowBytes, fat_end - start);
            window_.resize(static_cast<size_t>(take));
            auto got = io::read_fully(*dev_, start, window_.data(), window_.size());
            if (!got) {
                window_valid_ = false;
                return fail(got.error());
            }
            if (*got != window_.size()) {
                window_valid_ = false;
                return fail(ErrorCode::CorruptStructure, "short read of the FAT");
            }
            window_offset_ = start;
            window_size_ = window_.size();
            window_valid_ = true;
        }
        const size_t rel = static_cast<size_t>(offset - window_offset_);
        std::memcpy(raw, window_.data() + rel, sizeof raw);
    }
    return ByteView(raw, sizeof raw).u32le(0) & kFatValueMask;
}

Result<std::vector<uint32_t>> FatReader::chain(uint32_t start) const {
    if (!valid_cluster(start))
        return fail(ErrorCode::CorruptStructure, "FAT chain start cluster is outside the volume");
    std::vector<uint32_t> out;
    std::unordered_set<uint32_t> seen;
    uint32_t current = start;
    while (true) {
        if (out.size() >= kMaxChainClusters) {
            log::warn("FAT chain exceeds 2^24 clusters; truncating");
            break;
        }
        if (!seen.insert(current).second) {
            log::warn("cycle detected in FAT chain at cluster " + std::to_string(current));
            break;
        }
        out.push_back(current);
        auto next = entry(current);
        if (!next) return fail(next.error());
        const uint32_t value = *next;
        if (value == kFatFree || value == kFatBad || value >= kFatEndOfChain) break;
        if (!valid_cluster(value)) {
            log::warn("FAT chain link " + std::to_string(value) + " is outside the volume");
            break;
        }
        current = value;
    }
    return out;
}

uint64_t FatReader::cluster_to_byte(uint64_t cluster) const {
    return bpb_.data_start_byte + (cluster - 2) * bpb_.bytes_per_cluster;
}

bool FatAllocationMap::is_cluster_allocated(uint64_t cluster) const {
    if (!fat_->valid_cluster(cluster)) return true;
    auto value = fat_->entry(cluster);
    if (!value) return true;
    return *value != kFatFree;
}

uint64_t FatAllocationMap::cluster_to_byte_offset(uint64_t cluster) const {
    return fat_->cluster_to_byte(cluster);
}

FatShortEntry decode_short_entry(std::span<const uint8_t> raw) {
    FatShortEntry e;
    if (raw.size() < kDirEntryBytes) return e;
    ByteView v(raw);
    std::memcpy(e.name.data(), raw.data(), e.name.size());
    e.attr = v.u8(11);
    e.nt_res = v.u8(12);
    e.crt_time_tenth = v.u8(13);
    e.crt_time = v.u16le(14);
    e.crt_date = v.u16le(16);
    e.lst_acc_date = v.u16le(18);
    e.first_cluster = (static_cast<uint32_t>(v.u16le(20) & 0x0FFF) << 16) | v.u16le(26);
    e.wrt_time = v.u16le(22);
    e.wrt_date = v.u16le(24);
    e.file_size = v.u32le(28);
    e.deleted = e.name[0] == 0xE5;
    e.end_of_directory = e.name[0] == 0x00;
    return e;
}

std::string decode_short_name(const FatShortEntry& e, bool first_char_lost) {
    std::array<uint8_t, 8> base{};
    std::array<uint8_t, 3> ext{};
    std::memcpy(base.data(), e.name.data(), base.size());
    std::memcpy(ext.data(), e.name.data() + 8, ext.size());
    if (first_char_lost) {
        base[0] = '_';
    } else if (base[0] == 0x05) {
        base[0] = 0xE5;
    }
    std::string base_name = decode_name_bytes(base.data(), base.size(), (e.nt_res & 0x08) != 0);
    std::string ext_name = decode_name_bytes(ext.data(), ext.size(), (e.nt_res & 0x10) != 0);
    if (base_name.empty()) base_name = "_";
    if (ext_name.empty()) return base_name;
    return base_name + "." + ext_name;
}

uint8_t short_name_checksum(const std::array<uint8_t, 11>& name) {
    uint8_t sum = 0;
    for (uint8_t c : name)
        sum = static_cast<uint8_t>(((sum & 1) ? 0x80 : 0x00) + (sum >> 1) + c);
    return sum;
}

FatLfnEntry decode_lfn_entry(std::span<const uint8_t> raw) {
    FatLfnEntry e;
    if (raw.size() < kDirEntryBytes) return e;
    ByteView v(raw);
    e.ord = v.u8(0);
    e.checksum = v.u8(13);
    e.deleted = e.ord == 0xE5;
    size_t out = 0;
    constexpr std::array<size_t, 3> offsets = {1, 14, 28};
    constexpr std::array<size_t, 3> counts = {5, 6, 2};
    for (size_t part = 0; part < offsets.size(); ++part) {
        for (size_t i = 0; i < counts[part]; ++i) {
            e.name[out++] = v.u16le(offsets[part] + i * 2);
        }
    }
    return e;
}

std::optional<std::string> assemble_lfn(std::span<const FatLfnEntry> stack,
                                        const std::array<uint8_t, 11>& short_name,
                                        bool short_name_deleted) {
    if (stack.empty()) return std::nullopt;

    if (!short_name_deleted) {
        const size_t count = stack.size();
        if (count > kMaxLfnEntries) return std::nullopt;
        for (size_t i = 0; i < count; ++i) {
            const uint8_t ord = stack[i].ord;
            if (stack[i].deleted) return std::nullopt;
            if (i == 0) {
                if ((ord & 0x40) == 0) return std::nullopt;
            } else if ((ord & 0x40) != 0) {
                return std::nullopt;
            }
            const size_t sequence = ord & 0x1F;
            if (sequence < 1 || sequence > kMaxLfnEntries) return std::nullopt;
            if (sequence != count - i) return std::nullopt;
        }
    } else {
        for (const auto& e : stack)
            if (!e.deleted) return std::nullopt;
    }

    const uint8_t expected = short_name_checksum(short_name);
    bool checksum_ok = true;
    for (const auto& e : stack) {
        if (e.checksum != expected) {
            checksum_ok = false;
            break;
        }
    }
    if (!checksum_ok) {
        // The deleted short entry lost its first byte, so recover the checksum by
        // brute-forcing the missing character.
        if (!short_name_deleted) return std::nullopt;
        std::array<uint8_t, 11> candidate = short_name;
        bool found = false;
        for (uint32_t c = 0x21; c <= 0xFF; ++c) {
            candidate[0] = static_cast<uint8_t>(c);
            const uint8_t sum = short_name_checksum(candidate);
            bool all_match = true;
            for (const auto& e : stack) {
                if (e.checksum != sum) {
                    all_match = false;
                    break;
                }
            }
            if (all_match) {
                found = true;
                break;
            }
        }
        if (!found) return std::nullopt;
    }

    std::u16string units;
    bool terminated = false;
    for (size_t i = stack.size(); i-- > 0;) {
        for (uint16_t unit : stack[i].name) {
            if (unit == 0x0000) {
                terminated = true;
                break;
            }
            if (unit == 0xFFFF) continue;
            units.push_back(static_cast<char16_t>(unit));
        }
        if (terminated) break;
    }
    if (units.empty()) return std::nullopt;
    return utf16_to_utf8(units);
}

std::optional<int64_t> fat_datetime_to_unix(uint16_t date, uint16_t time) {
    const unsigned year = 1980 + ((date >> 9) & 0x7F);
    const unsigned month = (date >> 5) & 0x0F;
    const unsigned day = date & 0x1F;
    const unsigned hour = (time >> 11) & 0x1F;
    const unsigned minute = (time >> 5) & 0x3F;
    const unsigned second = (time & 0x1F) * 2;
    if (month < 1 || month > 12 || day < 1 || day > days_in_month(year, month) || hour > 23 ||
        minute > 59 || second > 59)
        return std::nullopt;

    int y = static_cast<int>(year);
    const unsigned m = month;
    y -= m <= 2 ? 1 : 0;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned mp = m <= 2 ? m + 9 : m - 3;
    const unsigned doy = (153 * mp + 2) / 5 + day - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const int64_t days =
        static_cast<int64_t>(era) * 146097 + static_cast<int64_t>(doe) - 719468;
    return days * 86400 + static_cast<int64_t>(hour) * 3600 + static_cast<int64_t>(minute) * 60 +
           static_cast<int64_t>(second);
}

Fat32Scanner::Fat32Scanner(std::shared_ptr<io::BlockDevice> dev, Fat32Bpb bpb)
    : dev_(std::move(dev)),
      bpb_(bpb),
      geometry_{bpb.bytes_per_sector, bpb.bytes_per_cluster, bpb.cluster_count},
      fat_(std::make_shared<FatReader>(dev_, bpb_)) {}

Result<std::unique_ptr<Fat32Scanner>> Fat32Scanner::open(std::shared_ptr<io::BlockDevice> dev) {
    if (!dev) return fail(ErrorCode::InvalidArgument, "null device");
    auto bpb = read_fat32_bpb(*dev);
    if (!bpb) return fail(bpb.error());
    return std::unique_ptr<Fat32Scanner>(new Fat32Scanner(std::move(dev), *bpb));
}

Result<std::vector<RecoveredFile>> Fat32Scanner::scan_deleted(const ScanOptions& options,
                                                             ProgressFn progress) {
    struct DirectoryTask {
        uint32_t cluster;
        std::string path;
        uint32_t depth;
    };

    std::vector<RecoveredFile> out;
    std::deque<DirectoryTask> queue;
    std::unordered_set<uint32_t> visited;
    queue.push_back(DirectoryTask{bpb_.root_cluster, "", 0});

    uint64_t done = 0;
    if (progress && !progress(0, 1)) return fail(ErrorCode::Cancelled, "scan cancelled");

    while (!queue.empty()) {
        DirectoryTask task = std::move(queue.front());
        queue.pop_front();
        if (!visited.insert(task.cluster).second) {
            ++done;
            continue;
        }

        auto chain = fat_->chain(task.cluster);
        if (!chain) {
            log::warn("cannot follow directory cluster chain: " + chain.error().message);
            ++done;
            continue;
        }

        std::vector<uint8_t> buffer(bpb_.bytes_per_cluster);
        std::vector<FatLfnEntry> lfn_stack;
        for (uint32_t cluster : *chain) {
            auto read = io::read_fully(*dev_, fat_->cluster_to_byte(cluster), buffer.data(),
                                       buffer.size());
            if (!read) {
                log::warn("directory cluster " + std::to_string(cluster) +
                          " read failed: " + read.error().message);
                lfn_stack.clear();
                continue;
            }
            if (*read != buffer.size()) {
                log::warn("directory cluster " + std::to_string(cluster) + " is truncated");
                lfn_stack.clear();
                continue;
            }

            for (size_t offset = 0; offset + kDirEntryBytes <= buffer.size();
                 offset += kDirEntryBytes) {
                const std::span<const uint8_t> raw(buffer.data() + offset, kDirEntryBytes);
                if (is_all_zero(raw)) {
                    lfn_stack.clear();
                    continue;
                }
                if (raw[0] == 0x00) {
                    lfn_stack.clear();
                    continue;
                }
                if (raw[11] == 0x0F) {
                    if (lfn_stack.size() >= kMaxLfnEntries) lfn_stack.clear();
                    lfn_stack.push_back(decode_lfn_entry(raw));
                    continue;
                }

                const FatShortEntry entry = decode_short_entry(raw);
                if ((entry.attr & 0x08) != 0) {
                    lfn_stack.clear();
                    continue;
                }
                if (entry.name[0] == '.') {
                    lfn_stack.clear();
                    continue;
                }

                const bool deleted = entry.deleted;
                std::optional<std::string> long_name = assemble_lfn(lfn_stack, entry.name, deleted);
                lfn_stack.clear();

                bool guessed_first_char = false;
                std::string raw_name;
                if (long_name && !long_name->empty()) {
                    raw_name = *long_name;
                } else {
                    raw_name = decode_short_name(entry, deleted);
                    guessed_first_char = deleted;
                }
                const std::string component = dir_component(raw_name);
                const std::string child_path = join_path(task.path, component);
                const uint32_t first_cluster = entry_cluster(entry);

                if (!deleted) {
                    if (entry.is_directory() && first_cluster >= 2 &&
                        fat_->valid_cluster(first_cluster)) {
                        if (task.depth + 1 > options.max_directory_depth) {
                            log::warn("directory depth limit reached at " + child_path);
                        } else if (visited.find(first_cluster) == visited.end()) {
                            queue.push_back(
                                DirectoryTask{first_cluster, child_path, task.depth + 1});
                        }
                    }
                    continue;
                }

                if (entry.is_directory()) {
                    if (first_cluster < 2 || !fat_->valid_cluster(first_cluster)) continue;
                    if (task.depth + 1 > options.max_directory_depth) continue;
                    if (!looks_like_deleted_directory(*fat_, *dev_, first_cluster)) continue;
                    if (visited.find(first_cluster) == visited.end()) {
                        queue.push_back(
                            DirectoryTask{first_cluster, child_path, task.depth + 1});
                    }
                    continue;
                }

                RecoveredFile file;
                file.path = child_path;
                file.name = component;
                file.size_bytes = entry.file_size;
                file.origin = FileOrigin::FilesystemMetadata;
                file.mtime_unix = fat_datetime_to_unix(entry.wrt_date, entry.wrt_time);
                file.ctime_unix = fat_datetime_to_unix(entry.crt_date, entry.crt_time);
                file.atime_unix = fat_datetime_to_unix(entry.lst_acc_date, 0);
                file.note = "contiguous_assumption";
                if (file.mtime_unix || file.ctime_unix || file.atime_unix)
                    file.note += "; fat_local_time_assumed_utc";
                if (guessed_first_char) file.flags |= file_flags::NameFirstCharGuessed;

                if (entry.file_size == 0) {
                    file.confidence = Confidence::High;
                    out.push_back(std::move(file));
                    continue;
                }

                if (first_cluster < 2 || !fat_->valid_cluster(first_cluster)) {
                    log::warn("skipping deleted file " + child_path +
                              ": first cluster is outside the volume");
                    continue;
                }
                const uint64_t clusters =
                    (static_cast<uint64_t>(entry.file_size) + bpb_.bytes_per_cluster - 1) /
                    bpb_.bytes_per_cluster;
                const uint64_t last_cluster = first_cluster + clusters - 1;
                if (last_cluster > bpb_.max_valid_cluster) {
                    log::warn("skipping deleted file " + child_path +
                              ": extent beyond volume");
                    continue;
                }
                const uint64_t data_offset = fat_->cluster_to_byte(first_cluster);
                if (data_offset > dev_->info().size_bytes ||
                    entry.file_size > dev_->info().size_bytes - data_offset) {
                    log::warn("skipping deleted file " + child_path +
                              ": extent outside the device");
                    continue;
                }

                bool reused = false;
                for (uint64_t c = first_cluster; c <= last_cluster; ++c) {
                    auto value = fat_->entry(c);
                    if (!value || *value != kFatFree) {
                        reused = true;
                        break;
                    }
                }
                if (reused) {
                    file.confidence = Confidence::Low;
                    file.flags |= file_flags::ClustersReallocated;
                } else {
                    file.confidence = Confidence::High;
                }
                file.extents.push_back(Extent{data_offset, entry.file_size, false});
                out.push_back(std::move(file));
            }
        }

        ++done;
        const uint64_t total = done + static_cast<uint64_t>(queue.size());
        if (progress && !progress(done, total)) return fail(ErrorCode::Cancelled, "scan cancelled");
    }

    if (progress && !progress(done, done)) return fail(ErrorCode::Cancelled, "scan cancelled");
    return out;
}

Result<std::unique_ptr<IAllocationMap>> Fat32Scanner::allocation_map() {
    std::unique_ptr<IAllocationMap> map = std::make_unique<FatAllocationMap>(fat_);
    return map;
}

Result<size_t> Fat32Scanner::read_file(const RecoveredFile& file, uint64_t file_offset,
                                       uint8_t* dst, size_t len) {
    if (file_offset >= file.size_bytes) return size_t{0};

    const uint64_t wanted = std::min<uint64_t>(len, file.size_bytes - file_offset);
    if (file.resident_data) {
        const auto& data = *file.resident_data;
        if (file_offset >= data.size()) return size_t{0};
        const uint64_t take =
            std::min<uint64_t>(wanted, static_cast<uint64_t>(data.size()) - file_offset);
        std::memcpy(dst, data.data() + static_cast<size_t>(file_offset), static_cast<size_t>(take));
        return static_cast<size_t>(take);
    }

    uint64_t logical = 0;
    uint64_t done = 0;
    for (const Extent& extent : file.extents) {
        if (done >= wanted) break;
        if (file_offset >= logical + extent.length_bytes) {
            logical += extent.length_bytes;
            continue;
        }
        const uint64_t within = file_offset > logical ? file_offset - logical : 0;
        const uint64_t take =
            std::min<uint64_t>(extent.length_bytes - within, wanted - done);
        if (extent.sparse) {
            std::memset(dst + done, 0, static_cast<size_t>(take));
        } else {
            auto read = io::read_fully(*dev_, extent.offset_bytes + within, dst + done,
                                       static_cast<size_t>(take));
            if (!read) return fail(read.error());
            if (*read != static_cast<size_t>(take))
                return fail(ErrorCode::CorruptStructure, "short read while recovering " + file.path);
        }
        done += take;
        logical += extent.length_bytes;
    }
    return static_cast<size_t>(done);
}

}  // namespace openrecover::fs
