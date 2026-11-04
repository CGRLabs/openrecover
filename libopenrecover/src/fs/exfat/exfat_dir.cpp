#include "openrecover/fs/exfat/exfat_dir.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/io/block_device.hpp"

#include "openrecover/fs/exfat/exfat_boot.hpp"
#include "openrecover/fs/exfat/exfat_fat.hpp"

namespace openrecover::fs {

namespace {

constexpr size_t kEntryBytes = 32;
constexpr uint64_t kMaxDirectoryBytes = 32ull << 20;

uint32_t u32le(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint32_t>(b[off]) | (static_cast<uint32_t>(b[off + 1]) << 8) |
           (static_cast<uint32_t>(b[off + 2]) << 16) | (static_cast<uint32_t>(b[off + 3]) << 24);
}
uint64_t u64le(const std::vector<uint8_t>& b, size_t off) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(b[off + i]) << (8 * i);
    return v;
}
uint16_t u16le(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>(b[off] | (static_cast<uint16_t>(b[off + 1]) << 8));
}

void append_utf8(std::string& out, uint32_t cp) {
    if (cp > 0x10FFFF) cp = 0xFFFD;
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string utf16le_to_utf8(const std::vector<uint8_t>& b, size_t off, size_t units) {
    std::string s;
    s.reserve(units);
    for (size_t i = 0; i < units; ++i) {
        uint32_t cp = static_cast<uint32_t>(b[off + i * 2] | (b[off + i * 2 + 1] << 8));
        if (cp == 0) break;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 1 < units) {
                const uint32_t lo =
                    static_cast<uint32_t>(b[off + (i + 1) * 2] | (b[off + (i + 1) * 2 + 1] << 8));
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    ++i;
                } else {
                    cp = 0xFFFD;
                }
            } else {
                cp = 0xFFFD;
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        append_utf8(s, cp);
    }
    return s;
}

std::optional<int64_t> exfat_timestamp_to_unix(uint32_t raw, uint8_t ten_ms, uint8_t utc_offset) {
    if (raw == 0) return std::nullopt;
    const unsigned second = (raw & 0x1F) * 2;
    const unsigned minute = (raw >> 5) & 0x3F;
    const unsigned hour = (raw >> 11) & 0x1F;
    const unsigned day = (raw >> 16) & 0x1F;
    const unsigned month = (raw >> 21) & 0x0F;
    const unsigned year = ((raw >> 25) & 0x7F) + 1980;
    if (second > 59 || minute > 59 || hour > 23 || day < 1 || day > 31 || month < 1 ||
        month > 12)
        return std::nullopt;

    using namespace std::chrono;
    const year_month_day ymd{std::chrono::year{static_cast<int>(year)},
                             std::chrono::month{month}, std::chrono::day{day}};
    if (!ymd.ok()) return std::nullopt;
    const sys_days date{ymd};

    int64_t seconds = duration_cast<std::chrono::seconds>(date.time_since_epoch()).count();
    seconds += static_cast<int64_t>(hour) * 3600 + static_cast<int64_t>(minute) * 60 + second;
    seconds += ten_ms / 100;
    // exFAT stores local time; 0x80 means the UTC offset is unknown.
    if (utc_offset != 0x80) {
        const int offset_minutes = static_cast<int8_t>(utc_offset) * 15;
        seconds -= static_cast<int64_t>(offset_minutes) * 60;
    }
    return seconds;
}

uint16_t entry_set_checksum(const std::vector<uint8_t>& bytes, size_t first, size_t last) {
    uint16_t sum = 0;
    for (size_t entry = first; entry < last; ++entry) {
        for (size_t i = 0; i < kEntryBytes; ++i) {
            if (entry == first && (i == 2 || i == 3)) continue;
            sum = static_cast<uint16_t>(((sum << 15) | (sum >> 1)) + bytes[entry * kEntryBytes + i]);
        }
    }
    return sum;
}

struct ClusterList {
    std::vector<uint32_t> clusters;
    bool chain_lost = false;
    bool truncated = false;
};

Result<ClusterList> directory_clusters(io::BlockDevice& dev, const ExfatBoot& boot,
                                       uint32_t first_cluster, uint64_t size_bytes,
                                       bool no_fat_chain) {
    ClusterList out;
    if (!boot.valid_cluster(first_cluster))
        return fail(ErrorCode::CorruptStructure, "exFAT directory cluster is out of range");

    uint64_t wanted = 0;
    if (size_bytes > 0) {
        wanted = (size_bytes + boot.bytes_per_cluster - 1) / boot.bytes_per_cluster;
        const uint64_t cap = std::max<uint64_t>(1, kMaxDirectoryBytes / boot.bytes_per_cluster);
        if (wanted > cap) {
            wanted = cap;
            out.truncated = true;
        }
    }

    const auto contiguous = [&](uint64_t count) -> Result<void> {
        if (static_cast<uint64_t>(first_cluster) - 2 + count > boot.cluster_count) {
            out.truncated = true;
            if (first_cluster >= boot.cluster_count + 2) {
                return fail(ErrorCode::CorruptStructure, "exFAT directory is outside the volume");
            }
        }
        const uint64_t available = static_cast<uint64_t>(boot.cluster_count) + 2 - first_cluster;
        const uint64_t take = std::min(count, available);
        out.clusters.reserve(static_cast<size_t>(take));
        for (uint64_t i = 0; i < take; ++i)
            out.clusters.push_back(static_cast<uint32_t>(first_cluster + i));
        return Result<void>{};
    };

    if (no_fat_chain) {
        auto built = contiguous(wanted == 0 ? 1 : wanted);
        if (!built) return fail(built.error());
        return out;
    }

    auto chain = read_exfat_chain(dev, boot, first_cluster);
    if (!chain) {
        // Deleted directories lose their FAT chain before their entries; fall back to
        // the contiguous run described by the stream extension. The root directory
        // has no stream, so a lost chain leaves only its first cluster readable.
        out.chain_lost = size_bytes > 0;
        auto built = contiguous(wanted == 0 ? 1 : wanted);
        if (!built) return fail(built.error());
        return out;
    }

    out.clusters = *chain;
    if (wanted > 0 && out.clusters.size() > wanted) {
        out.clusters.resize(static_cast<size_t>(wanted));
    } else if (wanted > 0 && out.clusters.size() < wanted) {
        out.truncated = true;
    }
    const uint64_t cap = std::max<uint64_t>(1, kMaxDirectoryBytes / boot.bytes_per_cluster);
    if (out.clusters.size() > cap) {
        out.clusters.resize(static_cast<size_t>(cap));
        out.truncated = true;
    }
    return out;
}

}  // namespace

Result<ExfatDirListing> read_exfat_directory(io::BlockDevice& dev, const ExfatBoot& boot,
                                             uint32_t first_cluster, uint64_t size_bytes,
                                             bool no_fat_chain) {
    ExfatDirListing listing;
    auto clusters = directory_clusters(dev, boot, first_cluster, size_bytes, no_fat_chain);
    if (!clusters) return fail(clusters.error());
    listing.chain_lost = clusters->chain_lost;
    listing.truncated = clusters->truncated;

    std::vector<uint8_t> bytes;
    bytes.reserve(clusters->clusters.size() * boot.bytes_per_cluster);
    std::vector<uint8_t> buffer(boot.bytes_per_cluster);
    for (uint32_t cluster : clusters->clusters) {
        auto got = io::read_fully(dev, boot.cluster_to_byte(cluster), buffer.data(),
                                  buffer.size());
        if (!got || *got != buffer.size()) {
            listing.truncated = true;
            break;
        }
        bytes.insert(bytes.end(), buffer.begin(), buffer.end());
    }

    const size_t entries = bytes.size() / kEntryBytes;
    size_t i = 0;
    while (i < entries) {
        const uint8_t type = bytes[i * kEntryBytes];
        if (type == 0x00) {
            // An end marker is followed by stale entries in shrinking directories;
            // keep scanning so deleted sets behind it are still recovered.
            ++i;
            continue;
        }
        const uint8_t base = type & 0x7F;
        const bool in_use = (type & 0x80) != 0;

        if (base == 0x01) {
            listing.has_allocation_bitmap = true;
            listing.allocation_bitmap_cluster = u32le(bytes, i * kEntryBytes + 20);
            listing.allocation_bitmap_bytes = u64le(bytes, i * kEntryBytes + 24);
            ++i;
            continue;
        }
        if (base == 0x02) {
            listing.has_upcase_table = true;
            listing.upcase_table_cluster = u32le(bytes, i * kEntryBytes + 20);
            listing.upcase_table_bytes = u64le(bytes, i * kEntryBytes + 24);
            ++i;
            continue;
        }
        if (base == 0x03) {
            ++i;
            continue;
        }
        if (base != 0x05) {
            ++i;
            continue;
        }

        const uint8_t secondary_count = bytes[i * kEntryBytes + 1];
        const size_t first = i;
        const size_t last = std::min(first + 1 + static_cast<size_t>(secondary_count), entries);
        i = last;
        if (secondary_count == 0 || first + 1 >= last) continue;

        if (in_use) {
            const uint16_t stored = u16le(bytes, first * kEntryBytes + 2);
            if (entry_set_checksum(bytes, first, last) != stored) continue;
        }

        ExfatFile file;
        file.deleted = !in_use;
        file.attributes = u16le(bytes, first * kEntryBytes + 4);
        file.ctime_unix = exfat_timestamp_to_unix(u32le(bytes, first * kEntryBytes + 8),
                                                  bytes[first * kEntryBytes + 20],
                                                  bytes[first * kEntryBytes + 22]);
        file.mtime_unix = exfat_timestamp_to_unix(u32le(bytes, first * kEntryBytes + 12),
                                                  bytes[first * kEntryBytes + 21],
                                                  bytes[first * kEntryBytes + 23]);
        file.atime_unix = exfat_timestamp_to_unix(u32le(bytes, first * kEntryBytes + 16), 0,
                                                  bytes[first * kEntryBytes + 24]);

        if (((bytes[(first + 1) * kEntryBytes]) & 0x7F) != 0x40) continue;
        const size_t stream = first + 1;
        const uint8_t flags = bytes[stream * kEntryBytes + 1];
        const uint8_t name_length = bytes[stream * kEntryBytes + 3];
        file.no_fat_chain = (flags & 0x02) != 0;
        file.valid_size = u64le(bytes, stream * kEntryBytes + 8);
        file.first_cluster = u32le(bytes, stream * kEntryBytes + 20);
        file.size = u64le(bytes, stream * kEntryBytes + 24);

        std::vector<uint8_t> name_bytes;
        name_bytes.reserve(static_cast<size_t>(secondary_count) * 30);
        for (size_t j = stream + 1; j < last; ++j) {
            if ((bytes[j * kEntryBytes] & 0x7F) != 0x41) continue;
            name_bytes.insert(name_bytes.end(), bytes.begin() + j * kEntryBytes + 2,
                              bytes.begin() + j * kEntryBytes + 32);
        }
        if (name_bytes.empty()) continue;

        size_t units = name_length;
        if (units == 0) units = name_bytes.size() / 2;
        units = std::min<size_t>(units, name_bytes.size() / 2);
        units = std::min<size_t>(units, 255);
        file.name = utf16le_to_utf8(name_bytes, 0, units);
        file.has_stream = true;
        listing.files.push_back(std::move(file));
    }
    return listing;
}

}  // namespace openrecover::fs
