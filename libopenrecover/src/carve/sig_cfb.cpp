#include "openrecover/carve/sig_cfb.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"

namespace openrecover::carve {

namespace {

constexpr size_t kHeaderBytes = 512;
constexpr size_t kEntryBytes = 128;
constexpr size_t kInlineDifat = 109;

// The sector ids the format reserves for itself; only values at or below the largest regular
// sector name a chain can point at a sector.
constexpr uint32_t kMaxRegSect = 0xFFFFFFFAu;
constexpr uint32_t kDifatSect = 0xFFFFFFFCu;
constexpr uint32_t kFatSect = 0xFFFFFFFDu;
constexpr uint32_t kEndOfChain = 0xFFFFFFFEu;
constexpr uint32_t kFreeSect = 0xFFFFFFFFu;

constexpr uint64_t kMaxDifatSectors = 8192;
constexpr uint64_t kMaxFatReads = 8192;
constexpr uint64_t kMaxDirSectors = 4096;

uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

bool is_sector_id(uint32_t value) { return value <= kMaxRegSect; }

uint64_t sector_at(uint64_t sector_size, uint32_t id) {
    return kHeaderBytes + static_cast<uint64_t>(id) * sector_size;
}

struct Header {
    bool version4 = false;
    uint64_t sector_size = 512;
    uint64_t entries = 128;  // sector ids one FAT sector holds
    uint32_t fat_sectors = 0;
    uint32_t dir_sectors = 0;
    uint32_t first_dir = kEndOfChain;
    uint32_t first_mini_fat = kEndOfChain;
    uint32_t mini_fat_sectors = 0;
    uint32_t first_difat = kEndOfChain;
    uint32_t difat_sectors = 0;
    std::array<uint32_t, kInlineDifat> inline_difat{};
};

bool parse_header(const uint8_t* h, Header& out) {
    static constexpr uint8_t kMagic[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    if (std::memcmp(h, kMagic, 8) != 0) return false;
    const uint16_t major = rd16(h + 0x1A);
    if (major != 3 && major != 4) return false;
    // The byte-order mark is written 0xFFFE by every producer; a container that says otherwise is
    // either foreign or damage.
    if (rd16(h + 0x1C) != 0xFFFE) return false;
    const uint16_t shift = rd16(h + 0x1E);
    if (shift != 9 && shift != 12) return false;
    if (major == 3 && shift != 9) return false;
    if (major == 4 && shift != 12) return false;
    if (rd16(h + 0x20) != 6) return false;
    for (uint16_t i = 0; i < 6; ++i) {
        if (h[0x22 + i] != 0) return false;  // reserved, written as zero by every producer
    }

    out.version4 = major == 4;
    out.sector_size = 1ull << shift;
    out.entries = out.sector_size / 4;
    out.dir_sectors = rd32(h + 0x28);
    out.fat_sectors = rd32(h + 0x2C);
    out.first_dir = rd32(h + 0x30);
    const uint32_t cutoff = rd32(h + 0x38);
    if (cutoff < 64 || cutoff > (1u << 20) || cutoff % 64 != 0) return false;
    out.first_mini_fat = rd32(h + 0x3C);
    out.mini_fat_sectors = rd32(h + 0x40);
    out.first_difat = rd32(h + 0x44);
    out.difat_sectors = rd32(h + 0x48);
    for (size_t i = 0; i < kInlineDifat; ++i) out.inline_difat[i] = rd32(h + 0x4C + i * 4);

    if (out.fat_sectors == 0) return false;
    // A chain head is either a sector or the end of nothing; the count beside it has to agree.
    if (out.mini_fat_sectors == 0) {
        if (is_sector_id(out.first_mini_fat)) return false;
    } else if (!is_sector_id(out.first_mini_fat)) {
        return false;
    }
    if (out.difat_sectors == 0) {
        if (is_sector_id(out.first_difat)) return false;
    } else if (!is_sector_id(out.first_difat)) {
        return false;
    }
    if (!out.version4 && out.dir_sectors != 0) return false;
    if (out.version4 && is_sector_id(out.first_dir) && out.dir_sectors == 0) return false;
    return true;
}

struct FatMap {
    bool malformed = false;
    bool past_window = false;
    std::vector<uint32_t> fat_sectors;
    std::vector<uint32_t> difat_chain;
};

// Names the sectors that hold the allocation table. The header lists the first 109 of them and a
// DIFAT chain carries the rest, sector by sector.
FatMap collect_fat_sectors(BoundedReader& reader, const Header& h) {
    FatMap map;
    for (uint32_t i = 0; i < h.fat_sectors && i < kInlineDifat; ++i) {
        if (!is_sector_id(h.inline_difat[i])) {
            map.malformed = true;
            return map;
        }
        map.fat_sectors.push_back(h.inline_difat[i]);
    }
    if (h.fat_sectors <= kInlineDifat) return map;

    uint32_t cur = h.first_difat;
    const uint64_t slots = h.entries - 2;
    for (uint64_t i = 0; i < h.difat_sectors; ++i) {
        if (!is_sector_id(cur)) {
            map.malformed = true;
            return map;
        }
        map.difat_chain.push_back(cur);
        const uint64_t at = sector_at(h.sector_size, cur);
        if (at + h.sector_size > reader.limit()) {
            map.past_window = true;
            return map;
        }
        auto block = reader.read_vec(at, h.sector_size);
        if (!block || block->size() != h.sector_size) {
            map.malformed = true;
            return map;
        }
        for (uint64_t j = 0; j < slots && map.fat_sectors.size() < h.fat_sectors; ++j) {
            const uint32_t id = rd32(block->data() + j * 4);
            if (!is_sector_id(id)) {
                map.malformed = true;
                return map;
            }
            map.fat_sectors.push_back(id);
        }
        if (rd32(block->data() + h.sector_size - 4) != h.difat_sectors) {
            map.malformed = true;
            return map;
        }
        cur = rd32(block->data() + h.sector_size - 8);
    }
    // The chain the header promises is the chain that has to be there, no longer.
    if (cur != kEndOfChain || map.fat_sectors.size() != h.fat_sectors) map.malformed = true;
    return map;
}

struct FatWalk {
    bool malformed = false;
    bool past_window = false;  // a table sector the scan window cannot reach
    bool capped = false;       // more table sectors than this validator reads
    uint64_t sectors_used = 0;  // one past the highest entry that is not free
    uint64_t highest_reference = 0;
    bool has_reference = false;
};

// Reads the allocation table and takes from it the two facts the format never stores anywhere
// else: how many sectors the file owns, and how far any chain reaches into them.
FatWalk walk_fat(BoundedReader& reader, const Header& h, const std::vector<uint32_t>& fat_sectors) {
    FatWalk walk;
    for (uint64_t k = 0; k < fat_sectors.size(); ++k) {
        if (k + 1 > kMaxFatReads) {
            walk.capped = true;
            break;
        }
        const uint64_t at = sector_at(h.sector_size, fat_sectors[static_cast<size_t>(k)]);
        if (at + h.sector_size > reader.limit()) {
            walk.past_window = true;
            break;
        }
        auto block = reader.read_vec(at, h.sector_size);
        if (!block || block->size() != h.sector_size) {
            walk.malformed = true;
            return walk;
        }
        for (uint64_t j = 0; j < h.entries; ++j) {
            const uint32_t value = rd32(block->data() + j * 4);
            // A free entry is the only one that names no sector; the reserved chain markers all sit
            // in sectors the file really owns.
            if (value != kFreeSect) walk.sectors_used = k * h.entries + j + 1;
            if (is_sector_id(value) && static_cast<uint64_t>(value) >= walk.highest_reference) {
                walk.highest_reference = static_cast<uint64_t>(value) + 1;
                walk.has_reference = true;
            }
        }
    }
    return walk;
}

bool read_fat_entry(BoundedReader& reader, const Header& h, const std::vector<uint32_t>& fat_sectors,
                    uint32_t sector, uint32_t& out) {
    const uint64_t index = sector / h.entries;
    if (index >= fat_sectors.size()) return false;
    const uint64_t at =
        sector_at(h.sector_size, fat_sectors[static_cast<size_t>(index)]) + (sector % h.entries) * 4;
    if (at + 4 > reader.limit()) return false;
    auto value = reader.read_vec(at, 4);
    if (!value || value->size() != 4) return false;
    out = rd32(value->data());
    return true;
}

// The name field is UTF-16 with its terminator counted, so a six-character stream is thirteen bytes.
bool name_is(const uint8_t* entry, uint32_t name_bytes, std::string_view want) {
    if (name_bytes < 4 || name_bytes > 64) return false;
    const uint32_t chars = name_bytes / 2 - 1;
    if (chars != want.size()) return false;
    for (uint32_t i = 0; i < chars; ++i) {
        if (rd16(entry + i * 2) != static_cast<uint16_t>(want[i])) return false;
    }
    return true;
}

struct DirectoryScan {
    bool malformed = false;
    bool has_root = false;
    uint64_t streams = 0;
    std::string subtype = "cfb";
};

// Walks the directory to the end of its chain. A container that lists no stream holds nothing a
// recovery report can hand back, so the walk has to find one.
DirectoryScan scan_directory(BoundedReader& reader, const Header& h,
                             const std::vector<uint32_t>& fat_sectors, uint64_t sectors_used,
                             uint64_t file_length) {
    DirectoryScan scan;
    uint32_t cur = h.first_dir;
    for (uint64_t steps = 0; steps < kMaxDirSectors; ++steps) {
        if (!is_sector_id(cur) || cur >= sectors_used) {
            if (steps == 0 || cur != kEndOfChain) scan.malformed = true;
            return scan;
        }
        const uint64_t at = sector_at(h.sector_size, cur);
        auto block = reader.read_vec(at, h.sector_size);
        if (!block || block->size() != h.sector_size) {
            scan.malformed = true;
            return scan;
        }
        for (uint64_t j = 0; j < h.sector_size / kEntryBytes; ++j) {
            const uint8_t* entry = block->data() + j * kEntryBytes;
            const uint32_t name_bytes = rd16(entry + 0x40);
            const uint8_t type = entry[0x42];
            if (type == 0) continue;  // an entry the container never used
            if (type != 1 && type != 2 && type != 5) {
                scan.malformed = true;
                return scan;
            }
            // Every entry sits in a red-black tree keyed by name, so its node is one of two colours.
            if (entry[0x43] > 1) {
                scan.malformed = true;
                return scan;
            }
            if (name_bytes < 4 || name_bytes > 64 || name_bytes % 2 != 0) {
                scan.malformed = true;
                return scan;
            }
            const uint32_t start = rd32(entry + 0x74);
            if (is_sector_id(start) && start >= sectors_used) {
                scan.malformed = true;
                return scan;
            }
            const uint64_t low = rd32(entry + 0x78);
            const uint64_t high = rd32(entry + 0x7C);
            if (!h.version4 && high != 0) {
                scan.malformed = true;
                return scan;
            }
            const uint64_t size = h.version4 ? (low | (high << 32)) : low;
            if (size > file_length) {
                scan.malformed = true;
                return scan;
            }
            if (type == 5) {
                scan.has_root = true;
            } else if (type == 2) {
                ++scan.streams;
                if (scan.subtype == "cfb") {
                    if (name_is(entry, name_bytes, "WordDocument")) {
                        scan.subtype = "doc";
                    } else if (name_is(entry, name_bytes, "Workbook") ||
                               name_is(entry, name_bytes, "Book")) {
                        scan.subtype = "xls";
                    } else if (name_is(entry, name_bytes, "PowerPoint Document")) {
                        scan.subtype = "ppt";
                    }
                }
            }
        }
        if (!read_fat_entry(reader, h, fat_sectors, cur, cur)) {
            scan.malformed = true;
            return scan;
        }
    }
    scan.malformed = true;  // a directory that long is a cycle, not a table of contents
    return scan;
}

}  // namespace

std::span<const std::span<const uint8_t>> CfbSignature::magics() const {
    static std::array<uint8_t, 8> m{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    static std::array<std::span<const uint8_t>, 1> arr{std::span<const uint8_t>(m.data(), 8)};
    return arr;
}

ValidationResult CfbSignature::validate(BoundedReader& reader) const {
    auto hdr = reader.read_vec(0, kHeaderBytes);
    if (!hdr || hdr->size() < kHeaderBytes) return ValidationResult::invalid();
    Header h;
    if (!parse_header(hdr->data(), h)) return ValidationResult::invalid();

    const uint64_t limit = reader.limit();
    const uint64_t max_sectors = (max_file_size() - kHeaderBytes) / h.sector_size;
    const uint64_t coverage = static_cast<uint64_t>(h.fat_sectors) * h.entries;
    if (coverage > max_sectors) return ValidationResult::invalid();
    // The map has to be able to name every table sector it claims exists.
    if (static_cast<uint64_t>(h.fat_sectors) >
        kInlineDifat + static_cast<uint64_t>(h.difat_sectors) * (h.entries - 2))
        return ValidationResult::invalid();
    if (h.difat_sectors > 0 && h.difat_sectors > kMaxDifatSectors) return ValidationResult::invalid();

    const FatMap map = collect_fat_sectors(reader, h);
    if (map.malformed) return ValidationResult::invalid();
    for (uint32_t id : map.fat_sectors) {
        if (id >= coverage) return ValidationResult::invalid();
    }

    const FatWalk walk = walk_fat(reader, h, map.fat_sectors);
    if (walk.malformed || walk.sectors_used == 0) return ValidationResult::invalid();
    if (walk.has_reference && walk.highest_reference > coverage) return ValidationResult::invalid();

    const bool table_readable =
        !map.past_window && !walk.past_window && !walk.capped;
    const bool free_tail = walk.sectors_used < coverage;

    ValidationResult result;
    if (!table_readable || !free_tail) {
        // Either the table continues where the window stops, or every sector it can name is in use
        // and the next one is unwritten. Neither says where the file ends.
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = limit;
        result.subtype = "cfb";
        result.confidence = Confidence::Low;
        if (map.past_window || walk.past_window)
            result.notes.push_back("the allocation table continues past the scan window");
        if (walk.capped) result.notes.push_back("the allocation table is longer than this walk");
        if (table_readable && !free_tail)
            result.notes.push_back("every sector the table describes is in use");
        return result;
    }

    const uint64_t length = kHeaderBytes + walk.sectors_used * h.sector_size;
    // A chain that aims at a sector the table leaves free describes a file that is not here.
    if (walk.has_reference && walk.highest_reference > walk.sectors_used)
        return ValidationResult::invalid();
    for (uint32_t id : map.fat_sectors) {
        if (id >= walk.sectors_used) return ValidationResult::invalid();
    }
    for (uint32_t id : map.difat_chain) {
        if (id >= walk.sectors_used) return ValidationResult::invalid();
    }

    if (length > limit) {
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.length_bytes = limit;
        result.subtype = "cfb";
        result.confidence = Confidence::Low;
        result.notes.push_back("the sector table extends past the scan window");
        return result;
    }

    const DirectoryScan dir = scan_directory(reader, h, map.fat_sectors, walk.sectors_used, length);
    if (dir.malformed || !dir.has_root || dir.streams == 0) return ValidationResult::invalid();

    result.verdict = ValidationResult::Verdict::Valid;
    result.length_bytes = length;
    result.subtype = dir.subtype;
    if (dir.subtype == "cfb") {
        result.confidence = Confidence::Medium;
        result.notes.push_back("no known application stream");
    } else {
        result.confidence = Confidence::High;
    }
    return result;
}

}  // namespace openrecover::carve
