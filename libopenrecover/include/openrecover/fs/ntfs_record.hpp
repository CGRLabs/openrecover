#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/fs/ntfs_attributes.hpp"

namespace openrecover::fs {

inline constexpr uint16_t kNtfsRecordInUse = 0x0001;
inline constexpr uint16_t kNtfsRecordDirectory = 0x0002;

struct NtfsRecord {
    uint64_t record_number = 0;
    uint64_t base_record_ref = 0;
    uint64_t log_sequence = 0;
    uint16_t sequence_number = 0;
    uint16_t hard_link_count = 0;
    uint16_t flags = 0;
    uint32_t bytes_in_use = 0;
    uint32_t bytes_allocated = 0;
    std::vector<NtfsAttribute> attributes;

    bool in_use() const noexcept { return (flags & kNtfsRecordInUse) != 0; }
    bool is_directory() const noexcept { return (flags & kNtfsRecordDirectory) != 0; }
    bool is_extension() const noexcept { return base_record_ref != 0; }
};

enum class NtfsRecordKind {
    File,
    Unused,
    Bad,
};

struct NtfsRecordParse {
    NtfsRecordKind kind = NtfsRecordKind::Bad;
    NtfsRecord record;
};

// Applies the update-sequence fixup and parses the record's attributes. `record_number_hint`
// supplies the record index when the old on-disk header lacks a record-number field.
// A zeroed slot is Unused, "BAAD" is Bad; torn or malformed records are CorruptStructure.
Result<NtfsRecordParse> parse_mft_record(std::span<const uint8_t> raw,
                                        uint64_t record_number_hint = 0);

}  // namespace openrecover::fs
