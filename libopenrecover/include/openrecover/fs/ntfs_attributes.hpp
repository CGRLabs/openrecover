#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"

namespace openrecover::fs {

inline constexpr uint32_t kNtfsAttrStandardInformation = 0x10;
inline constexpr uint32_t kNtfsAttrAttributeList = 0x20;
inline constexpr uint32_t kNtfsAttrFileName = 0x30;
inline constexpr uint32_t kNtfsAttrData = 0x80;
inline constexpr uint32_t kNtfsAttrIndexRoot = 0x90;
inline constexpr uint32_t kNtfsAttrIndexAllocation = 0xA0;
inline constexpr uint32_t kNtfsAttrBitmap = 0xB0;
inline constexpr uint32_t kNtfsAttrEnd = 0xFFFFFFFF;

inline constexpr uint16_t kNtfsAttrCompressed = 0x0001;
inline constexpr uint16_t kNtfsAttrEncrypted = 0x4000;
inline constexpr uint16_t kNtfsAttrSparse = 0x8000;

inline uint64_t ntfs_record_index(uint64_t file_ref) { return file_ref & 0x0000FFFFFFFFFFFFull; }
inline uint16_t ntfs_record_sequence(uint64_t file_ref) {
    return static_cast<uint16_t>(file_ref >> 48);
}

struct NtfsAttribute {
    uint32_t type = 0;
    uint32_t length = 0;
    uint16_t flags = 0;
    uint16_t attr_id = 0;
    bool non_resident = false;
    std::string name;

    // Resident attributes.
    std::vector<uint8_t> resident_data;

    // Non-resident attributes.
    uint64_t start_vcn = 0;
    uint64_t end_vcn = 0;
    uint64_t allocated_size = 0;
    uint64_t real_size = 0;
    uint64_t initialized_size = 0;
    uint16_t compression_unit = 0;
    std::vector<uint8_t> runlist;
    uint32_t record_offset = 0;

    bool compressed() const noexcept { return (flags & kNtfsAttrCompressed) != 0; }
    bool encrypted() const noexcept { return (flags & kNtfsAttrEncrypted) != 0; }
    bool sparse() const noexcept { return (flags & kNtfsAttrSparse) != 0; }
};

// Iterates the attributes inside a fixed-up MFT record. `bytes_in_use` bounds the iteration;
// the 0xFFFFFFFF terminator is required.
Result<std::vector<NtfsAttribute>> parse_attributes(std::span<const uint8_t> record,
                                                    uint16_t first_attr_offset,
                                                    uint32_t bytes_in_use);

// FILETIME (100 ns ticks since 1601-01-01 UTC) to Unix seconds.
int64_t filetime_to_unix(uint64_t ticks);

struct NtfsStandardInformation {
    int64_t created_unix = 0;
    int64_t modified_unix = 0;
    int64_t mft_changed_unix = 0;
    int64_t accessed_unix = 0;
};

Result<NtfsStandardInformation> parse_standard_information(std::span<const uint8_t> content);

struct NtfsFileName {
    uint64_t parent_ref = 0;
    int64_t created_unix = 0;
    int64_t modified_unix = 0;
    int64_t mft_changed_unix = 0;
    int64_t accessed_unix = 0;
    uint64_t allocated_size = 0;
    uint64_t real_size = 0;
    uint32_t file_attributes = 0;
    uint8_t name_space = 0;
    std::string name;

    uint64_t parent_record() const noexcept { return ntfs_record_index(parent_ref); }
    uint16_t parent_sequence() const noexcept { return ntfs_record_sequence(parent_ref); }
};

Result<NtfsFileName> parse_file_name(std::span<const uint8_t> content);

// Win32 (1) and Win32+DOS (3) beat POSIX (0), which beats DOS (2). Lower is better.
int ntfs_file_name_preference(uint8_t name_space) noexcept;
const NtfsFileName* best_file_name(std::span<const NtfsFileName> names) noexcept;

struct NtfsAttributeListEntry {
    uint32_t type = 0;
    std::string name;
    uint64_t start_vcn = 0;
    uint64_t mft_ref = 0;
    uint16_t attr_id = 0;

    uint64_t mft_record() const noexcept { return ntfs_record_index(mft_ref); }
    uint16_t sequence() const noexcept { return ntfs_record_sequence(mft_ref); }
};

Result<std::vector<NtfsAttributeListEntry>> parse_attribute_list(
    std::span<const uint8_t> content);

}  // namespace openrecover::fs
