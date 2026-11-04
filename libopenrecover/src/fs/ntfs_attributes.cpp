#include "openrecover/fs/ntfs_attributes.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "openrecover/common/bytes.hpp"

namespace openrecover::fs {

namespace {

constexpr size_t kMaxAttributes = 256;
constexpr size_t kMaxAttributeListEntries = 4096;

Result<std::vector<NtfsAttribute>> attr_error(const std::string& message) {
    return fail(ErrorCode::CorruptStructure, "invalid NTFS attribute: " + message);
}

}  // namespace

Result<std::vector<NtfsAttribute>> parse_attributes(std::span<const uint8_t> record,
                                                    uint16_t first_attr_offset,
                                                    uint32_t bytes_in_use) {
    if (first_attr_offset > bytes_in_use || bytes_in_use > record.size())
        return attr_error("attribute area is outside the record");

    const ByteView view(record);
    std::vector<NtfsAttribute> attributes;
    size_t pos = first_attr_offset;

    while (true) {
        if (pos + 4 > bytes_in_use) return attr_error("missing terminator");
        const uint32_t type = view.u32le(pos);
        if (type == kNtfsAttrEnd) break;
        if (attributes.size() >= kMaxAttributes) return attr_error("too many attributes");
        if (pos + 16 > bytes_in_use) return attr_error("truncated header");

        const uint32_t length = view.u32le(pos + 4);
        if (length < 16) return attr_error("attribute length is below 16");
        if (length % 8 != 0) return attr_error("attribute length is not a multiple of 8");
        if (length > bytes_in_use - pos) return attr_error("attribute extends past the used bytes");

        const uint8_t non_resident = view.u8(pos + 8);
        if (non_resident > 1) return attr_error("residency flag is invalid");

        NtfsAttribute attr;
        attr.type = type;
        attr.length = length;
        attr.flags = view.u16le(pos + 0x0C);
        attr.attr_id = view.u16le(pos + 0x0E);
        attr.non_resident = non_resident != 0;
        attr.record_offset = static_cast<uint32_t>(pos);

        const uint8_t name_length = view.u8(pos + 9);
        const uint16_t name_offset = view.u16le(pos + 0x0A);
        if (name_length != 0) {
            const size_t name_bytes = static_cast<size_t>(name_length) * 2;
            if (name_offset > length || name_bytes > length - name_offset)
                return attr_error("attribute name is outside the attribute");
            if (name_offset < 16) return attr_error("attribute name overlaps the header");
            attr.name = utf16le_to_utf8(
                record.subspan(pos + name_offset, name_bytes));
        }

        if (!attr.non_resident) {
            if (length < 0x18) return attr_error("resident header is truncated");
            const uint32_t content_length = view.u32le(pos + 0x10);
            const uint16_t content_offset = view.u16le(pos + 0x14);
            if (content_offset < 0x18) return attr_error("resident content overlaps the header");
            if (content_offset > length || content_length > length - content_offset)
                return attr_error("resident content is outside the attribute");
            attr.resident_data.assign(record.begin() + static_cast<std::ptrdiff_t>(pos + content_offset),
                                      record.begin() + static_cast<std::ptrdiff_t>(pos + content_offset +
                                                                                   content_length));
        } else {
            if (length < 0x40) return attr_error("non-resident header is truncated");
            attr.start_vcn = view.u64le(pos + 0x10);
            attr.end_vcn = view.u64le(pos + 0x18);
            attr.compression_unit = view.u16le(pos + 0x22);
            attr.allocated_size = view.u64le(pos + 0x28);
            attr.real_size = view.u64le(pos + 0x30);
            attr.initialized_size = view.u64le(pos + 0x38);

            const uint16_t runlist_offset = view.u16le(pos + 0x20);
            if (runlist_offset < 0x40) return attr_error("runlist overlaps the header");
            if (runlist_offset > length) return attr_error("runlist is outside the attribute");
            if (attr.end_vcn < attr.start_vcn) return attr_error("end VCN precedes start VCN");
            attr.runlist.assign(
                record.begin() + static_cast<std::ptrdiff_t>(pos + runlist_offset),
                record.begin() + static_cast<std::ptrdiff_t>(pos + length));
        }

        attributes.push_back(std::move(attr));
        pos += length;
    }
    return attributes;
}

int64_t filetime_to_unix(uint64_t ticks) {
    constexpr int64_t kUnixEpochInFiletime = 11644473600LL;
    return static_cast<int64_t>(ticks / 10000000ull) - kUnixEpochInFiletime;
}

Result<NtfsStandardInformation> parse_standard_information(std::span<const uint8_t> content) {
    if (content.size() < 0x20)
        return fail(ErrorCode::CorruptStructure, "$STANDARD_INFORMATION is truncated");
    const ByteView view(content);
    NtfsStandardInformation info;
    info.created_unix = filetime_to_unix(view.u64le(0x00));
    info.modified_unix = filetime_to_unix(view.u64le(0x08));
    info.mft_changed_unix = filetime_to_unix(view.u64le(0x10));
    info.accessed_unix = filetime_to_unix(view.u64le(0x18));
    return info;
}

Result<NtfsFileName> parse_file_name(std::span<const uint8_t> content) {
    if (content.size() < 0x42)
        return fail(ErrorCode::CorruptStructure, "$FILE_NAME is truncated");
    const ByteView view(content);
    const size_t name_length = view.u8(0x40);
    const size_t required = 0x42 + name_length * 2;
    if (content.size() < required)
        return fail(ErrorCode::CorruptStructure, "$FILE_NAME name is truncated");

    NtfsFileName name;
    name.parent_ref = view.u64le(0x00);
    name.created_unix = filetime_to_unix(view.u64le(0x08));
    name.modified_unix = filetime_to_unix(view.u64le(0x10));
    name.mft_changed_unix = filetime_to_unix(view.u64le(0x18));
    name.accessed_unix = filetime_to_unix(view.u64le(0x20));
    name.allocated_size = view.u64le(0x28);
    name.real_size = view.u64le(0x30);
    name.file_attributes = view.u32le(0x38);
    name.name_space = view.u8(0x41);
    name.name = utf16le_to_utf8(content.subspan(0x42, name_length * 2));
    return name;
}

int ntfs_file_name_preference(uint8_t name_space) noexcept {
    switch (name_space) {
        case 1:
        case 3:
            return 0;
        case 0:
            return 1;
        case 2:
            return 2;
        default:
            return 3;
    }
}

const NtfsFileName* best_file_name(std::span<const NtfsFileName> names) noexcept {
    const NtfsFileName* best = nullptr;
    int best_rank = std::numeric_limits<int>::max();
    for (const auto& name : names) {
        const int rank = ntfs_file_name_preference(name.name_space);
        if (rank < best_rank) {
            best_rank = rank;
            best = &name;
        }
    }
    return best;
}

Result<std::vector<NtfsAttributeListEntry>> parse_attribute_list(
    std::span<const uint8_t> content) {
    const ByteView view(content);
    std::vector<NtfsAttributeListEntry> entries;
    size_t pos = 0;

    while (pos < content.size()) {
        if (pos + 4 > content.size())
            return fail(ErrorCode::CorruptStructure, "truncated $ATTRIBUTE_LIST entry type");
        const uint32_t type = view.u32le(pos);
        if (type == kNtfsAttrEnd) break;
        if (pos + 0x1A > content.size())
            return fail(ErrorCode::CorruptStructure, "truncated $ATTRIBUTE_LIST entry");
        if (entries.size() >= kMaxAttributeListEntries)
            return fail(ErrorCode::CorruptStructure, "too many $ATTRIBUTE_LIST entries");

        const uint16_t length = view.u16le(pos + 4);
        if (length < 0x1A)
            return fail(ErrorCode::CorruptStructure, "$ATTRIBUTE_LIST entry is too short");
        if (length > content.size() - pos)
            return fail(ErrorCode::CorruptStructure, "$ATTRIBUTE_LIST entry extends past the attribute");

        const uint8_t name_length = view.u8(pos + 6);
        const uint8_t name_offset = view.u8(pos + 7);

        NtfsAttributeListEntry entry;
        entry.type = type;
        entry.start_vcn = view.u64le(pos + 8);
        entry.mft_ref = view.u64le(pos + 0x10);
        entry.attr_id = view.u16le(pos + 0x18);
        if (name_length != 0) {
            const size_t name_bytes = static_cast<size_t>(name_length) * 2;
            if (name_offset < 0x1A || name_offset > length || name_bytes > length - name_offset)
                return fail(ErrorCode::CorruptStructure,
                            "$ATTRIBUTE_LIST entry name is outside the entry");
            entry.name = utf16le_to_utf8(content.subspan(pos + name_offset, name_bytes));
        }
        entries.push_back(std::move(entry));
        pos += length;
    }
    return entries;
}

}  // namespace openrecover::fs
