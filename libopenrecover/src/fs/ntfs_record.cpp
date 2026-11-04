#include "openrecover/fs/ntfs_record.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "openrecover/common/bytes.hpp"

namespace openrecover::fs {

namespace {

Result<NtfsRecordParse> record_error(const char* message) {
    return fail(ErrorCode::CorruptStructure, std::string("invalid NTFS MFT record: ") + message);
}

}  // namespace

Result<NtfsRecordParse> parse_mft_record(std::span<const uint8_t> raw,
                                        uint64_t record_number_hint) {
    if (raw.size() < 512 || raw.size() % 512 != 0)
        return record_error("size is not a positive multiple of 512");

    if (std::all_of(raw.begin(), raw.end(), [](uint8_t b) { return b == 0; }))
        return NtfsRecordParse{NtfsRecordKind::Unused, {}};
    if (std::memcmp(raw.data(), "BAAD", 4) == 0)
        return NtfsRecordParse{NtfsRecordKind::Bad, {}};
    if (std::memcmp(raw.data(), "FILE", 4) != 0)
        return record_error("bad magic");

    std::vector<uint8_t> data(raw.begin(), raw.end());
    ByteView view(data);

    const uint16_t usa_offset = view.u16le(0x04);
    const uint16_t usa_count = view.u16le(0x06);
    if (usa_count == 0) return record_error("update sequence count is zero");
    const size_t usa_bytes = static_cast<size_t>(usa_count) * 2;
    if (usa_offset > data.size() || usa_bytes > data.size() - usa_offset)
        return record_error("update sequence array is outside the record");
    if (static_cast<size_t>(usa_count) - 1 != data.size() / 512)
        return record_error("update sequence count does not match the record size");

    const uint16_t usn = view.u16le(usa_offset);
    std::vector<uint16_t> replacements;
    replacements.reserve(usa_count - 1u);
    for (size_t i = 1; i < usa_count; ++i) {
        replacements.push_back(view.u16le(usa_offset + i * 2));
    }
    for (size_t i = 1; i < usa_count; ++i) {
        const size_t stripe_end = i * 512 - 2;
        if (view.u16le(stripe_end) != usn)
            return record_error("torn record: update sequence mismatch");
        data[stripe_end] = static_cast<uint8_t>(replacements[i - 1]);
        data[stripe_end + 1] = static_cast<uint8_t>(replacements[i - 1] >> 8);
    }

    NtfsRecord record;
    record.log_sequence = view.u64le(0x08);
    record.sequence_number = view.u16le(0x10);
    record.hard_link_count = view.u16le(0x12);
    const uint16_t first_attr_offset = view.u16le(0x14);
    record.flags = view.u16le(0x16);
    record.bytes_in_use = view.u32le(0x18);
    record.bytes_allocated = view.u32le(0x1C);
    record.base_record_ref = view.u64le(0x20);
    record.record_number =
        first_attr_offset >= 0x30 ? view.u32le(0x2C) : record_number_hint;

    if (first_attr_offset < 0x28)
        return record_error("first attribute offset overlaps the fixed header");
    if (record.bytes_in_use > data.size())
        return record_error("bytes in use exceeds the record size");
    if (first_attr_offset > record.bytes_in_use)
        return record_error("first attribute offset is past the used bytes");

    auto attributes = parse_attributes(data, first_attr_offset, record.bytes_in_use);
    if (!attributes) return fail(attributes.error());
    record.attributes = std::move(*attributes);

    return NtfsRecordParse{NtfsRecordKind::File, std::move(record)};
}

}  // namespace openrecover::fs
