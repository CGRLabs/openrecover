#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "openrecover/fs/ntfs_attributes.hpp"
#include "openrecover/fs/ntfs_record.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::fs;

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

size_t align8(size_t v) { return (v + 7) / 8 * 8; }

std::vector<uint8_t> utf16_bytes(std::u16string_view s) {
    std::vector<uint8_t> out;
    for (char16_t c : s) {
        out.push_back(static_cast<uint8_t>(c));
        out.push_back(static_cast<uint8_t>(c >> 8));
    }
    return out;
}

std::vector<uint8_t> make_resident(uint32_t type, uint16_t attr_id,
                                   std::span<const uint8_t> content,
                                   std::u16string_view name = u"", uint16_t flags = 0) {
    const size_t name_bytes = name.size() * 2;
    const size_t content_offset = align8(0x18 + name_bytes);
    const size_t length = align8(content_offset + content.size());
    std::vector<uint8_t> attr(length, 0);
    put32(attr, 0, type);
    put32(attr, 4, static_cast<uint32_t>(length));
    attr[8] = 0;
    attr[9] = static_cast<uint8_t>(name.size());
    put16(attr, 0x0A, name.empty() ? 0 : 0x18);
    put16(attr, 0x0C, flags);
    put16(attr, 0x0E, attr_id);
    put32(attr, 0x10, static_cast<uint32_t>(content.size()));
    put16(attr, 0x14, static_cast<uint16_t>(content_offset));
    const std::vector<uint8_t> name_data = utf16_bytes(name);
    std::copy(name_data.begin(), name_data.end(), attr.begin() + 0x18);
    std::copy(content.begin(), content.end(),
              attr.begin() + static_cast<std::ptrdiff_t>(content_offset));
    return attr;
}

std::vector<uint8_t> make_non_resident(uint32_t type, uint16_t attr_id,
                                       std::initializer_list<int> runlist,
                                       std::u16string_view name = u"") {
    const size_t name_bytes = name.size() * 2;
    const size_t runlist_offset = align8(0x40 + name_bytes);
    const size_t length = align8(runlist_offset + runlist.size());
    std::vector<uint8_t> attr(length, 0);
    put32(attr, 0, type);
    put32(attr, 4, static_cast<uint32_t>(length));
    attr[8] = 1;
    attr[9] = static_cast<uint8_t>(name.size());
    put16(attr, 0x0A, name.empty() ? 0 : 0x40);
    put16(attr, 0x0C, 0);
    put16(attr, 0x0E, attr_id);
    put64(attr, 0x10, 4);
    put64(attr, 0x18, 6);
    put16(attr, 0x20, static_cast<uint16_t>(runlist_offset));
    put64(attr, 0x28, 3072);
    put64(attr, 0x30, 2048);
    put64(attr, 0x38, 1024);
    const std::vector<uint8_t> name_data = utf16_bytes(name);
    std::copy(name_data.begin(), name_data.end(), attr.begin() + 0x40);
    size_t at = runlist_offset;
    for (int byte : runlist) attr[at++] = static_cast<uint8_t>(byte);
    return attr;
}

struct RecordOptions {
    uint32_t record_number = 24;
    uint16_t sequence = 7;
    uint16_t flags = kNtfsRecordInUse;
    uint64_t base_record_ref = 0;
    uint16_t first_attr_offset = 0x38;
    uint16_t usa_offset = 0x30;
    bool torn = false;
};

constexpr uint16_t kUsn = 0xA55A;
constexpr uint16_t kReplacement0 = 0x1234;
constexpr uint16_t kReplacement1 = 0x5678;

std::vector<uint8_t> make_record(const std::vector<uint8_t>& attrs,
                                 const RecordOptions& options = {}) {
    std::vector<uint8_t> rec(1024, 0);
    std::memcpy(rec.data(), "FILE", 4);
    put16(rec, 0x04, options.usa_offset);
    put16(rec, 0x06, 3);
    put64(rec, 0x08, 0x1122334455667788ull);
    put16(rec, 0x10, options.sequence);
    put16(rec, 0x12, 1);
    put16(rec, 0x14, options.first_attr_offset);
    put16(rec, 0x16, options.flags);
    put32(rec, 0x18, static_cast<uint32_t>(options.first_attr_offset + attrs.size() + 4));
    put32(rec, 0x1C, 1024);
    put64(rec, 0x20, options.base_record_ref);
    put16(rec, 0x28, 0x10);
    if (options.first_attr_offset >= 0x30) put32(rec, 0x2C, options.record_number);

    put16(rec, options.usa_offset, kUsn);
    put16(rec, static_cast<size_t>(options.usa_offset) + 2, kReplacement0);
    put16(rec, static_cast<size_t>(options.usa_offset) + 4, kReplacement1);

    std::copy(attrs.begin(), attrs.end(), rec.begin() + options.first_attr_offset);
    put32(rec, static_cast<size_t>(options.first_attr_offset) + attrs.size(), kNtfsAttrEnd);
    put16(rec, 510, kUsn);
    put16(rec, 1022, options.torn ? 0xFFFF : kUsn);
    return rec;
}

std::vector<uint8_t> file_name_content(std::u16string_view name, uint64_t parent_ref,
                                       uint8_t name_space = 1) {
    const size_t length = 0x42 + name.size() * 2;
    std::vector<uint8_t> content(length, 0);
    put64(content, 0x00, parent_ref);
    put64(content, 0x08, 132000000000000000ull);
    put64(content, 0x10, 133000000000000000ull);
    put64(content, 0x18, 134000000000000000ull);
    put64(content, 0x20, 135000000000000000ull);
    put64(content, 0x28, 4096);
    put64(content, 0x30, 3000);
    put32(content, 0x38, 0x20);
    content[0x40] = static_cast<uint8_t>(name.size());
    content[0x41] = name_space;
    const std::vector<uint8_t> name_data = utf16_bytes(name);
    std::copy(name_data.begin(), name_data.end(), content.begin() + 0x42);
    return content;
}

std::vector<uint8_t> attribute_list_entry(uint32_t type, uint64_t mft_ref, uint16_t attr_id,
                                          uint64_t start_vcn = 0, std::u16string_view name = u"") {
    const size_t name_bytes = name.size() * 2;
    const size_t length = align8(0x1A + name_bytes);
    std::vector<uint8_t> entry(length, 0);
    put32(entry, 0, type);
    put16(entry, 4, static_cast<uint16_t>(length));
    entry[6] = static_cast<uint8_t>(name.size());
    entry[7] = name.empty() ? 0 : 0x1A;
    put64(entry, 8, start_vcn);
    put64(entry, 0x10, mft_ref);
    put16(entry, 0x18, attr_id);
    const std::vector<uint8_t> name_data = utf16_bytes(name);
    std::copy(name_data.begin(), name_data.end(), entry.begin() + 0x1A);
    return entry;
}

std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

std::vector<uint8_t> with_attr_terminator(std::vector<uint8_t> area) {
    area.resize(area.size() + 4, 0);
    put32(area, area.size() - 4, kNtfsAttrEnd);
    return area;
}

}  // namespace

TEST_CASE("MFT record applies the update-sequence fixup", "[ntfs][record]") {
    const std::vector<uint8_t> file_name = file_name_content(u"report.txt", (5ull << 48) | 5);
    const std::vector<uint8_t> attr = make_resident(kNtfsAttrFileName, 3, file_name);
    RecordOptions options;
    options.first_attr_offset = 0x1F0;
    const std::vector<uint8_t> raw = make_record(attr, options);

    auto parsed = parse_mft_record(raw, 99);
    REQUIRE(parsed);
    CHECK(parsed->kind == NtfsRecordKind::File);
    const NtfsRecord& rec = parsed->record;
    CHECK(rec.record_number == 24);
    CHECK(rec.sequence_number == 7);
    CHECK(rec.flags == kNtfsRecordInUse);
    CHECK(rec.in_use());
    CHECK_FALSE(rec.is_directory());
    CHECK_FALSE(rec.is_extension());
    CHECK(rec.bytes_in_use == 0x1F0 + attr.size() + 4);
    REQUIRE(rec.attributes.size() == 1);
    CHECK(rec.attributes[0].attr_id == kReplacement0);
    CHECK(rec.attributes[0].type == kNtfsAttrFileName);
    REQUIRE(rec.attributes[0].resident_data.size() == file_name.size());
    CHECK(rec.attributes[0].resident_data == file_name);
}

TEST_CASE("MFT record exposes header and extension fields", "[ntfs][record]") {
    const std::vector<uint8_t> attrs = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{});
    RecordOptions options;
    options.record_number = 77;
    options.flags = 0;
    options.sequence = 0x1234;
    options.base_record_ref = (0x0005ull << 48) | 42;
    auto parsed = parse_mft_record(make_record(attrs, options));
    REQUIRE(parsed);
    REQUIRE(parsed->kind == NtfsRecordKind::File);
    CHECK(parsed->record.record_number == 77);
    CHECK(parsed->record.sequence_number == 0x1234);
    CHECK_FALSE(parsed->record.in_use());
    CHECK(parsed->record.is_extension());
    CHECK(parsed->record.base_record_ref == ((0x0005ull << 48) | 42));
}

TEST_CASE("MFT record derives its number for a legacy header", "[ntfs][record]") {
    RecordOptions options;
    options.first_attr_offset = 0x28;
    options.usa_offset = 0x100;
    const std::vector<uint8_t> attrs = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{});
    auto parsed = parse_mft_record(make_record(attrs, options), 4242);
    REQUIRE(parsed);
    REQUIRE(parsed->kind == NtfsRecordKind::File);
    CHECK(parsed->record.record_number == 4242);
}

TEST_CASE("MFT record reports unused and bad slots", "[ntfs][record]") {
    const std::vector<uint8_t> zeros(1024, 0);
    auto unused = parse_mft_record(zeros);
    REQUIRE(unused);
    CHECK(unused->kind == NtfsRecordKind::Unused);

    std::vector<uint8_t> baad(1024, 0);
    std::memcpy(baad.data(), "BAAD", 4);
    auto bad = parse_mft_record(baad);
    REQUIRE(bad);
    CHECK(bad->kind == NtfsRecordKind::Bad);

    std::vector<uint8_t> junk(1024, 0);
    std::memcpy(junk.data(), "JUNK", 4);
    auto invalid = parse_mft_record(junk);
    REQUIRE_FALSE(invalid);
    CHECK(invalid.error().code == ErrorCode::CorruptStructure);
}

TEST_CASE("MFT record rejects torn or malformed fixups", "[ntfs][record]") {
    RecordOptions torn;
    torn.torn = true;
    const std::vector<uint8_t> attrs = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{});

    auto torn_result = parse_mft_record(make_record(attrs, torn));
    REQUIRE_FALSE(torn_result);
    CHECK(torn_result.error().code == ErrorCode::CorruptStructure);

    auto wrong_count = make_record(attrs);
    put16(wrong_count, 0x06, 2);
    REQUIRE_FALSE(parse_mft_record(wrong_count));

    auto bad_offset = make_record(attrs);
    put16(bad_offset, 0x04, 0x7FE);
    REQUIRE_FALSE(parse_mft_record(bad_offset));

    auto zero_count = make_record(attrs);
    put16(zero_count, 0x06, 0);
    REQUIRE_FALSE(parse_mft_record(zero_count));

    REQUIRE_FALSE(parse_mft_record(std::vector<uint8_t>(256, 0)));
    REQUIRE_FALSE(parse_mft_record(std::vector<uint8_t>(1000, 0)));
}

TEST_CASE("MFT record rejects invalid header offsets", "[ntfs][record]") {
    const std::vector<uint8_t> attrs = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{});

    auto low_offset = make_record(attrs);
    put16(low_offset, 0x14, 0x20);
    REQUIRE_FALSE(parse_mft_record(low_offset));

    auto high_offset = make_record(attrs);
    put16(high_offset, 0x14, 0x3FF);
    REQUIRE_FALSE(parse_mft_record(high_offset));

    auto huge_use = make_record(attrs);
    put32(huge_use, 0x18, 4096);
    REQUIRE_FALSE(parse_mft_record(huge_use));
}

TEST_CASE("attribute parser reads resident and non-resident attributes", "[ntfs][attributes]") {
    const std::vector<uint8_t> content = {'h', 'e', 'l', 'l', 'o'};
    const std::vector<uint8_t> resident =
        make_resident(kNtfsAttrData, 4, content, u"stream", kNtfsAttrSparse);
    const std::vector<uint8_t> non_resident =
        make_non_resident(kNtfsAttrData, 5, {0x11, 0x02, 0x20, 0x00}, u"big");
    const std::vector<uint8_t> area = concat({resident, non_resident});

    auto attrs = parse_attributes(area, 0, static_cast<uint32_t>(area.size() + 4));
    REQUIRE_FALSE(attrs);

    const std::vector<uint8_t> with_terminator = with_attr_terminator(area);
    attrs = parse_attributes(with_terminator, 0,
                             static_cast<uint32_t>(with_terminator.size()));
    REQUIRE(attrs);
    REQUIRE(attrs->size() == 2);

    const NtfsAttribute& first = (*attrs)[0];
    CHECK(first.type == kNtfsAttrData);
    CHECK_FALSE(first.non_resident);
    CHECK(first.name == "stream");
    CHECK(first.resident_data == content);
    CHECK(first.flags == kNtfsAttrSparse);
    CHECK(first.sparse());
    CHECK(first.record_offset == 0);

    const NtfsAttribute& second = (*attrs)[1];
    CHECK(second.non_resident);
    CHECK(second.name == "big");
    CHECK(second.start_vcn == 4);
    CHECK(second.end_vcn == 6);
    CHECK(second.allocated_size == 3072);
    CHECK(second.real_size == 2048);
    CHECK(second.initialized_size == 1024);
    REQUIRE(second.runlist.size() >= 4);
    CHECK(second.runlist[0] == 0x11);
    CHECK(second.record_offset == resident.size());
}

TEST_CASE("attribute parser rejects truncated and looping attributes", "[ntfs][attributes]") {
    SECTION("missing terminator") {
        const std::vector<uint8_t> attr = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{});
        auto attrs = parse_attributes(attr, 0, static_cast<uint32_t>(attr.size()));
        REQUIRE_FALSE(attrs);
        CHECK(attrs.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("zero length is rejected instead of looping") {
        std::vector<uint8_t> area(64, 0);
        put32(area, 0, kNtfsAttrData);
        put32(area, 4, 0);
        put32(area, 16, kNtfsAttrEnd);
        auto attrs = parse_attributes(area, 0, 20);
        REQUIRE_FALSE(attrs);
    }
    SECTION("length below the minimum") {
        std::vector<uint8_t> area(64, 0);
        put32(area, 0, kNtfsAttrData);
        put32(area, 4, 8);
        put32(area, 16, kNtfsAttrEnd);
        auto attrs = parse_attributes(area, 0, 20);
        REQUIRE_FALSE(attrs);
    }
    SECTION("length not a multiple of eight") {
        std::vector<uint8_t> attr = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{});
        put32(attr, 4, 20);
        put32(attr, 20, kNtfsAttrEnd);
        auto attrs = parse_attributes(attr, 0, static_cast<uint32_t>(attr.size()));
        REQUIRE_FALSE(attrs);
    }
    SECTION("attribute extends past bytes in use") {
        const std::vector<uint8_t> attr = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{});
        const std::vector<uint8_t> area = with_attr_terminator(attr);
        auto attrs = parse_attributes(area, 0, static_cast<uint32_t>(area.size() - 8));
        REQUIRE_FALSE(attrs);
    }
    SECTION("name outside the attribute") {
        std::vector<uint8_t> attr = make_resident(kNtfsAttrData, 1, std::span<const uint8_t>{}, u"name");
        put16(attr, 0x0A, 0xFFF0);
        const std::vector<uint8_t> area = with_attr_terminator(attr);
        auto attrs = parse_attributes(area, 0, static_cast<uint32_t>(area.size()));
        REQUIRE_FALSE(attrs);
    }
    SECTION("resident content outside the attribute") {
        std::vector<uint8_t> attr = make_resident(kNtfsAttrData, 1, std::vector<uint8_t>{1, 2, 3});
        put32(attr, 0x10, 500);
        const std::vector<uint8_t> area = with_attr_terminator(attr);
        auto attrs = parse_attributes(area, 0, static_cast<uint32_t>(area.size()));
        REQUIRE_FALSE(attrs);
    }
    SECTION("non-resident runlist overlaps the header") {
        std::vector<uint8_t> attr = make_non_resident(kNtfsAttrData, 1, {0x00});
        put16(attr, 0x20, 0x10);
        const std::vector<uint8_t> area = with_attr_terminator(attr);
        auto attrs = parse_attributes(area, 0, static_cast<uint32_t>(area.size()));
        REQUIRE_FALSE(attrs);
    }
    SECTION("non-resident end VCN precedes start VCN") {
        std::vector<uint8_t> attr = make_non_resident(kNtfsAttrData, 1, {0x00});
        put64(attr, 0x18, 1);
        const std::vector<uint8_t> area = with_attr_terminator(attr);
        auto attrs = parse_attributes(area, 0, static_cast<uint32_t>(area.size()));
        REQUIRE_FALSE(attrs);
    }
}

TEST_CASE("attribute parser caps the attribute count", "[ntfs][attributes]") {
    std::vector<uint8_t> area;
    for (int i = 0; i < 257; ++i) {
        const std::vector<uint8_t> attr = make_resident(kNtfsAttrData, static_cast<uint16_t>(i), std::span<const uint8_t>{});
        area.insert(area.end(), attr.begin(), attr.end());
    }
    area = with_attr_terminator(area);
    auto attrs = parse_attributes(area, 0, static_cast<uint32_t>(area.size()));
    REQUIRE_FALSE(attrs);
    CHECK(attrs.error().code == ErrorCode::CorruptStructure);
}

TEST_CASE("FILETIME conversion covers the epoch boundaries", "[ntfs][attributes]") {
    CHECK(filetime_to_unix(0) == -11644473600LL);
    CHECK(filetime_to_unix(116444736000000000ull) == 0);
    CHECK(filetime_to_unix(157469184000000000ull) == 4102444800LL);
    CHECK(filetime_to_unix(116444736000000000ull + 25000000ull) == 2);
}

TEST_CASE("$STANDARD_INFORMATION supplies all four timestamps", "[ntfs][attributes]") {
    std::vector<uint8_t> content(0x48, 0);
    put64(content, 0x00, 116444736000000000ull);
    put64(content, 0x08, 116444736010000000ull);
    put64(content, 0x10, 116444736020000000ull);
    put64(content, 0x18, 116444736030000000ull);
    auto info = parse_standard_information(content);
    REQUIRE(info);
    CHECK(info->created_unix == 0);
    CHECK(info->modified_unix == 1);
    CHECK(info->mft_changed_unix == 2);
    CHECK(info->accessed_unix == 3);

    REQUIRE_FALSE(parse_standard_information(std::vector<uint8_t>(16, 0)));
}

TEST_CASE("$FILE_NAME decodes parent, sizes and UTF-16 name", "[ntfs][attributes]") {
    const uint64_t parent = (0x0003ull << 48) | 5;
    const std::vector<uint8_t> content = file_name_content(u"Quarterly \u00DCber.txt", parent);
    auto name = parse_file_name(content);
    REQUIRE(name);
    CHECK(name->parent_ref == parent);
    CHECK(name->parent_record() == 5);
    CHECK(name->parent_sequence() == 3);
    CHECK(name->allocated_size == 4096);
    CHECK(name->real_size == 3000);
    CHECK(name->file_attributes == 0x20);
    CHECK(name->name_space == 1);
    CHECK(name->name == "Quarterly \xC3\x9C" "ber.txt");
    CHECK(name->created_unix == filetime_to_unix(132000000000000000ull));

    REQUIRE_FALSE(parse_file_name(std::vector<uint8_t>(0x41, 0)));
}

TEST_CASE("$FILE_NAME namespace preference chooses the best name", "[ntfs][attributes]") {
    auto make = [](uint8_t name_space, std::string text) {
        NtfsFileName name;
        name.name_space = name_space;
        name.name = std::move(text);
        return name;
    };
    {
        std::vector<NtfsFileName> names = {make(2, "SHORT.TXT"), make(0, "posix"),
                                           make(1, "Win32.txt"), make(3, "both.txt")};
        const NtfsFileName* best = best_file_name(names);
        REQUIRE(best);
        CHECK(best->name == "Win32.txt");
    }
    {
        std::vector<NtfsFileName> names = {make(2, "SHORT.TXT"), make(0, "posix")};
        CHECK(best_file_name(names)->name == "posix");
    }
    {
        std::vector<NtfsFileName> names = {make(2, "SHORT.TXT"), make(3, "both.txt")};
        CHECK(best_file_name(names)->name == "both.txt");
    }
    {
        std::vector<NtfsFileName> names;
        CHECK(best_file_name(names) == nullptr);
    }
    CHECK(ntfs_file_name_preference(1) == 0);
    CHECK(ntfs_file_name_preference(3) == 0);
    CHECK(ntfs_file_name_preference(0) == 1);
    CHECK(ntfs_file_name_preference(2) == 2);
    CHECK(ntfs_file_name_preference(7) == 3);
}

TEST_CASE("$ATTRIBUTE_LIST entries reference extension records", "[ntfs][attributes]") {
    const uint64_t name_ref = (0x0004ull << 48) | 11;
    const uint64_t data_ref = (0x0009ull << 48) | 11;
    const std::vector<uint8_t> list = concat(
        {attribute_list_entry(kNtfsAttrFileName, 11, 3), attribute_list_entry(kNtfsAttrData, 11, 7),
         attribute_list_entry(kNtfsAttrData, data_ref, 8)});

    auto entries = parse_attribute_list(list);
    REQUIRE(entries);
    REQUIRE(entries->size() == 3);
    CHECK((*entries)[0].type == kNtfsAttrFileName);
    CHECK((*entries)[0].mft_ref == 11);
    CHECK((*entries)[0].mft_record() == 11);
    CHECK((*entries)[0].attr_id == 3);
    CHECK((*entries)[1].type == kNtfsAttrData);
    CHECK((*entries)[1].mft_ref == 11);
    CHECK((*entries)[2].mft_record() == 11);
    CHECK((*entries)[2].sequence() == 9);

    const std::vector<uint8_t> named = attribute_list_entry(kNtfsAttrData, name_ref, 12, 4, u"ADS");
    auto named_entries = parse_attribute_list(named);
    REQUIRE(named_entries);
    REQUIRE(named_entries->size() == 1);
    CHECK((*named_entries)[0].name == "ADS");
    CHECK((*named_entries)[0].start_vcn == 4);
    CHECK((*named_entries)[0].sequence() == 4);
}

TEST_CASE("$ATTRIBUTE_LIST rejects malformed entries", "[ntfs][attributes]") {
    SECTION("truncated type") {
        std::vector<uint8_t> data = {0x30, 0x00};
        REQUIRE_FALSE(parse_attribute_list(data));
    }
    SECTION("short entry") {
        std::vector<uint8_t> data(0x10, 0);
        put32(data, 0, kNtfsAttrFileName);
        put16(data, 4, 0x10);
        REQUIRE_FALSE(parse_attribute_list(data));
    }
    SECTION("entry extends past the attribute") {
        std::vector<uint8_t> data = attribute_list_entry(kNtfsAttrFileName, 11, 3);
        put16(data, 4, static_cast<uint16_t>(data.size() + 8));
        REQUIRE_FALSE(parse_attribute_list(data));
    }
    SECTION("name outside the entry") {
        std::vector<uint8_t> data = attribute_list_entry(kNtfsAttrData, 11, 3, 0, u"ADS");
        data[7] = 0xFF;
        REQUIRE_FALSE(parse_attribute_list(data));
    }
    SECTION("end marker stops parsing") {
        std::vector<uint8_t> data(4, 0);
        put32(data, 0, kNtfsAttrEnd);
        const std::vector<uint8_t> ignored = attribute_list_entry(kNtfsAttrFileName, 11, 3);
        data.insert(data.end(), ignored.begin(), ignored.end());
        auto entries = parse_attribute_list(data);
        REQUIRE(entries);
        CHECK(entries->empty());
    }
}
