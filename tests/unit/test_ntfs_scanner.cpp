#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/fs/ntfs.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::fs;
using openrecover::test::MemoryDevice;

constexpr uint16_t kUsn = 0xA55A;

constexpr uint64_t kReused1Lcn = 2300;
constexpr uint64_t kReused2Lcn = 2301;
constexpr uint64_t kLiveLcn = 2402;
constexpr uint64_t kInsideLcn = 2403;
constexpr uint64_t kCompressedLcn = 2404;
constexpr uint64_t kEncryptedLcn = 2405;
constexpr uint64_t kSparse1Lcn = 2400;
constexpr uint64_t kSparse2Lcn = 2401;
constexpr uint64_t kFrag1Lcn = 2410;
constexpr uint64_t kFrag2Lcn = 2412;

constexpr int64_t kCreated = 1704067200;
constexpr int64_t kModified = 1704067300;
constexpr int64_t kAccessed = 1704067400;

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

size_t align8(size_t v) { return (v + 7) / 8 * 8; }

uint64_t unix_to_filetime(int64_t seconds) {
    return static_cast<uint64_t>(seconds + 11644473600LL) * 10000000ull;
}

uint64_t pack_ref(uint64_t record, uint16_t sequence) {
    return (static_cast<uint64_t>(sequence) << 48) | (record & 0x0000FFFFFFFFFFFFull);
}

std::vector<uint8_t> bytes_of(std::string_view s) {
    std::vector<uint8_t> out;
    out.reserve(s.size());
    for (char ch : s) out.push_back(static_cast<uint8_t>(ch));
    return out;
}

std::vector<uint8_t> ascii_utf16(std::string_view s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() * 2);
    for (char ch : s) {
        out.push_back(static_cast<uint8_t>(ch));
        out.push_back(0);
    }
    return out;
}

void append_bytes(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

std::vector<uint8_t> join_bytes(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& part : parts) append_bytes(out, part);
    return out;
}

std::vector<uint8_t> resident_attr(uint32_t type, uint16_t attr_id,
                                   std::span<const uint8_t> content, uint16_t flags = 0) {
    const size_t content_offset = 0x18;
    const size_t length = align8(content_offset + content.size());
    std::vector<uint8_t> attr(length, 0);
    put32(attr, 0, type);
    put32(attr, 4, static_cast<uint32_t>(length));
    attr[8] = 0;
    attr[9] = 0;
    put16(attr, 0x0A, 0);
    put16(attr, 0x0C, flags);
    put16(attr, 0x0E, attr_id);
    put32(attr, 0x10, static_cast<uint32_t>(content.size()));
    put16(attr, 0x14, static_cast<uint16_t>(content_offset));
    std::copy(content.begin(), content.end(),
              attr.begin() + static_cast<std::ptrdiff_t>(content_offset));
    return attr;
}

struct RunSpec {
    uint64_t length_clusters = 0;
    int64_t lcn = -1;
};

std::vector<uint8_t> encode_runlist(const std::vector<RunSpec>& runs) {
    std::vector<uint8_t> out;
    int64_t previous_lcn = 0;
    for (const RunSpec& run : runs) {
        unsigned length_bytes = 1;
        while (length_bytes < 8 && (run.length_clusters >> (length_bytes * 8)) != 0)
            ++length_bytes;
        if (run.lcn < 0) {
            out.push_back(static_cast<uint8_t>(length_bytes));
            for (unsigned i = 0; i < length_bytes; ++i)
                out.push_back(static_cast<uint8_t>(run.length_clusters >> (8 * i)));
            continue;
        }
        const int64_t delta = run.lcn - previous_lcn;
        previous_lcn = run.lcn;
        auto fits = [](int64_t value, unsigned width) {
            if (width >= 8) return true;
            const int64_t limit = int64_t{1} << (width * 8 - 1);
            return value >= -limit && value < limit;
        };
        unsigned offset_bytes = 1;
        while (offset_bytes < 8 && !fits(delta, offset_bytes)) ++offset_bytes;
        out.push_back(static_cast<uint8_t>(length_bytes | (offset_bytes << 4)));
        for (unsigned i = 0; i < length_bytes; ++i)
            out.push_back(static_cast<uint8_t>(run.length_clusters >> (8 * i)));
        for (unsigned i = 0; i < offset_bytes; ++i)
            out.push_back(static_cast<uint8_t>(static_cast<uint64_t>(delta) >> (8 * i)));
    }
    out.push_back(0);
    return out;
}

std::vector<uint8_t> nonresident_attr(uint32_t type, uint16_t attr_id,
                                      const std::vector<RunSpec>& runs, uint64_t real_size,
                                      uint64_t initialized_size, uint32_t bytes_per_cluster,
                                      uint16_t flags = 0) {
    const std::vector<uint8_t> encoded = encode_runlist(runs);
    const size_t runlist_offset = 0x40;
    const size_t length = align8(runlist_offset + encoded.size());
    uint64_t total_clusters = 0;
    for (const RunSpec& run : runs) total_clusters += run.length_clusters;

    std::vector<uint8_t> attr(length, 0);
    put32(attr, 0, type);
    put32(attr, 4, static_cast<uint32_t>(length));
    attr[8] = 1;
    attr[9] = 0;
    put16(attr, 0x0A, 0);
    put16(attr, 0x0C, flags);
    put16(attr, 0x0E, attr_id);
    put64(attr, 0x10, 0);
    put64(attr, 0x18, total_clusters == 0 ? 0 : total_clusters - 1);
    put16(attr, 0x20, static_cast<uint16_t>(runlist_offset));
    put16(attr, 0x22, 0);
    put64(attr, 0x28, total_clusters * bytes_per_cluster);
    put64(attr, 0x30, real_size);
    put64(attr, 0x38, initialized_size);
    std::copy(encoded.begin(), encoded.end(),
              attr.begin() + static_cast<std::ptrdiff_t>(runlist_offset));
    return attr;
}

std::vector<uint8_t> file_name_content(std::string_view name, uint64_t parent_record,
                                       uint16_t parent_sequence, uint8_t name_space = 1,
                                       int64_t created = 0, int64_t modified = 0,
                                       int64_t accessed = 0) {
    std::vector<uint8_t> content(0x42 + name.size() * 2, 0);
    put64(content, 0x00, pack_ref(parent_record, parent_sequence));
    put64(content, 0x08, unix_to_filetime(created));
    put64(content, 0x10, unix_to_filetime(modified));
    put64(content, 0x18, unix_to_filetime(modified));
    put64(content, 0x20, unix_to_filetime(accessed));
    content[0x40] = static_cast<uint8_t>(name.size());
    content[0x41] = name_space;
    const std::vector<uint8_t> encoded = ascii_utf16(name);
    std::copy(encoded.begin(), encoded.end(),
              content.begin() + static_cast<std::ptrdiff_t>(0x42));
    return content;
}

std::vector<uint8_t> standard_info(int64_t created, int64_t modified, int64_t accessed) {
    std::vector<uint8_t> content(0x30, 0);
    put64(content, 0x00, unix_to_filetime(created));
    put64(content, 0x08, unix_to_filetime(modified));
    put64(content, 0x10, unix_to_filetime(modified));
    put64(content, 0x18, unix_to_filetime(accessed));
    return content;
}

std::vector<uint8_t> attribute_list_entry(uint32_t type, uint64_t record, uint16_t sequence,
                                          uint16_t attr_id) {
    std::vector<uint8_t> entry(0x20, 0);
    put32(entry, 0x00, type);
    put16(entry, 0x04, 0x20);
    put64(entry, 0x08, 0);
    put64(entry, 0x10, pack_ref(record, sequence));
    put16(entry, 0x18, attr_id);
    return entry;
}

struct RecordSpec {
    uint16_t sequence = 1;
    uint16_t flags = 0;
    uint64_t base_record_ref = 0;
    bool torn = false;
    std::vector<uint8_t> attrs;
};

std::vector<uint8_t> build_record(uint32_t record_size, uint64_t number,
                                  const RecordSpec& spec) {
    const uint16_t usa_count = static_cast<uint16_t>(record_size / 512 + 1);
    const size_t usa_offset = 0x30;
    const size_t first_attr = align8(usa_offset + static_cast<size_t>(usa_count) * 2);
    const size_t used = first_attr + spec.attrs.size() + 4;
    if (used > record_size) throw std::logic_error("record attributes do not fit");

    std::vector<uint8_t> rec(record_size, 0);
    std::memcpy(rec.data(), "FILE", 4);
    put16(rec, 0x04, static_cast<uint16_t>(usa_offset));
    put16(rec, 0x06, usa_count);
    put64(rec, 0x08, 0x1122334455667788ull);
    put16(rec, 0x10, spec.sequence);
    put16(rec, 0x12, 1);
    put16(rec, 0x14, static_cast<uint16_t>(first_attr));
    put16(rec, 0x16, spec.flags);
    put32(rec, 0x18, static_cast<uint32_t>(used));
    put32(rec, 0x1C, record_size);
    put64(rec, 0x20, spec.base_record_ref);
    put16(rec, 0x28, 0x10);
    put32(rec, 0x2C, static_cast<uint32_t>(number));

    put16(rec, usa_offset, kUsn);
    for (size_t i = 1; i < usa_count; ++i) {
        put16(rec, usa_offset + i * 2, static_cast<uint16_t>(0x4000 + i));
        const bool torn = spec.torn && i == static_cast<size_t>(usa_count) - 1;
        put16(rec, i * 512 - 2, torn ? 0xFFFF : kUsn);
    }

    std::copy(spec.attrs.begin(), spec.attrs.end(),
              rec.begin() + static_cast<std::ptrdiff_t>(first_attr));
    put32(rec, first_attr + spec.attrs.size(), kNtfsAttrEnd);
    return rec;
}

struct VolumeSpec {
    uint32_t bytes_per_sector = 512;
    uint32_t sectors_per_cluster = 1;
    uint64_t total_sectors = 8192;
    uint32_t record_size = 1024;
    uint8_t record_encoding = 0xF6;
    uint8_t index_encoding = 0xF4;
    uint64_t mft_lcn = 8;
    uint64_t mft_mirror_lcn = 2290;
    std::vector<RunSpec> mft_runs = {RunSpec{64, 8}, RunSpec{1984, 300}};
    uint64_t bitmap_lcn = 2295;
    uint32_t record_count = 1024;
    bool include_bitmap = true;
    bool mirror = true;
    bool corrupt_primary_mft = false;
    std::vector<uint64_t> allocated_clusters;
    std::map<uint64_t, RecordSpec> records;
};

void add_record(VolumeSpec& spec, uint64_t number, std::vector<uint8_t> attrs,
                uint16_t sequence = 2, uint16_t flags = 0, uint64_t base_record_ref = 0,
                bool torn = false) {
    spec.records[number] = RecordSpec{sequence, flags, base_record_ref, torn, std::move(attrs)};
}

std::vector<uint8_t> build_volume(const VolumeSpec& spec) {
    const uint64_t bpc64 = static_cast<uint64_t>(spec.bytes_per_sector) *
                           static_cast<uint64_t>(spec.sectors_per_cluster);
    const uint32_t bpc = static_cast<uint32_t>(bpc64);
    const uint64_t total_clusters = spec.total_sectors / spec.sectors_per_cluster;
    const uint64_t volume_bytes = spec.total_sectors * spec.bytes_per_sector;
    if (volume_bytes > static_cast<uint64_t>(SIZE_MAX))
        throw std::logic_error("volume is too large for the test image");

    uint64_t mft_capacity = 0;
    for (const RunSpec& run : spec.mft_runs) {
        if (run.lcn < 0) throw std::logic_error("the $MFT cannot be sparse");
        mft_capacity += run.length_clusters * bpc64;
    }
    const uint64_t mft_bytes = static_cast<uint64_t>(spec.record_count) * spec.record_size;
    if (mft_capacity < mft_bytes) throw std::logic_error("the $MFT runlist is too short");

    std::vector<uint8_t> img(static_cast<size_t>(volume_bytes), 0);
    std::map<uint64_t, RecordSpec> records = spec.records;

    if (records.find(0) == records.end()) {
        std::vector<uint8_t> attrs =
            resident_attr(kNtfsAttrStandardInformation, 2, standard_info(0, 0, 0));
        append_bytes(attrs, nonresident_attr(kNtfsAttrData, 1, spec.mft_runs, mft_bytes,
                                             mft_bytes, bpc));
        records[0] = RecordSpec{1, kNtfsRecordInUse, 0, false, std::move(attrs)};
    }

    std::vector<uint8_t> bitmap;
    if (spec.include_bitmap) {
        const uint64_t bitmap_size = (total_clusters + 7) / 8;
        bitmap.assign(static_cast<size_t>(bitmap_size), 0);
        auto mark = [&](uint64_t cluster) {
            if (cluster >= total_clusters) return;
            bitmap[static_cast<size_t>(cluster >> 3)] |=
                static_cast<uint8_t>(1u << (cluster & 7));
        };
        for (const RunSpec& run : spec.mft_runs) {
            for (uint64_t i = 0; i < run.length_clusters; ++i)
                mark(static_cast<uint64_t>(run.lcn) + i);
        }
        const uint64_t bitmap_clusters = (bitmap_size + bpc64 - 1) / bpc64;
        for (uint64_t i = 0; i < bitmap_clusters; ++i) mark(spec.bitmap_lcn + i);
        const uint64_t mirror_clusters = (spec.record_size + bpc64 - 1) / bpc64;
        for (uint64_t i = 0; i < mirror_clusters; ++i) mark(spec.mft_mirror_lcn + i);
        for (uint64_t cluster : spec.allocated_clusters) mark(cluster);

        std::vector<uint8_t> attrs = nonresident_attr(
            kNtfsAttrData, 1,
            {RunSpec{bitmap_clusters, static_cast<int64_t>(spec.bitmap_lcn)}}, bitmap_size,
            bitmap_size, bpc);
        records[6] = RecordSpec{1, kNtfsRecordInUse, 0, false, std::move(attrs)};
    }

    auto write_logical = [&](uint64_t logical, std::span<const uint8_t> data) {
        size_t src = 0;
        size_t remaining = data.size();
        uint64_t position = logical;
        uint64_t run_start = 0;
        for (const RunSpec& run : spec.mft_runs) {
            const uint64_t run_bytes = run.length_clusters * bpc64;
            const uint64_t run_end = run_start + run_bytes;
            if (remaining == 0) break;
            if (position >= run_start && position < run_end) {
                const uint64_t within = position - run_start;
                const size_t take =
                    static_cast<size_t>(std::min<uint64_t>(remaining, run_bytes - within));
                const uint64_t physical = static_cast<uint64_t>(run.lcn) * bpc64 + within;
                std::memcpy(img.data() + static_cast<size_t>(physical), data.data() + src, take);
                position += take;
                src += take;
                remaining -= take;
            }
            run_start = run_end;
        }
        if (remaining != 0) throw std::logic_error("record lies outside the $MFT runlist");
    };

    std::vector<uint8_t> record_zero;
    for (const auto& [number, record_spec] : records) {
        std::vector<uint8_t> raw = build_record(spec.record_size, number, record_spec);
        if (number == 0) record_zero = raw;
        write_logical(number * spec.record_size, raw);
    }

    if (spec.mirror && !record_zero.empty()) {
        const uint64_t mirror_offset = spec.mft_mirror_lcn * bpc64;
        std::memcpy(img.data() + static_cast<size_t>(mirror_offset), record_zero.data(),
                    record_zero.size());
    }
    if (spec.corrupt_primary_mft) {
        const size_t offset = static_cast<size_t>(spec.mft_lcn * bpc64);
        std::fill(img.begin() + static_cast<std::ptrdiff_t>(offset),
                  img.begin() + static_cast<std::ptrdiff_t>(offset + spec.record_size),
                  uint8_t{0});
    }

    img[0] = 0xEB;
    img[1] = 0x52;
    img[2] = 0x90;
    std::memcpy(img.data() + 3, "NTFS    ", 8);
    put16(img, 0x0B, static_cast<uint16_t>(spec.bytes_per_sector));
    img[0x0D] = static_cast<uint8_t>(spec.sectors_per_cluster);
    img[0x15] = 0xF8;
    put64(img, 0x28, spec.total_sectors);
    put64(img, 0x30, spec.mft_lcn);
    put64(img, 0x38, spec.mft_mirror_lcn);
    img[0x40] = spec.record_encoding;
    img[0x44] = spec.index_encoding;
    put64(img, 0x48, 0x0123456789ABCDEFull);
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    if (spec.include_bitmap) {
        const size_t offset = static_cast<size_t>(spec.bitmap_lcn * bpc64);
        std::memcpy(img.data() + offset, bitmap.data(), bitmap.size());
    }
    return img;
}

std::vector<uint8_t> build_main_image(bool include_bitmap = true,
                                      bool corrupt_primary_mft = false) {
    constexpr uint32_t kBpc = 512;
    constexpr uint64_t kRoot = 5;
    VolumeSpec spec;
    spec.include_bitmap = include_bitmap;
    spec.corrupt_primary_mft = corrupt_primary_mft;
    spec.allocated_clusters = {kReused1Lcn, kReused2Lcn};

    auto fn = [](std::string_view name, uint64_t parent, uint16_t parent_sequence,
                 uint8_t name_space = 1, int64_t created = 0, int64_t modified = 0,
                 int64_t accessed = 0) {
        return resident_attr(
            kNtfsAttrFileName, 0,
            file_name_content(name, parent, parent_sequence, name_space, created, modified,
                              accessed));
    };
    auto si = [](int64_t created, int64_t modified, int64_t accessed) {
        return resident_attr(kNtfsAttrStandardInformation, 2,
                             standard_info(created, modified, accessed));
    };
    auto data = [](std::string_view content, uint16_t attr_id = 1) {
        return resident_attr(kNtfsAttrData, attr_id, bytes_of(content));
    };

    add_record(spec, 5, join_bytes({si(0, 0, 0), fn(".", kRoot, 1)}), 1,
               kNtfsRecordInUse | kNtfsRecordDirectory);
    add_record(spec, 10, join_bytes({si(0, 0, 0), fn("DOCS", kRoot, 1)}), 1,
               kNtfsRecordInUse | kNtfsRecordDirectory);
    add_record(spec, 11, join_bytes({si(0, 0, 0), fn("OLD", kRoot, 1)}), 3,
               kNtfsRecordDirectory);

    add_record(spec, 24,
               join_bytes({si(kCreated, kModified, kAccessed), fn("deleted.txt", kRoot, 1),
                           data("hello NTFS")}));
    add_record(spec, 25,
               join_bytes({fn("inside.txt", 11, 2),
                           nonresident_attr(kNtfsAttrData, 1, {RunSpec{1, kInsideLcn}}, 512,
                                            512, kBpc)}),
               3);
    add_record(spec, 26, join_bytes({fn("A", 27, 5)}), 4, kNtfsRecordDirectory);
    add_record(spec, 27, join_bytes({fn("B", 26, 4)}), 5, kNtfsRecordDirectory);
    add_record(spec, 28, join_bytes({fn("missing.txt", 60, 1), data("lost")}));
    add_record(spec, 29, join_bytes({fn("bogus_parent.txt", 10, 7), data("x")}));
    add_record(spec, 30, join_bytes({fn("cycle.txt", 26, 4), data("y")}));
    add_record(spec, 31,
               join_bytes({fn("live_parent.txt", 10, 1),
                           nonresident_attr(kNtfsAttrData, 1, {RunSpec{1, kLiveLcn}}, 512,
                                            512, kBpc)}));
    add_record(spec, 32,
               join_bytes({fn("LONGFI~1.TXT", kRoot, 1, 2),
                           fn("LongFileName.txt", kRoot, 1, 1), data("dual names")}));
    add_record(spec, 33,
               join_bytes({fn("sparse.bin", kRoot, 1),
                           nonresident_attr(kNtfsAttrData, 1,
                                            {RunSpec{1, kSparse1Lcn}, RunSpec{1, -1},
                                             RunSpec{1, kSparse2Lcn}},
                                            1536, 1024, kBpc)}));
    add_record(spec, 34,
               join_bytes({fn("compressed.bin", kRoot, 1),
                           nonresident_attr(kNtfsAttrData, 1, {RunSpec{1, kCompressedLcn}},
                                            512, 512, kBpc, kNtfsAttrCompressed)}));
    add_record(spec, 35,
               join_bytes({fn("photo.jpg", kRoot, 1), data("not a jpeg image")}));
    const std::vector<uint8_t> jpeg = {0xFF, 0xD8, 0xFF, 0xE0, 'J', 'F', 'I', 'F',
                                       0,    1,    1,    0,    0,   1,   0,   1};
    add_record(spec, 36,
               join_bytes({fn("real.jpg", kRoot, 1), resident_attr(kNtfsAttrData, 1, jpeg)}));
    add_record(spec, 37,
               join_bytes({fn("reused.bin", kRoot, 1),
                           nonresident_attr(kNtfsAttrData, 1, {RunSpec{1, kReused1Lcn}}, 512,
                                            512, kBpc)}));
    const std::vector<uint8_t> list =
        join_bytes({attribute_list_entry(kNtfsAttrFileName, 38, 2, 0),
                    attribute_list_entry(kNtfsAttrData, 39, 1, 1)});
    add_record(spec, 38,
               join_bytes({si(0, 0, 0), fn("attrlist.bin", kRoot, 1),
                           resident_attr(kNtfsAttrAttributeList, 2, list)}));
    add_record(spec, 39, join_bytes({data("extension data")}), 1, kNtfsRecordInUse,
               pack_ref(38, 2));
    add_record(spec, 40, join_bytes({fn("torn.txt", kRoot, 1), data("torn")}), 2, 0, 0, true);
    add_record(spec, 41,
               join_bytes({fn("reused2.bin", kRoot, 1),
                           nonresident_attr(kNtfsAttrData, 1, {RunSpec{1, kReused2Lcn}}, 512,
                                            512, kBpc)}));
    add_record(spec, 42,
               join_bytes({fn("frag.bin", kRoot, 1),
                           nonresident_attr(kNtfsAttrData, 1,
                                            {RunSpec{1, kFrag1Lcn}, RunSpec{1, kFrag2Lcn}},
                                            1024, 1024, kBpc)}));
    add_record(spec, 43, join_bytes({fn("empty.txt", kRoot, 1), data("")}));
    add_record(spec, 44,
               join_bytes({fn("encrypted.bin", kRoot, 1),
                           nonresident_attr(kNtfsAttrData, 1, {RunSpec{1, kEncryptedLcn}}, 512,
                                            512, kBpc, kNtfsAttrEncrypted)}));

    std::vector<uint8_t> img = build_volume(spec);
    auto stamp = [&](uint64_t lcn, std::string_view text) {
        const size_t offset = static_cast<size_t>(lcn * kBpc);
        for (size_t i = 0; i < text.size(); ++i)
            img[offset + i] = static_cast<uint8_t>(text[i]);
    };
    stamp(kInsideLcn, "INSIDE");
    stamp(kLiveLcn, "LIVE");
    stamp(kCompressedLcn, "COMP");
    stamp(kSparse1Lcn, "AAAA");
    stamp(kSparse2Lcn, "BBBB");
    stamp(kFrag1Lcn, "AAAA");
    stamp(kFrag2Lcn, "BBBB");
    stamp(kReused1Lcn, "OLD1");
    stamp(kReused2Lcn, "OLD2");
    return img;
}

std::vector<uint8_t> build_depth_image() {
    constexpr uint64_t kRoot = 5;
    VolumeSpec spec;
    spec.record_count = 512;
    spec.mft_runs = {RunSpec{1024, 8}};
    spec.mft_mirror_lcn = 2040;
    spec.bitmap_lcn = 2050;

    add_record(spec, kRoot,
               join_bytes({resident_attr(kNtfsAttrStandardInformation, 2,
                                         standard_info(0, 0, 0)),
                           resident_attr(kNtfsAttrFileName, 0,
                                         file_name_content(".", kRoot, 1))}),
               1, kNtfsRecordInUse | kNtfsRecordDirectory);
    for (uint64_t number = 100; number <= 355; ++number) {
        const uint64_t parent = number == 355 ? kRoot : number + 1;
        const std::string name = "d" + std::to_string(number);
        add_record(spec, number,
                   join_bytes({resident_attr(kNtfsAttrFileName, 0,
                                             file_name_content(name, parent, 1))}),
                   1, kNtfsRecordDirectory);
    }
    return build_volume(spec);
}

std::vector<uint8_t> build_4k_image() {
    constexpr uint32_t kBpc = 4096;
    constexpr uint64_t kRoot = 5;
    VolumeSpec spec;
    spec.bytes_per_sector = kBpc;
    spec.sectors_per_cluster = 1;
    spec.total_sectors = 1024;
    spec.record_size = 4096;
    spec.record_encoding = 0xF4;
    spec.index_encoding = 0xF4;
    spec.mft_lcn = 2;
    spec.mft_mirror_lcn = 290;
    spec.mft_runs = {RunSpec{256, 2}};
    spec.bitmap_lcn = 300;
    spec.record_count = 256;

    add_record(spec, kRoot,
               join_bytes({resident_attr(kNtfsAttrStandardInformation, 2,
                                         standard_info(0, 0, 0)),
                           resident_attr(kNtfsAttrFileName, 0,
                                         file_name_content(".", kRoot, 1))}),
               1, kNtfsRecordInUse | kNtfsRecordDirectory);
    add_record(spec, 24,
               join_bytes({resident_attr(kNtfsAttrFileName, 0,
                                         file_name_content("resident4k.txt", kRoot, 1)),
                           resident_attr(kNtfsAttrData, 1, bytes_of("4k resident"))}));
    add_record(spec, 25,
               join_bytes({resident_attr(kNtfsAttrFileName, 0,
                                         file_name_content("data4k.bin", kRoot, 1)),
                           nonresident_attr(kNtfsAttrData, 1, {RunSpec{1, 400}}, 4096, 4096,
                                            kBpc)}));

    std::vector<uint8_t> img = build_volume(spec);
    const size_t offset = static_cast<size_t>(400) * kBpc;
    const std::vector<uint8_t> content = bytes_of("4K!!");
    std::copy(content.begin(), content.end(), img.begin() + static_cast<std::ptrdiff_t>(offset));
    return img;
}

std::map<std::string, const RecoveredFile*> index_files(
    const std::vector<RecoveredFile>& files) {
    std::map<std::string, const RecoveredFile*> index;
    for (const RecoveredFile& file : files) index.emplace(file.path, &file);
    return index;
}

std::vector<uint8_t> read_all(NtfsScanner& scanner, const RecoveredFile& file) {
    std::vector<uint8_t> out(static_cast<size_t>(file.size_bytes), 0xCC);
    auto got = scanner.read_file(file, 0, out.data(), out.size());
    REQUIRE(got);
    REQUIRE(*got == out.size());
    return out;
}

}  // namespace

TEST_CASE("NTFS $MFT reader follows a fragmented runlist") {
    const std::vector<uint8_t> image = build_main_image();
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);
    NtfsMftReader& mft = (*scanner)->mft();

    CHECK(mft.record_count() == 1024);
    CHECK(mft.record_size() == 1024);
    REQUIRE(mft.mft_runs().size() == 2);
    CHECK(mft.mft_runs()[0].lcn == 8);
    CHECK(mft.mft_runs()[0].length_clusters == 64);
    CHECK(mft.mft_runs()[1].lcn == 300);

    auto last_of_first_run = mft.load_record(31);
    REQUIRE(last_of_first_run);
    REQUIRE(*last_of_first_run);
    CHECK((**last_of_first_run).record_number == 31);

    auto first_of_second_run = mft.load_record(32);
    REQUIRE(first_of_second_run);
    REQUIRE(*first_of_second_run);
    CHECK((**first_of_second_run).record_number == 32);

    auto unused = mft.load_record(50);
    REQUIRE(unused);
    CHECK_FALSE(*unused);

    auto torn = mft.load_record(40);
    REQUIRE(torn);
    CHECK_FALSE(*torn);

    auto beyond = mft.load_record(4096);
    REQUIRE(beyond);
    CHECK_FALSE(*beyond);
}

TEST_CASE("NTFS $MFT reader falls back to the mirror") {
    const std::vector<uint8_t> image = build_main_image(true, true);
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);
    CHECK((*scanner)->mft().record_count() == 1024);

    auto record = (*scanner)->mft().load_record(24);
    REQUIRE(record);
    REQUIRE(*record);
    CHECK((**record).record_number == 24);

    auto files = (*scanner)->scan_deleted(ScanOptions{}, nullptr);
    REQUIRE(files);
    auto index = index_files(*files);
    CHECK(index.count("deleted.txt") == 1);
}

TEST_CASE("NTFS allocation map reads the non-resident $Bitmap") {
    const std::vector<uint8_t> image = build_main_image();
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);

    auto allocation = (*scanner)->allocation_map();
    REQUIRE(allocation);
    IAllocationMap& map = **allocation;
    CHECK(map.cluster_count() == 8192);
    CHECK(map.cluster_to_byte_offset(10) == 5120);
    CHECK(map.is_cluster_allocated(8));
    CHECK(map.is_cluster_allocated(2283));
    CHECK(map.is_cluster_allocated(kReused1Lcn));
    CHECK_FALSE(map.is_cluster_allocated(kSparse1Lcn));
    CHECK_FALSE(map.is_cluster_allocated(kSparse2Lcn));
    CHECK_FALSE(map.is_cluster_allocated(kFrag1Lcn));
    CHECK(map.is_cluster_allocated(8192));
}

TEST_CASE("NTFS path resolver handles cycles, orphans and stale sequences") {
    const std::vector<uint8_t> image = build_main_image();
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);
    NtfsPathResolver resolver((*scanner)->mft());

    auto nested = resolver.resolve(25);
    REQUIRE(nested);
    CHECK_FALSE(nested->uncertain);
    CHECK(nested->path == "OLD/inside.txt");

    auto live = resolver.resolve(31);
    REQUIRE(live);
    CHECK_FALSE(live->uncertain);
    CHECK(live->path == "DOCS/live_parent.txt");

    auto cycle = resolver.resolve(30);
    REQUIRE(cycle);
    CHECK(cycle->uncertain);
    CHECK(cycle->path == "B/A/cycle.txt");

    auto orphan = resolver.resolve(28);
    REQUIRE(orphan);
    CHECK(orphan->uncertain);
    CHECK(orphan->path == "__orphans__/missing.txt");

    auto mismatch = resolver.resolve(29);
    REQUIRE(mismatch);
    CHECK(mismatch->uncertain);
    CHECK(mismatch->path == "bogus_parent.txt");
}

TEST_CASE("NTFS path resolver enforces the depth limit") {
    const std::vector<uint8_t> image = build_depth_image();
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);
    NtfsPathResolver resolver((*scanner)->mft());

    auto deepest_allowed = resolver.resolve(101);
    REQUIRE(deepest_allowed);
    CHECK_FALSE(deepest_allowed->uncertain);
    CHECK(std::count(deepest_allowed->path.begin(), deepest_allowed->path.end(), '/') == 254);
    CHECK(deepest_allowed->path.rfind("d355/", 0) == 0);
    REQUIRE(deepest_allowed->path.size() >= 4);
    CHECK(deepest_allowed->path.compare(deepest_allowed->path.size() - 4, 4, "d101") == 0);

    auto too_deep = resolver.resolve(100);
    REQUIRE(too_deep);
    CHECK(too_deep->uncertain);
}

TEST_CASE("NTFS scanner recovers deleted files with confidence rules") {
    const std::vector<uint8_t> image = build_main_image();
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);
    NtfsScanner& scan = **scanner;

    CHECK(scan.kind() == FsKind::Ntfs);
    CHECK(scan.geometry().bytes_per_sector == 512);
    CHECK(scan.geometry().bytes_per_cluster == 512);
    CHECK(scan.geometry().total_clusters == 8192);
    CHECK(scan.boot().mft_lcn == 8);

    auto files = scan.scan_deleted(ScanOptions{}, nullptr);
    REQUIRE(files);
    CHECK(files->size() == 17);
    auto index = index_files(*files);

    REQUIRE(index.count("deleted.txt") == 1);
    const RecoveredFile& deleted = *index.at("deleted.txt");
    CHECK(deleted.name == "deleted.txt");
    CHECK(deleted.size_bytes == 10);
    CHECK(deleted.confidence == Confidence::High);
    CHECK(deleted.flags == 0);
    REQUIRE(deleted.resident_data);
    CHECK(*deleted.resident_data == bytes_of("hello NTFS"));
    CHECK(deleted.ctime_unix == kCreated);
    CHECK(deleted.mtime_unix == kModified);
    CHECK(deleted.atime_unix == kAccessed);
    CHECK(deleted.type_hint.empty());
    CHECK(deleted.note.empty());
    CHECK(deleted.origin == FileOrigin::FilesystemMetadata);

    REQUIRE(index.count("OLD/inside.txt") == 1);
    const RecoveredFile& inside = *index.at("OLD/inside.txt");
    CHECK(inside.confidence == Confidence::High);
    CHECK((inside.flags & file_flags::PathUncertain) == 0);
    REQUIRE(inside.extents.size() == 1);
    CHECK(inside.extents[0].offset_bytes == kInsideLcn * 512);
    CHECK(inside.extents[0].length_bytes == 512);
    CHECK_FALSE(inside.extents[0].sparse);

    REQUIRE(index.count("DOCS/live_parent.txt") == 1);
    CHECK(index.at("DOCS/live_parent.txt")->confidence == Confidence::High);

    REQUIRE(index.count("B/A/cycle.txt") == 1);
    CHECK((index.at("B/A/cycle.txt")->flags & file_flags::PathUncertain) != 0);

    REQUIRE(index.count("__orphans__/missing.txt") == 1);
    CHECK((index.at("__orphans__/missing.txt")->flags & file_flags::PathUncertain) != 0);

    REQUIRE(index.count("bogus_parent.txt") == 1);
    CHECK((index.at("bogus_parent.txt")->flags & file_flags::PathUncertain) != 0);

    REQUIRE(index.count("LongFileName.txt") == 1);
    CHECK(index.count("LONGFI~1.TXT") == 0);
    CHECK(index.at("LongFileName.txt")->confidence == Confidence::High);

    REQUIRE(index.count("sparse.bin") == 1);
    const RecoveredFile& sparse = *index.at("sparse.bin");
    CHECK(sparse.size_bytes == 1536);
    CHECK(sparse.confidence == Confidence::High);
    REQUIRE(sparse.extents.size() == 3);
    CHECK_FALSE(sparse.extents[0].sparse);
    CHECK(sparse.extents[1].sparse);
    CHECK(sparse.extents[2].sparse);

    REQUIRE(index.count("compressed.bin") == 1);
    const RecoveredFile& compressed = *index.at("compressed.bin");
    CHECK(compressed.confidence == Confidence::Low);
    CHECK((compressed.flags & file_flags::Unsupported) != 0);
    // A record whose compression unit field is zero cannot say how wide a unit is, so the
    // attribute is reported rather than decoded by guess.
    CHECK(compressed.note.starts_with("ntfs_compressed_unsupported"));
    CHECK(compressed.extents.empty());
    CHECK_FALSE(compressed.resident_data.has_value());

    REQUIRE(index.count("encrypted.bin") == 1);
    const RecoveredFile& encrypted = *index.at("encrypted.bin");
    CHECK(encrypted.confidence == Confidence::Low);
    CHECK((encrypted.flags & file_flags::Unsupported) != 0);
    CHECK(encrypted.note == "ntfs_encrypted");
    CHECK(encrypted.extents.empty());
    CHECK_FALSE(encrypted.resident_data.has_value());

    REQUIRE(index.count("photo.jpg") == 1);
    CHECK(index.at("photo.jpg")->confidence == Confidence::Medium);
    CHECK(index.at("photo.jpg")->type_hint == "jpeg");

    REQUIRE(index.count("real.jpg") == 1);
    CHECK(index.at("real.jpg")->confidence == Confidence::High);
    CHECK(index.at("real.jpg")->type_hint == "jpeg");

    REQUIRE(index.count("reused.bin") == 1);
    CHECK(index.at("reused.bin")->confidence == Confidence::Low);
    CHECK((index.at("reused.bin")->flags & file_flags::ClustersReallocated) != 0);

    REQUIRE(index.count("reused2.bin") == 1);
    CHECK(index.at("reused2.bin")->confidence == Confidence::Low);
    CHECK((index.at("reused2.bin")->flags & file_flags::ClustersReallocated) != 0);

    REQUIRE(index.count("attrlist.bin") == 1);
    const RecoveredFile& attrlist = *index.at("attrlist.bin");
    CHECK(attrlist.confidence == Confidence::High);
    REQUIRE(attrlist.resident_data);
    CHECK(*attrlist.resident_data == bytes_of("extension data"));

    REQUIRE(index.count("frag.bin") == 1);
    const RecoveredFile& frag = *index.at("frag.bin");
    CHECK(frag.confidence == Confidence::High);
    CHECK(frag.size_bytes == 1024);
    REQUIRE(frag.extents.size() == 2);

    REQUIRE(index.count("empty.txt") == 1);
    const RecoveredFile& empty = *index.at("empty.txt");
    CHECK(empty.size_bytes == 0);
    CHECK(empty.confidence == Confidence::High);
    REQUIRE(empty.resident_data);
    CHECK(empty.resident_data->empty());

    CHECK(index.count("torn.txt") == 0);
    CHECK(index.count("OLD") == 0);
    CHECK(index.count("DOCS") == 0);

    std::vector<uint8_t> dst(16, 0);
    auto partial = scan.read_file(deleted, 6, dst.data(), 4);
    REQUIRE(partial);
    CHECK(*partial == 4);
    CHECK(std::memcmp(dst.data(), "NTFS", 4) == 0);

    auto past_end = scan.read_file(deleted, deleted.size_bytes, dst.data(), dst.size());
    REQUIRE(past_end);
    CHECK(*past_end == 0);

    const std::vector<uint8_t> sparse_data = read_all(scan, sparse);
    CHECK(std::memcmp(sparse_data.data(), "AAAA", 4) == 0);
    CHECK(std::all_of(sparse_data.begin() + 512, sparse_data.end(),
                      [](uint8_t v) { return v == 0; }));

    const std::vector<uint8_t> frag_data = read_all(scan, frag);
    CHECK(std::memcmp(frag_data.data(), "AAAA", 4) == 0);
    CHECK(std::memcmp(frag_data.data() + 512, "BBBB", 4) == 0);
    CHECK(frag_data[4] == 0);
    CHECK(frag_data[516] == 0);

    const std::vector<uint8_t> empty_data = read_all(scan, empty);
    CHECK(empty_data.empty());

    auto unsupported = scan.read_file(compressed, 0, dst.data(), dst.size());
    REQUIRE_FALSE(unsupported);
    CHECK(unsupported.error().code == ErrorCode::Unsupported);

    auto cancelled =
        scan.scan_deleted(ScanOptions{}, [](uint64_t, uint64_t) { return false; });
    REQUIRE_FALSE(cancelled);
    CHECK(cancelled.error().code == ErrorCode::Cancelled);
}

TEST_CASE("NTFS without a $Bitmap falls back to medium confidence") {
    const std::vector<uint8_t> image = build_main_image(false);
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);

    auto files = (*scanner)->scan_deleted(ScanOptions{}, nullptr);
    REQUIRE(files);
    auto index = index_files(*files);
    REQUIRE(index.count("OLD/inside.txt") == 1);
    CHECK(index.at("OLD/inside.txt")->confidence == Confidence::Medium);
    REQUIRE(index.count("deleted.txt") == 1);
    CHECK(index.at("deleted.txt")->confidence == Confidence::High);
    REQUIRE(index.count("reused.bin") == 1);
    CHECK(index.at("reused.bin")->confidence == Confidence::Medium);
}

TEST_CASE("NTFS scan propagates $MFT read failures") {
    const std::vector<uint8_t> image = build_main_image();
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);

    dev->fail_at(8 * 512 + 6 * 1024);
    auto files = (*scanner)->scan_deleted(ScanOptions{}, nullptr);
    REQUIRE_FALSE(files);
    CHECK(files.error().code == ErrorCode::IoError);
}

TEST_CASE("NTFS scanner supports 4096-byte sectors and 4096-byte records") {
    const std::vector<uint8_t> image = build_4k_image();
    auto dev = std::make_shared<MemoryDevice>(image, 4096);
    auto scanner = NtfsScanner::open(dev);
    REQUIRE(scanner);
    NtfsScanner& scan = **scanner;

    CHECK(scan.geometry().bytes_per_sector == 4096);
    CHECK(scan.geometry().bytes_per_cluster == 4096);
    CHECK(scan.boot().record_size == 4096);
    CHECK(scan.mft().record_count() == 256);

    auto files = scan.scan_deleted(ScanOptions{}, nullptr);
    REQUIRE(files);
    auto index = index_files(*files);
    REQUIRE(index.count("resident4k.txt") == 1);
    const RecoveredFile& resident = *index.at("resident4k.txt");
    CHECK(resident.confidence == Confidence::High);
    REQUIRE(resident.resident_data);
    CHECK(*resident.resident_data == bytes_of("4k resident"));

    REQUIRE(index.count("data4k.bin") == 1);
    const RecoveredFile& data = *index.at("data4k.bin");
    CHECK(data.confidence == Confidence::High);
    CHECK(data.size_bytes == 4096);
    REQUIRE(data.extents.size() == 1);
    CHECK(data.extents[0].offset_bytes == 400ull * 4096);
    const std::vector<uint8_t> content = read_all(scan, data);
    CHECK(std::memcmp(content.data(), "4K!!", 4) == 0);
}

TEST_CASE("detect_and_open recognizes NTFS") {
    const std::vector<uint8_t> image = build_main_image();
    auto dev = std::make_shared<MemoryDevice>(image);
    auto scanner = detect_and_open(dev);
    REQUIRE(scanner);
    CHECK((*scanner)->kind() == FsKind::Ntfs);

    auto files = (*scanner)->scan_deleted(ScanOptions{}, nullptr);
    REQUIRE(files);
    auto index = index_files(*files);
    CHECK(index.count("deleted.txt") == 1);
}
