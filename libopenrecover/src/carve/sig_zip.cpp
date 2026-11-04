#include "openrecover/carve/sig_zip.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "inflate.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/common/crc32.hpp"

namespace openrecover::carve {

namespace {

constexpr size_t kIoChunk = 64u << 10;
// Bounded so a hostile central directory cannot exhaust memory. Each stored
// entry costs ~48 bytes; names stay in the reader and are re-read on demand.
constexpr uint64_t kMaxEntries = 1'000'000;
constexpr size_t kMaxEocdHits = 4096;
constexpr uint64_t kDeepEntryMax = 256ull << 20;
constexpr uint64_t kDeepBudget = 1ull << 30;
constexpr size_t kMaxNotes = 32;

constexpr uint32_t kLocalSig = 0x04034b50;
constexpr uint32_t kCentralSig = 0x02014b50;
constexpr uint32_t kZip64EocdSig = 0x06064b50;
constexpr uint32_t kZip64LocatorSig = 0x07064b50;
constexpr uint32_t kDataDescriptorSig = 0x08074b50;
constexpr uint32_t kDigitalSignatureSig = 0x05054b50;
constexpr uint8_t kEocdBytes[4] = {0x50, 0x4B, 0x05, 0x06};

bool add_ok(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > UINT64_MAX - b) return false;
    out = a + b;
    return true;
}

std::optional<uint16_t> le16(BoundedReader& reader, uint64_t off) {
    auto value = reader.u16be(off);
    if (!value) return std::nullopt;
    return static_cast<uint16_t>((*value >> 8) | (*value << 8));
}

std::optional<uint32_t> le32(BoundedReader& reader, uint64_t off) {
    auto value = reader.u32be(off);
    if (!value) return std::nullopt;
    const uint32_t v = *value;
    return (v >> 24) | ((v >> 8) & 0x0000FF00u) | ((v << 8) & 0x00FF0000u) | (v << 24);
}

std::optional<uint64_t> le64(BoundedReader& reader, uint64_t off) {
    auto value = reader.u64be(off);
    if (!value) return std::nullopt;
    uint64_t v = *value;
    v = ((v & 0xFF00FF00FF00FF00ull) >> 8) | ((v & 0x00FF00FF00FF00FFull) << 8);
    v = ((v & 0xFFFF0000FFFF0000ull) >> 16) | ((v & 0x0000FFFF0000FFFFull) << 16);
    return (v >> 32) | (v << 32);
}

uint32_t raw_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t raw_le64(const uint8_t* p) {
    uint64_t value = 0;
    for (int i = 7; i >= 0; --i) value = (value << 8) | p[i];
    return value;
}

bool read_name(BoundedReader& reader, uint64_t off, size_t len, std::string& out) {
    auto bytes = reader.read_vec(off, len);
    if (!bytes || bytes->size() != len) return false;
    out.assign(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return true;
}

bool has_control(std::string_view name) {
    return std::any_of(name.begin(), name.end(),
                       [](char c) { return static_cast<unsigned char>(c) < 0x20; });
}

bool method_allowed(uint16_t method) {
    switch (method) {
        case 0:
        case 8:
        case 9:
        case 12:
        case 14:
        case 93:
        case 95:
        case 99:
            return true;
        default:
            return false;
    }
}

struct LocalHeader {
    uint16_t version = 0;
    uint16_t flags = 0;
    uint16_t method = 0;
    uint32_t crc = 0;
    uint32_t comp32 = 0;
    uint32_t uncomp32 = 0;
    uint64_t data_start = 0;
    uint64_t data_end = 0;
    std::string name;
};

bool parse_local(BoundedReader& reader, uint64_t off, uint64_t bound, bool printable,
                 LocalHeader& out) {
    if (off >= bound || bound - off < 30) return false;
    auto sig = le32(reader, off);
    auto version = le16(reader, off + 4);
    auto flags = le16(reader, off + 6);
    auto method = le16(reader, off + 8);
    auto crc = le32(reader, off + 14);
    auto comp = le32(reader, off + 18);
    auto uncomp = le32(reader, off + 22);
    auto name_len = le16(reader, off + 26);
    auto extra_len = le16(reader, off + 28);
    if (!sig || !version || !flags || !method || !crc || !comp || !uncomp || !name_len ||
        !extra_len)
        return false;
    if (*sig != kLocalSig) return false;

    uint64_t data_start = 0;
    if (!add_ok(off, 30u + static_cast<uint64_t>(*name_len) + static_cast<uint64_t>(*extra_len),
                data_start))
        return false;
    if (data_start > bound) return false;
    std::string name;
    if (!read_name(reader, off + 30, *name_len, name)) return false;
    if (printable && has_control(name)) return false;

    out.version = *version;
    out.flags = *flags;
    out.method = *method;
    out.crc = *crc;
    out.comp32 = *comp;
    out.uncomp32 = *uncomp;
    out.data_start = data_start;
    out.data_end = data_start;
    out.name = std::move(name);
    if (*comp != 0xFFFFFFFFu && !add_ok(data_start, *comp, out.data_end)) return false;
    return true;
}

struct EocdInfo {
    uint64_t q = 0;
    uint64_t cd_offset = 0;
    uint64_t cd_size = 0;
    uint64_t cd_end = 0;
    uint64_t total_entries = 0;
    uint64_t comment_len = 0;
};

bool read_eocd(BoundedReader& reader, uint64_t q, uint64_t limit, EocdInfo& out) {
    if (q > limit || limit - q < 22) return false;
    auto disk = le16(reader, q + 4);
    auto cd_disk = le16(reader, q + 6);
    auto total16 = le16(reader, q + 10);
    auto cd_size32 = le32(reader, q + 12);
    auto cd_offset32 = le32(reader, q + 16);
    auto comment_len = le16(reader, q + 20);
    if (!disk || !cd_disk || !total16 || !cd_size32 || !cd_offset32 || !comment_len) return false;
    if (*disk != 0 || *cd_disk != 0) return false;
    if (*comment_len > limit - q - 22) return false;

    out.q = q;
    out.comment_len = *comment_len;

    const bool zip64 =
        *total16 == 0xFFFFu || *cd_size32 == 0xFFFFFFFFu || *cd_offset32 == 0xFFFFFFFFu;
    if (!zip64) {
        out.total_entries = *total16;
        out.cd_size = *cd_size32;
        out.cd_offset = *cd_offset32;
        if (!add_ok(out.cd_offset, out.cd_size, out.cd_end)) return false;
        return out.cd_end == q;
    }

    if (q < 20) return false;
    const uint64_t locator = q - 20;
    auto locator_sig = le32(reader, locator);
    auto locator_disk = le32(reader, locator + 4);
    auto zip64_offset = le64(reader, locator + 8);
    auto total_disks = le32(reader, locator + 16);
    if (!locator_sig || !locator_disk || !zip64_offset || !total_disks) return false;
    if (*locator_sig != kZip64LocatorSig) return false;
    if (*locator_disk != 0 || *total_disks != 1) return false;

    const uint64_t zip64_pos = *zip64_offset;
    if (zip64_pos > locator || locator - zip64_pos < 56) return false;
    auto zip64_sig = le32(reader, zip64_pos);
    auto record_size = le64(reader, zip64_pos + 4);
    if (!zip64_sig || !record_size) return false;
    if (*zip64_sig != kZip64EocdSig) return false;
    if (*record_size < 44) return false;
    uint64_t record_end = 0;
    if (!add_ok(zip64_pos, 12, record_end) || !add_ok(record_end, *record_size, record_end))
        return false;
    if (record_end > locator) return false;

    auto zip64_disk = le32(reader, zip64_pos + 16);
    auto zip64_cd_disk = le32(reader, zip64_pos + 20);
    auto total = le64(reader, zip64_pos + 32);
    auto cd_size = le64(reader, zip64_pos + 40);
    auto cd_offset = le64(reader, zip64_pos + 48);
    if (!zip64_disk || !zip64_cd_disk || !total || !cd_size || !cd_offset) return false;
    if (*zip64_disk != 0 || *zip64_cd_disk != 0) return false;

    out.total_entries = *total;
    out.cd_size = *cd_size;
    out.cd_offset = *cd_offset;
    if (!add_ok(out.cd_offset, out.cd_size, out.cd_end)) return false;
    return out.cd_end == zip64_pos;
}

std::vector<uint64_t> find_eocd(BoundedReader& reader, uint64_t limit) {
    std::vector<uint64_t> hits;
    std::array<uint8_t, kIoChunk + 4> buffer{};
    uint64_t pos = 0;
    uint64_t last = UINT64_MAX;
    while (pos < limit && hits.size() < kMaxEocdHits) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(kIoChunk, limit - pos));
        auto got = reader.read_at(pos, buffer.data(), want);
        if (!got || *got == 0) break;
        const size_t n = *got;
        size_t i = 0;
        while (i + 4 <= n) {
            const auto it = std::search(buffer.begin() + static_cast<std::ptrdiff_t>(i),
                                        buffer.begin() + static_cast<std::ptrdiff_t>(n),
                                        kEocdBytes, kEocdBytes + 4);
            if (it == buffer.begin() + static_cast<std::ptrdiff_t>(n)) break;
            const size_t index = static_cast<size_t>(it - buffer.begin());
            const uint64_t absolute = pos + index;
            if (absolute != last) {
                hits.push_back(absolute);
                last = absolute;
                if (hits.size() >= kMaxEocdHits) break;
            }
            i = index + 1;
        }
        if (*got < want) break;
        constexpr size_t kOverlap = 3;
        if (n <= kOverlap) break;
        pos += n - kOverlap;
    }
    return hits;
}

bool plausible_eocd(BoundedReader& reader, uint64_t pos, uint64_t limit) {
    if (pos > limit || limit - pos < 22) return false;
    auto comment_len = le16(reader, pos + 20);
    if (!comment_len) return false;
    return *comment_len <= limit - pos - 22;
}

struct Entry {
    uint64_t lho = 0;
    uint64_t data_start = 0;
    uint64_t region_end = 0;
    uint64_t comp_size = 0;
    uint64_t uncomp_size = 0;
    uint64_t name_pos = 0;
    uint32_t crc = 0;
    uint16_t name_len = 0;
    uint16_t method = 0;
};

struct Classification {
    bool content_types = false;
    bool word = false;
    bool xl = false;
    bool ppt = false;
    bool android_manifest = false;
    bool classes_dex = false;
    bool manifest_mf = false;
    bool first_is_mimetype_stored = false;
    bool epub_mimetype = false;
    std::string first_mime;
};

void update_classification(BoundedReader& reader, const std::string& name, bool first,
                           uint16_t method, uint64_t data_start, uint64_t comp_size,
                           uint64_t uncomp_size, Classification& cls) {
    if (name == "[Content_Types].xml") cls.content_types = true;
    if (name.starts_with("word/")) cls.word = true;
    if (name.starts_with("xl/")) cls.xl = true;
    if (name.starts_with("ppt/")) cls.ppt = true;
    if (name == "AndroidManifest.xml") cls.android_manifest = true;
    if (name == "classes.dex") cls.classes_dex = true;
    if (name == "META-INF/MANIFEST.MF") cls.manifest_mf = true;

    if (name == "mimetype" && method == 0 && comp_size == uncomp_size && comp_size <= 128) {
        const size_t len = static_cast<size_t>(comp_size);
        auto bytes = reader.read_vec(data_start, len);
        if (!bytes || bytes->size() != len) return;
        const std::string value(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        if (first) {
            cls.first_is_mimetype_stored = true;
            cls.first_mime = value;
        }
        if (value == "application/epub+zip") cls.epub_mimetype = true;
    }
}

std::string classify(const Classification& cls) {
    if (cls.content_types && cls.word) return "docx";
    if (cls.content_types && cls.xl) return "xlsx";
    if (cls.content_types && cls.ppt) return "pptx";
    if (cls.first_is_mimetype_stored) {
        if (cls.first_mime.starts_with("application/vnd.oasis.opendocument.text")) return "odt";
        if (cls.first_mime.starts_with("application/vnd.oasis.opendocument.spreadsheet"))
            return "ods";
        if (cls.first_mime.starts_with("application/vnd.oasis.opendocument.presentation"))
            return "odp";
    }
    if (cls.android_manifest && cls.classes_dex) return "apk";
    if (cls.manifest_mf) return "jar";
    if (cls.epub_mimetype) return "epub";
    return "zip";
}

bool parse_central(BoundedReader& reader, uint64_t pos, uint64_t cd_start, uint64_t cd_end,
                   bool first, Entry& entry, Classification& cls, uint64_t& entry_len) {
    if (pos > cd_end || cd_end - pos < 46) return false;
    auto sig = le32(reader, pos);
    if (!sig || *sig != kCentralSig) return false;

    auto flags = le16(reader, pos + 8);
    auto method = le16(reader, pos + 10);
    auto crc = le32(reader, pos + 16);
    auto comp32 = le32(reader, pos + 20);
    auto uncomp32 = le32(reader, pos + 24);
    auto name_len = le16(reader, pos + 28);
    auto extra_len = le16(reader, pos + 30);
    auto comment_len = le16(reader, pos + 32);
    auto disk16 = le16(reader, pos + 34);
    auto lho32 = le32(reader, pos + 42);
    if (!flags || !method || !crc || !comp32 || !uncomp32 || !name_len || !extra_len ||
        !comment_len || !disk16 || !lho32)
        return false;

    entry_len = 46u + static_cast<uint64_t>(*name_len) + static_cast<uint64_t>(*extra_len) +
                static_cast<uint64_t>(*comment_len);
    if (entry_len > cd_end - pos) return false;

    std::string name;
    if (!read_name(reader, pos + 46, *name_len, name)) return false;
    std::vector<uint8_t> extra;
    if (*extra_len != 0) {
        auto bytes = reader.read_vec(pos + 46 + *name_len, *extra_len);
        if (!bytes || bytes->size() != *extra_len) return false;
        extra = std::move(*bytes);
    }

    uint64_t comp = *comp32;
    uint64_t uncomp = *uncomp32;
    uint64_t lho = *lho32;
    bool zip64_entry = false;
    if (*comp32 == 0xFFFFFFFFu || *uncomp32 == 0xFFFFFFFFu || *lho32 == 0xFFFFFFFFu ||
        *disk16 == 0xFFFFu) {
        zip64_entry = true;
        const uint8_t* zip64 = nullptr;
        size_t zip64_len = 0;
        size_t at = 0;
        while (at + 4 <= extra.size()) {
            const uint16_t id =
                static_cast<uint16_t>(extra[at] | (extra[at + 1] << 8));
            const uint16_t size =
                static_cast<uint16_t>(extra[at + 2] | (extra[at + 3] << 8));
            if (at + 4 + size > extra.size()) break;
            if (id == 0x0001) {
                zip64 = extra.data() + at + 4;
                zip64_len = size;
                break;
            }
            at += 4 + size;
        }
        size_t cursor = 0;
        auto take64 = [&](uint64_t& value) {
            if (zip64 == nullptr || cursor + 8 > zip64_len) return false;
            value = raw_le64(zip64 + cursor);
            cursor += 8;
            return true;
        };
        auto take32 = [&](uint32_t& value) {
            if (zip64 == nullptr || cursor + 4 > zip64_len) return false;
            value = raw_le32(zip64 + cursor);
            cursor += 4;
            return true;
        };
        if (*uncomp32 == 0xFFFFFFFFu && !take64(uncomp)) return false;
        if (*comp32 == 0xFFFFFFFFu && !take64(comp)) return false;
        if (*lho32 == 0xFFFFFFFFu && !take64(lho)) return false;
        if (*disk16 == 0xFFFFu) {
            uint32_t disk = 0;
            if (!take32(disk) || disk != 0) return false;
        }
    }

    if (lho >= cd_start) return false;
    LocalHeader local;
    if (!parse_local(reader, lho, cd_start, false, local)) return false;
    if (local.name != name) return false;

    uint64_t data_end = 0;
    if (!add_ok(local.data_start, comp, data_end) || data_end > cd_start) return false;
    uint64_t region_end = data_end;
    if ((*flags & 0x0008u) != 0) {
        bool descriptor_signature = false;
        if (cd_start - data_end >= 4) {
            auto descriptor_sig = le32(reader, data_end);
            descriptor_signature = descriptor_sig && *descriptor_sig == kDataDescriptorSig;
        }
        const bool wide_descriptor = zip64_entry || local.version >= 45;
        const uint64_t descriptor_size =
            (descriptor_signature ? 4u : 0u) + (wide_descriptor ? 16u : 8u);
        if (!add_ok(data_end, descriptor_size, region_end) || region_end > cd_start) return false;
    }

    entry.lho = lho;
    entry.data_start = local.data_start;
    entry.region_end = region_end;
    entry.comp_size = comp;
    entry.uncomp_size = uncomp;
    entry.name_pos = pos + 46;
    entry.name_len = *name_len;
    entry.crc = *crc;
    entry.method = *method;
    update_classification(reader, name, first, *method, local.data_start, comp, uncomp, cls);
    return true;
}

std::string entry_note_name(BoundedReader& reader, const Entry& entry) {
    std::string out;
    const size_t want = std::min<size_t>(entry.name_len, 200);
    auto bytes = reader.read_vec(entry.name_pos, want);
    if (!bytes) return out;
    out.reserve(bytes->size());
    for (uint8_t c : *bytes)
        out.push_back(c >= 0x20 && c <= 0x7E ? static_cast<char>(c) : '?');
    return out;
}

bool deep_check(BoundedReader& reader, const std::vector<Entry>& entries,
                std::vector<std::string>& notes) {
    uint64_t budget = kDeepBudget;
    bool mismatch = false;
    std::vector<uint8_t> buffer(kIoChunk);

    for (const Entry& entry : entries) {
        if (entry.method != 0 && entry.method != 8) continue;
        if (entry.uncomp_size > kDeepEntryMax) continue;
        if (entry.uncomp_size > budget) {
            notes.push_back("deep_budget_exhausted");
            mismatch = true;
            break;
        }

        bool ok = false;
        uint64_t produced = 0;
        if (entry.method == 0) {
            uint32_t crc = 0;
            uint64_t left = entry.comp_size;
            uint64_t off = entry.data_start;
            while (left > 0) {
                const size_t take = static_cast<size_t>(std::min<uint64_t>(buffer.size(), left));
                auto got = reader.read_at(off, buffer.data(), take);
                if (!got || *got != take) break;
                crc = crc32_update(crc, buffer.data(), take);
                off += take;
                left -= take;
            }
            produced = entry.comp_size;
            ok = left == 0 && entry.comp_size == entry.uncomp_size && crc == entry.crc;
        } else {
            detail::Inflator inflator(false);
            uint64_t left = entry.comp_size;
            uint64_t off = entry.data_start;
            bool good = true;
            while (left > 0) {
                const size_t take = static_cast<size_t>(std::min<uint64_t>(buffer.size(), left));
                auto got = reader.read_at(off, buffer.data(), take);
                if (!got || *got != take) {
                    good = false;
                    break;
                }
                if (!inflator.feed(buffer.data(), take)) {
                    good = false;
                    break;
                }
                if (inflator.output() > entry.uncomp_size) {
                    good = false;
                    break;
                }
                off += take;
                left -= take;
            }
            if (good && left == 0 && inflator.finish())
                ok = inflator.output() == entry.uncomp_size && inflator.crc() == entry.crc;
            produced = inflator.output();
        }

        budget -= std::min<uint64_t>(produced, budget);
        if (!ok) {
            mismatch = true;
            if (notes.size() < kMaxNotes)
                notes.push_back("entry_crc_mismatch:" + entry_note_name(reader, entry));
        }
    }
    return mismatch;
}

bool validate_archive(BoundedReader& reader, const EocdInfo& eocd, ValidationResult& result) {
    if (eocd.total_entries == 0 || eocd.total_entries > kMaxEntries) return false;
    if (eocd.cd_size < eocd.total_entries * 46) return false;

    std::vector<Entry> entries;
    entries.reserve(static_cast<size_t>(eocd.total_entries));
    Classification cls;
    uint64_t pos = eocd.cd_offset;
    for (uint64_t i = 0; i < eocd.total_entries; ++i) {
        Entry entry;
        uint64_t entry_len = 0;
        if (!parse_central(reader, pos, eocd.cd_offset, eocd.cd_end, i == 0, entry, cls,
                           entry_len))
            return false;
        entries.push_back(entry);
        pos += entry_len;
    }

    if (pos != eocd.cd_end) {
        if (eocd.cd_end - pos < 6) return false;
        auto sig = le32(reader, pos);
        auto length = le16(reader, pos + 4);
        if (!sig || !length || *sig != kDigitalSignatureSig) return false;
        if (pos + 6 + *length != eocd.cd_end) return false;
    }

    std::sort(entries.begin(), entries.end(),
              [](const Entry& a, const Entry& b) { return a.lho < b.lho; });
    if (entries.front().lho != 0) return false;
    for (size_t i = 1; i < entries.size(); ++i)
        if (entries[i].lho < entries[i - 1].region_end) return false;

    std::vector<std::string> notes;
    const bool mismatch = reader.deep_validate() && deep_check(reader, entries, notes);

    result.verdict = ValidationResult::Verdict::Valid;
    result.length_bytes = eocd.q + 22 + eocd.comment_len;
    result.subtype = classify(cls);
    result.confidence = mismatch ? Confidence::Medium : Confidence::High;
    result.notes = std::move(notes);
    return true;
}

ValidationResult truncated_zip(BoundedReader& reader) {
    const uint64_t limit = reader.limit();
    uint64_t pos = 0;
    uint64_t last_end = 0;
    uint64_t count = 0;
    Classification cls;
    while (count < kMaxEntries) {
        LocalHeader local;
        if (!parse_local(reader, pos, limit, pos == 0, local)) break;
        if ((local.flags & 0x0008u) != 0) break;
        if (local.comp32 == 0xFFFFFFFFu) break;
        if (local.data_end > limit) break;
        update_classification(reader, local.name, count == 0, local.method, local.data_start,
                              local.comp32, local.uncomp32, cls);
        last_end = local.data_end;
        ++count;
        pos = local.data_end;
    }
    if (count == 0) return ValidationResult::invalid();

    ValidationResult result;
    result.verdict = ValidationResult::Verdict::ValidTruncated;
    result.length_bytes = last_end;
    result.subtype = classify(cls);
    result.confidence = Confidence::Low;
    result.notes.push_back("truncated");
    return result;
}

}  // namespace

std::span<const std::span<const uint8_t>> ZipSignature::magics() const {
    static const uint8_t magic[] = {0x50, 0x4B, 0x03, 0x04};
    static const std::span<const uint8_t> list[] = {magic};
    return list;
}

ValidationResult ZipSignature::validate(BoundedReader& reader) const {
    const uint64_t limit = reader.limit();
    if (limit < 30) return ValidationResult::invalid();

    LocalHeader first;
    if (!parse_local(reader, 0, limit, true, first)) return ValidationResult::invalid();
    if (!method_allowed(first.method)) return ValidationResult::invalid();

    const std::vector<uint64_t> eocds = find_eocd(reader, limit);

    // An EOCD whose comment contains another EOCD-like record is tried last, so a
    // real record embedded in a comment wins; the outer record remains a fallback.
    std::vector<uint64_t> deferred;
    for (uint64_t q : eocds) {
        EocdInfo eocd;
        if (!read_eocd(reader, q, limit, eocd)) continue;
        const uint64_t comment_end = q + 22 + eocd.comment_len;
        bool nested = false;
        for (uint64_t inner : eocds) {
            if (inner <= q) continue;
            if (inner >= comment_end) break;
            if (plausible_eocd(reader, inner, limit)) {
                nested = true;
                break;
            }
        }
        if (nested) {
            deferred.push_back(q);
            continue;
        }
        ValidationResult result;
        if (validate_archive(reader, eocd, result)) return result;
    }
    for (uint64_t q : deferred) {
        EocdInfo eocd;
        if (!read_eocd(reader, q, limit, eocd)) continue;
        ValidationResult result;
        if (validate_archive(reader, eocd, result)) return result;
    }

    return truncated_zip(reader);
}

}  // namespace openrecover::carve
