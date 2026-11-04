#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_seeds.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_cfb.hpp"

namespace {
using namespace openrecover;
using namespace openrecover::carve;

constexpr uint32_t kEndOfChain = 0xFFFFFFFEu;
constexpr uint32_t kFreeSect = 0xFFFFFFFFu;
constexpr uint32_t kFatSect = 0xFFFFFFFDu;
constexpr uint32_t kDifatSect = 0xFFFFFFFCu;
constexpr uint32_t kNoStream = 0xFFFFFFFFu;
constexpr size_t kHeaderBytes = 512;
constexpr size_t kEntryBytes = 128;
constexpr size_t kInlineDifat = 109;

void put16le(std::vector<uint8_t>& out, size_t at, uint16_t value) {
    out[at] = static_cast<uint8_t>(value & 0xFF);
    out[at + 1] = static_cast<uint8_t>(value >> 8);
}

void put32le(std::vector<uint8_t>& out, size_t at, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) out[at + i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
}

void put64le(std::vector<uint8_t>& out, size_t at, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) out[at + i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
}

uint16_t rd16(const std::vector<uint8_t>& bytes, size_t at) {
    return static_cast<uint16_t>(bytes[at] | (bytes[at + 1] << 8));
}

uint32_t rd32(const std::vector<uint8_t>& bytes, size_t at) {
    return static_cast<uint32_t>(bytes[at]) | (static_cast<uint32_t>(bytes[at + 1]) << 8) |
           (static_cast<uint32_t>(bytes[at + 2]) << 16) | (static_cast<uint32_t>(bytes[at + 3]) << 24);
}

struct StreamSpec {
    std::string name;
    size_t size;
};

struct CfbParts {
    uint16_t version = 3;
    uint16_t sector_shift = 9;
    std::vector<StreamSpec> streams = {{"WordDocument", 8192}, {"1Table", 4096}};
    size_t extra_fat_sectors = 0;
};

void put_entry(std::vector<uint8_t>& out, size_t at, std::string_view name, uint8_t type,
               uint32_t start, uint64_t size, uint32_t child, uint32_t right) {
    for (size_t i = 0; i < name.size(); ++i) put16le(out, at + i * 2, static_cast<uint8_t>(name[i]));
    put16le(out, at + name.size() * 2, 0);  // the terminator is part of the stored name
    put16le(out, at + 0x40, static_cast<uint16_t>((name.size() + 1) * 2));
    out[at + 0x42] = type;
    out[at + 0x43] = 1;  // black
    put32le(out, at + 0x44, kNoStream);
    put32le(out, at + 0x48, right);
    put32le(out, at + 0x4C, child);
    put32le(out, at + 0x74, start);
    put64le(out, at + 0x78, size);
}

// A compound file laid out the way a legacy Word document is: the allocation table first, then the
// directory, then each stream in its own chain. The table is the only thing in the container that
// says where the file ends, so the builder has to write it from the same arithmetic the format uses.
std::vector<uint8_t> build_cfb(const CfbParts& parts) {
    const uint64_t sector_size = 1ull << parts.sector_shift;
    const uint64_t entries = sector_size / 4;

    std::vector<size_t> chain_lengths;
    uint64_t data_sectors = 0;
    for (const StreamSpec& stream : parts.streams) {
        const size_t length = static_cast<size_t>((stream.size + sector_size - 1) / sector_size);
        chain_lengths.push_back(length);
        data_sectors += length;
    }
    const uint64_t dir_sectors =
        (parts.streams.size() + 1) * kEntryBytes / sector_size +
        ((parts.streams.size() + 1) * kEntryBytes % sector_size != 0 ? 1 : 0);

    uint64_t fat_sectors = 1;
    for (;;) {
        const uint64_t difat = fat_sectors <= kInlineDifat
                                  ? 0
                                  : (fat_sectors - kInlineDifat + entries - 3) / (entries - 2);
        if (fat_sectors + dir_sectors + data_sectors + difat <= fat_sectors * entries) break;
        ++fat_sectors;
    }
    fat_sectors += parts.extra_fat_sectors;
    const uint64_t difat_sectors =
        fat_sectors <= kInlineDifat ? 0 : (fat_sectors - kInlineDifat + entries - 3) / (entries - 2);

    const uint64_t dir_start = fat_sectors;
    const uint64_t difat_start = dir_start + dir_sectors;
    const uint64_t data_start = difat_start + difat_sectors;

    std::vector<uint32_t> fat(static_cast<size_t>(fat_sectors * entries), kFreeSect);
    for (uint64_t i = 0; i < fat_sectors; ++i) fat[static_cast<size_t>(i)] = kFatSect;
    for (uint64_t i = 0; i < dir_sectors; ++i) {
        fat[static_cast<size_t>(dir_start + i)] =
            (i + 1 < dir_sectors) ? static_cast<uint32_t>(dir_start + i + 1) : kEndOfChain;
    }
    // A DIFAT sector is named by the chain inside the sectors themselves, so its own table entry
    // says only what it is.
    for (uint64_t i = 0; i < difat_sectors; ++i)
        fat[static_cast<size_t>(difat_start + i)] = kDifatSect;
    std::vector<uint32_t> starts;
    uint64_t cursor = data_start;
    for (size_t length : chain_lengths) {
        starts.push_back(static_cast<uint32_t>(cursor));
        for (size_t i = 0; i < length; ++i) {
            fat[static_cast<size_t>(cursor + i)] =
                (i + 1 < length) ? static_cast<uint32_t>(cursor + i + 1) : kEndOfChain;
        }
        cursor += length;
    }
    const uint64_t total_sectors = cursor;

    std::vector<uint8_t> out(kHeaderBytes, 0);
    static constexpr uint8_t kMagic[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    std::memcpy(out.data(), kMagic, 8);
    put16le(out, 0x18, 0x003E);
    put16le(out, 0x1A, parts.version);
    put16le(out, 0x1C, 0xFFFE);
    put16le(out, 0x1E, parts.sector_shift);
    put16le(out, 0x20, 6);
    put32le(out, 0x28, parts.version == 4 ? static_cast<uint32_t>(dir_sectors) : 0u);
    put32le(out, 0x2C, static_cast<uint32_t>(fat_sectors));
    put32le(out, 0x30, static_cast<uint32_t>(dir_start));
    put32le(out, 0x38, 0x1000);
    put32le(out, 0x3C, kEndOfChain);  // every stream here is big enough to need no mini stream
    put32le(out, 0x40, 0);
    put32le(out, 0x44, difat_sectors == 0 ? kEndOfChain : static_cast<uint32_t>(difat_start));
    put32le(out, 0x48, static_cast<uint32_t>(difat_sectors));
    for (size_t i = 0; i < kInlineDifat; ++i) {
        put32le(out, 0x4C + i * 4,
                i < fat_sectors ? static_cast<uint32_t>(i) : kFreeSect);
    }

    for (uint64_t k = 0; k < fat_sectors; ++k) {
        const size_t at = out.size();
        out.resize(at + sector_size);
        for (uint64_t j = 0; j < entries; ++j) {
            put32le(out, at + static_cast<size_t>(j * 4),
                    fat[static_cast<size_t>(k * entries + j)]);
        }
    }

    const size_t directory_at = out.size();
    out.resize(directory_at + dir_sectors * sector_size);
    put_entry(out, directory_at, "Root Entry", 5, kEndOfChain, 0,
              parts.streams.empty() ? kNoStream : 1u, kNoStream);
    for (size_t i = 0; i < parts.streams.size(); ++i) {
        const uint32_t right = i + 1 < parts.streams.size()
                                   ? static_cast<uint32_t>(i + 2)
                                   : kNoStream;
        put_entry(out, directory_at + (i + 1) * kEntryBytes, parts.streams[i].name, 2, starts[i],
                  parts.streams[i].size, kNoStream, right);
    }

    for (uint64_t k = 0; k < difat_sectors; ++k) {
        const size_t at = out.size();
        out.resize(at + sector_size);
        for (uint64_t j = 0; j + 2 < entries; ++j) {
            const uint64_t id = kInlineDifat + k * (entries - 2) + j;
            put32le(out, at + static_cast<size_t>(j * 4),
                    id < fat_sectors ? static_cast<uint32_t>(id) : kFreeSect);
        }
        const uint32_t next =
            k + 1 == difat_sectors ? kEndOfChain : static_cast<uint32_t>(difat_start + k + 1);
        put32le(out, at + static_cast<size_t>((entries - 2) * 4), next);
        put32le(out, at + static_cast<size_t>((entries - 1) * 4),
                static_cast<uint32_t>(difat_sectors));
    }

    for (size_t i = 0; i < parts.streams.size(); ++i) {
        const size_t at = out.size();
        out.resize(at + chain_lengths[i] * sector_size);
        const size_t seed = 3 + parts.streams[i].name.size();
        for (size_t j = 0; j < parts.streams[i].size; ++j)
            out[at + j] = static_cast<uint8_t>((j * seed) & 0xFF);
    }

    REQUIRE(out.size() == kHeaderBytes + total_sectors * sector_size);
    return out;
}

ValidationResult validate(const std::vector<uint8_t>& bytes, size_t limit = 0) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, limit == 0 ? bytes.size() : limit);
    return CfbSignature{}.validate(reader);
}

// The name sits at the start of a directory entry, so finding it finds the entry.
size_t entry_at(const std::vector<uint8_t>& bytes, std::string_view name) {
    std::vector<uint8_t> label(name.size() * 2, 0);
    for (size_t i = 0; i < name.size(); ++i) label[i * 2] = static_cast<uint8_t>(name[i]);
    auto found = std::search(bytes.begin(), bytes.end(), label.begin(), label.end());
    REQUIRE(found != bytes.end());
    return static_cast<size_t>(found - bytes.begin());
}

size_t fat_entry_at(const std::vector<uint8_t>& bytes, uint64_t sector) {
    const uint64_t sector_size = 1ull << rd16(bytes, 0x1E);
    return kHeaderBytes + static_cast<size_t>(sector / (sector_size / 4)) * sector_size +
           static_cast<size_t>(sector % (sector_size / 4)) * 4;
}

std::vector<StreamSpec> only(std::string_view name, size_t size) {
    return {StreamSpec{std::string(name), size}};
}

constexpr std::array<std::string_view, 4> kSubtypes{"cfb", "doc", "xls", "ppt"};

}  // namespace

TEST_CASE("cfb: a Word document says where it ends through its allocation table", "[cfb][m3]") {
    const std::vector<uint8_t> bytes = build_cfb({});
    const ValidationResult res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.confidence == Confidence::High);
    CHECK(res.subtype == "doc");
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.notes.empty());

    // The table is the length field of this format: one sector short of the end is a shorter file.
    const size_t last_fat = fat_entry_at(bytes, rd32(bytes, 0x30));
    CHECK(rd32(bytes, last_fat) != kFreeSect);
}

TEST_CASE("cfb: the stream the directory lists names the file", "[cfb][m3]") {
    struct Case {
        std::string_view stream;
        std::string_view subtype;
    };
    for (const Case& e : {Case{"Workbook", "xls"}, Case{"Book", "xls"},
                          Case{"PowerPoint Document", "ppt"}, Case{"WordDocument", "doc"}}) {
        CfbParts parts;
        parts.streams = only(e.stream, 4096);
        const ValidationResult res = validate(build_cfb(parts));
        REQUIRE(res.is_valid());
        CHECK(res.subtype == e.subtype);
        CHECK(res.confidence == Confidence::High);
    }

    // A compound file that holds no application stream is still a compound file.
    CfbParts generic;
    generic.streams = {StreamSpec{"\x01" "CompObj", 4096}};
    const ValidationResult res = validate(build_cfb(generic));
    REQUIRE(res.is_valid());
    CHECK(res.subtype == "cfb");
    CHECK(res.confidence == Confidence::Medium);
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "no known application stream");
}

TEST_CASE("cfb: version 4 keeps the same facts in four kibibyte sectors", "[cfb][m3]") {
    CfbParts parts;
    parts.version = 4;
    parts.sector_shift = 12;
    parts.streams = only("WordDocument", 20000);
    const std::vector<uint8_t> bytes = build_cfb(parts);
    const ValidationResult res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.subtype == "doc");
    CHECK(res.length_bytes == bytes.size());
}

TEST_CASE("cfb: an allocation table the header cannot list keeps going", "[cfb][m3]") {
    CfbParts parts;
    parts.streams = only("WordDocument", 4096);
    parts.extra_fat_sectors = 110;  // past the 109 sectors the header itself can name
    const std::vector<uint8_t> bytes = build_cfb(parts);
    REQUIRE(rd32(bytes, 0x2C) > kInlineDifat);
    REQUIRE(rd32(bytes, 0x48) >= 1);

    const ValidationResult res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.subtype == "doc");

    // The map the chain carries has to be the map the header promises.
    const uint64_t sector_size = 1ull << rd16(bytes, 0x1E);
    const uint64_t entries = sector_size / 4;
    const size_t difat_at =
        kHeaderBytes + static_cast<size_t>(rd32(bytes, 0x44)) * sector_size;
    std::vector<uint8_t> broken = bytes;
    put32le(broken, difat_at + static_cast<size_t>((entries - 1) * 4), 7);
    CHECK_FALSE(validate(broken).is_valid());

    broken = bytes;
    put32le(broken, difat_at + static_cast<size_t>((entries - 2) * 4), 4);  // a chain that never ends
    CHECK_FALSE(validate(broken).is_valid());
}

TEST_CASE("cfb: a table with no free sector at the end claims no end", "[cfb][m3]") {
    CfbParts parts;
    parts.streams = {StreamSpec{"WordDocument", 126 * 512}};  // fills the one table sector exactly
    const std::vector<uint8_t> bytes = build_cfb(parts);
    REQUIRE(rd32(bytes, 0x2C) == 1);

    const ValidationResult res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.confidence == Confidence::Low);
    CHECK(res.length_bytes == bytes.size());
    REQUIRE(res.notes.size() == 1);
    CHECK(res.notes[0] == "every sector the table describes is in use");
}

TEST_CASE("cfb: a cut container is claimed only as far as its table reaches", "[cfb][m3]") {
    const std::vector<uint8_t> whole = build_cfb({});

    std::vector<uint8_t> cut = whole;
    cut.resize(4096);  // the table is readable, the streams it describes are not all there
    const ValidationResult partial = validate(cut);
    REQUIRE(partial.is_valid());
    CHECK(partial.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(partial.confidence == Confidence::Low);
    CHECK(partial.length_bytes == cut.size());
    REQUIRE(partial.notes.size() == 1);
    CHECK(partial.notes[0] == "the sector table extends past the scan window");

    cut = whole;
    cut.resize(600);  // not even one sector of the table is inside the window
    const ValidationResult head_only = validate(cut);
    CHECK_FALSE(head_only.is_valid());

    // The same container scanned a little further reaches its first table sector, and the entries
    // in it are enough to say the file goes on.
    cut = whole;
    cut.resize(1024);
    const ValidationResult one_sector = validate(cut);
    REQUIRE(one_sector.is_valid());
    CHECK(one_sector.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(one_sector.length_bytes == cut.size());
    REQUIRE(one_sector.notes.size() == 1);
    CHECK(one_sector.notes[0] == "the sector table extends past the scan window");

    // A table with more sectors than the window covers says so, whatever else it could tell.
    CfbParts many;
    many.streams = only("WordDocument", 4096);
    many.extra_fat_sectors = 110;
    std::vector<uint8_t> wide = build_cfb(many);
    REQUIRE(rd32(wide, 0x2C) > 2);
    wide.resize(1536);  // two of its table sectors
    const ValidationResult partly = validate(wide);
    REQUIRE(partly.is_valid());
    CHECK(partly.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(partly.confidence == Confidence::Low);
    CHECK(partly.length_bytes == wide.size());
    REQUIRE(partly.notes.size() == 1);
    CHECK(partly.notes[0] == "the allocation table continues past the scan window");
}

TEST_CASE("cfb: a chain that aims at a sector the table left free is refused", "[cfb][m3]") {
    std::vector<uint8_t> bytes = build_cfb({});
    const uint32_t first = rd32(bytes, entry_at(bytes, "WordDocument") + 0x74);
    put32le(bytes, fat_entry_at(bytes, first), 100);  // a sector the file never uses
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("cfb: a directory entry that points past the last sector is refused", "[cfb][m3]") {
    std::vector<uint8_t> bytes = build_cfb({});
    put32le(bytes, entry_at(bytes, "1Table") + 0x74, 0x00FF0000);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("cfb: a stream larger than its container is refused", "[cfb][m3]") {
    std::vector<uint8_t> bytes = build_cfb({});
    put32le(bytes, entry_at(bytes, "1Table") + 0x78, 1u << 31);
    put32le(bytes, entry_at(bytes, "1Table") + 0x7C, 0);
    CHECK_FALSE(validate(bytes).is_valid());

    // A version 3 container has no room for a stream that large in the first place.
    bytes = build_cfb({});
    put32le(bytes, entry_at(bytes, "WordDocument") + 0x7C, 1);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("cfb: a directory that chains to itself is refused", "[cfb][m3]") {
    std::vector<uint8_t> bytes = build_cfb({});
    const uint32_t directory = rd32(bytes, 0x30);
    put32le(bytes, fat_entry_at(bytes, directory), directory);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("cfb: a container with only a root entry holds nothing to recover", "[cfb][m3]") {
    CfbParts parts;
    parts.streams.clear();
    CHECK_FALSE(validate(build_cfb(parts)).is_valid());
}

TEST_CASE("cfb: a map that names a sector the table cannot reach is refused", "[cfb][m3]") {
    std::vector<uint8_t> bytes = build_cfb({});
    put32le(bytes, 0x4C, 0x00FF0000);  // the first table sector is now out of the table's range
    CHECK_FALSE(validate(bytes).is_valid());

    // A table larger than the signature allows is not a document, it is a corrupted count.
    bytes = build_cfb({});
    put32le(bytes, 0x2C, 0xFFFFFFFF);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("cfb: header fields that are not the format's are refused", "[cfb][m3]") {
    const auto refused = [](auto mutate) {
        std::vector<uint8_t> bytes = build_cfb({});
        mutate(bytes);
        CHECK_FALSE(validate(bytes).is_valid());
    };

    refused([](std::vector<uint8_t>& b) { put16le(b, 0x1C, 0x00FE); });   // foreign byte order
    refused([](std::vector<uint8_t>& b) { put16le(b, 0x1E, 10); });       // no such sector size
    refused([](std::vector<uint8_t>& b) { put16le(b, 0x1E, 12); });       // a v3 file with v4 sectors
    refused([](std::vector<uint8_t>& b) { put16le(b, 0x1A, 5); });        // a version nobody wrote
    refused([](std::vector<uint8_t>& b) { put16le(b, 0x20, 7); });        // mini sectors are 64 bytes
    refused([](std::vector<uint8_t>& b) { b[0x24] = 0x40; });             // a reserved byte in use
    refused([](std::vector<uint8_t>& b) { put32le(b, 0x2C, 0); });        // no table at all
    refused([](std::vector<uint8_t>& b) { put32le(b, 0x28, 3); });        // v3 has no sector count
    refused([](std::vector<uint8_t>& b) { put32le(b, 0x38, 100); });      // a cutoff in no unit
    refused([](std::vector<uint8_t>& b) { put32le(b, 0x3C, 4); });        // a mini table with none
    refused([](std::vector<uint8_t>& b) { put32le(b, 0x44, 4); });        // a map with no sectors
    refused([](std::vector<uint8_t>& b) { b[0] = 0xD1; });               // not this container
}

TEST_CASE("cfb: directory entries are the three kinds the format defines", "[cfb][m3]") {
    const auto refused = [](auto mutate) {
        std::vector<uint8_t> bytes = build_cfb({});
        mutate(bytes);
        CHECK_FALSE(validate(bytes).is_valid());
    };

    refused([](std::vector<uint8_t>& b) {
        b[entry_at(b, "Root Entry") + 0x42] = 4;  // no object type 4
    });
    refused([](std::vector<uint8_t>& b) { b[entry_at(b, "Root Entry") + 0x43] = 2; });  // colour
    refused([](std::vector<uint8_t>& b) { put16le(b, entry_at(b, "Root Entry") + 0x40, 5); });
    refused([](std::vector<uint8_t>& b) { put16le(b, entry_at(b, "Root Entry") + 0x40, 66); });
}

TEST_CASE("cfb: the signature's own identity", "[cfb][m3]") {
    CfbSignature sig;
    CHECK(sig.name() == "cfb");
    CHECK(sig.default_extension() == "cfb");
    CHECK(sig.min_header_bytes() == kHeaderBytes);
    REQUIRE(sig.magics().size() == 1);
    REQUIRE(sig.magics()[0].size() == 8);
    static constexpr uint8_t kWant[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    CHECK(std::memcmp(sig.magics()[0].data(), kWant, 8) == 0);
}

TEST_CASE("cfb: a candidate shorter than the header is refused", "[cfb][m3]") {
    std::vector<uint8_t> bytes(511, 0);
    static constexpr uint8_t kMagic[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    std::memcpy(bytes.data(), kMagic, 8);
    CHECK_FALSE(validate(bytes).is_valid());

    // The header is 512 bytes even when the version 4 sectors behind it are not there yet.
    CHECK_FALSE(validate(bytes, 8).is_valid());
}

TEST_CASE("cfb: every single-byte mutation is refused or stays inside the window",
          "[cfb][m3][mutation]") {
    const std::vector<uint8_t> good = build_cfb({});
    size_t accepted = 0;
    size_t refused = 0;
    for (size_t offset = 0; offset < good.size(); ++offset) {
        for (uint8_t value : {uint8_t{0x00}, uint8_t{0xFF}, uint8_t{0x20}, uint8_t{0x41}}) {
            std::vector<uint8_t> mutated = good;
            mutated[offset] = value;
            const ValidationResult res = validate(mutated);
            if (!res.is_valid()) {
                ++refused;
                continue;
            }
            ++accepted;
            CHECK(res.length_bytes > 0);
            CHECK(res.length_bytes <= mutated.size());
            CHECK((res.subtype == "cfb" || res.subtype == "doc" || res.subtype == "xls" ||
                   res.subtype == "ppt"));
            if (res.verdict == ValidationResult::Verdict::Valid) {
                CHECK(res.confidence != Confidence::Low);
                // A generic container is still a full file; it is only less sure of what it holds.
                for (const std::string& note : res.notes)
                    CHECK(note == "no known application stream");
            }
            if (res.verdict == ValidationResult::Verdict::ValidTruncated) {
                CHECK(res.length_bytes == mutated.size());
                CHECK(res.confidence == Confidence::Low);
            }
        }
    }
    CHECK(accepted > 0);
    CHECK(refused > 0);
}

TEST_CASE("cfb: the committed fuzz seeds validate as named", "[cfb][m3][fuzz]") {
    test::check_signature_seed_corpus(OPENRECOVER_FUZZ_SEED_DIR, CfbSignature{}, kSubtypes);
}
