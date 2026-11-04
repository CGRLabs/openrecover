#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <tuple>
#include <utility>
#include <vector>

#include "ext4_fixture.hpp"
#include "memory_device.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"
#include "openrecover/fs/ext4/ext4_dir.hpp"

namespace {

using namespace openrecover;
using openrecover::test::ext4fx::Volume;
using openrecover::test::MemoryDevice;
namespace fx = openrecover::test::ext4fx;
namespace lay = openrecover::fs::ext4_layout;

fs::Ext4Super super_of(const Volume& v) {
    MemoryDevice dev(v.data(), 512);
    auto s = fs::read_superblock(dev);
    REQUIRE(s.has_value());
    return *s;
}

struct Parsed {
    std::vector<fs::Ext4DirEntry> entries;
    bool truncated = false;
};

Parsed parse_raw(const Volume& v, const std::vector<uint8_t>& block) {
    const auto s = super_of(v);
    auto out = fs::parse_ext4_dir_block(std::span<const uint8_t>(block.data(), block.size()), s);
    REQUIRE(out.has_value());
    Parsed p;
    p.entries = std::move(out->entries);
    p.truncated = out->truncated;
    return p;
}

Parsed parse_block(const Volume& v, uint32_t block) {
    const size_t off = fx::block_byte(block);
    std::vector<uint8_t> bytes(v.data().begin() + static_cast<std::ptrdiff_t>(off),
                               v.data().begin() +
                                   static_cast<std::ptrdiff_t>(off + fx::kBlock));
    return parse_raw(v, bytes);
}

// One record at an explicit byte offset, for the block shapes only a hand-built image can
// express: a checksum pseudo-entry, or a deleted name living in another record's slack.
void put_rec(std::vector<uint8_t>& block, size_t at, uint32_t ino, uint16_t rec_len,
             const std::string& name, uint8_t type) {
    fx::put32(block, at + lay::kDirEntryInode, ino);
    fx::put16(block, at + lay::kDirEntryRecLen, rec_len);
    block[at + lay::kDirEntryNameLen] = static_cast<uint8_t>(name.size());
    block[at + lay::kDirEntryFileType] = type;
    std::memcpy(block.data() + at + lay::kDirEntryNameOffset, name.data(), name.size());
}

// One hand-made block from record fields, for the shapes the fixture cannot express.
Parsed make_and_parse(const Volume& v,
                      const std::vector<std::tuple<int, int, int, int, std::string>>& records,
                      bool junk_tail = false) {
    std::vector<uint8_t> block(fx::kBlock, 0);
    size_t off = 0;
    for (const auto& [ino, rec_len, name_len, type, name] : records) {
        fx::put32(block, off + lay::kDirEntryInode, static_cast<uint32_t>(ino));
        fx::put16(block, off + lay::kDirEntryRecLen, static_cast<uint16_t>(rec_len));
        block[off + lay::kDirEntryNameLen] = static_cast<uint8_t>(name_len);
        block[off + lay::kDirEntryFileType] = static_cast<uint8_t>(type);
        std::memcpy(block.data() + off + lay::kDirEntryNameOffset, name.data(), name.size());
        off += static_cast<size_t>(rec_len);
    }
    if (junk_tail)
        for (size_t i = off; i < block.size(); ++i)
            if (block[i] == 0) block[i] = 0x7A;
    return parse_raw(v, block);
}

std::string joined(const std::vector<fs::Ext4DirEntry>& entries) {
    std::string out;
    for (const fs::Ext4DirEntry& e : entries) {
        if (!out.empty()) out += ",";
        out += e.name;
        if (e.deleted) out += "!";
    }
    return out;
}

}  // namespace

TEST_CASE("ext4 directory block yields live and deleted records", "[ext4][dir]") {
    Volume v;
    const Parsed root = parse_block(v, fx::kRootBlock);
    // "." and ".." are not files, and the deleted entry sits inside the slack of the record
    // whose length absorbed it.
    CHECK(joined(root.entries) == "notes.txt,secret.txt!,subdir,misc");
    CHECK_FALSE(root.truncated);

    const fs::Ext4DirEntry& secret = root.entries[1];
    CHECK(secret.deleted);
    CHECK(secret.inode == 0);
    CHECK(secret.file_type == fs::ext4_file_type::kRegular);
    CHECK(root.entries[0].inode == fx::kNotesIno);
    CHECK(root.entries[2].type_is_directory());
    CHECK_FALSE(root.entries[2].deleted);
}

TEST_CASE("ext4 directory records folded into a parent slot", "[ext4][dir]") {
    Volume v;
    SECTION("one deleted name in the slack of a lengthened entry") {
        const Parsed sub = parse_block(v, fx::kSubBlock);
        CHECK(joined(sub.entries) == "photo.jpg!,keep.dat");
        CHECK_FALSE(sub.truncated);
    }
    SECTION("two deleted names in one slot, in block order") {
        const Parsed misc = parse_block(v, fx::kMiscBlock);
        CHECK(joined(misc.entries) == "a.bin!,b.bin!");
        CHECK_FALSE(misc.truncated);
    }
}

TEST_CASE("ext4 directory padding is not truncation", "[ext4][dir]") {
    Volume v;
    SECTION("a zero-length record with only zeros after it ends the block cleanly") {
        const Parsed p = make_and_parse(v, {{2, 24, 5, 1, "files"}});
        CHECK(joined(p.entries) == "files");
        CHECK_FALSE(p.truncated);
    }
    SECTION("a record claiming more bytes than the block holds stops the walk") {
        const Parsed p = make_and_parse(v, {{2, 24, 5, 1, "files"}, {3, 4000, 4, 1, "tail"}});
        CHECK(joined(p.entries) == "files");
        CHECK(p.truncated);
    }
    SECTION("bytes that are neither a record nor an empty tail are corruption") {
        const Parsed p = make_and_parse(v, {{2, 24, 5, 1, "files"}}, /*junk_tail=*/true);
        CHECK(joined(p.entries) == "files");
        CHECK(p.truncated);
    }
}

TEST_CASE("ext4 directory pseudo-entries and stale slack", "[ext4][dir]") {
    Volume v;
    SECTION("the metadata_csum head entry is skipped by the length it claims") {
        std::vector<uint8_t> block(fx::kBlock, 0);
        put_rec(block, 0, 0xFFFFFFFEu, 16, "", fs::ext4_file_type::kDirCsum);
        put_rec(block, 16, 5, 24, "data", fs::ext4_file_type::kRegular);
        const Parsed p = parse_raw(v, block);
        CHECK(joined(p.entries) == "data");
        CHECK_FALSE(p.truncated);
    }
    SECTION("a name in slack that claims less space than it needs is stale bytes") {
        // "hold" was lengthened by a deletion and its slot reaches past 24, so a reader that
        // only checks that a name fits would accept the entry there. Its own rec_len is
        // shorter than its name, which no written record ever was.
        std::vector<uint8_t> block(fx::kBlock, 0);
        put_rec(block, 0, 2, 12, ".", fs::ext4_file_type::kDirectory);
        put_rec(block, 12, 7, 60, "hold", fs::ext4_file_type::kRegular);
        put_rec(block, 24, 0x44, 8, "leftovers", fs::ext4_file_type::kRegular);
        const Parsed p = parse_raw(v, block);
        CHECK(joined(p.entries) == "hold");
        CHECK_FALSE(p.truncated);
    }
    SECTION("a deleted record in that same slack is still found") {
        // Same layout, with the inner record's length made honest: it is a deletion, and it
        // has to come back.
        std::vector<uint8_t> block(fx::kBlock, 0);
        put_rec(block, 0, 2, 12, ".", fs::ext4_file_type::kDirectory);
        put_rec(block, 12, 7, 60, "hold", fs::ext4_file_type::kRegular);
        put_rec(block, 24, 0, 24, "leftovers", fs::ext4_file_type::kRegular);
        CHECK(joined(parse_raw(v, block).entries) == "hold,leftovers!");
    }
}

TEST_CASE("ext4 directory walk survives an empty or short block", "[ext4][dir]") {
    Volume v;
    SECTION("an all-zero block holds no records and is not truncated") {
        std::vector<uint8_t> block(fx::kBlock, 0);
        const Parsed p = parse_raw(v, block);
        CHECK(p.entries.empty());
        CHECK_FALSE(p.truncated);
    }
    SECTION("a block smaller than one record header yields nothing") {
        std::vector<uint8_t> block(4, 0);
        const auto s = super_of(v);
        auto out = fs::parse_ext4_dir_block(std::span<const uint8_t>(block.data(), block.size()),
                                            s);
        REQUIRE(out.has_value());
        CHECK(out->entries.empty());
        CHECK_FALSE(out->truncated);
    }
    SECTION("an entry wider than its slot is not read past the record") {
        // rec_len 8 with a name that needs 20 bytes: the name belongs to whatever owns the
        // rest of the block, so nothing here is a record.
        const Parsed p = make_and_parse(v, {{2, 8, 9, 1, "leftovers"}});
        CHECK(p.entries.empty());
    }
}
