#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"
#include "openrecover/fs/ext4/ext4_dir.hpp"
#include "openrecover/fs/ext4/ext4_inode.hpp"
#include "openrecover/io/block_device.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using openrecover::test::MemoryDevice;
namespace fsys = openrecover::fs;
namespace stdfs = std::filesystem;

// A seed corpus is only worth committing if the seeds are shapes the parser is supposed
// to accept; a seed that already fails proves nothing when the fuzzer mutates it.
std::vector<uint8_t> seed(const char* corpus, const char* name) {
    const stdfs::path path = stdfs::path(OPENRECOVER_FUZZ_SEED_DIR) / corpus / name;
    REQUIRE(stdfs::exists(path));
    return test::load_test_file(path);
}

fsys::Ext4Super small_super() {
    const std::vector<uint8_t> bytes = seed("ext4_super", "valid_small.img");
    MemoryDevice dev(bytes, 512);
    auto super = fsys::read_superblock(dev);
    REQUIRE(super.has_value());
    return *super;
}

fsys::Ext4DirBlock listing(const char* corpus, const char* name, const fsys::Ext4Super& s) {
    const std::vector<uint8_t> bytes = seed(corpus, name);
    auto block = fsys::parse_ext4_dir_block(bytes, s);
    REQUIRE(block.has_value());
    return *block;
}

const fsys::Ext4DirEntry* find(const fsys::Ext4DirBlock& block, const std::string& name) {
    for (const fsys::Ext4DirEntry& entry : block.entries)
        if (entry.name == name) return &entry;
    return nullptr;
}

}  // namespace

TEST_CASE("ext4 fuzz seeds parse", "[ext4][fuzz]") {
    SECTION("the small volume is a volume the superblock reader accepts") {
        const fsys::Ext4Super s = small_super();
        CHECK(s.block_size == 1024);
        CHECK(s.group_count() == 2);
        CHECK(s.inodes_count == 16);
        CHECK(s.filetype());
        CHECK(s.extents_required());
    }
    SECTION("the broken superblock seeds are rejected") {
        for (const char* name : {"bad_magic.img", "bad_geometry.img", "short_volume.img"}) {
            const std::vector<uint8_t> bytes = seed("ext4_super", name);
            MemoryDevice dev(bytes, 512);
            CHECK_FALSE(fsys::read_superblock(dev).has_value());
        }
    }

    const fsys::Ext4Super s = small_super();
    SECTION("a deleted name survives in the slack of a live record") {
        const fsys::Ext4DirBlock root = listing("ext4_dir", "root_with_slack.bin", s);
        REQUIRE(find(root, "notes.txt") != nullptr);
        CHECK_FALSE(find(root, "notes.txt")->deleted);
        REQUIRE(find(root, "secret.txt") != nullptr);
        CHECK(find(root, "secret.txt")->deleted);
    }
    SECTION("two deletions in one second both survive") {
        const fsys::Ext4DirBlock block = listing("ext4_dir", "two_deleted.bin", s);
        for (const char* name : {"a.bin", "b.bin"}) {
            REQUIRE(find(block, name) != nullptr);
            CHECK(find(block, name)->deleted);
        }
    }
    SECTION("the checksum pseudo-entry is skipped, not reported as a name") {
        const fsys::Ext4DirBlock block = listing("ext4_dir", "csum_pseudo_entry.bin", s);
        for (const fsys::Ext4DirEntry& entry : block.entries) CHECK(entry.file_type != 0xDE);
        // The walk has to come out at the same records as the block without the pseudo-entry.
        CHECK(find(block, "notes.txt") != nullptr);
        REQUIRE(find(block, "secret.txt") != nullptr);
        CHECK(find(block, "secret.txt")->deleted);
    }
    SECTION("a block that ends mid-record is reported as truncated, not dropped") {
        const fsys::Ext4DirBlock block = listing("ext4_dir", "short_tail.bin", s);
        CHECK_FALSE(block.entries.empty());
        CHECK(block.truncated);
    }

    SECTION("the inode seeds decode into the inode kinds they were cut from") {
        const std::vector<uint8_t> leaf = seed("ext4_inode", "extent_leaf.bin");
        auto inode = fsys::parse_inode(leaf, s, 14);
        REQUIRE(inode.has_value());
        CHECK(inode->deleted());
        CHECK(inode->extents);
        CHECK(inode->size == 1500);

        auto inline_file = fsys::parse_inode(seed("ext4_inode", "inline_data.bin"), s, 21);
        REQUIRE(inline_file.has_value());
        CHECK(inline_file->inline_data);

        auto indirect = fsys::parse_inode(seed("ext4_inode", "indirect.bin"), s, 23);
        REQUIRE(indirect.has_value());
        CHECK_FALSE(indirect->extents);

        auto encrypted = fsys::parse_inode(seed("ext4_inode", "encrypted.bin"), s, 25);
        REQUIRE(encrypted.has_value());
        CHECK(encrypted->encrypted);
    }
}
