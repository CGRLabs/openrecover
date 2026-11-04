#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ext4_fixture.hpp"
#include "memory_device.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/fs/ext4/ext4_checksum.hpp"
#include "openrecover/fs/ext4/ext4_scanner.hpp"
#include "openrecover/fs/filesystem.hpp"

namespace {

using namespace openrecover;
using openrecover::test::ext4fx::Volume;
using openrecover::test::MemoryDevice;
namespace fx = openrecover::test::ext4fx;

struct Opened {
    std::shared_ptr<MemoryDevice> dev;
    std::unique_ptr<fs::Ext4Scanner> scanner;
    std::vector<RecoveredFile> files;
};

Opened open_volume(const Volume& v) {
    Opened o;
    o.dev = std::make_shared<MemoryDevice>(v.data(), 512);
    auto scanner = fs::Ext4Scanner::open(o.dev);
    REQUIRE(scanner.has_value());
    o.scanner = std::move(*scanner);
    auto files = o.scanner->scan_deleted(fs::ScanOptions{}, nullptr);
    REQUIRE(files.has_value());
    o.files = std::move(*files);
    return o;
}

const RecoveredFile* find(const std::vector<RecoveredFile>& files, const std::string& path) {
    for (const RecoveredFile& f : files)
        if (f.path == path) return &f;
    return nullptr;
}

const RecoveredFile& need(const std::vector<RecoveredFile>& files, const std::string& path) {
    const RecoveredFile* f = find(files, path);
    REQUIRE(f != nullptr);
    return *f;
}

bool note_has(const RecoveredFile& f, const std::string& fragment) {
    return f.note.find(fragment) != std::string::npos;
}

std::vector<uint8_t> read_all(fs::Ext4Scanner& scanner, const RecoveredFile& f) {
    std::vector<uint8_t> buf(static_cast<size_t>(f.size_bytes));
    auto got = scanner.read_file(f, 0, buf.data(), buf.size());
    REQUIRE(got.has_value());
    buf.resize(*got);
    return buf;
}

bool is_zeros(const std::vector<uint8_t>& buf, size_t from, size_t to) {
    return std::all_of(buf.begin() + static_cast<std::ptrdiff_t>(from),
                       buf.begin() + static_cast<std::ptrdiff_t>(to),
                       [](uint8_t b) { return b == 0; });
}

void check_matches_block(const std::vector<uint8_t>& buf, size_t from, uint32_t blk) {
    const std::vector<uint8_t> want = fx::block_content(blk);
    REQUIRE(from + want.size() <= buf.size());
    CHECK(std::equal(want.begin(), want.end(),
                     buf.begin() + static_cast<std::ptrdiff_t>(from)));
}

}  // namespace

TEST_CASE("ext4 scanner recovers the deleted files it was built to find", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    // Two matched names, two ambiguous ones, and seven bodies found in the inode tables --
    // one of which is a reallocated slot and so is not reported at all.
    REQUIRE(o.files.size() == 11);
    CHECK(std::vector<std::string>{o.files[0].path, o.files[1].path} ==
          std::vector<std::string>{"secret.txt", "subdir/photo.jpg"});
    for (size_t i = 2; i < o.files.size(); ++i)
        CHECK(o.files[i].path.rfind("inode-", 0) == 0);

    SECTION("nothing that is still live is reported") {
        CHECK(find(o.files, "notes.txt") == nullptr);
        CHECK(find(o.files, "subdir/keep.dat") == nullptr);
        CHECK(find(o.files, "subdir") == nullptr);
        CHECK(find(o.files, "inode-19") == nullptr);  // its slot was handed to another file
    }

    SECTION("every report is a deleted regular file with a deletion timestamp") {
        for (const RecoveredFile& f : o.files) {
            CHECK(f.origin == FileOrigin::FilesystemMetadata);
            CHECK(f.deleted_unix.has_value());
            CHECK(f.size_bytes > 0);
        }
    }
}

TEST_CASE("ext4 scanner pairs a deleted name with its body by timestamp", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    SECTION("a single name and a single inode at the same second is a confident match") {
        const RecoveredFile& f = need(o.files, "secret.txt");
        CHECK(f.name == "secret.txt");
        CHECK(f.confidence == Confidence::High);
        CHECK(f.flags == 0);
        CHECK(f.note.empty());
        CHECK(f.size_bytes == 1500);
        CHECK(f.deleted_unix == std::optional<int64_t>(fx::kDelSecret));
        CHECK(f.mtime_unix == std::optional<int64_t>(1700000400));
    }
    SECTION("the path comes from the directory that held the file") {
        const RecoveredFile& f = need(o.files, "subdir/photo.jpg");
        CHECK(f.name == "photo.jpg");
        CHECK(f.confidence == Confidence::High);
        CHECK(f.size_bytes == 2500);
        CHECK(f.deleted_unix == std::optional<int64_t>(fx::kDelPhoto));
    }
    SECTION("two names and two inodes in the same second are not guessed apart") {
        const RecoveredFile& a = need(o.files, "inode-17");
        const RecoveredFile& b = need(o.files, "inode-18");
        for (const RecoveredFile* f : {&a, &b}) {
            CHECK((f->flags & file_flags::PathUncertain) != 0);
            CHECK(f->name == f->path);
            CHECK(note_has(*f, "ambiguous_name_at_deletion_time"));
            // The bytes are still the file's own; only the name is in doubt.
            CHECK(f->confidence == Confidence::High);
        }
        CHECK(a.size_bytes == 1024);
        CHECK(b.size_bytes == 1024);
    }
    SECTION("a body with no surviving name is reported by inode number") {
        const RecoveredFile& f = need(o.files, "inode-21");
        CHECK((f.flags & file_flags::PathUncertain) != 0);
        CHECK(note_has(f, "no_deleted_entry_with_this_timestamp"));
    }
}

TEST_CASE("ext4 scanner reads recovered content from the block map", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    SECTION("a two-block deleted file reads back whole") {
        const RecoveredFile& f = need(o.files, "secret.txt");
        REQUIRE(f.extents.size() == 1);
        CHECK(f.extents[0].offset_bytes == 22 * fx::kBlock);
        CHECK(f.extents[0].length_bytes == 1500);  // clamped to the file size, not the run
        CHECK_FALSE(f.extents[0].sparse);

        const std::vector<uint8_t> buf = read_all(*o.scanner, f);
        REQUIRE(buf.size() == 1500);
        check_matches_block(buf, 0, 22);
        const std::vector<uint8_t> tail = fx::block_prefix(23, 476);
        CHECK(std::equal(tail.begin(), tail.end(), buf.begin() + 1024));
    }
    SECTION("a short read and a read at the end of the file") {
        const RecoveredFile& f = need(o.files, "secret.txt");
        std::vector<uint8_t> buf(100, 0xFF);
        auto got = o.scanner->read_file(f, 1490, buf.data(), buf.size());
        REQUIRE(got.has_value());
        CHECK(*got == 10);  // the file ends 10 bytes later, however long the ask was
        auto none = o.scanner->read_file(f, 1500, buf.data(), buf.size());
        REQUIRE(none.has_value());
        CHECK(*none == 0);
    }
    SECTION("a three-block file spanning a partial last block") {
        const RecoveredFile& f = need(o.files, "subdir/photo.jpg");
        REQUIRE(f.extents.size() == 1);
        CHECK(f.extents[0].offset_bytes == 30 * fx::kBlock);
        CHECK(f.extents[0].length_bytes == 2500);
        const std::vector<uint8_t> buf = read_all(*o.scanner, f);
        REQUIRE(buf.size() == 2500);
        check_matches_block(buf, 0, 30);
        check_matches_block(buf, 1024, 31);
        const std::vector<uint8_t> tail = fx::block_prefix(32, 452);
        CHECK(std::equal(tail.begin(), tail.end(), buf.begin() + 2048));
    }
}

TEST_CASE("ext4 scanner marks a file whose blocks were taken back", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    const RecoveredFile& f = need(o.files, "inode-20");
    CHECK((f.flags & file_flags::ClustersReallocated) != 0);
    CHECK(f.confidence == Confidence::Low);
    CHECK(note_has(f, "data_blocks_reused_or_outside_volume"));
    CHECK(f.size_bytes == 2048);
    // The map is still reported; the caller decides whether stale bytes are worth writing.
    REQUIRE(f.extents.size() == 1);
    CHECK(f.extents[0].offset_bytes == 140 * fx::kBlock);
}

TEST_CASE("ext4 scanner recovers inline data without touching the block map", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    const RecoveredFile& f = need(o.files, "inode-21");
    REQUIRE(f.resident_data.has_value());
    CHECK(*f.resident_data == std::vector<uint8_t>(
                  reinterpret_cast<const uint8_t*>("recover me if you can!!"),
                  reinterpret_cast<const uint8_t*>("recover me if you can!!") + 23));
    CHECK(f.extents.empty());
    CHECK(f.confidence == Confidence::High);
    CHECK(f.size_bytes == 23);

    const std::vector<uint8_t> buf = read_all(*o.scanner, f);
    CHECK(buf == *f.resident_data);
}

TEST_CASE("ext4 scanner turns holes and unwritten extents into zeros", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    SECTION("an unmapped range and a punched hole both read as zeros") {
        const RecoveredFile& f = need(o.files, "inode-22");
        REQUIRE(f.extents.size() == 2);
        CHECK(f.extents[0].offset_bytes == 150 * fx::kBlock);
        CHECK(f.extents[0].length_bytes == 2048);
        CHECK_FALSE(f.extents[0].sparse);
        CHECK(f.extents[1].sparse);
        CHECK(f.extents[1].length_bytes == 6144);
        CHECK(note_has(f, "contains_holes_or_unwritten_extents"));
        CHECK(f.confidence == Confidence::High);

        const std::vector<uint8_t> buf = read_all(*o.scanner, f);
        REQUIRE(buf.size() == 8192);
        check_matches_block(buf, 0, 150);
        check_matches_block(buf, 1024, 151);
        CHECK(is_zeros(buf, 2048, 8192));
    }
    SECTION("an unwritten extent does not return the stale bytes underneath it") {
        const RecoveredFile& f = need(o.files, "inode-26");
        REQUIRE(f.extents.size() == 1);
        CHECK(f.extents[0].sparse);
        const std::vector<uint8_t> buf = read_all(*o.scanner, f);
        REQUIRE(buf.size() == 2048);
        CHECK(is_zeros(buf, 0, 2048));
        // The volume really does still hold the previous occupant's bytes there.
        CHECK_FALSE(is_zeros(fx::block_content(200), 0, 1024));
    }
    SECTION("a pre-extents file with holes in its direct slots and its index block") {
        const RecoveredFile& f = need(o.files, "inode-23");
        CHECK(f.size_bytes == 13 * fx::kBlock + 5);
        REQUIRE(f.extents.size() == 6);
        CHECK(f.extents[0].offset_bytes == 160 * fx::kBlock);
        CHECK(f.extents[0].length_bytes == 1024);
        CHECK(f.extents[1].sparse);
        CHECK(f.extents[2].offset_bytes == 161 * fx::kBlock);
        CHECK(f.extents[3].sparse);
        CHECK(f.extents[3].length_bytes == 9 * 1024);
        CHECK(f.extents[4].offset_bytes == 170 * fx::kBlock);
        CHECK(f.extents[5].sparse);

        const std::vector<uint8_t> buf = read_all(*o.scanner, f);
        REQUIRE(buf.size() == 13 * fx::kBlock + 5);
        check_matches_block(buf, 0, 160);
        CHECK(is_zeros(buf, 1024, 2048));
        check_matches_block(buf, 2048, 161);
        CHECK(is_zeros(buf, 3072, 12288));
        check_matches_block(buf, 12288, 170);
        CHECK(is_zeros(buf, 13312, 13317));
    }
}

TEST_CASE("ext4 scanner reports a damaged inode record as a weaker match", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    SECTION("an inode whose checksum no longer fits") {
        const RecoveredFile& f = need(o.files, "inode-24");
        CHECK(f.confidence == Confidence::Medium);
        CHECK(note_has(f, "inode_checksum_mismatch"));
        CHECK(f.size_bytes == 1024);
    }
    SECTION("an encrypted file is named and refused, not misread") {
        const RecoveredFile& f = need(o.files, "inode-25");
        CHECK((f.flags & file_flags::Unsupported) != 0);
        CHECK(note_has(f, "encrypted_content"));
        std::vector<uint8_t> buf(16);
        auto got = o.scanner->read_file(f, 0, buf.data(), buf.size());
        REQUIRE_FALSE(got.has_value());
        CHECK(got.error().code == ErrorCode::Unsupported);
    }
}

TEST_CASE("ext4 scanner answers for the volume it opened", "[ext4][scanner]") {
    Volume v;
    Opened o = open_volume(v);

    CHECK(o.scanner->kind() == fs::FsKind::Ext4);
    CHECK(o.scanner->geometry().bytes_per_cluster == fx::kBlock);
    CHECK(o.scanner->geometry().total_clusters == fx::kBlocksCount);
    CHECK(o.scanner->super().block_size == fx::kBlock);
    CHECK(o.scanner->super().group_count() == 2);
    CHECK(o.scanner->super().super_csum_valid);

    auto inode = o.scanner->read_inode(fx::kSecretIno);
    REQUIRE(inode.has_value());
    CHECK(inode->deleted());
    CHECK(inode->dtime == fx::kDelSecret);
    CHECK_FALSE(o.scanner->read_inode(0).has_value());
    CHECK_FALSE(o.scanner->read_inode(fx::kInodesCount + 1).has_value());
}

TEST_CASE("ext4 scanner warns that a dirty volume's journal is not replayed", "[ext4][scanner]") {
    auto warning_for = [](uint16_t state) {
        Volume v;
        fx::put16(v.data(), fx::lay::kSuperOffset + fx::lay::kState, state);
        std::string warning;
        openrecover::log::set_sink([&](openrecover::LogLevel level, std::string_view message) {
            if (level == openrecover::LogLevel::Warn && warning.empty()) warning.assign(message);
        });
        auto dev = std::make_shared<MemoryDevice>(v.data(), 512);
        auto scanner = fs::Ext4Scanner::open(dev);
        openrecover::log::set_sink(nullptr);
        if (!scanner) return std::string("<open failed>");
        return warning;
    };
    CHECK(warning_for(fx::lay::kStateErrorFs).find("journal") != std::string::npos);
    // A zero state is a volume whose "valid" bit was never set: the kernel would replay first.
    CHECK(warning_for(0).find("journal") != std::string::npos);
    CHECK(warning_for(fx::lay::kStateValidFs).empty());
}

TEST_CASE("ext4 allocation map reads both group bitmaps", "[ext4][scanner]") {
    Volume v;
    auto dev = std::make_shared<MemoryDevice>(v.data(), 512);
    auto scanner = fs::Ext4Scanner::open(dev);
    REQUIRE(scanner.has_value());
    auto map = (*scanner)->allocation_map();
    REQUIRE(map.has_value());

    // Group 0: metadata and live files are claimed, a deleted file's blocks are not.
    CHECK((*map)->is_cluster_allocated(1));
    CHECK((*map)->is_cluster_allocated(20));
    CHECK_FALSE((*map)->is_cluster_allocated(22));
    // Group 1: the block a later write took back, next to the one it did not.
    CHECK((*map)->is_cluster_allocated(140));
    CHECK_FALSE((*map)->is_cluster_allocated(141));
    CHECK((*map)->cluster_count() == fx::kBlocksCount);
    CHECK((*map)->cluster_to_byte_offset(7) == 7 * fx::kBlock);

    CHECK((*map)->is_cluster_allocated(fx::kBlocksCount));  // past the volume is not free
}

TEST_CASE("ext4 allocation map follows each group's own bitmap under flex_bg", "[ext4][scanner]") {
    Volume v;
    auto& img = v.data();
    const size_t s = fx::lay::kSuperOffset;
    const std::span<const uint8_t> image(img.data(), img.size());
    fx::put32(img, s + fx::lay::kFeatureIncompat,
              fs::u32_at(image, s + fx::lay::kFeatureIncompat) |
                  fs::ext4_feature::kIncompatFlexBg);
    fx::put8(img, s + fx::lay::kLogGroupsPerFlex, 1);  // both groups share one flex cluster
    fx::put32(img, s + fx::lay::kSuperChecksum,
              fs::crc32c_continue(0xFFFFFFFFu, img.data() + s, fx::lay::kSuperChecksum));

    auto scanner = fs::Ext4Scanner::open(std::make_shared<MemoryDevice>(img, 512));
    REQUIRE(scanner.has_value());
    auto map = (*scanner)->allocation_map();
    REQUIRE(map.has_value());
    // 140 is allocated only in group 1's bitmap; reading the cluster's first bitmap,
    // which is what flex_bg packs next to it, would call it free.
    CHECK((*map)->is_cluster_allocated(140));
    CHECK_FALSE((*map)->is_cluster_allocated(141));
}

TEST_CASE("ext4 scanner reacts to a volume that changed under it", "[ext4][scanner]") {
    SECTION("a name is lost when its body is claimed again") {
        Volume v;
        // The allocator takes secret.txt's two blocks back.
        v.data()[fx::block_bit_byte(22)] |= 1u << (22 % 8);
        v.data()[fx::block_bit_byte(23)] |= 1u << (23 % 8);
        Opened o = open_volume(v);
        const RecoveredFile& f = need(o.files, "secret.txt");
        CHECK((f.flags & file_flags::ClustersReallocated) != 0);
        CHECK(f.confidence == Confidence::Low);
    }
    SECTION("a deleted inode whose slot is in use again is not reported") {
        Volume v;
        v.data()[fx::inode_bit_byte(fx::kSecretIno)] |= 1u << ((fx::kSecretIno - 1) % 8);
        Opened o = open_volume(v);
        CHECK(find(o.files, "secret.txt") == nullptr);
        CHECK(o.files.size() == 10);
    }
    SECTION("a directory block that stops mid-record still yields what came before it") {
        Volume v;
        // Break the folded length of the entry that hides secret.txt.
        fx::put16(v.data(), fx::block_byte(fx::kRootBlock) + 24 + fx::lay::kDirEntryRecLen, 4000);
        Opened o = open_volume(v);
        CHECK(find(o.files, "secret.txt") == nullptr);
        CHECK(find(o.files, "inode-14") != nullptr);
    }
}

TEST_CASE("ext4 scanner can be cancelled", "[ext4][scanner]") {
    Volume v;
    auto dev = std::make_shared<MemoryDevice>(v.data(), 512);
    auto scanner = fs::Ext4Scanner::open(dev);
    REQUIRE(scanner.has_value());
    auto files = (*scanner)->scan_deleted(fs::ScanOptions{}, [](uint64_t, uint64_t) { return false; });
    REQUIRE_FALSE(files.has_value());
    CHECK(files.error().code == ErrorCode::Cancelled);
}

TEST_CASE("ext4 detection hands an ext4 volume to the ext4 scanner", "[ext4][scanner][detect]") {
    Volume v;
    auto dev = std::make_shared<MemoryDevice>(v.data(), 512);
    auto scanner = fs::detect_and_open(dev);
    REQUIRE(scanner.has_value());
    CHECK((*scanner)->kind() == fs::FsKind::Ext4);
    CHECK((*scanner)->geometry().bytes_per_cluster == fx::kBlock);
}
