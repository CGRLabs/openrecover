#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "openrecover/common/types.hpp"
#include "openrecover/fs/ntfs_recyclebin.hpp"

namespace {

using namespace openrecover;
namespace fsys = openrecover::fs;

constexpr uint64_t kUnixEpochInFiletime = 11644473600ull;
constexpr int64_t kDeletedUnix = 1704153600;
constexpr uint64_t kDeletedTicks =
    static_cast<uint64_t>(kDeletedUnix + kUnixEpochInFiletime) * 10000000ull;
constexpr const char* kBin = "$Recycle.Bin/S-1-5-21-0-0-0-1001/";

void put32(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
    for (int i = 0; i < 4; ++i) out[offset + i] = static_cast<uint8_t>(value >> (8 * i));
}

void put64(std::vector<uint8_t>& out, size_t offset, uint64_t value) {
    for (int i = 0; i < 8; ++i) out[offset + i] = static_cast<uint8_t>(value >> (8 * i));
}

std::vector<uint8_t> utf16le(std::string_view text) {
    std::vector<uint8_t> out;
    for (char c : text) {
        out.push_back(static_cast<uint8_t>(c));
        out.push_back(0);
    }
    return out;
}

// A version 2 record: the path is followed by its end-of-string character and counted with it.
std::vector<uint8_t> record_v2(std::string_view path, uint64_t size, uint64_t ticks) {
    std::vector<uint8_t> units = utf16le(path);
    const uint32_t characters = static_cast<uint32_t>(units.size() / 2 + 1);
    std::vector<uint8_t> out(28 + units.size() + 2, 0);
    put64(out, 0, 2);
    put64(out, 8, size);
    put64(out, 16, ticks);
    put32(out, 24, characters);
    std::copy(units.begin(), units.end(), out.begin() + 28);
    return out;
}

// A version 1 record: a fixed 260-character field padded with zeroes.
std::vector<uint8_t> record_v1(std::string_view path, uint64_t size, uint64_t ticks) {
    std::vector<uint8_t> out(24 + 520, 0);
    put64(out, 0, 1);
    put64(out, 8, size);
    put64(out, 16, ticks);
    const std::vector<uint8_t> units = utf16le(path);
    std::copy(units.begin(), units.end(), out.begin() + 24);
    return out;
}

RecoveredFile metadata_file(const std::string& stem, std::vector<uint8_t> record) {
    RecoveredFile file;
    file.path = std::string(kBin) + "$I" + stem;
    file.name = "$I" + stem;
    file.size_bytes = record.size();
    file.resident_data = std::move(record);
    file.confidence = Confidence::High;
    return file;
}

RecoveredFile data_file(const std::string& stem, uint64_t size) {
    RecoveredFile file;
    file.path = std::string(kBin) + "$R" + stem;
    file.name = "$R" + stem;
    file.size_bytes = size;
    file.resident_data = std::vector<uint8_t>(static_cast<size_t>(std::min<uint64_t>(size, 64)));
    file.confidence = Confidence::High;
    return file;
}

}  // namespace

TEST_CASE("a version 2 record gives the path, the size and the deletion time", "[M2][ntfs][rb]") {
    const std::vector<uint8_t> record =
        record_v2(R"(C:\Users\bob\My Documents\notes.txt)", 5000, kDeletedTicks);
    auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
    REQUIRE(info.has_value());
    CHECK(info->format_version == 2);
    CHECK(info->original_path == R"(C:\Users\bob\My Documents\notes.txt)");
    CHECK(info->declared_size == 5000);
    REQUIRE(info->deleted_unix.has_value());
    CHECK(*info->deleted_unix == kDeletedUnix);
}

TEST_CASE("a version 1 record stops at the end of the path, padding and all", "[M2][ntfs][rb]") {
    const std::vector<uint8_t> record = record_v1(R"(C:\dir\photo.jpg)", 300, kDeletedTicks);
    auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
    REQUIRE(info.has_value());
    CHECK(info->format_version == 1);
    CHECK(info->original_path == R"(C:\dir\photo.jpg)");
    CHECK(*info->deleted_unix == kDeletedUnix);
}

TEST_CASE("a record without a deletion time is still a record", "[M2][ntfs][rb]") {
    const std::vector<uint8_t> record = record_v2(R"(C:\dir\a.txt)", 10, 0);
    auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
    REQUIRE(info.has_value());
    CHECK(info->original_path == R"(C:\dir\a.txt)");
    CHECK_FALSE(info->deleted_unix.has_value());
}

TEST_CASE("a record we cannot read is an error, not a guess", "[M2][ntfs][rb]") {
    SECTION("a version we do not know") {
        std::vector<uint8_t> record = record_v2(R"(C:\dir\a.txt)", 10, kDeletedTicks);
        put64(record, 0, 3);
        auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
        REQUIRE_FALSE(info.has_value());
        CHECK(info.error().code == ErrorCode::Unsupported);
    }
    SECTION("a header that is not there") {
        const std::vector<uint8_t> record(20, 0);
        auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
        REQUIRE_FALSE(info.has_value());
        CHECK(info.error().code == ErrorCode::CorruptStructure);
    }
    SECTION("a version 2 length that outruns the record") {
        std::vector<uint8_t> record = record_v2(R"(C:\dir\a.txt)", 10, kDeletedTicks);
        put32(record, 24, 4000);
        auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
        REQUIRE_FALSE(info.has_value());
    }
    SECTION("a version 2 record with no path at all") {
        std::vector<uint8_t> record = record_v2(R"(C:\dir\a.txt)", 10, kDeletedTicks);
        put32(record, 24, 0);
        auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
        REQUIRE_FALSE(info.has_value());
    }
    SECTION("a path that is only end-of-string characters") {
        std::vector<uint8_t> record(30, 0);
        put64(record, 0, 2);
        put32(record, 24, 1);
        auto info = fsys::parse_recycle_info(std::span<const uint8_t>(record));
        REQUIRE_FALSE(info.has_value());
    }
    SECTION("an empty record") {
        auto info = fsys::parse_recycle_info(std::span<const uint8_t>{});
        REQUIRE_FALSE(info.has_value());
    }
}

TEST_CASE("a paired record moves the data file back to the path it came from",
          "[M2][ntfs][rb]") {
    std::vector<RecoveredFile> files;
    files.push_back(metadata_file("notes.txt", record_v2(R"(C:\Users\bob\Documents\notes.txt)",
                                                         5000, kDeletedTicks)));
    files.push_back(data_file("notes.txt", 5000));
    files.push_back(metadata_file("photo.jpg", record_v1(R"(C:\dir\2024\photo.jpg)", 300,
                                                         kDeletedTicks)));
    files.push_back(data_file("photo.jpg", 300));

    fsys::apply_recycle_bin_metadata(files);

    const RecoveredFile& notes = files[1];
    CHECK(notes.path == "Users/bob/Documents/notes.txt");
    CHECK(notes.name == "notes.txt");
    CHECK((notes.flags & file_flags::OriginalPathRestored) != 0);
    CHECK(notes.note == "original path restored from $Recycle.Bin metadata");
    CHECK(*notes.deleted_unix == kDeletedUnix);
    CHECK(notes.size_bytes == 5000);

    CHECK(files[3].path == "dir/2024/photo.jpg");
    // The metadata files keep the place the directory tree gives them.
    CHECK(files[0].path == std::string(kBin) + "$Inotes.txt");
    CHECK(files[0].flags == 0);
}

TEST_CASE("metadata that disagrees about the size is marked as uncertain", "[M2][ntfs][rb]") {
    std::vector<RecoveredFile> files;
    files.push_back(
        metadata_file("report.docx", record_v2(R"(C:\Users\bob\Desktop\report.docx)", 99999,
                                               kDeletedTicks)));
    files.push_back(data_file("report.docx", 4096));

    fsys::apply_recycle_bin_metadata(files);

    CHECK(files[1].path == "Users/bob/Desktop/report.docx");
    CHECK((files[1].flags & file_flags::OriginalPathRestored) != 0);
    CHECK((files[1].flags & file_flags::PathUncertain) != 0);
    CHECK(files[1].note ==
          "original path restored from $Recycle.Bin metadata; $I records 99999 bytes, recovered 4096");
}

TEST_CASE("a recorded path that cannot be placed still gives its time", "[M2][ntfs][rb]") {
    for (const char* path : {R"(..\..\Windows\System32\evil.dll)", R"(\\server\share\a.txt)"}) {
        std::vector<RecoveredFile> files;
        files.push_back(metadata_file("a.dll", record_v2(path, 512, kDeletedTicks)));
        files.push_back(data_file("a.dll", 512));
        fsys::apply_recycle_bin_metadata(files);

        INFO("path: " << path);
        CHECK(files[1].path == std::string(kBin) + "$Ra.dll");
        CHECK((files[1].flags & file_flags::OriginalPathRestored) == 0);
        CHECK((files[1].flags & file_flags::PathUncertain) == 0);
        CHECK(*files[1].deleted_unix == kDeletedUnix);
        CHECK(files[1].note == "deletion time from $Recycle.Bin metadata");
    }
}

TEST_CASE("nothing is claimed when the sibling is missing or unreadable", "[M2][ntfs][rb]") {
    std::vector<RecoveredFile> files;
    // A data file whose record was overwritten.
    std::vector<uint8_t> broken = record_v2(R"(C:\dir\b.txt)", 10, kDeletedTicks);
    put32(broken, 24, 4000);
    files.push_back(metadata_file("b.txt", broken));
    files.push_back(data_file("b.txt", 10));
    // A data file with no record at all.
    files.push_back(data_file("c.bin", 10));
    // A file that is not in a recycle bin, named like one that is.
    RecoveredFile outside = data_file("d.txt", 10);
    outside.path = "backup/$Rd.txt";
    files.push_back(outside);

    fsys::apply_recycle_bin_metadata(files);

    CHECK(files[1].path == std::string(kBin) + "$Rb.txt");
    CHECK(files[1].note.empty());
    CHECK_FALSE(files[1].deleted_unix.has_value());
    CHECK(files[2].note.empty());
    CHECK(files[3].path == "backup/$Rd.txt");
    CHECK(files[3].flags == 0);
}

TEST_CASE("a record whose data is not in memory cannot be read here", "[M2][ntfs][rb]") {
    RecoveredFile record = metadata_file("e.txt", record_v2(R"(C:\dir\e.txt)", 10, kDeletedTicks));
    record.resident_data.reset();
    std::vector<RecoveredFile> files;
    files.push_back(std::move(record));
    files.push_back(data_file("e.txt", 10));

    fsys::apply_recycle_bin_metadata(files);

    CHECK(files[1].path == std::string(kBin) + "$Re.txt");
    CHECK(files[1].note.empty());
}

TEST_CASE("hostile records do not invent a path", "[M2][ntfs][rb]") {
    const std::vector<uint8_t> good = record_v2(R"(C:\Users\bob\Documents\notes.txt)", 5000,
                                                kDeletedTicks);
    size_t restored = 0;
    size_t refused = 0;
    for (size_t offset = 0; offset < good.size(); offset += 7) {
        std::vector<uint8_t> mutated = good;
        mutated[offset] ^= 0xA5;
        mutated.push_back(0);

        std::vector<RecoveredFile> files;
        files.push_back(metadata_file("notes.txt", mutated));
        files.push_back(data_file("notes.txt", 5000));
        fsys::apply_recycle_bin_metadata(files);

        const RecoveredFile& data = files[1];
        if ((data.flags & file_flags::OriginalPathRestored) != 0) {
            ++restored;
            // Whatever came out of a mutated record has to be a path the exporter can use.
            CHECK(data.path.find('\\') == std::string::npos);
            CHECK(data.path.find(':') == std::string::npos);
            CHECK(data.path.find("..") == std::string::npos);
            CHECK_FALSE(data.path.empty());
            CHECK(data.path != std::string(kBin) + "$Rnotes.txt");
        } else {
            ++refused;
            CHECK(data.path == std::string(kBin) + "$Rnotes.txt");
        }
        const bool claims_time = data.deleted_unix.has_value();
        const bool silent = data.note.empty();
        const bool claimed_path =
            data.note.starts_with("original path restored from $Recycle.Bin metadata");
        const bool claimed_time =
            data.note.starts_with("deletion time from $Recycle.Bin metadata");
        const bool explained = claimed_path || claimed_time;
        // A record that could not be read claims nothing, and a record that was read says which.
        const bool coherent = silent ? !claims_time : explained;
        CHECK(coherent);
        if (silent) CHECK(data.flags == 0);
        const size_t claim = data.note.find("$I records ");
        if (claim != std::string::npos) {
            // Only the size the record claims can differ; the recovered size is ours.
            CHECK(data.note.ends_with("bytes, recovered 5000"));
        }
    }
    CHECK(restored > 0);
    CHECK(refused > 0);
}
