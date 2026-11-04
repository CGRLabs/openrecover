#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "fuzz_seeds.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_sqlite.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

void put_be16(std::vector<uint8_t>& out, size_t off, uint16_t v) {
    out[off] = static_cast<uint8_t>(v >> 8);
    out[off + 1] = static_cast<uint8_t>(v & 0xFF);
}

void put_be32(std::vector<uint8_t>& out, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i)
        out[off + i] = static_cast<uint8_t>((v >> (8 * (3 - i))) & 0xFF);
}

// A database image whose header declares `pages` pages of `page_size_raw`. The 4-byte
// field at 16 encodes 64 KiB as 1, exactly like the format does.
std::vector<uint8_t> build_sqlite(size_t bytes, uint16_t page_size_raw, uint32_t pages,
                                  uint32_t version_valid_for = 7, uint32_t change_counter = 7) {
    REQUIRE(bytes >= 100);
    std::vector<uint8_t> out(bytes, 0);
    std::memcpy(out.data(), "SQLite format 3\0", 16);
    put_be16(out, 16, page_size_raw);
    put_be32(out, 24, change_counter);
    put_be32(out, 28, pages);
    put_be32(out, 92, version_valid_for);
    return out;
}

ValidationResult validate(const std::vector<uint8_t>& bytes) {
    // A BoundedReader carries a 256 KiB block cache, so it must not outlive one case.
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    return SqliteSignature{}.validate(reader);
}

}  // namespace

TEST_CASE("sqlite: valid database reports its declared size", "[sqlite][m3]") {
    auto res = validate(build_sqlite(4096 * 3, 4096, 3));
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == 4096 * 3);
    CHECK(res.subtype == "sqlite");
    CHECK(res.confidence == Confidence::High);
}

TEST_CASE("sqlite: supported page sizes", "[sqlite][m3]") {
    auto small = validate(build_sqlite(512 * 4, 512, 4));
    REQUIRE(small.is_valid());
    CHECK(small.length_bytes == 2048);

    // 64 KiB pages are stored as the value 1.
    auto large = validate(build_sqlite(65536, 1, 1));
    REQUIRE(large.is_valid());
    CHECK(large.length_bytes == 65536);
}

TEST_CASE("sqlite: an unaligned scan window still yields the whole file", "[sqlite][m3]") {
    // The window is a property of the scan, not of the database: 100 unrelated bytes after
    // the last page must not invalidate the hit.
    auto bytes = build_sqlite(4096 * 2, 4096, 2);
    bytes.insert(bytes.end(), 100, 0x7F);

    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == 4096 * 2);
    CHECK(res.confidence == Confidence::High);
}

TEST_CASE("sqlite: a database that runs past the window is truncated, not rejected",
          "[sqlite][m3]") {
    auto bytes = build_sqlite(4096 * 4, 4096, 4);
    bytes.resize(4096 * 2 + 100);  // the device ends mid-page-three

    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == 4096 * 2);
    CHECK(res.confidence == Confidence::Low);
    CHECK_FALSE(res.notes.empty());
}

TEST_CASE("sqlite: a window shorter than one page cannot be claimed", "[sqlite][m3]") {
    auto bytes = build_sqlite(4096 * 4, 4096, 4);
    bytes.resize(500);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("sqlite: bad magic and implausible headers are rejected", "[sqlite][m3]") {
    std::vector<uint8_t> wrong_magic(4096, 0);
    std::memcpy(wrong_magic.data(), "SQLite format 2\0", 16);
    CHECK_FALSE(validate(wrong_magic).is_valid());

    for (uint16_t bad : {uint16_t{0}, uint16_t{256}, uint16_t{1000}, uint16_t{0xFFFE}}) {
        INFO("page size field " << bad);
        CHECK_FALSE(validate(build_sqlite(4096 * 2, bad, 2)).is_valid());
    }

    CHECK_FALSE(validate(build_sqlite(4096, 4096, 0)).is_valid());

    auto short_header = build_sqlite(4096, 4096, 1);
    short_header.resize(99);  // the header itself is no longer readable
    CHECK_FALSE(validate(short_header).is_valid());
}

TEST_CASE("sqlite: a declared size beyond the signature cap is rejected", "[sqlite][m3]") {
    CHECK_FALSE(validate(build_sqlite(1024, 4096, 0xFFFF'FFFFu)).is_valid());
}

TEST_CASE("sqlite: a stale page count lowers confidence but keeps the hit", "[sqlite][m3]") {
    auto res = validate(build_sqlite(4096 * 2, 4096, 2, /*version_valid_for=*/7,
                                     /*change_counter=*/9));
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == 4096 * 2);
    CHECK(res.confidence == Confidence::Medium);
    CHECK_FALSE(res.notes.empty());
}

TEST_CASE("sqlite: name, extension and header requirements", "[sqlite][m3]") {
    SqliteSignature sig;
    CHECK(sig.name() == "sqlite");
    CHECK(sig.default_extension() == "sqlite");
    CHECK(sig.min_header_bytes() == 100);
    CHECK(sig.max_file_size() == 512ull << 20);
    REQUIRE(sig.magics().size() == 1);
    CHECK(sig.magics()[0].size() == 16);
    CHECK(std::memcmp(sig.magics()[0].data(), "SQLite format 3", 15) == 0);
}

TEST_CASE("sqlite: the committed fuzz seeds validate as named", "[sqlite][m3][fuzz]") {
    test::check_signature_seed_corpus(OPENRECOVER_FUZZ_SEED_DIR, SqliteSignature{});
}
