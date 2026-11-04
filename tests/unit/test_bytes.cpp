#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/crc32.hpp"
#include "openrecover/common/hash.hpp"

using namespace openrecover;

TEST_CASE("little-endian readers", "[bytes]") {
    const uint8_t d[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF};
    ByteView v(d, sizeof d);
    CHECK(v.u8(0) == 0x01);
    CHECK(v.u16le(0) == 0x0201);
    CHECK(v.u32le(0) == 0x04030201u);
    CHECK(v.u64le(0) == 0x0807060504030201ull);
    CHECK(v.u64le(1) == 0xFF08070605040302ull);
    CHECK(v.s8(8) == -1);
    CHECK(v.ok());
}

TEST_CASE("big-endian readers", "[bytes]") {
    const uint8_t d[] = {0x89, 0x50, 0x4E, 0x47};
    ByteView v(d, sizeof d);
    CHECK(v.u16be(0) == 0x8950);
    CHECK(v.u32be(0) == 0x89504E47u);
    CHECK(v.ok());
    CHECK(v.u64be(0) == 0);
    CHECK(v.failed());
    v.clear_failure();

    const uint8_t q[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    ByteView w(q, sizeof q);
    CHECK(w.u64be(0) == 0x0102030405060708ull);
    CHECK(w.u64be(1) == 0);
    CHECK(w.failed());
}

TEST_CASE("variable-width integers", "[bytes]") {
    const uint8_t d[] = {0x34, 0x12, 0xF0, 0xFF, 0x80};
    ByteView v(d, sizeof d);
    CHECK(v.uint_le(0, 2) == 0x1234);
    CHECK(v.uint_le(0, 3) == 0xF01234);
    CHECK(v.sint_le(2, 1) == -16);
    CHECK(v.sint_le(2, 2) == -16);
    CHECK(v.sint_le(0, 2) == 0x1234);
    CHECK(v.sint_le(4, 1) == -128);
    CHECK(v.ok());
    CHECK(v.uint_le(0, 0) == 0);
    CHECK(v.failed());
    v.clear_failure();
    CHECK(v.uint_le(0, 9) == 0);
    CHECK(v.failed());
}

TEST_CASE("overrun sets the sticky failure flag", "[bytes]") {
    const uint8_t d[] = {1, 2, 3, 4};
    ByteView v(d, sizeof d);
    CHECK(v.u32le(0) == 0x04030201u);
    CHECK(v.ok());
    CHECK(v.u32le(1) == 0);
    CHECK(v.failed());
    CHECK(v.u8(0) == 1);
    CHECK(v.failed());  // sticky
    v.clear_failure();
    CHECK(v.u64le(0) == 0);
    CHECK(v.failed());
    v.clear_failure();
    CHECK(v.u16be(3) == 0);
    CHECK(v.failed());
    v.clear_failure();
    CHECK(v.u8(4) == 0);
    CHECK(v.failed());
    v.clear_failure();
    CHECK(v.sint_le(2, 4) == 0);
    CHECK(v.failed());
}

TEST_CASE("huge offsets do not wrap", "[bytes]") {
    const uint8_t d[] = {1, 2, 3, 4};
    ByteView v(d, sizeof d);
    CHECK(v.u32le(SIZE_MAX - 1) == 0);
    CHECK(v.failed());
    v.clear_failure();
    CHECK_FALSE(v.has(2, SIZE_MAX));
    auto s = v.sub(1, SIZE_MAX);
    CHECK(s.size() == 0);
    CHECK(v.failed());
}

TEST_CASE("sub-views and equals", "[bytes]") {
    const uint8_t d[] = {'%', 'P', 'D', 'F', '-', '1'};
    ByteView v(d, sizeof d);
    auto s = v.sub(1, 3);
    CHECK(s.size() == 3);
    CHECK(s.equals(0, "PDF"));
    CHECK_FALSE(s.equals(1, "PDF"));
    CHECK(v.equals(0, "%PDF-"));
    CHECK_FALSE(v.equals(4, "-1x"));
    CHECK(v.ok());
    ByteView empty;
    CHECK(empty.size() == 0);
    CHECK(empty.u8(0) == 0);
    CHECK(empty.failed());
}

TEST_CASE("UTF-16LE to UTF-8", "[bytes][utf16]") {
    SECTION("ASCII and BMP") {
        const uint8_t d[] = {'A', 0, 0xE9, 0x00, 0x2C, 0x67};  // A, é, 本
        CHECK(utf16le_to_utf8(d) == "A\xC3\xA9\xE6\x9C\xAC");
    }
    SECTION("surrogate pair") {
        const uint8_t d[] = {0x3D, 0xD8, 0x00, 0xDE};  // U+1F600
        CHECK(utf16le_to_utf8(d) == "\xF0\x9F\x98\x80");
    }
    SECTION("unpaired high surrogate") {
        const uint8_t d[] = {0x3D, 0xD8, 'x', 0};
        CHECK(utf16le_to_utf8(d) == "\xEF\xBF\xBDx");
    }
    SECTION("unpaired high surrogate at end") {
        const uint8_t d[] = {'a', 0, 0x3D, 0xD8};
        CHECK(utf16le_to_utf8(d) == "a\xEF\xBF\xBD");
    }
    SECTION("lone low surrogate") {
        const uint8_t d[] = {0x00, 0xDE, 'b', 0};
        CHECK(utf16le_to_utf8(d) == "\xEF\xBF\xBD" "b");
    }
    SECTION("reversed pair") {
        const uint8_t d[] = {0x00, 0xDE, 0x3D, 0xD8};
        CHECK(utf16le_to_utf8(d) == "\xEF\xBF\xBD\xEF\xBF\xBD");
    }
    SECTION("odd trailing byte") {
        const uint8_t d[] = {'a', 0, 'b'};
        CHECK(utf16le_to_utf8(d) == "a\xEF\xBF\xBD");
    }
}

TEST_CASE("sanitize_component", "[bytes][sanitize]") {
    CHECK(sanitize_component("photo.jpg") == "photo.jpg");
    CHECK(sanitize_component("a/b\\c:d*e?f\"g<h>i|j") == "a_b_c_d_e_f_g_h_i_j");
    CHECK(sanitize_component(std::string("x\x01y\x1Fz\x7F", 6)) == "x_y_z_");
    CHECK(sanitize_component(std::string("a\0b", 3)) == "a_b");

    SECTION("reserved device names") {
        CHECK(sanitize_component("CON") == "_CON");
        CHECK(sanitize_component("con") == "_con");
        CHECK(sanitize_component("CON.txt") == "_CON.txt");
        CHECK(sanitize_component("NUL") == "_NUL");
        CHECK(sanitize_component("com1") == "_com1");
        CHECK(sanitize_component("LPT9.log") == "_LPT9.log");
        CHECK(sanitize_component("CONSOLE") == "CONSOLE");
        CHECK(sanitize_component("COM0") == "COM0");
    }
    SECTION("dot names") {
        CHECK(sanitize_component("..") == "_");
        CHECK(sanitize_component(".") == "_");
        CHECK(sanitize_component("") == "_");
        CHECK(sanitize_component("...") == "_");
        CHECK(sanitize_component(".hidden") == ".hidden");
    }
    SECTION("trailing dots and spaces") {
        CHECK(sanitize_component("name.") == "name");
        CHECK(sanitize_component("name. . ") == "name");
        CHECK(sanitize_component("   ") == "_");
    }
    SECTION("300-byte names are truncated to 200 bytes") {
        std::string s(300, 'a');
        auto r = sanitize_component(s);
        CHECK(r.size() == 200);
        CHECK(r == std::string(200, 'a'));
    }
    SECTION("truncation respects UTF-8 boundaries") {
        std::string s(199, 'a');
        for (int i = 0; i < 50; ++i) s += "\xE6\x9C\xAC";  // 3-byte code point straddles byte 200
        auto r = sanitize_component(s);
        CHECK(r.size() == 199);
        std::string t;
        for (int i = 0; i < 100; ++i) t += "\xC3\xA9";
        t += "\xC3\xA9";
        auto r2 = sanitize_component(t);
        CHECK(r2.size() == 200);
        CHECK(r2 == t.substr(0, 200));
    }
    SECTION("reserved prefix does not exceed the length cap") {
        std::string s = "CON." + std::string(296, 'x');
        auto r = sanitize_component(s);
        CHECK(r.size() == 200);
        CHECK(r.rfind("_CON.", 0) == 0);
    }
}

TEST_CASE("checked arithmetic and alignment", "[bytes]") {
    uint64_t out = 0;
    CHECK(checked_add<uint64_t>(1, 2, out));
    CHECK(out == 3);
    CHECK_FALSE(checked_add<uint64_t>(UINT64_MAX, 1, out));
    CHECK(checked_mul<uint64_t>(1ull << 31, 1ull << 31, out));
    CHECK(out == 1ull << 62);
    CHECK_FALSE(checked_mul<uint64_t>(1ull << 32, 1ull << 32, out));
    CHECK(align_down(1000, 512) == 512);
    CHECK(align_up(1000, 512, out));
    CHECK(out == 1024);
    CHECK(align_up(1024, 512, out));
    CHECK(out == 1024);
    CHECK_FALSE(align_up(UINT64_MAX, 512, out));
}

TEST_CASE("CRC32, Adler-32 and SHA-256 vectors", "[bytes][hash]") {
    const std::string s = "123456789";
    std::span<const uint8_t> b(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    CHECK(crc32(b) == 0xCBF43926u);
    CHECK(adler32_update(1, b.data(), b.size()) == 0x091E01DEu);
    CHECK(sha256_hex({}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const std::string abc = "abc";
    CHECK(sha256_hex({reinterpret_cast<const uint8_t*>(abc.data()), abc.size()}) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    Sha256Hasher h;
    std::vector<uint8_t> million(1000000, 'a');
    h.update(million.data(), 400000);
    h.update(million.data() + 400000, 600000);
    CHECK(h.finish_hex() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}
