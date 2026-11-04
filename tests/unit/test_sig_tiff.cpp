#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "fuzz_seeds.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_tiff.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

void put_u16le(std::vector<uint8_t>& out, size_t off, uint16_t v) {
    out[off] = static_cast<uint8_t>(v & 0xFF);
    out[off + 1] = static_cast<uint8_t>(v >> 8);
}
void put_u32le(std::vector<uint8_t>& out, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) out[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}
void put_u16be(std::vector<uint8_t>& out, size_t off, uint16_t v) {
    out[off] = static_cast<uint8_t>(v >> 8);
    out[off + 1] = static_cast<uint8_t>(v & 0xFF);
}
void put_u32be(std::vector<uint8_t>& out, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) out[off + i] = static_cast<uint8_t>((v >> (8 * (3 - i))) & 0xFF);
}

std::vector<uint8_t> build_tiff(bool little, uint32_t ifd_off = 8, uint16_t nentries = 0) {
    std::vector<uint8_t> b(8 + 2 + nentries * 12 + 4, 0);
    if (little) {
        b[0] = 'I'; b[1] = 'I'; put_u16le(b, 2, 42); put_u32le(b, 4, ifd_off);
    } else {
        b[0] = 'M'; b[1] = 'M'; put_u16be(b, 2, 42); put_u32be(b, 4, ifd_off);
    }
    size_t base = ifd_off;
    if (little) put_u16le(b, base, nentries); else put_u16be(b, base, nentries);
    if (little) put_u32le(b, base + 2 + nentries * 12, 0); else put_u32be(b, base + 2 + nentries * 12, 0);
    return b;
}

// An IFD at offset 8 holding `nentries` entries, inside a `size`-byte image.
std::vector<uint8_t> build_entries(uint16_t nentries, size_t size, uint32_t next_ifd = 0) {
    std::vector<uint8_t> b = build_tiff(true, 8, nentries);
    b.resize(size, 0);
    if (next_ifd != 0) put_u32le(b, 10 + static_cast<size_t>(nentries) * 12, next_ifd);
    return b;
}

void put_entry_at(std::vector<uint8_t>& b, size_t at, uint16_t tag, uint16_t type,
                  uint32_t count, uint32_t value) {
    put_u16le(b, at, tag);
    put_u16le(b, at + 2, type);
    put_u32le(b, at + 4, count);
    put_u32le(b, at + 8, value);
}

void put_entry(std::vector<uint8_t>& b, uint16_t index, uint16_t tag, uint16_t type,
               uint32_t count, uint32_t value) {
    put_entry_at(b, 10 + static_cast<size_t>(index) * 12, tag, type, count, value);
}

// A BoundedReader holds a 256 KiB block cache, so several of them must not share a frame.
ValidationResult validate(const std::vector<uint8_t>& bytes) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    return TiffSignature{}.validate(reader);
}

} // namespace

TEST_CASE("tiff: valid minimal header accepted", "[tiff][m3]") {
    auto bytes = build_tiff(true);
    test::MemoryDevice device(bytes); BoundedReader r(device, 0, bytes.size());
    TiffSignature sig;
    auto res = sig.validate(r);
    CHECK(res.is_valid());
    CHECK(res.subtype == "tiff");
}

TEST_CASE("tiff: big-endian accepted", "[tiff][m3]") {
    auto bytes = build_tiff(false);
    test::MemoryDevice device(bytes); BoundedReader r(device, 0, bytes.size());
    TiffSignature sig;
    auto res = sig.validate(r);
    CHECK(res.is_valid());
}

TEST_CASE("tiff: bigtiff magic rejected", "[tiff][m3]") {
    std::vector<uint8_t> b(8, 0);
    b[0] = 'I'; b[1] = 'I'; b[2] = 43; b[3] = 0;
    test::MemoryDevice device(b); BoundedReader r(device, 0, b.size());
    TiffSignature sig;
    CHECK_FALSE(sig.validate(r).is_valid());
}

TEST_CASE("tiff: tiny buffer rejected", "[tiff][m3]") {
    std::vector<uint8_t> b = {'I', 'I'};
    test::MemoryDevice device(b); BoundedReader r(device, 0, b.size());
    TiffSignature sig;
    CHECK_FALSE(sig.validate(r).is_valid());
}

TEST_CASE("tiff: the length is the highest referenced byte", "[tiff][m3]") {
    // ImageDescription (0x011E) as ASCII, count 100, stored out of line at 100.
    auto bytes = build_entries(1, 512);
    put_entry(bytes, 0, 0x011E, 2, 100, 100);
    test::MemoryDevice device(bytes); BoundedReader r(device, 0, bytes.size());
    TiffSignature sig;
    auto res = sig.validate(r);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == 200);
    CHECK(res.confidence == Confidence::Medium);
}

TEST_CASE("tiff: a scan window far larger than the image is still the image", "[tiff][m3]") {
    // Free space on a device is not part of the file: the validator must not judge the
    // candidate by how much room the scan happened to give it.
    auto image = build_entries(1, 200);
    put_entry(image, 0, 0x011A, 2, 100, 100);  // XMP, referenced up to byte 200
    const size_t image_size = image.size();

    std::vector<uint8_t> bytes = image;
    bytes.resize((8ull << 20) + 8192, 0);  // a scan window 128k times the image

    test::MemoryDevice device(bytes);
    BoundedReader r(device, 0, bytes.size());
    TiffSignature sig;
    auto res = sig.validate(r);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == image_size);
}

TEST_CASE("tiff: malformed entry tables are rejected", "[tiff][m3]") {
    {
        auto bytes = build_entries(1, 64);
        put_entry(bytes, 0, 0x0100, 99, 1, 0);  // undefined field type
        CHECK_FALSE(validate(bytes).is_valid());
    }
    {
        auto bytes = build_entries(1, 64);
        put_entry(bytes, 0, 0x011A, 2, 40, 200);  // value runs past the candidate
        CHECK_FALSE(validate(bytes).is_valid());
    }
    {
        auto bytes = build_entries(1, 64);
        put_entry(bytes, 0, 0x0100, 3, 1, 0);
        put_u32le(bytes, 10 + 12, 8);  // the next IFD points back at this one
        CHECK_FALSE(validate(bytes).is_valid());
    }
    {
        auto bytes = build_entries(0, 64, 40);
        put_u16le(bytes, 40, 9000);  // more entries than the IFD cap allows
        CHECK_FALSE(validate(bytes).is_valid());
    }
    CHECK_FALSE(validate(build_tiff(true, 4)).is_valid());  // the first IFD overlaps the header
}

TEST_CASE("tiff: a second IFD extends the reported length", "[tiff][m3]") {
    auto bytes = build_entries(0, 64, 40);
    put_u16le(bytes, 40, 1);            // the sub-IFD holds one entry
    put_entry_at(bytes, 42, 0x011A, 2, 10, 20);
    put_u32le(bytes, 54, 0);            // end of the IFD chain
    test::MemoryDevice device(bytes); BoundedReader r(device, 0, bytes.size());
    TiffSignature sig;
    auto res = sig.validate(r);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == 58);
}

TEST_CASE("tiff: name and magics", "[tiff][m3]") {
    TiffSignature sig;
    CHECK(sig.name() == "tiff");
    CHECK(sig.default_extension() == "tif");
    REQUIRE(sig.magics().size() == 2);
    CHECK(sig.min_header_bytes() == 8);
}

TEST_CASE("tiff: the committed fuzz seeds validate as named", "[tiff][m3][fuzz]") {
    test::check_signature_seed_corpus(OPENRECOVER_FUZZ_SEED_DIR, TiffSignature{});
}
