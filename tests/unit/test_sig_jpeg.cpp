#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "jpeg_samples.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_jpeg.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

ValidationResult validate(const std::vector<uint8_t>& bytes, bool deep = false) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    reader.set_deep_validate(deep);
    JpegSignature signature;
    return signature.validate(reader);
}

}  // namespace

TEST_CASE("jpeg: minimal baseline JFIF is valid and reports its exact length", "[jpeg][m3]") {
    const std::vector<uint8_t> bytes = test::make_jpeg();
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.subtype == "jfif");
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("jpeg: progressive files with two scans are valid", "[jpeg][m3]") {
    test::JpegOptions options;
    options.progressive = true;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("jpeg: Exif with an embedded thumbnail is valid and the thumbnail stays inside the hit",
          "[jpeg][m3]") {
    test::JpegOptions options;
    options.exif_thumbnail = true;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.subtype == "exif");
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("jpeg: a bad Exif TIFF header degrades confidence but stays valid", "[jpeg][m3]") {
    test::JpegOptions options;
    options.bad_exif = true;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.confidence == Confidence::Medium);
    bool noted = false;
    for (const std::string& note : result.notes) noted = noted || note == "exif_tiff_header_invalid";
    CHECK(noted);
}

TEST_CASE("jpeg: fill bytes and restart markers inside the scan are accepted", "[jpeg][m3]") {
    test::JpegOptions options;
    options.fill_bytes = true;
    options.rst_markers = true;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes, true);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("jpeg: a missing EOI is reported as a low-confidence truncation", "[jpeg][m3]") {
    test::JpegOptions options;
    options.eoi = false;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.confidence == Confidence::Low);
}

TEST_CASE("jpeg: a segment length past the end of the buffer is rejected", "[jpeg][m3]") {
    const std::vector<uint8_t> bytes = {0xFF, 0xD8, 0xFF, 0xDB, 0xFF, 0xF0};
    const ValidationResult result = validate(bytes);
    CHECK_FALSE(result.is_valid());
}

TEST_CASE("jpeg: two SOF markers are rejected", "[jpeg][m3]") {
    test::JpegOptions options;
    options.sof_count = 2;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes);
    CHECK_FALSE(result.is_valid());
}

TEST_CASE("jpeg: a scan before any SOF is rejected", "[jpeg][m3]") {
    std::vector<uint8_t> bytes;
    test::append_bytes(bytes, {0xFF, 0xD8});
    test::append_segment(bytes, 0xE0, test::app0_payload());
    test::append_segment(bytes, 0xDB, test::dqt_payload());
    test::append_segment(bytes, 0xC4, test::dht_payload());
    test::append_segment(bytes, 0xDA, test::sos_payload(3, 0, 63));
    test::append_bytes(bytes, {0x12, 0x34, 0xFF, 0xD9});
    const ValidationResult result = validate(bytes);
    CHECK_FALSE(result.is_valid());
}

TEST_CASE("jpeg: zero width is rejected", "[jpeg][m3]") {
    test::JpegOptions options;
    options.zero_width = true;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes);
    CHECK_FALSE(result.is_valid());
}

TEST_CASE("jpeg: deep validation requires entropy-coded bytes", "[jpeg][m3]") {
    test::JpegOptions options;
    options.entropy = false;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    CHECK(validate(bytes, false).is_valid());
    CHECK_FALSE(validate(bytes, true).is_valid());
}

TEST_CASE("jpeg: a valid structure without APP segments is only medium confidence", "[jpeg][m3]") {
    test::JpegOptions options;
    options.jfif = false;
    const std::vector<uint8_t> bytes = test::make_jpeg(options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.confidence == Confidence::Medium);
}

namespace {

// A baseline JPEG with a long entropy run, so a cut inside the scan is unambiguous.
std::vector<uint8_t> make_long_jpeg(size_t entropy_bytes = 4096) {
    std::vector<uint8_t> bytes = test::make_jpeg();
    bytes.insert(bytes.end() - 2, entropy_bytes, static_cast<uint8_t>(0x42));
    return bytes;
}

}  // namespace

TEST_CASE("jpeg: a scan that runs into other data is cut at the discontinuity",
          "[jpeg][m3][fragment]") {
    const std::vector<uint8_t> full = make_long_jpeg();
    const uint64_t cut = full.size() - 2 - 2000;  // 2000 bytes of entropy survive
    std::vector<uint8_t> bytes(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut));
    test::append_bytes(bytes, {0xFF, 0x02, 'J', 'U', 'N', 'K'});
    bytes.insert(bytes.end(), 32, static_cast<uint8_t>(0x5A));

    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(result.length_bytes == cut);
    CHECK_FALSE(result.notes.empty());
    CHECK(std::find(result.notes.begin(), result.notes.end(), "discontinuity") !=
          result.notes.end());
}

TEST_CASE("jpeg: a continuation is claimed only when it ends in EOI", "[jpeg][m3][fragment]") {
    const std::vector<uint8_t> full = make_long_jpeg();
    const size_t cut = full.size() - 2 - 2000;
    const std::vector<uint8_t> tail(full.begin() + static_cast<std::ptrdiff_t>(cut), full.end());
    const JpegSignature signature;

    {
        test::MemoryDevice device(tail);
        BoundedReader reader(device, 0, tail.size());
        const auto continuation = signature.find_continuation(reader);
        REQUIRE(continuation.has_value());
        CHECK(continuation->start == 0);
        CHECK(continuation->length == tail.size());
        CHECK(continuation->complete);
    }

    {
        // Data that is not entropy-coded ends the run at its first marker, and the walk reports
        // that cut so the engine can resume past the bytes in between.
        std::vector<uint8_t> junk = {0x42, 0x43, 0xFF, 0x02, 0x44, 0xFF, 0xD9};
        test::MemoryDevice device(junk);
        BoundedReader reader(device, 0, junk.size());
        const auto continuation = signature.find_continuation(reader);
        REQUIRE(continuation.has_value());
        CHECK(continuation->start == 0);
        CHECK(continuation->length == 2);
        CHECK_FALSE(continuation->complete);
    }

    {
        // A tail that never reaches EOI within the window is not a continuation.
        std::vector<uint8_t> unended(4096, static_cast<uint8_t>(0x42));
        test::MemoryDevice device(unended);
        BoundedReader reader(device, 0, unended.size());
        CHECK_FALSE(signature.find_continuation(reader).has_value());
    }

    {
        // An EOI with no scanned data in front of it is a stray, not a tail.
        std::vector<uint8_t> stray = {0xFF, 0xD9};
        test::MemoryDevice device(stray);
        BoundedReader reader(device, 0, stray.size());
        CHECK_FALSE(signature.find_continuation(reader).has_value());
    }
}

TEST_CASE("jpeg: a walk never crosses into another image", "[jpeg][m3][fragment]") {
    const JpegSignature signature;
    std::vector<uint8_t> bytes(64, static_cast<uint8_t>(0x42));
    bytes.insert(bytes.end(), {0xFF, 0xD8, 0xFF, 0xE0});
    bytes.insert(bytes.end(), 64, static_cast<uint8_t>(0x42));
    bytes.insert(bytes.end(), {0xFF, 0xD9});

    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    CHECK_FALSE(signature.find_continuation(reader).has_value());
}

TEST_CASE("jpeg: a run cut by a segment marker resumes after it", "[jpeg][m3][fragment]") {
    const JpegSignature signature;
    std::vector<uint8_t> bytes(64, static_cast<uint8_t>(0x42));
    bytes.insert(bytes.end(), {0xFF, 0xDA, 0x00, 0x02});
    bytes.insert(bytes.end(), 64, static_cast<uint8_t>(0x42));
    bytes.insert(bytes.end(), {0xFF, 0xD9});

    test::MemoryDevice device(bytes);
    {
        BoundedReader reader(device, 0, bytes.size());
        const auto first = signature.find_continuation(reader);
        REQUIRE(first.has_value());
        CHECK(first->start == 0);
        CHECK(first->length == 64);
        CHECK_FALSE(first->complete);
    }
    {
        BoundedReader reader(device, 68, bytes.size() - 68);
        const auto second = signature.find_continuation(reader);
        REQUIRE(second.has_value());
        CHECK(second->start == 0);
        CHECK(second->length == bytes.size() - 68);
        CHECK(second->complete);
    }
}
