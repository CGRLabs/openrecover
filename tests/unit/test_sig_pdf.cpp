#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_pdf.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

ValidationResult validate(const std::vector<uint8_t>& bytes) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, bytes.size());
    return PdfSignature{}.validate(reader);
}

void append_text(std::vector<uint8_t>& out, std::string_view text) {
    out.insert(out.end(), text.begin(), text.end());
}

std::string digits(uint64_t value, size_t width) {
    std::string s = std::to_string(value);
    if (s.size() < width) s.insert(0, width - s.size(), '0');
    return s;
}

std::string xref_line(uint64_t offset, uint64_t generation, char kind) {
    return digits(offset, 10) + " " + digits(generation, 5) + " " + kind + " \n";
}

bool has_note(const ValidationResult& result, std::string_view note) {
    return std::find(result.notes.begin(), result.notes.end(), note) != result.notes.end();
}

const std::string kCatalog = "<< /Type /Catalog /Pages 2 0 R >>";
const std::string kPages = "<< /Type /Pages /Kids [] /Count 0 >>";

struct ClassicOptions {
    uint64_t root = 1;
    std::string trailer_extra;
    uint64_t xrefstm = 0;
    uint64_t bad_offset_obj = 0;  // xref entry for this object points at garbage
    uint64_t startxref_adjust = 0;
    bool self_prev = false;
    bool append_trailer = true;
    std::string header = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
};

std::vector<uint8_t> build_classic(const std::vector<std::string>& bodies,
                                   const ClassicOptions& options = {}) {
    std::vector<uint8_t> out;
    append_text(out, options.header);
    std::vector<uint64_t> offsets;
    offsets.reserve(bodies.size());
    for (size_t i = 0; i < bodies.size(); ++i) {
        offsets.push_back(out.size());
        append_text(out, std::to_string(i + 1) + " 0 obj\n" + bodies[i] + "\nendobj\n");
    }
    if (!options.append_trailer) return out;

    const uint64_t xref = out.size();
    const uint64_t count = bodies.size();
    append_text(out, "xref\n0 " + std::to_string(count + 1) + "\n");
    append_text(out, xref_line(0, 65535, 'f'));
    for (size_t i = 0; i < bodies.size(); ++i) {
        uint64_t offset = offsets[i];
        if (options.bad_offset_obj == i + 1) offset = 5;
        append_text(out, xref_line(offset, 0, 'n'));
    }

    std::string trailer = "<< /Size " + std::to_string(count + 1);
    if (options.root != 0) trailer += " /Root " + std::to_string(options.root) + " 0 R";
    if (options.xrefstm != 0) trailer += " /XRefStm " + std::to_string(options.xrefstm);
    if (options.self_prev) trailer += " /Prev " + std::to_string(xref);
    trailer += options.trailer_extra;
    trailer += " >>";
    append_text(out, "trailer\n" + trailer + "\nstartxref\n" +
                         std::to_string(xref + options.startxref_adjust) + "\n%%EOF\n");
    return out;
}

std::vector<uint8_t> build_incremental() {
    std::vector<uint8_t> out;
    append_text(out, "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    std::vector<uint64_t> offsets;
    const std::vector<std::string> base_bodies = {kCatalog, kPages};
    for (size_t i = 0; i < base_bodies.size(); ++i) {
        offsets.push_back(out.size());
        append_text(out, std::to_string(i + 1) + " 0 obj\n" + base_bodies[i] + "\nendobj\n");
    }
    const uint64_t xref1 = out.size();
    append_text(out, "xref\n0 3\n" + xref_line(0, 65535, 'f') + xref_line(offsets[0], 0, 'n') +
                         xref_line(offsets[1], 0, 'n'));
    append_text(out, "trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n" +
                         std::to_string(xref1) + "\n%%EOF\n");

    const uint64_t offset3 = out.size();
    append_text(out, "3 0 obj\n<< /Type /Pages /Parent 2 0 R /Count 0 >>\nendobj\n");
    const uint64_t xref2 = out.size();
    append_text(out, "xref\n1 3\n" + xref_line(offsets[0], 0, 'n') +
                         xref_line(offsets[1], 0, 'n') + xref_line(offset3, 0, 'n'));
    append_text(out, "trailer\n<< /Size 4 /Root 1 0 R /Prev " + std::to_string(xref1) +
                         " >>\nstartxref\n" + std::to_string(xref2) + "\n%%EOF\n");
    return out;
}

std::vector<uint8_t> build_xref_stream() {
    std::vector<uint8_t> out;
    append_text(out, "%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
    const uint64_t offset1 = out.size();
    append_text(out, "1 0 obj\n" + kCatalog + "\nendobj\n");
    const uint64_t offset2 = out.size();
    append_text(out, "2 0 obj\n" + kPages + "\nendobj\n");
    const uint64_t offset3 = out.size();

    std::vector<uint8_t> data;
    auto entry = [&data](uint8_t type, uint64_t offset, uint64_t generation) {
        data.push_back(type);
        data.push_back(static_cast<uint8_t>(offset >> 24));
        data.push_back(static_cast<uint8_t>(offset >> 16));
        data.push_back(static_cast<uint8_t>(offset >> 8));
        data.push_back(static_cast<uint8_t>(offset));
        data.push_back(static_cast<uint8_t>(generation >> 8));
        data.push_back(static_cast<uint8_t>(generation));
    };
    entry(0, 0, 65535);
    entry(1, offset1, 0);
    entry(1, offset2, 0);
    entry(1, offset3, 0);

    append_text(out, "3 0 obj\n<< /Type /XRef /Size 4 /Root 1 0 R /W [1 4 2] /Length " +
                         std::to_string(data.size()) + " >>\nstream\n");
    out.insert(out.end(), data.begin(), data.end());
    append_text(out, "\nendstream\nendobj\nstartxref\n" + std::to_string(offset3) + "\n%%EOF\n");
    return out;
}

// `declared` is written as a fixed-width value so the rebuild keeps every offset stable.
std::vector<uint8_t> build_linearized(bool correct_length) {
    auto make = [](const std::string& declared) {
        ClassicOptions options;
        options.root = 2;
        return build_classic({"<< /Linearized 1 /L " + declared +
                                  " /H [ 100 200 ] /O 2 /E 100 /N 1 >>",
                              "<< /Type /Catalog /Pages 3 0 R >>", kPages},
                             options);
    };
    const auto probe = make("0000000000");
    const uint64_t declared = correct_length ? probe.size() : probe.size() + 7;
    return make(digits(declared, 10));
}

}  // namespace

TEST_CASE("PDF classic xref validates with exact length", "[sig_pdf]") {
    const auto bytes = build_classic({kCatalog, kPages});
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.subtype == "pdf-1.4");
    CHECK(result.confidence == Confidence::High);
    CHECK(has_note(result, "binary_comment"));
}

TEST_CASE("PDF xref stream validates as Medium", "[sig_pdf]") {
    const auto bytes = build_xref_stream();
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.subtype == "pdf-1.5");
    CHECK(result.confidence == Confidence::Medium);
}

TEST_CASE("PDF incremental update extends through linked %%EOF", "[sig_pdf]") {
    const auto bytes = build_incremental();
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("PDF linearized length is required for High confidence", "[sig_pdf]") {
    const auto good = build_linearized(true);
    const ValidationResult high = validate(good);
    REQUIRE(high.verdict == ValidationResult::Verdict::Valid);
    CHECK(high.length_bytes == good.size());
    CHECK(high.confidence == Confidence::High);

    const auto bad = build_linearized(false);
    const ValidationResult medium = validate(bad);
    REQUIRE(medium.verdict == ValidationResult::Verdict::Valid);
    CHECK(medium.length_bytes == bad.size());
    CHECK(medium.confidence == Confidence::Medium);
    CHECK(has_note(medium, "linearized_length_mismatch"));
}

TEST_CASE("PDF wrong startxref is invalid", "[sig_pdf]") {
    ClassicOptions options;
    options.startxref_adjust = 3;
    const auto bytes = build_classic({kCatalog, kPages}, options);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("PDF cyclic Prev chain is invalid", "[sig_pdf]") {
    ClassicOptions options;
    options.self_prev = true;
    const auto bytes = build_classic({kCatalog, kPages}, options);
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("PDF encrypted trailer is valid with a note", "[sig_pdf]") {
    ClassicOptions options;
    options.trailer_extra = " /Encrypt 3 0 R";
    const auto bytes = build_classic(
        {kCatalog, kPages, "<< /Filter /Standard /V 1 /R 2 >>"}, options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.confidence == Confidence::High);
    CHECK(has_note(result, "encrypted"));
}

TEST_CASE("PDF trailer without Root but with XRefStm is Medium", "[sig_pdf]") {
    ClassicOptions options;
    options.root = 0;
    options.xrefstm = 123;
    const auto bytes = build_classic({kCatalog}, options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.confidence == Confidence::Medium);
}

TEST_CASE("PDF spot-check mismatch downgrades to Low", "[sig_pdf]") {
    ClassicOptions options;
    options.bad_offset_obj = 3;
    const auto bytes = build_classic(
        {kCatalog, kPages, "<< /Producer (openrecover test) >>"}, options);
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.confidence == Confidence::Low);
}

TEST_CASE("PDF truncated without EOF is ValidTruncated at last endobj", "[sig_pdf]") {
    std::vector<uint8_t> bytes;
    append_text(bytes, "%PDF-1.5\n");
    append_text(bytes, "1 0 obj\n" + kCatalog + "\nendobj\n");
    append_text(bytes, "2 0 obj\n" + kPages + "\nendobj");
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.confidence == Confidence::Low);
    CHECK(has_note(result, "truncated_no_eof"));
}

TEST_CASE("PDF embedded document inside a stream does not end the candidate", "[sig_pdf]") {
    std::vector<uint8_t> inner;
    append_text(inner, "%PDF-1.4\n");
    append_text(inner, "1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    const uint64_t inner_xref = inner.size();
    append_text(inner, "xref\n0 2\n" + xref_line(0, 65535, 'f') +
                           xref_line(9, 0, 'n'));
    append_text(inner, "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n" +
                           std::to_string(inner_xref) + "\n%%EOF\n");

    std::string streamed(inner.begin(), inner.end());
    const std::string stream_object =
        "<< /Length " + std::to_string(streamed.size()) + " >>\nstream\n" + streamed +
        "\nendstream";

    const auto bytes = build_classic({kCatalog, kPages, stream_object});
    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == bytes.size());
    CHECK(result.confidence == Confidence::High);
}

TEST_CASE("PDF candidate does not extend into an adjacent document", "[sig_pdf]") {
    const std::vector<uint8_t> first = build_classic({kCatalog, kPages});
    std::vector<uint8_t> bytes = first;
    bytes.resize(first.size() + 97, 0x00);
    const std::vector<uint8_t> second = build_classic({kCatalog, kPages});
    bytes.insert(bytes.end(), second.begin(), second.end());

    const ValidationResult result = validate(bytes);
    REQUIRE(result.verdict == ValidationResult::Verdict::Valid);
    CHECK(result.length_bytes == first.size());
}

TEST_CASE("PDF hostile subsection count is rejected", "[sig_pdf]") {
    std::vector<uint8_t> bytes;
    append_text(bytes, "%PDF-1.4\n");
    append_text(bytes, "1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    append_text(bytes, "xref\n0 99999999999999999999\n");
    append_text(bytes, "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n15\n%%EOF\n");
    CHECK_FALSE(validate(bytes).is_valid());
}
