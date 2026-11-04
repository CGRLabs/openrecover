#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_seeds.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_mp4.hpp"

namespace {
using namespace openrecover;
using namespace openrecover::carve;

constexpr std::string_view kSubtypes[] = {"mp4", "mov", "m4a", "3gp", "heic"};

void push_be32(std::vector<uint8_t>& out, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
}

void push_be64(std::vector<uint8_t>& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
}

void put_be32(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
    for (size_t i = 0; i < 4; ++i)
        out[offset + i] = static_cast<uint8_t>((value >> (24 - 8 * i)) & 0xFF);
}

std::vector<uint8_t> payload(size_t bytes, uint8_t seed) {
    std::vector<uint8_t> out(bytes);
    for (size_t i = 0; i < bytes; ++i) out[i] = static_cast<uint8_t>((i * seed) & 0xFF);
    return out;
}

std::vector<uint8_t> make_box(std::string_view type, std::vector<uint8_t> body) {
    std::vector<uint8_t> out;
    push_be32(out, static_cast<uint32_t>(body.size() + 8));
    out.insert(out.end(), type.begin(), type.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// The 64-bit form: a size of one says the real length follows the fourcc.
std::vector<uint8_t> make_box64(std::string_view type, std::vector<uint8_t> body) {
    std::vector<uint8_t> out;
    push_be32(out, 1);
    out.insert(out.end(), type.begin(), type.end());
    push_be64(out, body.size() + 16);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

void append(std::vector<uint8_t>& out, std::vector<uint8_t> box) {
    out.insert(out.end(), box.begin(), box.end());
}

std::vector<uint8_t> make_ftyp(std::string_view major,
                               const std::vector<std::string_view>& brands) {
    std::vector<uint8_t> body(major.begin(), major.end());
    push_be32(body, 0x200000);  // minor version
    for (std::string_view brand : brands) body.insert(body.end(), brand.begin(), brand.end());
    return make_box("ftyp", body);
}

// Two compatible brands make the header 24 bytes; the tests below use that to locate boxes.
constexpr size_t kFtypBytes = 24;
constexpr size_t kMoovBytes = 120 + 8;
constexpr size_t kMdatBytes = 4096 + 8;

struct Layout {
    std::string major = "isom";
    std::vector<std::string_view> brands{"isom", "mp42"};
    bool moov_last = false;
    bool mdat_64 = false;
    size_t moov_bytes = 120;
    size_t mdat_bytes = 4096;
    size_t free_bytes = 0;
    std::vector<uint8_t> trailing;
};

std::vector<uint8_t> build_media(const Layout& layout) {
    const std::vector<uint8_t> moov = make_box("moov", payload(layout.moov_bytes, 11));
    const std::vector<uint8_t> mdat =
        layout.mdat_64 ? make_box64("mdat", payload(layout.mdat_bytes, 7))
                       : make_box("mdat", payload(layout.mdat_bytes, 7));
    std::vector<uint8_t> out = make_ftyp(layout.major, layout.brands);
    if (layout.free_bytes != 0) append(out, make_box("free", std::vector<uint8_t>(layout.free_bytes, 0)));
    append(out, layout.moov_last ? mdat : moov);
    append(out, layout.moov_last ? moov : mdat);
    out.insert(out.end(), layout.trailing.begin(), layout.trailing.end());
    return out;
}

ValidationResult validate(const std::vector<uint8_t>& bytes, uint64_t limit = 0) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, limit != 0 ? limit : bytes.size());
    return Mp4Signature{}.validate(reader);
}
}  // namespace

TEST_CASE("mp4: an isom file with moov then mdat is claimed in full", "[mp4][m3]") {
    const std::vector<uint8_t> bytes = build_media({});
    REQUIRE(bytes.size() == kFtypBytes + kMoovBytes + kMdatBytes);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.subtype == "mp4");
    CHECK(res.confidence == Confidence::High);
    CHECK(res.notes.empty());
}

TEST_CASE("mp4: a camera file that puts moov after the media is claimed in full", "[mp4][m3]") {
    Layout layout;
    layout.moov_last = true;
    layout.free_bytes = 16;
    layout.major = "avc1";
    const std::vector<uint8_t> bytes = build_media(layout);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.subtype == "mp4");
}

TEST_CASE("mp4: the brand decides the family the file is reported as", "[mp4][m3]") {
    struct Expected {
        std::string major;
        std::string brand;
        std::string subtype;
    };
    const std::vector<Expected> cases{
        {"qt  ", "qt  ", "mov"}, {"M4A ", "M4A ", "m4a"}, {"m4a ", "mp42", "m4a"},
        {"3gp5", "3gp4", "3gp"}, {"mif1", "mif1", "heic"}, {"heix", "heic", "heic"},
        {"isom", "isom", "mp4"}, {"dash", "mp42", "mp4"},
    };
    for (const Expected& item : cases) {
        INFO("brand: " << item.major);
        Layout layout;
        layout.major = item.major;
        layout.brands = {std::string_view(item.brand)};
        const std::vector<uint8_t> bytes = build_media(layout);
        auto res = validate(bytes);
        REQUIRE(res.is_valid());
        CHECK(res.subtype == item.subtype);
    }
}

TEST_CASE("mp4: an unknown major brand falls back to the compatible list", "[mp4][m3]") {
    Layout layout;
    layout.major = "VEVO";  // written by some encoders, not a family this library names
    layout.brands = {"isom", "mp42"};
    auto res = validate(build_media(layout));
    REQUIRE(res.is_valid());
    CHECK(res.subtype == "mp4");
}

TEST_CASE("mp4: a brand list nobody recognises is refused", "[mp4][m3]") {
    Layout layout;
    layout.major = "WXYZ";
    layout.brands = {"ABCD", "EFGH"};
    CHECK_FALSE(validate(build_media(layout)).is_valid());
}

TEST_CASE("mp4: a HEIF image is carried by a meta box, not a moov", "[mp4][m3]") {
    std::vector<uint8_t> out = make_ftyp("mif1", {"mif1", "heic"});
    append(out, make_box("meta", payload(96, 3)));
    append(out, make_box("mdat", payload(2048, 5)));
    auto res = validate(out);
    REQUIRE(res.is_valid());
    CHECK(res.subtype == "heic");
    CHECK(res.length_bytes == out.size());
    CHECK(res.confidence == Confidence::High);
}

TEST_CASE("mp4: a 64-bit media box is followed", "[mp4][m3]") {
    Layout layout;
    layout.mdat_64 = true;
    layout.major = "3gp5";
    layout.brands = {"3gp4", "isom"};
    const std::vector<uint8_t> bytes = build_media(layout);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.subtype == "3gp");
    CHECK(res.length_bytes == bytes.size());
}

TEST_CASE("mp4: what follows the last box is not part of the file", "[mp4][m3]") {
    Layout layout;
    layout.trailing = std::vector<uint8_t>(512, 0);  // the clusters the next deleted file had
    const std::vector<uint8_t> bytes = build_media(layout);
    const size_t media_bytes = bytes.size() - layout.trailing.size();
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == media_bytes);
}

TEST_CASE("mp4: a box header that is not a media box ends the file", "[mp4][m3]") {
    const std::vector<uint8_t> media = build_media({});
    std::vector<uint8_t> bytes = media;
    append(bytes, make_box("VND?", payload(64, 1)));
    bytes.resize(media.size() + 256, 0xAA);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == media.size());
}

TEST_CASE("mp4: a box that runs past the scan window is a fragment", "[mp4][m3]") {
    std::vector<uint8_t> bytes = build_media({});
    const size_t mdat_at = bytes.size() - kMdatBytes;
    put_be32(bytes, mdat_at, 1u << 20);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.confidence == Confidence::Low);
    REQUIRE_FALSE(res.notes.empty());
    CHECK(res.notes[0] == "the file continues past the scan window");
}

TEST_CASE("mp4: a window that ends inside the media still reports a fragment", "[mp4][m3]") {
    const std::vector<uint8_t> bytes = build_media({});
    const size_t cut = bytes.size() - 2000;  // the moov is whole, the mdat is not
    auto partial = validate(std::vector<uint8_t>(bytes.begin(), bytes.begin() + cut));
    REQUIRE(partial.is_valid());
    CHECK(partial.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(partial.confidence == Confidence::Low);
    CHECK(partial.length_bytes == cut);
}

TEST_CASE("mp4: a header with no media and no metadata is refused", "[mp4][m3]") {
    std::vector<uint8_t> out = make_ftyp("isom", {"isom", "mp42"});
    append(out, make_box("free", std::vector<uint8_t>(24, 0)));
    CHECK_FALSE(validate(out).is_valid());
}

TEST_CASE("mp4: a brand header longer than the candidate is refused", "[mp4][m3]") {
    std::vector<uint8_t> bytes = build_media({});
    put_be32(bytes, 0, 512);
    bytes.resize(40);
    CHECK_FALSE(validate(bytes).is_valid());

    bytes = build_media({});
    put_be32(bytes, 0, 8);  // shorter than the header the format requires
    CHECK_FALSE(validate(bytes).is_valid());

    bytes = build_media({});
    put_be32(bytes, 0, 1000000);  // a brand list nobody writes
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("mp4: a broken box after a complete file is left out", "[mp4][m3]") {
    const std::vector<uint8_t> media = build_media({});
    std::vector<uint8_t> bytes = media;
    append(bytes, make_box("free", payload(64, 1)));
    put_be32(bytes, media.size(), 4);  // a size smaller than the header it sits in
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == media.size());
    CHECK(res.confidence == Confidence::High);
}

TEST_CASE("mp4: a box that breaks off before any media is refused", "[mp4][m3]") {
    std::vector<uint8_t> bytes = build_media({});
    put_be32(bytes, kFtypBytes, 4);  // the moov is unusable and the mdat never gets read
    CHECK_FALSE(validate(bytes).is_valid());
}

TEST_CASE("mp4: a zero-sized media box runs to an end the scan cannot see", "[mp4][m3]") {
    std::vector<uint8_t> bytes = build_media({});
    const size_t mdat_at = bytes.size() - kMdatBytes;
    put_be32(bytes, mdat_at, 0);
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == bytes.size());
}

TEST_CASE("mp4: a fragment with metadata but no media says which half is missing", "[mp4][m3]") {
    std::vector<uint8_t> out = make_ftyp("isom", {"isom", "mp42"});
    append(out, make_box("moov", payload(4096, 11)));
    put_be32(out, kFtypBytes, 64 * 1024);  // the moov claims far more than the file holds
    auto res = validate(out);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    REQUIRE(res.notes.size() == 2);
    CHECK(res.notes[0] == "metadata or media data runs past the scan window");
    CHECK(res.notes[1] == "no media data inside the window");
}

TEST_CASE("mp4: a window that ends where the boxes end is a whole file", "[mp4][m3]") {
    const std::vector<uint8_t> bytes = build_media({});
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());

    // A box header that does not fit is not evidence of more media; nothing was left to read.
    std::vector<uint8_t> header_only = make_ftyp("isom", {"isom", "mp42"});
    append(header_only, make_box("free", std::vector<uint8_t>(16, 0)));
    append(header_only, std::vector<uint8_t>(4, 0));
    CHECK_FALSE(validate(header_only).is_valid());
}

TEST_CASE("mp4: name, magic and where the magic sits", "[mp4][m3]") {
    Mp4Signature sig;
    CHECK(sig.name() == "mp4");
    CHECK(sig.default_extension() == "mp4");
    CHECK(sig.magic_offset() == 4);
    CHECK(sig.min_header_bytes() == 16);
    REQUIRE(sig.magics().size() == 1);
    REQUIRE(sig.magics()[0].size() == 4);
    CHECK(std::memcmp(sig.magics()[0].data(), "ftyp", 4) == 0);
}

TEST_CASE("mp4: a candidate too short to hold a header is refused", "[mp4][m3]") {
    std::vector<uint8_t> bytes(19, 0);
    std::memcpy(bytes.data() + 4, "ftyp", 4);
    CHECK_FALSE(validate(bytes).is_valid());
    CHECK_FALSE(validate(std::vector<uint8_t>()).is_valid());
}

TEST_CASE("mp4: every single-byte mutation is refused or stays inside the window",
          "[mp4][m3][mutation]") {
    const std::vector<uint8_t> good = build_media({});
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
            CHECK(std::find(std::begin(kSubtypes), std::end(kSubtypes),
                            std::string_view(res.subtype)) != std::end(kSubtypes));
            if (res.verdict == ValidationResult::Verdict::Valid) CHECK(res.notes.empty());
            if (res.verdict == ValidationResult::Verdict::ValidTruncated) {
                CHECK(res.length_bytes == mutated.size());
                CHECK(res.confidence == Confidence::Low);
            }
        }
    }
    CHECK(accepted > 0);
    CHECK(refused > 0);
}

TEST_CASE("mp4: the committed fuzz seeds validate as named", "[mp4][m3][fuzz]") {
    test::check_signature_seed_corpus(OPENRECOVER_FUZZ_SEED_DIR, Mp4Signature{},
                                      kSubtypes);
}
