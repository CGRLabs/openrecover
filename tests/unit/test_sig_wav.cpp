#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "fuzz_seeds.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/sig_wav.hpp"

namespace {
using namespace openrecover;
using namespace openrecover::carve;

void put32le(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

void append_chunk(std::vector<uint8_t>& b, std::string_view id, std::vector<uint8_t> payload) {
    const size_t at = b.size();
    b.resize(at + 8 + payload.size());
    std::memcpy(b.data() + at, id.data(), 4);
    put32le(b, at + 4, static_cast<uint32_t>(payload.size()));
    std::memcpy(b.data() + at + 8, payload.data(), payload.size());
    if (payload.size() % 2) b.push_back(0);  // chunks are word aligned
}

std::vector<uint8_t> start_wav(uint32_t declared_riff_size) {
    std::vector<uint8_t> b(12, 0);
    std::memcpy(b.data(), "RIFF", 4);
    put32le(b, 4, declared_riff_size);
    std::memcpy(b.data() + 8, "WAVE", 4);
    return b;
}

// fmt (16 bytes) + data (4 bytes); the RIFF size covers both chunks.
std::vector<uint8_t> build_wav() {
    std::vector<uint8_t> b = start_wav(0);
    append_chunk(b, "fmt ", std::vector<uint8_t>(16, 0));
    append_chunk(b, "data", std::vector<uint8_t>{1, 2, 3, 4});
    put32le(b, 4, static_cast<uint32_t>(b.size() - 8));
    return b;
}

ValidationResult validate(const std::vector<uint8_t>& bytes, uint64_t limit = 0) {
    test::MemoryDevice device(bytes);
    BoundedReader reader(device, 0, limit != 0 ? limit : bytes.size());
    return WavSignature{}.validate(reader);
}
}  // namespace

TEST_CASE("wav: valid minimal accepted", "[wav][m3]") {
    auto bytes = build_wav();
    auto res = validate(bytes);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::Valid);
    CHECK(res.length_bytes == bytes.size());
    CHECK(res.subtype == "wav");
    CHECK(res.confidence == Confidence::High);
}

TEST_CASE("wav: odd chunk payloads keep the list word aligned", "[wav][m3]") {
    std::vector<uint8_t> b = start_wav(0);
    append_chunk(b, "fmt ", std::vector<uint8_t>(15, 0));
    append_chunk(b, "LIST", std::vector<uint8_t>(3, 0));
    append_chunk(b, "data", std::vector<uint8_t>(6, 7));
    const uint32_t declared = static_cast<uint32_t>(b.size() - 8);
    put32le(b, 4, declared);
    REQUIRE(b.size() == 8u + declared);
    auto res = validate(b);
    REQUIRE(res.is_valid());
    CHECK(res.length_bytes == b.size());
}

TEST_CASE("wav: bad magic rejected", "[wav][m3]") {
    std::vector<uint8_t> b(12, 0);
    CHECK_FALSE(validate(b).is_valid());

    b = start_wav(4);
    std::memcpy(b.data() + 8, "AVI ", 4);  // RIFF container, not a wave
    CHECK_FALSE(validate(b).is_valid());
}

TEST_CASE("wav: a truncated candidate still needs a format chunk", "[wav][m3]") {
    std::vector<uint8_t> bytes = build_wav();
    put32le(bytes, 4, 100000);  // the declared size runs far past the device
    const size_t available = bytes.size();

    std::vector<uint8_t> cut(bytes.begin(), bytes.begin() + available);
    cut.resize(512, 0);
    auto res = validate(cut);
    REQUIRE(res.is_valid());
    CHECK(res.verdict == ValidationResult::Verdict::ValidTruncated);
    CHECK(res.length_bytes == 512);
    CHECK(res.confidence == Confidence::Low);

    std::vector<uint8_t> no_fmt = start_wav(100000);
    no_fmt.resize(512, 0);
    CHECK_FALSE(validate(no_fmt).is_valid());
}

TEST_CASE("wav: a missing data chunk is rejected", "[wav][m3]") {
    std::vector<uint8_t> b = start_wav(0);
    append_chunk(b, "fmt ", std::vector<uint8_t>(16, 0));
    put32le(b, 4, static_cast<uint32_t>(b.size() - 8));
    CHECK_FALSE(validate(b).is_valid());
}

TEST_CASE("wav: a chunk that overruns the RIFF size is rejected", "[wav][m3]") {
    std::vector<uint8_t> b = start_wav(0);
    append_chunk(b, "fmt ", std::vector<uint8_t>(16, 0));
    append_chunk(b, "data", std::vector<uint8_t>(64, 0));
    put32le(b, 4, 40);  // claims the data chunk is inside the first 48 bytes
    CHECK_FALSE(validate(b).is_valid());
}

TEST_CASE("wav: an absurd chunk size is rejected", "[wav][m3]") {
    std::vector<uint8_t> b = start_wav(0);
    append_chunk(b, "fmt ", std::vector<uint8_t>(16, 0));
    const size_t at = b.size();
    append_chunk(b, "data", std::vector<uint8_t>(64, 0));
    put32le(b, at + 4, 0xFFFF'FFFFu);
    put32le(b, 4, static_cast<uint32_t>(b.size() - 8));
    CHECK_FALSE(validate(b).is_valid());
}

TEST_CASE("wav: the declared size is capped by the signature", "[wav][m3]") {
    std::vector<uint8_t> b = start_wav(1u << 30);
    b.resize(4096, 0);
    auto res = validate(b);
    CHECK_FALSE(res.is_valid());
}

TEST_CASE("wav: name and extension", "[wav][m3]") {
    WavSignature sig;
    CHECK(sig.name() == "wav");
    CHECK(sig.default_extension() == "wav");
    CHECK(sig.min_header_bytes() == 12);
    REQUIRE(sig.magics().size() == 1);
    CHECK(std::memcmp(sig.magics()[0].data(), "RIFF", 4) == 0);
}

TEST_CASE("wav: the committed fuzz seeds validate as named", "[wav][m3][fuzz]") {
    test::check_signature_seed_corpus(OPENRECOVER_FUZZ_SEED_DIR, WavSignature{});
}