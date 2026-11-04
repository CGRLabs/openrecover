#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <initializer_list>
#include <span>
#include <vector>

#include "openrecover/fs/ntfs_runlist.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::fs;

std::vector<uint8_t> bytes(std::initializer_list<int> values) {
    std::vector<uint8_t> out;
    for (int v : values) out.push_back(static_cast<uint8_t>(v));
    return out;
}

Result<std::vector<DataRun>> decode(std::initializer_list<int> values, uint64_t start_vcn = 0,
                                    uint64_t total_clusters = 1u << 20) {
    const std::vector<uint8_t> data = bytes(values);
    return decode_runlist(std::span<const uint8_t>(data), start_vcn, total_clusters);
}

}  // namespace

TEST_CASE("runlist decodes a single non-sparse run", "[ntfs][runlist]") {
    auto runs = decode({0x21, 0x18, 0x34, 0x56, 0x00});
    REQUIRE(runs);
    REQUIRE(runs->size() == 1);
    CHECK((*runs)[0].vcn == 0);
    CHECK((*runs)[0].lcn == 0x5634);
    CHECK((*runs)[0].length_clusters == 0x18);
    CHECK_FALSE((*runs)[0].is_sparse());
}

TEST_CASE("runlist applies relative signed offsets", "[ntfs][runlist]") {
    auto runs = decode({0x11, 0x10, 0x20, 0x11, 0x08, 0xF0, 0x00});
    REQUIRE(runs);
    REQUIRE(runs->size() == 2);
    CHECK((*runs)[0].vcn == 0);
    CHECK((*runs)[0].lcn == 0x20);
    CHECK((*runs)[0].length_clusters == 16);
    CHECK((*runs)[1].vcn == 16);
    CHECK((*runs)[1].lcn == 16);
    CHECK((*runs)[1].length_clusters == 8);
}

TEST_CASE("runlist sparse runs do not move the previous LCN", "[ntfs][runlist]") {
    auto runs = decode({0x01, 0x10, 0x11, 0x08, 0x20, 0x01, 0x04, 0x11, 0x02, 0x10, 0x00});
    REQUIRE(runs);
    REQUIRE(runs->size() == 4);
    CHECK((*runs)[0].is_sparse());
    CHECK((*runs)[0].length_clusters == 16);
    CHECK((*runs)[1].lcn == 0x20);
    CHECK((*runs)[2].is_sparse());
    CHECK((*runs)[2].vcn == 24);
    CHECK((*runs)[3].lcn == 0x30);
    CHECK((*runs)[3].vcn == 28);
}

TEST_CASE("runlist honors the starting VCN", "[ntfs][runlist]") {
    auto runs = decode({0x11, 0x04, 0x40, 0x00}, 100);
    REQUIRE(runs);
    REQUIRE(runs->size() == 1);
    CHECK((*runs)[0].vcn == 100);
    CHECK((*runs)[0].lcn == 0x40);
    CHECK((*runs)[0].length_clusters == 4);
}

TEST_CASE("runlist decodes three-byte length and offset fields", "[ntfs][runlist]") {
    auto runs = decode({0x33, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00});
    REQUIRE(runs);
    REQUIRE(runs->size() == 1);
    CHECK((*runs)[0].length_clusters == 0x010203);
    CHECK((*runs)[0].lcn == 1);
}

TEST_CASE("runlist accepts a run ending exactly at the last cluster", "[ntfs][runlist]") {
    auto runs = decode({0x11, 0x10, 0x50, 0x00}, 0, 0x60);
    REQUIRE(runs);
    REQUIRE(runs->size() == 1);
    CHECK((*runs)[0].lcn == 0x50);
}

TEST_CASE("runlist stops at the terminator and ignores trailing bytes", "[ntfs][runlist]") {
    auto runs = decode({0x11, 0x02, 0x10, 0x00, 0xFF, 0xFF});
    REQUIRE(runs);
    REQUIRE(runs->size() == 1);
    CHECK((*runs)[0].length_clusters == 2);
}

TEST_CASE("runlist accepts an empty or terminator-only list", "[ntfs][runlist]") {
    CHECK(decode({})->empty());
    CHECK(decode({0x00})->empty());
}

TEST_CASE("runlist rejects malformed run headers", "[ntfs][runlist]") {
    for (auto bad : {decode({0x10, 0x01, 0x00}),      // empty length field
                     decode({0x91, 0x01, 0x00, 0x00}),  // offset field wider than 8
                     decode({0x19, 0x01, 0x00})})       // length field wider than 8
    {
        REQUIRE_FALSE(bad);
        CHECK(bad.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("runlist rejects truncated runs", "[ntfs][runlist]") {
    for (auto bad : {decode({0x21, 0x18, 0x34}), decode({0x11}), decode({0x21, 0x18})}) {
        REQUIRE_FALSE(bad);
        CHECK(bad.error().code == ErrorCode::CorruptStructure);
    }
}

TEST_CASE("runlist rejects zero-length, negative and out-of-volume runs", "[ntfs][runlist]") {
    auto zero_length = decode({0x11, 0x00, 0x05, 0x00});
    REQUIRE_FALSE(zero_length);
    CHECK(zero_length.error().code == ErrorCode::CorruptStructure);

    auto negative = decode({0x11, 0x08, 0xF0, 0x00});
    REQUIRE_FALSE(negative);
    CHECK(negative.error().code == ErrorCode::CorruptStructure);

    auto beyond = decode({0x11, 0x10, 0x50, 0x00}, 0, 0x5F);
    REQUIRE_FALSE(beyond);
    CHECK(beyond.error().code == ErrorCode::CorruptStructure);
}

TEST_CASE("runlist rejects arithmetic overflow", "[ntfs][runlist]") {
    auto vcn_overflow = decode({0x18, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00}, 1);
    REQUIRE_FALSE(vcn_overflow);
    CHECK(vcn_overflow.error().code == ErrorCode::CorruptStructure);

    auto lcn_overflow = decode({0x81, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
                                0x81, 0x01, 0x01, 0x00},
                               0, UINT64_MAX);
    REQUIRE_FALSE(lcn_overflow);
    CHECK(lcn_overflow.error().code == ErrorCode::CorruptStructure);
}
