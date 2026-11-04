#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"

namespace {

using namespace openrecover;
using namespace openrecover::carve;

std::vector<uint8_t> pattern(size_t n) {
    std::vector<uint8_t> data(n);
    for (size_t i = 0; i < n; ++i) data[i] = static_cast<uint8_t>(i * 7 + 3);
    return data;
}

}  // namespace

TEST_CASE("BoundedReader clamps its limit to the device size", "[carve][m3]") {
    const std::vector<uint8_t> data = pattern(100);
    test::MemoryDevice device(data);
    BoundedReader reader(device, 90, 1000);
    CHECK(reader.limit() == 10);

    std::array<uint8_t, 32> buffer{};
    auto got = reader.read_at(0, buffer.data(), buffer.size());
    REQUIRE(got.has_value());
    CHECK(*got == 10);
    CHECK(std::equal(buffer.begin(), buffer.begin() + 10, data.begin() + 90));

    auto past = reader.u32be(8);
    CHECK_FALSE(past.has_value());
    CHECK(past.error().code == ErrorCode::CorruptStructure);
}

TEST_CASE("BoundedReader reads exactly across cache block boundaries", "[carve][m3]") {
    const std::vector<uint8_t> data = pattern(200000);
    test::MemoryDevice device(data);
    BoundedReader reader(device, 0, data.size());

    std::vector<uint8_t> buffer(70000);
    auto got = reader.read_at(60000, buffer.data(), buffer.size());
    REQUIRE(got.has_value());
    CHECK(*got == buffer.size());
    CHECK(std::equal(buffer.begin(), buffer.end(), data.begin() + 60000));

    auto u32 = reader.u32be(65534);
    REQUIRE(u32.has_value());
    CHECK(*u32 == ((static_cast<uint32_t>(data[65534]) << 24) |
                   (static_cast<uint32_t>(data[65535]) << 16) |
                   (static_cast<uint32_t>(data[65536]) << 8) | data[65537]));
}

TEST_CASE("BoundedReader makes device failures sticky", "[carve][m3]") {
    const std::vector<uint8_t> data = pattern(1000);
    test::MemoryDevice device(data);
    device.fail_at(0);
    BoundedReader reader(device, 0, data.size());

    uint8_t byte = 0;
    auto first = reader.read_at(0, &byte, 1);
    REQUIRE_FALSE(first.has_value());
    CHECK(first.error().code == ErrorCode::IoError);
    REQUIRE(reader.error().has_value());
    CHECK(reader.error()->code == ErrorCode::IoError);

    auto second = reader.read_at(500, &byte, 1);
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().code == ErrorCode::IoError);
}

TEST_CASE("BoundedReader read_vec stops at the limit and magic matching is exact", "[carve][m3]") {
    const std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6};
    test::MemoryDevice device(data);
    BoundedReader reader(device, 0, data.size());

    auto vec = reader.read_vec(4, 100);
    REQUIRE(vec.has_value());
    CHECK(vec->size() == 2);
    CHECK((*vec)[0] == 5);
    CHECK((*vec)[1] == 6);

    const std::vector<uint8_t> yes = {3, 4, 5};
    const std::vector<uint8_t> no = {3, 5};
    auto yes_result = reader.matches(2, yes);
    REQUIRE(yes_result.has_value());
    CHECK(*yes_result);
    auto no_result = reader.matches(2, no);
    REQUIRE(no_result.has_value());
    CHECK_FALSE(*no_result);

    const std::vector<uint8_t> too_long = {9, 9};
    auto near_end = reader.matches(5, too_long);
    REQUIRE(near_end.has_value());
    CHECK_FALSE(*near_end);
}

TEST_CASE("BoundedReader rejects a start past the end of the device", "[carve][m3]") {
    const std::vector<uint8_t> data = pattern(64);
    test::MemoryDevice device(data);
    BoundedReader reader(device, 64, 4096);
    CHECK(reader.limit() == 0);
    std::array<uint8_t, 4> buffer{};
    auto got = reader.read_at(0, buffer.data(), buffer.size());
    REQUIRE(got.has_value());
    CHECK(*got == 0);
}
