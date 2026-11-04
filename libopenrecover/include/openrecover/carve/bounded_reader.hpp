#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "openrecover/common/error.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::carve {

// Reads relative to a candidate start with a hard upper bound. Validators can never
// read outside [start, start + limit). A small block cache keeps field-level parsing
// from issuing one device read per byte.
class BoundedReader {
public:
    BoundedReader(io::BlockDevice& device, uint64_t start, uint64_t max_length);

    Result<size_t> read_at(uint64_t rel, uint8_t* dst, size_t len);
    uint64_t limit() const noexcept { return limit_; }
    bool deep_validate() const noexcept { return deep_validate_; }
    void set_deep_validate(bool deep) noexcept { deep_validate_ = deep; }

    Result<uint8_t> u8(uint64_t rel);
    Result<uint16_t> u16be(uint64_t rel);
    Result<uint32_t> u32be(uint64_t rel);
    Result<uint64_t> u64be(uint64_t rel);
    Result<bool> matches(uint64_t rel, std::span<const uint8_t> magic);
    Result<std::vector<uint8_t>> read_vec(uint64_t rel, size_t len);

    // First I/O error observed while validating; the engine turns it into a failed run.
    const std::optional<Error>& error() const noexcept { return error_; }

private:
    static constexpr size_t kBlockBytes = 64u << 10;
    static constexpr size_t kCacheBlocks = 4;

    struct CacheBlock {
        uint64_t index = 0;
        size_t size = 0;
        uint64_t age = 0;
        bool valid = false;
        std::array<uint8_t, kBlockBytes> data{};
    };

    Result<size_t> copy_from_block(uint64_t rel, uint8_t* dst, size_t len);
    CacheBlock* lookup(uint64_t index);
    CacheBlock* insert(uint64_t index);

    io::BlockDevice& device_;
    uint64_t start_;
    uint64_t limit_;
    std::optional<Error> error_;
    std::array<CacheBlock, kCacheBlocks> cache_{};
    uint64_t clock_ = 0;
    bool deep_validate_ = false;
};

}  // namespace openrecover::carve
