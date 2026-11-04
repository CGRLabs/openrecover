#include "openrecover/carve/bounded_reader.hpp"

#include <algorithm>
#include <cstring>

namespace openrecover::carve {

namespace {

template <typename T>
Result<T> reader_error(const char* message, uint64_t offset) {
    return fail(ErrorCode::CorruptStructure, message, offset);
}

}  // namespace

BoundedReader::BoundedReader(io::BlockDevice& device, uint64_t start, uint64_t max_length)
    : device_(device), start_(start) {
    const uint64_t device_size = device.info().size_bytes;
    if (start >= device_size) {
        limit_ = 0;
        return;
    }
    limit_ = std::min<uint64_t>(max_length, device_size - start);
}

BoundedReader::CacheBlock* BoundedReader::lookup(uint64_t index) {
    for (CacheBlock& block : cache_) {
        if (block.valid && block.index == index) {
            block.age = ++clock_;
            return &block;
        }
    }
    return nullptr;
}

BoundedReader::CacheBlock* BoundedReader::insert(uint64_t index) {
    CacheBlock* victim = &cache_[0];
    for (CacheBlock& block : cache_) {
        if (!block.valid) {
            victim = &block;
            break;
        }
        if (block.age < victim->age) victim = &block;
    }

    victim->valid = false;
    victim->index = index;
    victim->age = ++clock_;
    const uint64_t block_start = index * kBlockBytes;
    const uint64_t device_size = device_.info().size_bytes;
    if (block_start >= device_size) {
        victim->size = 0;
        return victim;
    }
    const size_t want =
        static_cast<size_t>(std::min<uint64_t>(kBlockBytes, device_size - block_start));
    auto got = io::read_fully(device_, block_start, victim->data.data(), want);
    if (!got) {
        if (!error_) error_ = got.error();
        return nullptr;
    }
    victim->size = *got;
    victim->valid = true;
    return victim;
}

Result<size_t> BoundedReader::copy_from_block(uint64_t rel, uint8_t* dst, size_t len) {
    const uint64_t absolute = start_ + rel;
    const uint64_t index = absolute / kBlockBytes;
    const size_t within = static_cast<size_t>(absolute % kBlockBytes);

    CacheBlock* block = lookup(index);
    if (!block) {
        block = insert(index);
        if (!block) return fail(*error_);
    }
    if (block->size <= within) return size_t{0};
    const size_t take = std::min(len, block->size - within);
    std::memcpy(dst, block->data.data() + within, take);
    return take;
}

Result<size_t> BoundedReader::read_at(uint64_t rel, uint8_t* dst, size_t len) {
    if (error_) return fail(*error_);
    if (rel >= limit_ || len == 0) return size_t{0};
    const size_t want = static_cast<size_t>(std::min<uint64_t>(len, limit_ - rel));

    size_t done = 0;
    while (done < want) {
        auto got = copy_from_block(rel + done, dst + done, want - done);
        if (!got) return fail(got.error());
        if (*got == 0) break;
        done += *got;
    }
    return done;
}

Result<uint8_t> BoundedReader::u8(uint64_t rel) {
    uint8_t value = 0;
    auto got = read_at(rel, &value, 1);
    if (!got) return fail(got.error());
    if (*got != 1) return reader_error<uint8_t>("read past the bounded candidate", start_ + rel);
    return value;
}

Result<uint16_t> BoundedReader::u16be(uint64_t rel) {
    uint8_t bytes[2]{};
    auto got = read_at(rel, bytes, sizeof bytes);
    if (!got) return fail(got.error());
    if (*got != sizeof bytes) return reader_error<uint16_t>("read past the bounded candidate", start_ + rel);
    return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
}

Result<uint32_t> BoundedReader::u32be(uint64_t rel) {
    uint8_t bytes[4]{};
    auto got = read_at(rel, bytes, sizeof bytes);
    if (!got) return fail(got.error());
    if (*got != sizeof bytes) return reader_error<uint32_t>("read past the bounded candidate", start_ + rel);
    return (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) | static_cast<uint32_t>(bytes[3]);
}

Result<uint64_t> BoundedReader::u64be(uint64_t rel) {
    uint8_t bytes[8]{};
    auto got = read_at(rel, bytes, sizeof bytes);
    if (!got) return fail(got.error());
    if (*got != sizeof bytes) return reader_error<uint64_t>("read past the bounded candidate", start_ + rel);
    uint64_t value = 0;
    for (uint8_t byte : bytes) value = (value << 8) | byte;
    return value;
}

Result<bool> BoundedReader::matches(uint64_t rel, std::span<const uint8_t> magic) {
    if (magic.empty()) return true;
    if (magic.size() > 32)
        return fail(ErrorCode::InvalidArgument, "signature magic is longer than 32 bytes");
    std::array<uint8_t, 32> buffer{};
    auto got = read_at(rel, buffer.data(), magic.size());
    if (!got) return fail(got.error());
    if (*got != magic.size()) return false;
    return std::equal(magic.begin(), magic.end(), buffer.begin());
}

Result<std::vector<uint8_t>> BoundedReader::read_vec(uint64_t rel, size_t len) {
    if (rel >= limit_) return std::vector<uint8_t>{};
    const size_t want = static_cast<size_t>(std::min<uint64_t>(len, limit_ - rel));
    std::vector<uint8_t> out(want);
    auto got = read_at(rel, out.data(), want);
    if (!got) return fail(got.error());
    out.resize(*got);
    return out;
}

}  // namespace openrecover::carve
