#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "fuzz_common.hpp"
#include "openrecover/fs/lznt1.hpp"

namespace {
// One compression unit of the widest shape NTFS writes, and the ceiling a single chunk may
// expand to. Nothing the decoder allocates is on the heap, so the buffer is fixed.
constexpr size_t kUnitBytes = 65536;
constexpr size_t kChunkBytes = 4096;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::silence_logs();
    if (size < 2) return 0;
    const std::span<const uint8_t> src(data, size);
    std::array<uint8_t, kUnitBytes> unit{};

    // A whole unit, one chunk of it, and a destination shorter than a chunk: the last one is what
    // the tail unit of a file asks for, and padding past the stream must not become an error.
    (void)openrecover::fs::decompress_lznt1(src, std::span<uint8_t>(unit));
    (void)openrecover::fs::decompress_lznt1_chunk(src, std::span<uint8_t>(unit.data(), kChunkBytes));
    const size_t tail_bytes = size % kChunkBytes;
    if (tail_bytes != 0)
        (void)openrecover::fs::decompress_lznt1(src, std::span<uint8_t>(unit.data(), tail_bytes));
    return 0;
}
