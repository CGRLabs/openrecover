#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "openrecover/common/result.hpp"

namespace openrecover::fs {

// NTFS writes an LZNT1-compressed attribute as a sequence of compression units, and a unit as a
// sequence of chunks: each chunk expands to at most 4096 bytes, and a chunk's on-disk length is
// variable, so the reader has to walk them one at a time. This is that step.
//
// `src` starts at a chunk's 2-byte header and may run past the chunk (the caller hands it the rest
// of the unit); `dst` is the room left for this chunk. The result reports how many source bytes the
// chunk occupies and how many output bytes were written, which is how the caller finds the next
// chunk. A chunk holds up to eight entries per flag byte, each entry one literal byte or a
// two-byte back-reference, so the entries run consecutively and a group takes 9 to 17 bytes on
// disk rather than a fixed 17. Only the 4096-byte chunk shape NTFS uses is accepted; the 512-byte
// shape is refused as `Unsupported` rather than decoded by an untested path.
struct Lznt1Chunk {
    size_t consumed = 0;
    size_t produced = 0;
    // A header with an empty count ends the stream; the unit is shorter than it looks.
    bool end_of_stream = false;
};

Result<Lznt1Chunk> decompress_lznt1_chunk(std::span<const uint8_t> src, std::span<uint8_t> dst);

// Walks the chunks of one compression unit until `dst` is full or a header says the stream ended.
// Returns the number of bytes written; a unit that does not fill `dst` is normal, since the last
// unit of a stream is partial. Each chunk expands into a buffer of its own first, so a `dst`
// shorter than one chunk takes the bytes it wanted and stops rather than reporting a chunk that
// does not fit.
Result<size_t> decompress_lznt1(std::span<const uint8_t> src, std::span<uint8_t> dst);

}  // namespace openrecover::fs
