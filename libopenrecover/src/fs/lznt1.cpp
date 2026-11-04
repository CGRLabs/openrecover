#include "openrecover/fs/lznt1.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "openrecover/common/bytes.hpp"

namespace openrecover::fs {

namespace {

constexpr size_t kHeaderBytes = 2;
constexpr size_t kEntriesPerGroup = 8;
// The largest expansion one chunk can have, for the signature this decoder accepts.
constexpr size_t kChunkOutputLimit = 4096;
// Signature 3 means the 4096-byte chunk shape NTFS uses. Signature 2 is the 512-byte shape, which is
// not implemented here rather than decoded along a path nothing exercises.
constexpr size_t kSupportedSignature = 3;
constexpr size_t kMinimumMatch = 3;
// Below sixteen bytes produced a back-reference needs only four displacement bits, which leaves
// twelve for the length; every time the produced count doubles one bit moves to the displacement.
constexpr size_t kFirstDisplacementDoubling = 16;

Result<Lznt1Chunk> corrupt(const std::string& message) {
    return fail(ErrorCode::CorruptStructure, "invalid LZNT1 chunk: " + message);
}

struct TupleFields {
    size_t offset_shift = 12;
    uint16_t length_mask = 0x0FFF;
};

TupleFields fields_for(size_t produced_in_chunk) {
    TupleFields fields;
    // produced_in_chunk - 1 is the zero-based position a back-reference starts from, so four
    // displacement bits stay enough up to and including the sixteenth produced byte.
    for (size_t probe = produced_in_chunk == 0 ? 0 : produced_in_chunk - 1;
         probe >= kFirstDisplacementDoubling;
         probe >>= 1) {
        --fields.offset_shift;
        fields.length_mask = static_cast<uint16_t>(fields.length_mask >> 1);
    }
    return fields;
}

}  // namespace

Result<Lznt1Chunk> decompress_lznt1_chunk(std::span<const uint8_t> src, std::span<uint8_t> dst) {
    if (src.size() < kHeaderBytes) return corrupt("the chunk header is truncated");

    const ByteView view(src);
    const uint16_t header = view.u16le(0);
    const size_t count = header & 0x0FFF;
    const size_t signature = (header >> 12) & 0x07;
    const bool compressed = (header & 0x8000) != 0;

    // An empty count is how a unit says it ended early; there is no chunk here at all.
    if (count == 0) return Lznt1Chunk{kHeaderBytes, 0, true};

    // The count covers everything but the header and its own bias, so the chunk is count + 3.
    const size_t chunk_bytes = count + 3;
    if (src.size() < chunk_bytes)
        return corrupt("the chunk claims " + std::to_string(chunk_bytes) + " bytes but only " +
                       std::to_string(src.size()) + " are present");
    const size_t body_bytes = count + 1;
    const size_t room = std::min(dst.size(), kChunkOutputLimit);

    if (!compressed) {
        if (body_bytes > room)
            return corrupt("a raw chunk of " + std::to_string(body_bytes) +
                           " bytes does not fit the room left");
        std::copy_n(src.begin() + static_cast<std::ptrdiff_t>(kHeaderBytes), body_bytes, dst.begin());
        return Lznt1Chunk{chunk_bytes, body_bytes, false};
    }

    if (signature != kSupportedSignature)
        return fail(ErrorCode::Unsupported, "LZNT1 chunk signature " + std::to_string(signature) +
                                                " is not supported");

    const uint8_t* body = src.data() + kHeaderBytes;
    size_t produced = 0;
    size_t position = 0;

    // Groups are read one flag byte at a time and their entries consume the bytes that follow
    // consecutively: a group of eight literals takes nine bytes on disk, a group of eight matches
    // takes seventeen. Whatever is left of the chunk after eight entries is the next flag byte.
    while (position < body_bytes) {
        const uint8_t flags = body[position++];
        for (size_t bit = 0; bit < kEntriesPerGroup && position < body_bytes; ++bit) {
            if ((flags & (1u << bit)) != 0) {
                if (position + 2 > body_bytes)
                    return corrupt("a match is cut off by the end of the chunk");
                const size_t tuple = static_cast<size_t>(body[position]) |
                                     (static_cast<size_t>(body[position + 1]) << 8);
                position += 2;

                const TupleFields fields = fields_for(produced);
                const size_t length = (tuple & fields.length_mask) + kMinimumMatch;
                const size_t displacement = (tuple >> fields.offset_shift) + 1;
                if (displacement > produced)
                    return corrupt("a match reaches " + std::to_string(displacement) +
                                   " bytes back with only " + std::to_string(produced) + " produced");
                if (length > room - produced)
                    return corrupt("a match of " + std::to_string(length) +
                                   " bytes does not fit the room left");

                // Byte by byte, so a match that overlaps itself repeats the pattern it starts writing.
                for (size_t i = 0; i < length; ++i) dst[produced + i] = dst[produced - displacement + i];
                produced += length;
                continue;
            }
            if (produced == room) return corrupt("the chunk expands past its destination");
            dst[produced++] = body[position++];
        }
    }

    return Lznt1Chunk{chunk_bytes, produced, false};
}

Result<size_t> decompress_lznt1(std::span<const uint8_t> src, std::span<uint8_t> dst) {
    size_t produced = 0;
    size_t read = 0;
    // Each chunk is expanded on its own and then copied as far as the caller needs. A destination
    // shorter than a chunk, which is what the last unit of a file asks for, therefore stops the
    // walk at the byte it wanted instead of complaining that the chunk does not fit.
    std::array<uint8_t, kChunkOutputLimit> stage;

    while (read < src.size() && produced < dst.size()) {
        auto chunk = decompress_lznt1_chunk(src.subspan(read), stage);
        if (!chunk) return fail(chunk.error());
        read += chunk->consumed;
        if (chunk->produced != 0) {
            const size_t take = std::min(chunk->produced, dst.size() - produced);
            std::copy_n(stage.begin(), static_cast<std::ptrdiff_t>(take),
                        dst.begin() + static_cast<std::ptrdiff_t>(produced));
            produced += take;
        }
        if (chunk->end_of_stream) break;
    }

    return produced;
}

}  // namespace openrecover::fs
