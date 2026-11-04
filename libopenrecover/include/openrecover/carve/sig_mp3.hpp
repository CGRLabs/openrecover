#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

// MPEG audio: an optional ID3v2 tag followed by a run of frames, each of which says how long it
// is. There is no total length in the format, so the file ends where the frames do.
class Mp3Signature final : public ISignature {
public:
    std::string_view name() const override { return "mp3"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return 4; }
    uint64_t max_file_size() const override { return 1ull << 31; }
    std::string_view default_extension() const override { return "mp3"; }
    ValidationResult validate(BoundedReader& reader) const override;
};

}  // namespace openrecover::carve
