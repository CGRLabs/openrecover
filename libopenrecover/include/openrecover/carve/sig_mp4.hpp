#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

// ISO base media file format: MP4, QuickTime, M4A, 3GPP and HEIF all open with an `ftyp` box.
class Mp4Signature final : public ISignature {
public:
    std::string_view name() const override { return "mp4"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t magic_offset() const override { return 4; }
    size_t min_header_bytes() const override { return 16; }
    uint64_t max_file_size() const override { return 4ull << 30; }
    std::string_view default_extension() const override { return "mp4"; }
    ValidationResult validate(BoundedReader& reader) const override;
};

}  // namespace openrecover::carve
