#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

// RIFF AVI: a video container that shares its four-byte magic with WAV and is told apart by the
// form type at offset 8.
class AviSignature final : public ISignature {
public:
    std::string_view name() const override { return "avi"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return 12; }
    uint64_t max_file_size() const override { return 4ull << 30; }
    std::string_view default_extension() const override { return "avi"; }
    ValidationResult validate(BoundedReader& reader) const override;
};

}  // namespace openrecover::carve
