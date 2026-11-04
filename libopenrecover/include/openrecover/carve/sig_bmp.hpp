#pragma once

#include <span>
#include <string_view>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

class BmpSignature final : public ISignature {
public:
    std::string_view name() const override { return "bmp"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return 26; }
    uint64_t max_file_size() const override { return 512ull << 20; }
    std::string_view default_extension() const override { return "bmp"; }
    ValidationResult validate(BoundedReader& reader) const override;
};

}  // namespace openrecover::carve
