#pragma once

#include <span>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

class ZipSignature final : public ISignature {
public:
    std::string_view name() const override { return "zip"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return 4; }
    uint64_t max_file_size() const override { return 2ull << 30; }
    std::string_view default_extension() const override { return "zip"; }
    ValidationResult validate(BoundedReader& reader) const override;
};

}  // namespace openrecover::carve
