#pragma once

#include <span>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

class PngSignature final : public ISignature {
public:
    std::string_view name() const override { return "png"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return 8; }
    uint64_t max_file_size() const override { return 128ull << 20; }
    std::string_view default_extension() const override { return "png"; }
    ValidationResult validate(BoundedReader& reader) const override;
    std::optional<Continuation> find_continuation(BoundedReader& reader) const override;
};

}  // namespace openrecover::carve
