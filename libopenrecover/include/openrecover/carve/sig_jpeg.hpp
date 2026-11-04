#pragma once

#include <span>
#include <string_view>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

class JpegSignature final : public ISignature {
public:
    std::string_view name() const override { return "jpeg"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return 4; }
    uint64_t max_file_size() const override { return 64ull << 20; }
    std::string_view default_extension() const override { return "jpg"; }
    ValidationResult validate(BoundedReader& r) const override;
    std::optional<Continuation> find_continuation(BoundedReader& r) const override;
};

}  // namespace openrecover::carve
