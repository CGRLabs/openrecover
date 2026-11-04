#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

// MS-CFB: the compound file binary container that holds a legacy Office document. The container
// describes itself with an allocation table rather than a length field, so the file is sized from
// the sectors the table says it owns and named from the stream the directory lists.
class CfbSignature final : public ISignature {
public:
    std::string_view name() const override { return "cfb"; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return 512; }
    uint64_t max_file_size() const override { return 1ull << 30; }
    std::string_view default_extension() const override { return "cfb"; }
    ValidationResult validate(BoundedReader& reader) const override;
};

}  // namespace openrecover::carve
