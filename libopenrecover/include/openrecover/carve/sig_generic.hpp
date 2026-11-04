#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/signature.hpp"

namespace openrecover::carve {

class GenericSignature final : public ISignature {
public:
    GenericSignature(std::string name, std::vector<uint8_t> magic,
                     std::string extension, uint64_t max_size);

    std::string_view name() const override { return name_; }
    std::span<const std::span<const uint8_t>> magics() const override;
    size_t min_header_bytes() const override { return magic_.size(); }
    uint64_t max_file_size() const override { return max_size_; }
    std::string_view default_extension() const override { return extension_; }
    ValidationResult validate(BoundedReader& r) const override;

private:
    std::string name_;
    std::vector<uint8_t> magic_;
    std::string extension_;
    uint64_t max_size_;
    mutable std::vector<std::span<const uint8_t>> spans_;
    mutable bool spans_built_ = false;
};

}  // namespace openrecover::carve