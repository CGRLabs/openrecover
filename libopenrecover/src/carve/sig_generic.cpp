#include "openrecover/carve/sig_generic.hpp"

#include <nlohmann/json.hpp>

#include "openrecover/carve/bounded_reader.hpp"

namespace openrecover::carve {

GenericSignature::GenericSignature(std::string name, std::vector<uint8_t> magic,
                                  std::string extension, uint64_t max_size)
    : name_(std::move(name)), magic_(std::move(magic)),
      extension_(std::move(extension)), max_size_(max_size) {}

std::span<const std::span<const uint8_t>> GenericSignature::magics() const {
    if (!spans_built_) {
        spans_.clear();
        spans_.push_back(std::span<const uint8_t>(magic_.data(), magic_.size()));
        spans_built_ = true;
    }
    return std::span<const std::span<const uint8_t>>(spans_.data(), spans_.size());
}

ValidationResult GenericSignature::validate(BoundedReader& r) const {
    ValidationResult result;
    auto m = r.matches(0, std::span<const uint8_t>(magic_.data(), magic_.size()));
    if (!m || !*m) return result; // invalid (or io error -> invalid here)
    uint64_t available = r.limit();
    uint64_t len = max_size_;
    if (len > available) len = available;
    if (len < max_size_) {
        result.verdict = ValidationResult::Verdict::ValidTruncated;
        result.confidence = Confidence::Low;
    } else {
        result.verdict = ValidationResult::Verdict::Valid;
        result.confidence = Confidence::Medium;
    }
    result.length_bytes = len;
    result.subtype = name_;
    return result;
}

}  // namespace openrecover::carve