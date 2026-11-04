#include "openrecover/common/hash.hpp"

#include <sha256.h>

namespace openrecover {

struct Sha256Hasher::Impl {
    or_sha256::Sha256 ctx;
};

Sha256Hasher::Sha256Hasher() : impl_(std::make_unique<Impl>()) {}
Sha256Hasher::~Sha256Hasher() = default;
Sha256Hasher::Sha256Hasher(Sha256Hasher&&) noexcept = default;
Sha256Hasher& Sha256Hasher::operator=(Sha256Hasher&&) noexcept = default;

void Sha256Hasher::update(const uint8_t* data, size_t len) { impl_->ctx.update(data, len); }

std::string Sha256Hasher::finish_hex() { return impl_->ctx.finish_hex(); }

std::string sha256_hex(std::span<const uint8_t> data) {
    or_sha256::Sha256 h;
    h.update(data.data(), data.size());
    return h.finish_hex();
}

}  // namespace openrecover
