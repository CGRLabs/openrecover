#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace openrecover {

class Sha256Hasher {
public:
    Sha256Hasher();
    ~Sha256Hasher();
    Sha256Hasher(Sha256Hasher&&) noexcept;
    Sha256Hasher& operator=(Sha256Hasher&&) noexcept;
    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;

    void update(const uint8_t* data, size_t len);
    void update(std::span<const uint8_t> s) { update(s.data(), s.size()); }
    std::string finish_hex();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::string sha256_hex(std::span<const uint8_t> data);

}  // namespace openrecover
