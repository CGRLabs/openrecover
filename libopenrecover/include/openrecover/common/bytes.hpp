#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>

namespace openrecover {

// Bounds-checked view over hostile on-disk bytes. Any out-of-range access returns 0
// and sets a sticky failure flag; parsers check failed() at their checkpoints.
class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const uint8_t* p, size_t n) noexcept : p_(p), n_(p ? n : 0) {}
    constexpr explicit ByteView(std::span<const uint8_t> s) noexcept : p_(s.data()), n_(s.size()) {}

    constexpr size_t size() const noexcept { return n_; }
    constexpr const uint8_t* data() const noexcept { return p_; }
    constexpr bool failed() const noexcept { return failed_; }
    constexpr bool ok() const noexcept { return !failed_; }
    constexpr void clear_failure() noexcept { failed_ = false; }

    constexpr bool has(size_t off, size_t len) const noexcept {
        return off <= n_ && len <= n_ - off;
    }

    uint8_t u8(size_t off) const noexcept { return check(off, 1) ? p_[off] : 0; }
    int8_t s8(size_t off) const noexcept { return static_cast<int8_t>(u8(off)); }

    uint16_t u16le(size_t off) const noexcept {
        if (!check(off, 2)) return 0;
        return static_cast<uint16_t>(p_[off] | (p_[off + 1] << 8));
    }
    uint32_t u32le(size_t off) const noexcept {
        if (!check(off, 4)) return 0;
        return static_cast<uint32_t>(p_[off]) | (static_cast<uint32_t>(p_[off + 1]) << 8) |
               (static_cast<uint32_t>(p_[off + 2]) << 16) | (static_cast<uint32_t>(p_[off + 3]) << 24);
    }
    uint64_t u64le(size_t off) const noexcept {
        if (!check(off, 8)) return 0;
        uint64_t v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | p_[off + static_cast<size_t>(i)];
        return v;
    }
    uint16_t u16be(size_t off) const noexcept {
        if (!check(off, 2)) return 0;
        return static_cast<uint16_t>((p_[off] << 8) | p_[off + 1]);
    }
    uint32_t u32be(size_t off) const noexcept {
        if (!check(off, 4)) return 0;
        return (static_cast<uint32_t>(p_[off]) << 24) | (static_cast<uint32_t>(p_[off + 1]) << 16) |
               (static_cast<uint32_t>(p_[off + 2]) << 8) | static_cast<uint32_t>(p_[off + 3]);
    }
    uint64_t u64be(size_t off) const noexcept {
        if (!check(off, 8)) return 0;
        uint64_t v = 0;
        for (size_t i = 0; i < 8; ++i) v = (v << 8) | p_[off + i];
        return v;
    }
    // Unsigned little-endian integer of 1..8 bytes.
    uint64_t uint_le(size_t off, size_t width) const noexcept;
    // Signed little-endian integer of 1..8 bytes, sign-extended from the top bit of the last byte.
    int64_t sint_le(size_t off, size_t width) const noexcept;

    // Sub-view; on overrun returns an empty view and marks this view failed.
    ByteView sub(size_t off, size_t len) const noexcept {
        if (!check(off, len)) return ByteView{};
        return ByteView{p_ + off, len};
    }
    bool equals(size_t off, std::string_view lit) const noexcept;
    bool equals(size_t off, std::span<const uint8_t> bytes) const noexcept;

private:
    bool check(size_t off, size_t len) const noexcept {
        if (has(off, len)) return true;
        failed_ = true;
        return false;
    }

    const uint8_t* p_ = nullptr;
    size_t n_ = 0;
    mutable bool failed_ = false;
};

// Converts UTF-16LE code units to UTF-8. Unpaired surrogates become U+FFFD.
std::string utf16le_to_utf8(std::span<const uint8_t> bytes);
std::string utf16_to_utf8(std::u16string_view units);
void append_utf8(std::string& out, uint32_t codepoint);
// Strict UTF-8 validation: rejects overlong forms, surrogates and truncated sequences.
bool is_valid_utf8(std::string_view s) noexcept;

// Makes a single path component safe for any host filesystem.
std::string sanitize_component(std::string name);

template <typename T>
constexpr bool checked_add(T a, T b, T& out) noexcept {
    static_assert(std::numeric_limits<T>::is_integer && !std::numeric_limits<T>::is_signed);
    if (a > std::numeric_limits<T>::max() - b) return false;
    out = a + b;
    return true;
}

template <typename T>
constexpr bool checked_mul(T a, T b, T& out) noexcept {
    static_assert(std::numeric_limits<T>::is_integer && !std::numeric_limits<T>::is_signed);
    if (a != 0 && b > std::numeric_limits<T>::max() / a) return false;
    out = a * b;
    return true;
}

constexpr uint64_t align_down(uint64_t v, uint64_t a) noexcept { return a ? v / a * a : v; }
// Returns false on overflow.
constexpr bool align_up(uint64_t v, uint64_t a, uint64_t& out) noexcept {
    if (a == 0) {
        out = v;
        return true;
    }
    uint64_t r = v % a;
    if (r == 0) {
        out = v;
        return true;
    }
    return checked_add<uint64_t>(v, a - r, out);
}

std::string to_hex(std::span<const uint8_t> bytes);

}  // namespace openrecover
