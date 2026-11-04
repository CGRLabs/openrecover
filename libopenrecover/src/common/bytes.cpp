#include "openrecover/common/bytes.hpp"

#include <array>
#include <cstring>

namespace openrecover {

uint64_t ByteView::uint_le(size_t off, size_t width) const noexcept {
    if (width == 0 || width > 8 || !check(off, width)) {
        failed_ = true;
        return 0;
    }
    uint64_t v = 0;
    for (size_t i = width; i-- > 0;) v = (v << 8) | p_[off + i];
    return v;
}

int64_t ByteView::sint_le(size_t off, size_t width) const noexcept {
    if (width == 0 || width > 8 || !has(off, width)) {
        failed_ = true;
        return 0;
    }
    uint64_t v = uint_le(off, width);
    if (width == 8) return static_cast<int64_t>(v);
    const uint64_t sign = uint64_t{1} << (width * 8 - 1);
    if (v & sign) v |= ~((sign << 1) - 1);
    return static_cast<int64_t>(v);
}

bool ByteView::equals(size_t off, std::string_view lit) const noexcept {
    if (!has(off, lit.size())) return false;
    return std::memcmp(p_ + off, lit.data(), lit.size()) == 0;
}

bool ByteView::equals(size_t off, std::span<const uint8_t> bytes) const noexcept {
    if (!has(off, bytes.size())) return false;
    return bytes.empty() || std::memcmp(p_ + off, bytes.data(), bytes.size()) == 0;
}

void append_utf8(std::string& out, uint32_t cp) {    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

bool is_valid_utf8(std::string_view s) noexcept {
    size_t i = 0;
    while (i < s.size()) {
        const auto lead = static_cast<unsigned char>(s[i]);
        if (lead < 0x80) {
            ++i;
            continue;
        }
        size_t extra = 0;
        uint32_t cp = 0;
        if ((lead & 0xE0) == 0xC0) {
            extra = 1;
            cp = lead & 0x1Fu;
            if (cp < 2) return false;
        } else if ((lead & 0xF0) == 0xE0) {
            extra = 2;
            cp = lead & 0x0Fu;
        } else if ((lead & 0xF8) == 0xF0) {
            extra = 3;
            cp = lead & 0x07u;
            if (cp > 4) return false;
        } else {
            return false;
        }
        if (extra > s.size() - i - 1) return false;
        for (size_t k = 1; k <= extra; ++k) {
            const auto c = static_cast<unsigned char>(s[i + k]);
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3Fu);
        }
        if (extra == 2 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) return false;
        if (extra == 3 && (cp < 0x10000 || cp > 0x10FFFF)) return false;
        i += extra + 1;
    }
    return true;
}

std::string utf16_to_utf8(std::u16string_view u) {
    std::string out;
    out.reserve(u.size());
    for (size_t i = 0; i < u.size(); ++i) {
        uint32_t c = u[i];
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 < u.size() && u[i + 1] >= 0xDC00 && u[i + 1] <= 0xDFFF) {
                uint32_t lo = u[i + 1];
                append_utf8(out, 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00));
                ++i;
            } else {
                append_utf8(out, 0xFFFD);
            }
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            append_utf8(out, 0xFFFD);
        } else {
            append_utf8(out, c);
        }
    }
    return out;
}

std::string utf16le_to_utf8(std::span<const uint8_t> bytes) {
    std::u16string units;
    units.reserve(bytes.size() / 2);
    for (size_t i = 0; i + 1 < bytes.size(); i += 2)
        units.push_back(static_cast<char16_t>(bytes[i] | (bytes[i + 1] << 8)));
    std::string out = utf16_to_utf8(units);
    if (bytes.size() % 2 != 0) append_utf8(out, 0xFFFD);
    return out;
}

namespace {

bool is_reserved_windows_name(const std::string& name) {
    std::string base = name.substr(0, name.find('.'));
    while (!base.empty() && base.back() == ' ') base.pop_back();
    std::string up;
    for (char ch : base) up.push_back((ch >= 'a' && ch <= 'z') ? static_cast<char>(ch - 32) : ch);
    static const std::array<const char*, 4> plain = {"CON", "PRN", "AUX", "NUL"};
    for (const char* r : plain)
        if (up == r) return true;
    if (up.size() == 4 && (up.compare(0, 3, "COM") == 0 || up.compare(0, 3, "LPT") == 0) && up[3] >= '1' &&
        up[3] <= '9')
        return true;
    return false;
}

}  // namespace

std::string sanitize_component(std::string name) {
    for (char& ch : name) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7F || ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?' ||
            ch == '"' || ch == '<' || ch == '>' || ch == '|')
            ch = '_';
    }
    if (is_reserved_windows_name(name)) name.insert(name.begin(), '_');
    constexpr size_t kMax = 200;
    if (name.size() > kMax) {
        size_t cut = kMax;
        while (cut > 0 && (static_cast<unsigned char>(name[cut]) & 0xC0) == 0x80) --cut;
        name.resize(cut);
    }
    while (!name.empty() && (name.back() == '.' || name.back() == ' ')) name.pop_back();
    if (name.empty() || name == "." || name == "..") return "_";
    return name;
}

std::string to_hex(std::span<const uint8_t> bytes) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        s.push_back(hex[b >> 4]);
        s.push_back(hex[b & 15]);
    }
    return s;
}

}  // namespace openrecover
