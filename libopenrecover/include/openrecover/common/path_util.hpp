#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace openrecover {

inline std::filesystem::path path_from_utf8(std::string_view s) {
    std::u8string u;
    u.reserve(s.size());
    for (char c : s) u.push_back(static_cast<char8_t>(c));
    return std::filesystem::path(u);
}

inline std::string path_to_utf8(const std::filesystem::path& p) {
    std::u8string u = p.u8string();
    std::string s;
    s.reserve(u.size());
    for (char8_t c : u) s.push_back(static_cast<char>(c));
    return s;
}

// '/'-separated UTF-8 form, used in reports.
inline std::string path_to_generic_utf8(const std::filesystem::path& p) {
    std::u8string u = p.generic_u8string();
    std::string s;
    s.reserve(u.size());
    for (char8_t c : u) s.push_back(static_cast<char>(c));
    return s;
}

#if defined(_WIN32)
// Absolute path with the \\?\ long-path prefix (\\?\UNC\ for network shares).
inline std::filesystem::path win_long_path(const std::filesystem::path& p) {
    std::error_code ec;
    std::wstring w = std::filesystem::absolute(p, ec).make_preferred().wstring();
    if (ec) w = p.wstring();
    if (w.rfind(L"\\\\?\\", 0) == 0 || w.rfind(L"\\\\.\\", 0) == 0) return w;
    if (w.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + w.substr(2);
    return L"\\\\?\\" + w;
}
#endif

}  // namespace openrecover
