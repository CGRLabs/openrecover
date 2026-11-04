#pragma once

#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/result.hpp"

namespace openrecover::android {

enum class AndroidRootKind { Thumbnail, Trash, Cache };

const char* android_root_kind_name(AndroidRootKind kind) noexcept;
std::optional<AndroidRootKind> android_root_kind_from_string(std::string_view name) noexcept;

struct AndroidScanRoot {
    std::string id;
    std::string path;
    AndroidRootKind kind = AndroidRootKind::Thumbnail;
    bool recursive = true;
    std::string name_regex;
    std::string dir_regex;
    std::optional<std::regex> name_pattern;
    std::optional<std::regex> dir_pattern;
    // -1 means no depth limit. Depth counts '/'-separated components below the root.
    int max_depth = -1;
    bool optional = false;
};

struct AndroidScanProfile {
    int schema = 1;
    std::string name;
    std::vector<AndroidScanRoot> roots;
    std::vector<std::string> type_filter;
    uint64_t max_file_size = std::numeric_limits<uint64_t>::max();
};

// Section 6.3 profile loader. Unknown fields, bad regexes and paths outside shared
// storage are rejected rather than silently ignored.
Result<AndroidScanProfile> parse_scan_profile(std::string_view json, std::string_view source_name);
Result<AndroidScanProfile> load_scan_profile(const std::filesystem::path& path);

struct TrashedName {
    uint64_t expires_at = 0;
    std::string original_name;
};

// `.trashed-<expiry_epoch>-<original name>` (Android 11+ MediaStore).
std::optional<TrashedName> parse_trashed_name(std::string_view filename);

}  // namespace openrecover::android
