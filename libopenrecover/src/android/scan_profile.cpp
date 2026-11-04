#include "openrecover/android/scan_profile.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "nlohmann/json.hpp"
#include "openrecover/android/adb_command_policy.hpp"
#include "openrecover/common/path_util.hpp"

namespace openrecover::android {

namespace {

using json = nlohmann::json;

constexpr size_t kMaxProfileBytes = 1u << 20;
constexpr size_t kMaxRoots = 128;
constexpr size_t kMaxRegexBytes = 512;

std::string lower_ascii(std::string text) {
    for (char& c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (u >= 'A' && u <= 'Z') c = static_cast<char>(u - 'A' + 'a');
    }
    return text;
}

Result<std::string> required_string(const json& object, const char* key, std::string_view where,
                                    size_t max_length) {
    if (!object.contains(key)) {
        return fail(ErrorCode::InvalidArgument,
                    std::string(where) + ": missing required field '" + key + "'");
    }
    const json& value = object.at(key);
    if (!value.is_string()) {
        return fail(ErrorCode::InvalidArgument,
                    std::string(where) + ": field '" + key + "' must be a string");
    }
    std::string text = value.get<std::string>();
    if (text.empty() || text.size() > max_length) {
        return fail(ErrorCode::InvalidArgument,
                    std::string(where) + ": field '" + key + "' must be 1.." +
                        std::to_string(max_length) + " characters");
    }
    return text;
}

Result<bool> optional_bool(const json& object, const char* key, bool fallback,
                           std::string_view where) {
    if (!object.contains(key)) return fallback;
    if (!object.at(key).is_boolean()) {
        return fail(ErrorCode::InvalidArgument,
                    std::string(where) + ": field '" + key + "' must be a boolean");
    }
    return object.at(key).get<bool>();
}

Result<std::string> optional_string(const json& object, const char* key, size_t max_length,
                                    std::string_view where) {
    if (!object.contains(key) || object.at(key).is_null()) return std::string();
    if (!object.at(key).is_string()) {
        return fail(ErrorCode::InvalidArgument,
                    std::string(where) + ": field '" + key + "' must be a string");
    }
    std::string text = object.at(key).get<std::string>();
    if (text.size() > max_length) {
        return fail(ErrorCode::InvalidArgument,
                    std::string(where) + ": field '" + key + "' exceeds " +
                        std::to_string(max_length) + " characters");
    }
    return text;
}

Result<void> reject_unknown_fields(const json& object, std::initializer_list<const char*> allowed,
                                   std::string_view where) {
    for (auto it = object.begin(); it != object.end(); ++it) {
        const bool known = std::any_of(allowed.begin(), allowed.end(),
                                       [&it](const char* name) { return it.key() == name; });
        if (!known) {
            return fail(ErrorCode::InvalidArgument,
                        std::string(where) + ": unknown field '" + it.key() + "'");
        }
    }
    return {};
}

bool valid_root_id(std::string_view id) {
    if (id.empty() || id.size() > 64) return false;
    return std::all_of(id.begin(), id.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.';
    });
}

Result<std::regex> compile_regex(const std::string& pattern, const char* field,
                                 std::string_view where) {
    try {
        return std::regex(pattern, std::regex::ECMAScript);
    } catch (const std::regex_error& error) {
        return fail(ErrorCode::InvalidArgument,
                    std::string(where) + ": invalid " + field + ": " + error.what());
    }
}

Result<AndroidScanRoot> parse_root(const json& value, size_t index, std::string_view source) {
    const std::string where =
        std::string(source) + ": roots[" + std::to_string(index) + "]";
    if (!value.is_object()) {
        return fail(ErrorCode::InvalidArgument, where + " must be an object");
    }
    auto unknown = reject_unknown_fields(value,
                                         {"id", "path", "kind", "recursive", "name_regex",
                                          "dir_regex", "max_depth", "optional", "comment"},
                                         where);
    if (!unknown) return fail(unknown.error());

    auto id = required_string(value, "id", where, 64);
    if (!id) return fail(id.error());
    if (!valid_root_id(*id)) {
        return fail(ErrorCode::InvalidArgument,
                    where + ": id may only contain letters, digits, '.', '_' and '-'");
    }

    auto path = required_string(value, "path", where, kMaxRemotePathBytes);
    if (!path) return fail(path.error());
    auto valid_path = validate_remote_path(*path);
    if (!valid_path) {
        return fail(ErrorCode::InvalidArgument, where + ": " + valid_path.error().message);
    }

    auto kind_text = required_string(value, "kind", where, 32);
    if (!kind_text) return fail(kind_text.error());
    const auto kind = android_root_kind_from_string(*kind_text);
    if (!kind) {
        return fail(ErrorCode::InvalidArgument,
                    where + ": unknown kind '" + *kind_text +
                        "' (expected thumbnail, trash or cache)");
    }

    AndroidScanRoot root;
    root.id = std::move(*id);
    root.path = std::move(*path);
    root.kind = *kind;

    auto recursive = optional_bool(value, "recursive", true, where);
    if (!recursive) return fail(recursive.error());
    root.recursive = *recursive;

    auto optional = optional_bool(value, "optional", false, where);
    if (!optional) return fail(optional.error());
    root.optional = *optional;

    auto name_regex = optional_string(value, "name_regex", kMaxRegexBytes, where);
    if (!name_regex) return fail(name_regex.error());
    root.name_regex = std::move(*name_regex);
    if (!root.name_regex.empty()) {
        auto compiled = compile_regex(root.name_regex, "name_regex", where);
        if (!compiled) return fail(compiled.error());
        root.name_pattern = std::move(*compiled);
    }

    auto dir_regex = optional_string(value, "dir_regex", kMaxRegexBytes, where);
    if (!dir_regex) return fail(dir_regex.error());
    root.dir_regex = std::move(*dir_regex);
    if (!root.dir_regex.empty()) {
        auto compiled = compile_regex(root.dir_regex, "dir_regex", where);
        if (!compiled) return fail(compiled.error());
        root.dir_pattern = std::move(*compiled);
    }

    if (value.contains("max_depth") && !value.at("max_depth").is_null()) {
        const json& depth_value = value.at("max_depth");
        if (!depth_value.is_number_integer()) {
            return fail(ErrorCode::InvalidArgument,
                        where + ": max_depth must be an integer");
        }
        int64_t depth = 0;
        if (depth_value.is_number_unsigned()) {
            const uint64_t raw = depth_value.get<uint64_t>();
            if (raw > 64) {
                return fail(ErrorCode::InvalidArgument, where + ": max_depth must be 1..64");
            }
            depth = static_cast<int64_t>(raw);
        } else {
            depth = depth_value.get<int64_t>();
        }
        if (depth < 1 || depth > 64) {
            return fail(ErrorCode::InvalidArgument, where + ": max_depth must be 1..64");
        }
        root.max_depth = static_cast<int>(depth);
    }

    auto comment = optional_string(value, "comment", 4096, where);
    if (!comment) return fail(comment.error());
    return root;
}

}  // namespace

const char* android_root_kind_name(AndroidRootKind kind) noexcept {
    switch (kind) {
        case AndroidRootKind::Thumbnail: return "thumbnail";
        case AndroidRootKind::Trash: return "trash";
        case AndroidRootKind::Cache: return "cache";
    }
    return "unknown";
}

std::optional<AndroidRootKind> android_root_kind_from_string(std::string_view name) noexcept {
    if (name == "thumbnail") return AndroidRootKind::Thumbnail;
    if (name == "trash") return AndroidRootKind::Trash;
    if (name == "cache") return AndroidRootKind::Cache;
    return std::nullopt;
}

Result<AndroidScanProfile> parse_scan_profile(std::string_view text, std::string_view source_name) {
    const std::string source(source_name);
    if (text.size() > kMaxProfileBytes) {
        return fail(ErrorCode::InvalidArgument, source + ": profile exceeds 1 MiB");
    }
    json document = json::parse(text.begin(), text.end(), nullptr, false);
    if (document.is_discarded()) {
        return fail(ErrorCode::InvalidArgument, source + ": profile is not valid JSON");
    }
    if (!document.is_object()) {
        return fail(ErrorCode::InvalidArgument, source + ": profile must be a JSON object");
    }
    auto unknown = reject_unknown_fields(document,
                                         {"schema", "name", "comment", "roots", "type_filter",
                                          "max_file_size"},
                                         source);
    if (!unknown) return fail(unknown.error());

    AndroidScanProfile profile;
    if (!document.contains("schema") || !document.at("schema").is_number_integer() ||
        document.at("schema") != 1) {
        return fail(ErrorCode::InvalidArgument, source + ": schema must be 1");
    }
    auto name = required_string(document, "name", source, 128);
    if (!name) return fail(name.error());
    profile.name = std::move(*name);

    auto comment = optional_string(document, "comment", 8192, source);
    if (!comment) return fail(comment.error());

    if (!document.contains("roots") || !document.at("roots").is_array()) {
        return fail(ErrorCode::InvalidArgument, source + ": roots must be an array");
    }
    const json& roots = document.at("roots");
    if (roots.empty() || roots.size() > kMaxRoots) {
        return fail(ErrorCode::InvalidArgument,
                    source + ": roots must contain 1.." + std::to_string(kMaxRoots) +
                        " entries");
    }
    std::set<std::string> ids;
    for (size_t i = 0; i < roots.size(); ++i) {
        auto root = parse_root(roots.at(i), i, source);
        if (!root) return fail(root.error());
        if (!ids.insert(root->id).second) {
            return fail(ErrorCode::InvalidArgument,
                        source + ": duplicate root id '" + root->id + "'");
        }
        profile.roots.push_back(std::move(*root));
    }

    if (document.contains("type_filter") && !document.at("type_filter").is_null()) {
        if (!document.at("type_filter").is_array() ||
            document.at("type_filter").size() > 64) {
            return fail(ErrorCode::InvalidArgument,
                        source + ": type_filter must be an array of at most 64 extensions");
        }
        for (const json& entry : document.at("type_filter")) {
            if (!entry.is_string()) {
                return fail(ErrorCode::InvalidArgument,
                            source + ": type_filter entries must be strings");
            }
            std::string extension = lower_ascii(entry.get<std::string>());
            if (extension.empty() || extension.size() > 16 ||
                !std::all_of(extension.begin(), extension.end(), [](char c) {
                    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
                })) {
                return fail(ErrorCode::InvalidArgument,
                            source + ": invalid type_filter entry '" + extension + "'");
            }
            if (std::find(profile.type_filter.begin(), profile.type_filter.end(), extension) ==
                profile.type_filter.end()) {
                profile.type_filter.push_back(std::move(extension));
            }
        }
    }

    if (document.contains("max_file_size") && !document.at("max_file_size").is_null()) {
        const json& value = document.at("max_file_size");
        uint64_t limit = 0;
        if (value.is_number_unsigned()) {
            limit = value.get<uint64_t>();
        } else if (value.is_number_integer() && value.get<int64_t>() >= 0) {
            limit = static_cast<uint64_t>(value.get<int64_t>());
        } else {
            return fail(ErrorCode::InvalidArgument,
                        source + ": max_file_size must be a non-negative integer");
        }
        if (limit == 0) {
            return fail(ErrorCode::InvalidArgument, source + ": max_file_size must be positive");
        }
        profile.max_file_size = limit;
    }

    return profile;
}

Result<AndroidScanProfile> load_scan_profile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return fail(ErrorCode::NotFound, "cannot open profile: " + path_to_utf8(path));
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (in.bad()) return fail(ErrorCode::IoError, "cannot read profile: " + path_to_utf8(path));
    if (text.size() > kMaxProfileBytes) {
        return fail(ErrorCode::InvalidArgument, path_to_utf8(path) + ": profile exceeds 1 MiB");
    }
    return parse_scan_profile(text, path_to_utf8(path));
}

std::optional<TrashedName> parse_trashed_name(std::string_view filename) {
    constexpr std::string_view kPrefix = ".trashed-";
    if (filename.size() <= kPrefix.size() || filename.substr(0, kPrefix.size()) != kPrefix) {
        return std::nullopt;
    }
    const std::string_view rest = filename.substr(kPrefix.size());
    const size_t dash = rest.find('-');
    if (dash == std::string_view::npos || dash == 0 || dash + 1 >= rest.size()) {
        return std::nullopt;
    }
    const std::string_view digits = rest.substr(0, dash);
    if (digits.size() > 20) return std::nullopt;
    uint64_t expiry = 0;
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), expiry);
    if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) {
        return std::nullopt;
    }
    TrashedName result;
    result.expires_at = expiry;
    result.original_name = std::string(rest.substr(dash + 1));
    return result;
}

}  // namespace openrecover::android
