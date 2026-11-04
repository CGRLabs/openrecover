#include "openrecover/fs/ntfs_recyclebin.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/fs/ntfs_attributes.hpp"

namespace openrecover::fs {

namespace {

// Version, size and deletion FILETIME, eight bytes each.
constexpr size_t kHeaderBytes = 24;
constexpr size_t kVersion2LengthBytes = 4;
// A Windows path is 260 wide characters at most; a record claiming far more is not one to trust.
constexpr uint32_t kMaxPathUnits = 1024;

Result<RecycleBinInfo> info_error(const std::string& message) {
    return fail(ErrorCode::CorruptStructure, "invalid $I record: " + message);
}

char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

bool starts_with_ci(std::string_view text, std::string_view prefix) noexcept {
    if (text.size() < prefix.size()) return false;
    return std::equal(prefix.begin(), prefix.end(), text.begin(),
                      [](char a, char b) { return ascii_lower(a) == ascii_lower(b); });
}

// Decodes UTF-16LE up to the first end-of-string code unit.
std::string decode_path(std::span<const uint8_t> bytes) {
    size_t used = 0;
    while (used + 1 < bytes.size() && (bytes[used] != 0 || bytes[used + 1] != 0)) used += 2;
    return utf16le_to_utf8(bytes.first(used));
}

// The lowercase suffix an `$I`/`$R` pair shares: "2abc3.txt" for "$I2ABC3.txt". Windows gives both
// halves the same random suffix and keeps the extension, so the suffix is the only reliable link.
std::optional<std::string> pair_key(std::string_view component) {
    if (component.size() < 3 || component[0] != '$') return std::nullopt;
    const char kind = ascii_lower(component[1]);
    if (kind != 'i' && kind != 'r') return std::nullopt;
    std::string key;
    key.reserve(component.size() - 2);
    for (size_t i = 2; i < component.size(); ++i) key.push_back(ascii_lower(component[i]));
    return key;
}

bool lives_in_recycle_bin(std::string_view path) noexcept {
    const size_t end = path.find('/');
    return starts_with_ci(path.substr(0, end), "$Recycle.Bin");
}

// Puts a recorded Windows path into the library's '/'-separated, root-relative form. A drive
// letter names the mount rather than a place inside the volume, and a path that walks out of its
// own directory with ".." cannot be placed anywhere, so both are dropped.
std::optional<std::string> usable_path(std::string_view raw) {
    if (raw.empty() || raw[0] == '\\') return std::nullopt;
    const bool drive_prefixed = raw.size() >= 2 && raw[1] == ':' &&
                                ((raw[0] >= 'A' && raw[0] <= 'Z') || (raw[0] >= 'a' && raw[0] <= 'z'));
    if (drive_prefixed) raw.remove_prefix(2);

    std::string out;
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t end = raw.find_first_of("\\/", pos);
        if (end == std::string_view::npos) end = raw.size();
        const std::string_view component = raw.substr(pos, end - pos);
        pos = end + 1;
        if (component.empty() || component == ".") continue;
        if (component == "..") return std::nullopt;
        if (!out.empty()) out.push_back('/');
        out += sanitize_component(std::string(component));
    }
    if (out.empty()) return std::nullopt;
    return out;
}

void note_addition(RecoveredFile& file, std::string_view addition) {
    if (!file.note.empty()) file.note += "; ";
    file.note += addition;
}

}  // namespace

Result<RecycleBinInfo> parse_recycle_info(std::span<const uint8_t> content) {
    if (content.size() < kHeaderBytes) return info_error("the header is truncated");
    const ByteView view(content);

    const uint64_t version = view.u64le(0);
    if (version != 1 && version != 2)
        return fail(ErrorCode::Unsupported,
                    "unsupported $I record version " + std::to_string(version));

    RecycleBinInfo info;
    info.format_version = static_cast<uint32_t>(version);
    info.declared_size = view.u64le(8);
    // A zero FILETIME means the producer never set the time, so it is the 1601 epoch rather than
    // a deletion date; reporting it as one would put the file 370 years in the past.
    const uint64_t deletion_ticks = view.u64le(16);
    if (deletion_ticks != 0) info.deleted_unix = filetime_to_unix(deletion_ticks);

    std::span<const uint8_t> path_bytes;
    if (version == 1) {
        // Version 1 stores the path inline, padded with end-of-string characters.
        path_bytes = content.subspan(kHeaderBytes);
        if (path_bytes.size() > kMaxPathUnits * 2) path_bytes = path_bytes.first(kMaxPathUnits * 2);
    } else {
        // Version 2 says how many characters it wrote, end-of-string character included.
        constexpr size_t kPathOffset = kHeaderBytes + kVersion2LengthBytes;
        if (content.size() < kPathOffset) return info_error("the recorded path length is truncated");
        const uint32_t units = view.u32le(kHeaderBytes);
        if (units == 0) return info_error("the recorded path has no characters");
        if (units > kMaxPathUnits) return info_error("the recorded path is too long");
        const size_t bytes = static_cast<size_t>(units) * 2;
        if (bytes > content.size() - kPathOffset) return info_error("the recorded path is truncated");
        path_bytes = content.subspan(kPathOffset, bytes);
    }

    info.original_path = decode_path(path_bytes);
    if (info.original_path.empty()) return info_error("the recorded path is empty");
    return info;
}

void apply_recycle_bin_metadata(std::vector<RecoveredFile>& files) {
    std::unordered_map<std::string, size_t> records;
    std::vector<size_t> data_entries;
    for (size_t index = 0; index < files.size(); ++index) {
        const RecoveredFile& file = files[index];
        if (!lives_in_recycle_bin(file.path)) continue;
        const std::optional<std::string> key = pair_key(file.name);
        if (!key) continue;
        if (starts_with_ci(file.name, "$I")) {
            records.try_emplace(*key, index);
        } else {
            data_entries.push_back(index);
        }
    }

    for (const size_t index : data_entries) {
        const std::optional<std::string> key = pair_key(files[index].name);
        const auto record = records.find(*key);
        if (record == records.end()) continue;
        const RecoveredFile& source = files[record->second];
        if (!source.resident_data) continue;
        auto info = parse_recycle_info(*source.resident_data);
        if (!info) continue;

        RecoveredFile& file = files[index];
        file.deleted_unix = info->deleted_unix;
        const std::optional<std::string> path = usable_path(info->original_path);
        if (path) {
            file.path = *path;
            const size_t tail = path->rfind('/');
            file.name = tail == std::string::npos ? *path : path->substr(tail + 1);
            file.flags |= file_flags::OriginalPathRestored;
            note_addition(file, "original path restored from $Recycle.Bin metadata");
        } else {
            note_addition(file, "deletion time from $Recycle.Bin metadata");
        }
        if (info->declared_size != file.size_bytes) {
            // The size the record carries is the size of the file it was made for, so a mismatch
            // says the metadata and the data may not belong to each other after all.
            file.flags |= file_flags::PathUncertain;
            note_addition(file, "$I records " + std::to_string(info->declared_size) +
                                    " bytes, recovered " + std::to_string(file.size_bytes));
        }
    }
}

}  // namespace openrecover::fs
