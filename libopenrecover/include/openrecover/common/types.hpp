#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace openrecover {

// Progress callback for long operations. Returning false requests cancellation.
using ProgressFn = std::function<bool(uint64_t done, uint64_t total)>;

enum class Confidence { High, Medium, Low };
enum class FileOrigin { FilesystemMetadata, Carved, AndroidPull };

struct Extent {
    uint64_t offset_bytes;
    uint64_t length_bytes;
    bool sparse;
};

namespace file_flags {
inline constexpr uint32_t PathUncertain = 1;
inline constexpr uint32_t Truncated = 2;
inline constexpr uint32_t ClustersReallocated = 4;
inline constexpr uint32_t NameFirstCharGuessed = 8;
inline constexpr uint32_t Fragmented = 16;
inline constexpr uint32_t Unsupported = 32;
// The path and deletion time came from $Recycle.Bin metadata rather than the directory tree.
inline constexpr uint32_t OriginalPathRestored = 64;
}  // namespace file_flags

struct RecoveredFile {
    std::string path;
    std::string name;
    uint64_t size_bytes = 0;
    std::vector<Extent> extents;
    std::optional<std::vector<uint8_t>> resident_data;
    std::optional<int64_t> mtime_unix, ctime_unix, atime_unix;
    // When the file was deleted, as recorded out-of-band ($Recycle.Bin metadata).
    std::optional<int64_t> deleted_unix;
    FileOrigin origin = FileOrigin::FilesystemMetadata;
    Confidence confidence = Confidence::Low;
    uint32_t flags = 0;
    std::string note;
    std::string type_hint;
};

const char* confidence_name(Confidence c) noexcept;
const char* origin_name(FileOrigin o) noexcept;
std::vector<std::string> flag_names(uint32_t flags);

// Lower value = better; Low is the weakest.
inline int confidence_rank(Confidence c) noexcept { return static_cast<int>(c); }
inline bool meets_confidence(Confidence actual, Confidence minimum) noexcept {
    return confidence_rank(actual) <= confidence_rank(minimum);
}

}  // namespace openrecover
