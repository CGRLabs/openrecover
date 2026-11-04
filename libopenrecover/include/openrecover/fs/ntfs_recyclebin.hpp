#pragma once

#include <optional>
#include <span>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"

namespace openrecover::fs {

// What one $Recycle.Bin `$I` file records about the file it moved there. Windows writes the
// record next to the data copy (`$R<same suffix>`) and both are deleted together when the bin
// is emptied, so a soft-deleted file usually still carries its original path.
struct RecycleBinInfo {
    // Verbatim recorded path, still in Windows form (`C:\dir\file.txt`).
    std::string original_path;
    // Size the original file had when it was deleted.
    uint64_t declared_size = 0;
    // Deletion time, absent when the record holds a zero FILETIME (recorded but never set).
    std::optional<int64_t> deleted_unix;
    // 1 for the Vista..8 layout, 2 for the Windows 10+ layout.
    uint32_t format_version = 0;
};

// Parses the resident `$DATA` of a `$I` file. Unknown versions and records whose path does not
// fit are errors, not guesses; the caller then leaves the paired file where the MFT puts it.
Result<RecycleBinInfo> parse_recycle_info(std::span<const uint8_t> content);

// Rewrites the entries of a scan that came from `$Recycle.Bin` with the path and deletion time
// their `$I` sibling recorded. Files with no readable sibling are left alone.
void apply_recycle_bin_metadata(std::vector<RecoveredFile>& files);

}  // namespace openrecover::fs
