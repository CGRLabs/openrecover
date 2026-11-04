#pragma once

#include <filesystem>
#include <memory>
#include <string>

#include "openrecover/io/block_device.hpp"

namespace openrecover::io {

// Flat raw image (.dd/.img/.raw/.bin or any regular file). Thin factory over the platform device.
Result<std::unique_ptr<BlockDevice>> open_image_raw(const std::filesystem::path& path, const OpenOptions& opts);

// Reads the file as flat bytes with no container-format classification. Container openers
// call this so that they never re-enter their own detection.
Result<std::unique_ptr<BlockDevice>> open_image_flat(const std::filesystem::path& path, const OpenOptions& opts);

}  // namespace openrecover::io
