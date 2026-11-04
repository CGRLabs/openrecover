#pragma once

#include <memory>

#include "openrecover/io/block_device.hpp"

namespace openrecover::io {

// Presents a VHDX container as a read-only BlockDevice of the virtual disk. The file
// identifier, both headers, both region tables and the metadata region are validated;
// blocks that VHDX marks not-present, undefined or zero, and sectors a partly-present
// block does not cover, read back as zeros. Differencing disks report Unsupported
// because they need the parent chain.
Result<std::unique_ptr<BlockDevice>> open_vhdx(std::shared_ptr<BlockDevice> container);

}  // namespace openrecover::io
