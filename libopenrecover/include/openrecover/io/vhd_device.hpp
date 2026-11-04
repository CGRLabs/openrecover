#pragma once

#include <memory>

#include "openrecover/io/block_device.hpp"

namespace openrecover::io {

// Presents a fixed or dynamic VHD container as a read-only BlockDevice of the
// virtual disk. Unallocated dynamic blocks and sectors read back as zeros.
// Differencing VHDs report Unsupported because they need the parent chain.
Result<std::unique_ptr<BlockDevice>> open_vhd(std::shared_ptr<BlockDevice> container);

}  // namespace openrecover::io
