#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/io/block_device.hpp"

#include "openrecover/fs/exfat/exfat_boot.hpp"

namespace openrecover::fs {

Result<std::vector<uint32_t>> read_exfat_chain(io::BlockDevice& dev,
                                               const ExfatBoot& boot,
                                               uint32_t first_cluster);

bool exfat_chain_contiguous(const std::vector<uint32_t>& chain);

}  // namespace openrecover::fs