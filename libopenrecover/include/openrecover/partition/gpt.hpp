#pragma once

#include <vector>

#include "openrecover/partition/partition_scanner.hpp"

namespace openrecover::partition {

// Parses the primary GPT; if it is unusable, parses the backup header at the last LBA.
// Both entry arrays are CRC-checked. Returns an error only when neither copy is valid.
Result<std::vector<PartitionInfo>> parse_gpt(io::BlockDevice& dev);

}  // namespace openrecover::partition
