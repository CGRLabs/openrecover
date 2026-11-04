#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "openrecover/common/result.hpp"

namespace openrecover::fs {

struct DataRun {
    uint64_t vcn = 0;
    int64_t lcn = -1;  // -1 marks a sparse run
    uint64_t length_clusters = 0;

    bool is_sparse() const noexcept { return lcn < 0; }
};

// Decodes an NTFS data runlist. `bytes` starts at RunlistOffset and ends at the
// attribute boundary. Runs are validated against `total_clusters`; `start_vcn`
// is the starting VCN from the attribute header.
Result<std::vector<DataRun>> decode_runlist(std::span<const uint8_t> bytes, uint64_t start_vcn,
                                            uint64_t total_clusters);

}  // namespace openrecover::fs
