#pragma once

#include <cstdint>

namespace openrecover::fs {

// Cluster allocation state used by the carving engine to restrict itself to free space.
class IAllocationMap {
public:
    virtual ~IAllocationMap() = default;
    virtual bool is_cluster_allocated(uint64_t cluster) const = 0;
    virtual uint64_t cluster_to_byte_offset(uint64_t cluster) const = 0;
    virtual uint64_t cluster_count() const = 0;
    // Optional chain hint for reassembly (v1.2): returns the next cluster in a
    // run, or 0 when the run ends / the map does not provide chain info.
    virtual uint64_t next_cluster(uint64_t /*cluster*/) const { return 0; }
};

}  // namespace openrecover::fs
