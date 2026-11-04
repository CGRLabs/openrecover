#include "openrecover/fs/ntfs_runlist.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "openrecover/common/bytes.hpp"

namespace openrecover::fs {

namespace {

Result<std::vector<DataRun>> runlist_error(const std::string& message) {
    return fail(ErrorCode::CorruptStructure, "invalid NTFS runlist: " + message);
}

}  // namespace

Result<std::vector<DataRun>> decode_runlist(std::span<const uint8_t> bytes, uint64_t start_vcn,
                                            uint64_t total_clusters) {
    std::vector<DataRun> runs;
    ByteView view(bytes);
    size_t pos = 0;
    uint64_t vcn = start_vcn;
    int64_t previous_lcn = 0;

    while (pos < bytes.size()) {
        const uint8_t header = view.u8(pos++);
        if (view.failed()) return runlist_error("truncated run header");
        if (header == 0) break;

        const size_t length_size = header & 0x0F;
        const size_t offset_size = header >> 4;
        if (length_size == 0) return runlist_error("run length field is empty");
        if (length_size > 8) return runlist_error("run length field is wider than 8 bytes");
        if (offset_size > 8) return runlist_error("run offset field is wider than 8 bytes");
        if (!view.has(pos, length_size + offset_size)) return runlist_error("truncated run body");

        const uint64_t length = view.uint_le(pos, length_size);
        pos += length_size;
        if (view.failed()) return runlist_error("truncated run length");
        if (length == 0) return runlist_error("zero-length run");

        uint64_t next_vcn = 0;
        if (!checked_add<uint64_t>(vcn, length, next_vcn))
            return runlist_error("virtual cluster number overflow");

        DataRun run;
        run.vcn = vcn;
        run.length_clusters = length;
        if (offset_size == 0) {
            run.lcn = -1;
        } else {
            const int64_t delta = view.sint_le(pos, offset_size);
            pos += offset_size;
            if (view.failed()) return runlist_error("truncated run offset");

            if ((delta > 0 && previous_lcn > std::numeric_limits<int64_t>::max() - delta) ||
                (delta < 0 && previous_lcn < std::numeric_limits<int64_t>::min() - delta))
                return runlist_error("logical cluster number overflow");
            const int64_t lcn = previous_lcn + delta;
            if (lcn < 0) return runlist_error("negative logical cluster number");
            const uint64_t unsigned_lcn = static_cast<uint64_t>(lcn);
            uint64_t run_end = 0;
            if (!checked_add<uint64_t>(unsigned_lcn, length, run_end) || run_end > total_clusters)
                return runlist_error("run extends beyond the volume");
            run.lcn = lcn;
            previous_lcn = lcn;
        }
        runs.push_back(run);
        vcn = next_vcn;
    }

    return runs;
}

}  // namespace openrecover::fs
