#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "openrecover/carve/signature.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/output_sink.hpp"

namespace openrecover::carve {

struct CarveOptions {
    enum class Scope { UnallocatedOnly, All };

    Scope scope = Scope::UnallocatedOnly;
    bool unaligned = false;
    uint32_t alignment = 0;  // 0 -> cluster size when known, else logical sector size
    bool nested = false;
    bool deep_validate = false;
    // A run that stops at a discontinuity (junk between the file's fragments) may be joined to
    // the pieces the format recognises beyond the gap, up to the format's own terminator. Off by
    // default in the library so callers opt in; the CLI enables it.
    bool reassemble = false;
    // How far past the last byte attributed to the file the search may resume when joining
    // pieces; also the most a single resumed run may contribute before it must end at a marker.
    uint64_t max_reassembly_gap = 8ull << 20;
    std::set<std::string> types;  // empty = all registered
    uint64_t start_byte = 0;
    uint64_t end_byte = UINT64_MAX;
    Confidence min_confidence = Confidence::Low;

    // Optional metadata-recovery results used to mark carved duplicates.
    const std::vector<RecoveredFile>* existing_files = nullptr;
};

// One device run of a recovered file. A contiguous hit has a single fragment covering
// [offset, offset + length); a reassembled hit has several, in file order.
struct CarveFragment {
    uint64_t offset = 0;
    uint64_t length = 0;
};

struct CarveHit {
    uint64_t offset = 0;
    uint64_t length = 0;  // logical file length: the sum of the fragment lengths
    std::string type;
    std::string subtype;
    Confidence confidence = Confidence::Low;
    uint32_t flags = 0;  // Truncated when the run ends without its terminator; Fragmented when reassembled
    std::string sha256;
    std::string duplicate_of;  // FS-recovered path, empty when not a duplicate
    // Empty when the file is one contiguous run.
    std::vector<CarveFragment> fragments;
};

class CarveEngine {
public:
    static Result<std::vector<CarveHit>> run(io::BlockDevice& device,
                                             const fs::IAllocationMap* allocation,
                                             const CarveOptions& options, ProgressFn progress);

    static Result<std::vector<CarveHit>> run(io::BlockDevice& device,
                                             const fs::IAllocationMap* allocation,
                                             const CarveOptions& options, ProgressFn progress,
                                             const SignatureRegistry& registry);
};

// Writes each non-duplicate hit to carved/<type>/<offset16>_<len>.<ext>.
Result<std::vector<io::WrittenFile>> export_hits(io::OutputSink& sink, io::BlockDevice& device,
                                                 const std::vector<CarveHit>& hits,
                                                 bool skip_duplicates = true);

}  // namespace openrecover::carve
