#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "fuzz_common.hpp"
#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/signature.hpp"

namespace openrecover::fuzz {

// Runs one validator over a read-only memory device. The first input byte selects
// shallow or deep validation so both paths are reachable from the same corpus. A
// truncated verdict also drives the continuation hook, because that is the other way a
// signature reads input.
inline void run_signature(const carve::ISignature& signature, const uint8_t* data, size_t size) {
    silence_logs();
    std::vector<uint8_t> copy;
    if (size != 0) copy.assign(data, data + size);
    test::MemoryDevice device(copy);
    const bool deep = size != 0 && (data[0] & 1) != 0;
    carve::BoundedReader reader(device, 0, size);
    reader.set_deep_validate(deep);
    const carve::ValidationResult result = signature.validate(reader);
    if (result.verdict != carve::ValidationResult::Verdict::ValidTruncated) return;
    // Walk the chain the engine would walk from the cut, bounded so a corpus of marker
    // spam cannot turn one input into unbounded work. The cut sits on the marker that
    // stopped validation, so the walk starts just past it, as the engine's first
    // allocation-unit boundary would.
    uint64_t at = std::min<uint64_t>(result.length_bytes + 2, size);
    for (int hop = 0; hop < 8 && at < size; ++hop) {
        carve::BoundedReader tail(device, at, size - at);
        tail.set_deep_validate(deep);
        const auto continuation = signature.find_continuation(tail);
        if (!continuation || continuation->length == 0) return;
        at += continuation->start + continuation->length;
        if (continuation->complete) return;
        at += 2;  // the marker that cut the run, as the first boundary past it
    }
}

}  // namespace openrecover::fuzz
