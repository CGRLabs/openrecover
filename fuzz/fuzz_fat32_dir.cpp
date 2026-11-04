#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "fuzz_common.hpp"
#include "openrecover/fs/fat32.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace openrecover;
    fuzz::silence_logs();
    const std::span<const uint8_t> bytes(data, size);
    std::vector<fs::FatLfnEntry> lfn;
    fs::FatShortEntry last_short;
    bool have_short = false;

    for (size_t off = 0; off + 32 <= size; off += 32) {
        const std::span<const uint8_t> raw = bytes.subspan(off, 32);
        const fs::FatShortEntry entry = fs::decode_short_entry(raw);
        if (entry.is_lfn()) {
            lfn.push_back(fs::decode_lfn_entry(raw));
            continue;
        }
        last_short = entry;
        have_short = true;
        (void)fs::decode_short_name(entry);
        (void)fs::decode_short_name(entry, true);
        (void)fs::fat_datetime_to_unix(entry.wrt_date, entry.wrt_time);
        (void)fs::fat_datetime_to_unix(entry.crt_date, entry.crt_time);
        (void)fs::short_name_checksum(entry.name);
    }

    if (have_short) {
        (void)fs::assemble_lfn(lfn, last_short.name, last_short.deleted);
        (void)fs::assemble_lfn(lfn, last_short.name, true);
    }
    return 0;
}
