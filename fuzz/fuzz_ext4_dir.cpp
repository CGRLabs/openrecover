#include <cstddef>
#include <cstdint>
#include <span>

#include "fuzz_common.hpp"
#include "fuzz_ext4_common.hpp"
#include "openrecover/fs/ext4/ext4_dir.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace openrecover;
    fuzz::silence_logs();
    const std::span<const uint8_t> bytes(data, size);
    const fs::Ext4Super plain = fuzz::ext4_super(false);
    const fs::Ext4Super csum = fuzz::ext4_super(true);

    // Both spellings of a directory block: one where every record stands alone, and one
    // with the checksum pseudo-entry and its skipped field.
    for (const fs::Ext4Super* s : {&plain, &csum}) {
        auto listing = fs::parse_ext4_dir_block(bytes, *s);
        if (!listing) continue;
        for (const fs::Ext4DirEntry& entry : listing->entries) {
            (void)entry.deleted;
            (void)entry.type_is_directory();
        }
    }
    return 0;
}
