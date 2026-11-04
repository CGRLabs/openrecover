#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/fs/ext4/ext4_boot.hpp"

namespace openrecover::fs {

// One directory record. A deleted unlink() leaves the name in place and zeroes only the
// inode field, so `deleted` records carry a name and no inode number -- which is why the
// scanner pairs them with deleted inodes by timestamp instead of by number.
struct Ext4DirEntry {
    uint32_t inode = 0;      // 0 when the entry was deleted
    uint8_t file_type = 0;   // ext4_file_type value; only trustworthy with INCOMPAT_FILETYPE
    std::string name;
    bool deleted = false;

    bool type_is_directory() const noexcept {
        return file_type == ext4_file_type::kDirectory;
    }
};

struct Ext4DirBlock {
    std::vector<Ext4DirEntry> entries;
    // Some prefix of the block could not be walked as records. The entries found before
    // that point are still reported; a caller uses this to note uncertainty.
    bool truncated = false;
};

// Decodes one directory block.
//
// The block is walked record by record, and each record's bytes are then walked again at
// the width of the names inside them: unlink() folds a removed entry's length into the
// entry before it, so the deleted names live in the slack of a live record that rec_len
// alone would step straight over.
//
// Nothing here rejects a block on checksum grounds. On a metadata_csum volume a directory
// block's checksum changes when an entry is deleted, so a block whose checksum no longer
// matches is the normal case, not a corrupt one.
Result<Ext4DirBlock> parse_ext4_dir_block(std::span<const uint8_t> block, const Ext4Super& s);

}  // namespace openrecover::fs
