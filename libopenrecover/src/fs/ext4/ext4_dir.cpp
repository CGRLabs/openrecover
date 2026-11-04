#include "openrecover/fs/ext4/ext4_dir.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "openrecover/common/result.hpp"

namespace openrecover::fs {
namespace {

namespace lay = ext4_layout;

size_t rounded(size_t name_len) {
    return (name_len + lay::kDirRound) & ~static_cast<size_t>(lay::kDirRound);
}

bool is_link_marker(std::span<const uint8_t> name) {
    if (name.empty() || name[0] != '.') return false;
    for (uint8_t c : name.subspan(1))
        if (c != '.') return false;
    return name.size() <= 2;  // "." and ".." only; "..." is a checksum pseudo-entry
}

// The kernel's `empty_dir`: a zero-length record ends the block only when every byte
// from there to the end is zero. Anything else is not a record at all.
bool unused_tail(std::span<const uint8_t> block, size_t off) {
    for (size_t i = off; i < block.size(); ++i)
        if (block[i] != 0) return false;
    return true;
}

}  // namespace

Result<Ext4DirBlock> parse_ext4_dir_block(std::span<const uint8_t> block, const Ext4Super& s) {
    if (s.block_size < lay::kDirEntryHeaderBytes)
        return fail(ErrorCode::CorruptStructure, "ext4: block size cannot hold a directory entry");
    Ext4DirBlock out;
    if (block.size() < lay::kDirEntryHeaderBytes) return out;

    size_t off = 0;
    while (off + lay::kDirEntryHeaderBytes <= block.size()) {
        const uint16_t rec_len = u16_at(block, off + lay::kDirEntryRecLen);
        const uint8_t file_type = block[off + lay::kDirEntryFileType];

        // A checksum pseudo-entry holds no name; it takes the length it claims for itself.
        if (file_type == ext4_file_type::kDirCsum) {
            if (rec_len < lay::kDirEntryHeaderBytes ||
                static_cast<size_t>(rec_len) > block.size() - off) {
                out.truncated = true;
                break;
            }
            off += rec_len;
            continue;
        }
        // A record that claims a length the block cannot hold ends the walk: everything
        // after it is unconstrained bytes.
        if (rec_len == 0) {
            if (!unused_tail(block, off)) out.truncated = true;
            break;
        }
        if (rec_len < lay::kDirEntryHeaderBytes ||
            static_cast<size_t>(rec_len) > block.size() - off) {
            out.truncated = true;
            break;
        }

        // The record at `off` owns `rec_len` bytes, and an unlink() folds a removed
        // record's length into the record before it. Following rec_len alone would step over
        // exactly the entries a recovery scan exists to find, so the bytes the record claims
        // are walked again at the width of each name in turn.
        const size_t end = off + rec_len;
        size_t pos = off;
        while (pos + lay::kDirEntryHeaderBytes <= end) {
            const uint32_t slot_ino = u32_at(block, pos + lay::kDirEntryInode);
            const uint8_t name_len = block[pos + lay::kDirEntryNameLen];
            const uint8_t slot_type = block[pos + lay::kDirEntryFileType];
            if (name_len == 0 || slot_type == ext4_file_type::kDirCsum) break;  // padding
            const size_t own = lay::kDirEntryHeaderBytes + rounded(name_len);
            if (own > end - pos) break;  // the name does not fit the space the block offers
            // A record hidden in the slack of a longer one still carries the length it was
            // written with. One that claims less than its own name is stale bytes from some
            // earlier entry, not a deletion.
            if (pos != off && u16_at(block, pos + lay::kDirEntryRecLen) < own) break;

            std::span<const uint8_t> raw(block.data() + pos + lay::kDirEntryNameOffset, name_len);
            if (!is_link_marker(raw)) {
                Ext4DirEntry entry;
                entry.inode = slot_ino;
                entry.file_type = slot_type;
                entry.deleted = slot_ino == 0;
                size_t stop = 0;
                while (stop < name_len && raw[stop] != 0) ++stop;  // a name never legally holds NUL
                entry.name.assign(reinterpret_cast<const char*>(raw.data()), stop);
                out.entries.push_back(std::move(entry));
            }
            pos += own;
        }
        off = end;
    }
    return out;
}

}  // namespace openrecover::fs
