#pragma once

#include "openrecover/fs/ext4/ext4_boot.hpp"

namespace openrecover::fuzz {

// The geometry of the committed ext4 fixture, so those parsers that need a superblock get
// one a real mkfs would have written instead of bytes rejected at the door. Turning on
// `with_csum` switches every consumer onto the metadata_csum code path, which is a
// different branch in the superblock, the directory walk and the inode checksum.
inline fs::Ext4Super ext4_super(bool with_csum = false) {
    fs::Ext4Super s;
    s.inodes_count = 32;
    s.blocks_count = 256;
    s.log_block_size = 0;
    s.block_size = 1024;
    s.blocks_per_group = 128;
    s.inodes_per_group = 16;
    s.first_data_block = 0;
    s.rev_level = 1;
    s.inode_size = 256;
    s.first_ino = 11;
    s.desc_size = 32;
    s.creator_os = fs::ext4_layout::kOsLinux;
    s.feature_incompat = fs::ext4_feature::kIncompatFiletype | fs::ext4_feature::kIncompatExtents;
    if (with_csum) {
        s.feature_incompat |= fs::ext4_feature::kIncompatCsumSeed;
        s.feature_ro_compat |= fs::ext4_feature::kRoCompatMetadataCsum;
        s.checksum_seed = 0xC0FFEE01u;
    }
    return s;
}

}  // namespace openrecover::fuzz
