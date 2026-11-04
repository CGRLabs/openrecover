#include "openrecover/fs/exfat/exfat_fat.hpp"

#include <array>
#include <cstdint>
#include <unordered_set>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/io/block_device.hpp"

namespace openrecover::fs {

Result<std::vector<uint32_t>> read_exfat_chain(io::BlockDevice& dev,
                                               const ExfatBoot& boot,
                                               uint32_t first_cluster) {
    if (first_cluster < 2) return fail(ErrorCode::InvalidArgument, "exFAT first cluster must be >= 2");
    if (first_cluster >= 2 + boot.cluster_count)
        return fail(ErrorCode::InvalidArgument, "exFAT first cluster out of range");

    constexpr size_t kMaxChainClusters = size_t{1} << 24;
    std::vector<uint32_t> chain;
    chain.reserve(64);
    std::unordered_set<uint32_t> seen;
    seen.reserve(64);

    uint32_t cur = first_cluster;
    while (true) {
        if (cur < 2 || static_cast<uint64_t>(cur) >= static_cast<uint64_t>(boot.cluster_count) + 2)
            return fail(ErrorCode::CorruptStructure, "exFAT FAT entry out of range");
        if (!seen.insert(cur).second)
            return fail(ErrorCode::CorruptStructure, "exFAT FAT chain loop");
        chain.push_back(cur);
        if (chain.size() > kMaxChainClusters)
            return fail(ErrorCode::CorruptStructure, "exFAT FAT chain is too long");

        const uint64_t fat_byte = boot.fat_byte_offset() + static_cast<uint64_t>(cur) * 4;
        std::array<uint8_t, 4> buf{};
        auto got = io::read_fully(dev, fat_byte, buf.data(), buf.size());
        if (!got || *got < buf.size())
            return fail(ErrorCode::IoError, "exFAT FAT read failed");
        const uint32_t next = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);

        if (next == 0xFFFFFFFFu) break;
        if (next == 0) return fail(ErrorCode::CorruptStructure, "exFAT FAT entry is free mid-chain");
        if (next < 2) return fail(ErrorCode::CorruptStructure, "exFAT FAT entry invalid");
        cur = next;
    }
    return chain;
}

bool exfat_chain_contiguous(const std::vector<uint32_t>& chain) {
    for (size_t i = 1; i < chain.size(); ++i)
        if (chain[i] != chain[i - 1] + 1) return false;
    return true;
}

}  // namespace openrecover::fs