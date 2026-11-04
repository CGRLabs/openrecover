#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "fuzz_common.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/ntfs_recyclebin.hpp"

namespace {

constexpr const char* kBin = "$Recycle.Bin/S-1-5-21-0-0-0-1001/";

openrecover::RecoveredFile named(const char* prefix, std::vector<uint8_t> data,
                                 uint64_t size) {
    openrecover::RecoveredFile file;
    file.name = std::string(prefix) + "hostage";
    file.path = std::string(kBin) + file.name;
    file.size_bytes = size;
    file.resident_data = std::move(data);
    return file;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    openrecover::fuzz::silence_logs();
    const std::span<const uint8_t> record(data, size);
    auto info = openrecover::fs::parse_recycle_info(record);
    if (!info) return 0;

    // The record parsed, so hand it to the pass that rewrites a scan together with the data file
    // it claims to describe. The size is taken from the record so the agreement check runs on the
    // input's own numbers.
    std::vector<openrecover::RecoveredFile> files;
    files.push_back(named("$I", std::vector<uint8_t>(data, data + size), size));
    files.push_back(named("$R", {}, info->declared_size));
    openrecover::fs::apply_recycle_bin_metadata(files);
    return 0;
}
