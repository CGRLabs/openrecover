#pragma once

// Shared golden-comparison helpers for the fixture-driven recovery tests.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "openrecover/common/types.hpp"
#include "openrecover/fs/filesystem.hpp"

namespace openrecover::test {

inline nlohmann::json actual_files_json(const std::vector<RecoveredFile>& files) {
    nlohmann::json out = nlohmann::json::array();
    for (const RecoveredFile& file : files) {
        nlohmann::json extents = nlohmann::json::array();
        for (const Extent& extent : file.extents) {
            extents.push_back({{"offset_bytes", extent.offset_bytes},
                               {"length_bytes", extent.length_bytes},
                               {"sparse", extent.sparse}});
        }
        nlohmann::json item;
        item["path"] = file.path;
        item["name"] = file.name;
        item["size_bytes"] = file.size_bytes;
        item["extents"] = std::move(extents);
        item["confidence"] = confidence_name(file.confidence);
        item["flags"] = flag_names(file.flags);
        item["note"] = file.note;
        item["mtime_unix"] = file.mtime_unix ? nlohmann::json(*file.mtime_unix) : nlohmann::json(nullptr);
        item["ctime_unix"] = file.ctime_unix ? nlohmann::json(*file.ctime_unix) : nlohmann::json(nullptr);
        item["atime_unix"] = file.atime_unix ? nlohmann::json(*file.atime_unix) : nlohmann::json(nullptr);
        item["origin"] = origin_name(file.origin);
        out.push_back(std::move(item));
    }
    std::sort(out.begin(), out.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        return a.at("path").get<std::string>() < b.at("path").get<std::string>();
    });
    return out;
}

inline const RecoveredFile* find_file(const std::vector<RecoveredFile>& files, const std::string& path) {
    const auto it = std::find_if(files.begin(), files.end(),
                                 [&](const RecoveredFile& file) { return file.path == path; });
    return it == files.end() ? nullptr : &*it;
}

// Reads a whole file in odd-sized chunks so extent boundaries are crossed mid-read.
inline std::vector<uint8_t> read_all(fs::IFileSystemScanner& scanner, const RecoveredFile& file,
                                    std::size_t chunk = 777) {
    std::vector<uint8_t> data(static_cast<std::size_t>(file.size_bytes));
    uint64_t offset = 0;
    while (offset < file.size_bytes) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<uint64_t>(chunk, file.size_bytes - offset));
        auto got = scanner.read_file(file, offset, data.data() + static_cast<std::size_t>(offset), want);
        REQUIRE(got.has_value());
        REQUIRE(*got == want);
        offset += want;
    }
    return data;
}

}  // namespace openrecover::test
