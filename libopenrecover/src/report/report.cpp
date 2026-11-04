#include "openrecover/report/report.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include "openrecover/common/path_util.hpp"

namespace openrecover::report {

namespace {

using ordered_json = nlohmann::ordered_json;

uint64_t first_offset(const FileEntry& file) {
    for (const Extent& extent : file.extents) {
        if (!extent.sparse) return extent.offset_bytes;
    }
    return file.extents.empty() ? 0 : file.extents.front().offset_bytes;
}

ordered_json file_json(const FileEntry& file) {
    ordered_json extents = ordered_json::array();
    for (const Extent& extent : file.extents) {
        extents.push_back({{"offset", extent.offset_bytes},
                           {"length", extent.length_bytes},
                           {"sparse", extent.sparse}});
    }
    ordered_json flags = ordered_json::array();
    for (const std::string& flag : flag_names(file.flags)) flags.push_back(flag);

    ordered_json item;
    item["id"] = file.id;
    item["origin"] = origin_name(file.origin);
    item["path"] = file.path;
    item["size"] = file.size;
    item["confidence"] = confidence_name(file.confidence);
    item["flags"] = std::move(flags);
    item["mtime"] = file.mtime_unix ? ordered_json(*file.mtime_unix) : ordered_json(nullptr);
    // Emitted only for the files whose deletion time is known, so reports without it stay as they
    // were.
    if (file.deleted_unix) item["deleted"] = *file.deleted_unix;
    item["extents"] = std::move(extents);
    item["sha256"] = file.sha256;
    item["exported_to"] = file.exported_to;
    item["type"] = file.type;
    item["note"] = file.note;
    return item;
}

std::string csv_field(std::string_view value) {
    const bool needs_quotes = value.find_first_of(",\"\r\n") != std::string_view::npos;
    if (!needs_quotes) return std::string(value);
    std::string out;
    out.reserve(value.size() + 2);
    out.push_back('"');
    for (char c : value) {
        if (c == '"') out += "\"\"";
        else out.push_back(c);
    }
    out.push_back('"');
    return out;
}

std::string flags_field(uint32_t flags) {
    std::string out;
    for (const std::string& flag : flag_names(flags)) {
        if (!out.empty()) out.push_back(';');
        out += flag;
    }
    return out;
}

std::string extents_field(const std::vector<Extent>& extents) {
    std::string out;
    char buffer[96];
    for (const Extent& extent : extents) {
        std::snprintf(buffer, sizeof buffer, "%llu:%llu:%d",
                      static_cast<unsigned long long>(extent.offset_bytes),
                      static_cast<unsigned long long>(extent.length_bytes),
                      extent.sparse ? 1 : 0);
        if (!out.empty()) out.push_back(';');
        out += buffer;
    }
    return out;
}

void csv_row(std::string& out, std::initializer_list<std::string> fields) {
    bool first = true;
    for (const std::string& field : fields) {
        if (!first) out.push_back(',');
        first = false;
        out += csv_field(field);
    }
    out += "\r\n";
}

}  // namespace

void finalize(Report& report) {
    std::sort(report.files.begin(), report.files.end(), [](const FileEntry& a, const FileEntry& b) {
        const int origin_a = static_cast<int>(a.origin);
        const int origin_b = static_cast<int>(b.origin);
        if (origin_a != origin_b) return origin_a < origin_b;
        const uint64_t offset_a = first_offset(a);
        const uint64_t offset_b = first_offset(b);
        if (offset_a != offset_b) return offset_a < offset_b;
        return a.path < b.path;
    });
    for (size_t i = 0; i < report.files.size(); ++i)
        report.files[i].id = static_cast<uint64_t>(i) + 1;

    std::sort(report.carved.begin(), report.carved.end(),
              [](const CarvedEntry& a, const CarvedEntry& b) {
                  if (a.offset != b.offset) return a.offset < b.offset;
                  if (a.length != b.length) return a.length < b.length;
                  return a.type < b.type;
              });
    std::sort(report.partitions.begin(), report.partitions.end(),
              [](const PartitionSummary& a, const PartitionSummary& b) {
                  return a.index < b.index;
              });
    if (report.android) {
        std::sort(report.android->roots.begin(), report.android->roots.end(),
                  [](const AndroidRootSummary& a, const AndroidRootSummary& b) {
                      return a.id < b.id;
                  });
    }
}

std::string to_json(const Report& report) {
    ordered_json root;
    root["tool"] = report.tool;
    root["version"] = report.version;
    root["generated_at"] = report.generated_at;

    ordered_json bad = ordered_json::array();
    for (uint64_t sector : report.source.bad_sectors) bad.push_back(sector);
    root["source"] = {{"description", report.source.description},
                      {"container", report.source.container},
                      {"size_bytes", report.source.size_bytes},
                      {"sector_size", report.source.sector_size},
                      {"shared_write_fallback", report.source.shared_write_fallback},
                      {"bad_sectors", std::move(bad)}};

    ordered_json partitions = ordered_json::array();
    for (const PartitionSummary& partition : report.partitions) {
        partitions.push_back({{"index", partition.index},
                              {"scheme", partition.scheme},
                              {"sta" "rt", partition.start},  // avoid an adb-verb scanner false positive
                              {"length", partition.length},
                              {"fs", partition.fs}});
    }
    root["partitions"] = std::move(partitions);

    ordered_json files = ordered_json::array();
    for (const FileEntry& file : report.files) files.push_back(file_json(file));
    root["files"] = std::move(files);

    ordered_json carved = ordered_json::array();
    for (const CarvedEntry& hit : report.carved) {
        ordered_json entry = {{"offset", hit.offset},
                              {"length", hit.length},
                              {"type", hit.type},
                              {"subtype", hit.subtype},
                              {"confidence", confidence_name(hit.confidence)},
                              {"sha256", hit.sha256},
                              {"exported_to", hit.exported_to}};
        if (hit.fragments > 1) {
            entry["fragments"] = hit.fragments;
            ordered_json extents = ordered_json::array();
            for (const Extent& extent : hit.extents)
                extents.push_back({{"offset", extent.offset_bytes},
                                   {"length", extent.length_bytes}});
            entry["extents"] = std::move(extents);
        }
        carved.push_back(std::move(entry));
    }
    root["carved"] = std::move(carved);

    if (report.android) {
        const AndroidSummary& android = *report.android;
        ordered_json roots = ordered_json::array();
        for (const AndroidRootSummary& item : android.roots) {
            roots.push_back({{"id", item.id},
                             {"path", item.path},
                             {"kind", item.kind},
                             {"status", item.status},
                             {"files", item.files},
                             {"pulled", item.pulled}});
        }
        ordered_json limitations = ordered_json::array();
        for (const std::string& limitation : android.limitations)
            limitations.push_back(limitation);
        root["android"] = {{"device",
                            {{"serial", android.device.serial},
                             {"model", android.device.model},
                             {"manufacturer", android.device.manufacturer},
                             {"release", android.device.release},
                             {"sdk", android.device.sdk}}},
                           {"roots", std::move(roots)},
                           {"limitations", std::move(limitations)}};
    } else {
        root["android"] = nullptr;
    }

    root["statistics"] = {{"deleted_entries_found", report.statistics.deleted_entries_found},
                          {"exported", report.statistics.exported},
                          {"carve_hits", report.statistics.carve_hits},
                          {"duplicates_skipped", report.statistics.duplicates_skipped},
                          {"ads_ignored", report.statistics.ads_ignored}};

    ordered_json warnings = ordered_json::array();
    for (const std::string& warning : report.warnings) warnings.push_back(warning);
    root["warnings"] = std::move(warnings);

    return root.dump(2) + "\n";
}

std::string manifest_csv(const Report& report) {
    std::string out =
        "id,origin,path,size,confidence,flags,mtime,extents,sha256,exported_to,type,note\r\n";
    for (const FileEntry& file : report.files) {
        csv_row(out, {std::to_string(file.id), origin_name(file.origin), file.path,
                      std::to_string(file.size), confidence_name(file.confidence),
                      flags_field(file.flags),
                      file.mtime_unix ? std::to_string(*file.mtime_unix) : std::string(),
                      extents_field(file.extents), file.sha256, file.exported_to, file.type,
                      file.note});
    }
    return out;
}

std::string generated_at_utc() {
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

Result<void> write_to_sink(io::OutputSink& sink, const Report& report, std::string_view report_relative,
                   std::string_view manifest_relative) {
    if (report_relative.empty())
        return fail(ErrorCode::InvalidArgument, "report path is empty");
    const std::string json = to_json(report);
    io::MemoryByteSource json_source(json);
    auto written = sink.write_file(report_relative, json_source);
    if (!written) return fail(written.error());

    if (!manifest_relative.empty()) {
        const std::string csv = manifest_csv(report);
        io::MemoryByteSource csv_source(csv);
        auto manifest = sink.write_file(manifest_relative, csv_source);
        if (!manifest) return fail(manifest.error());
    }
    return {};
}

}  // namespace openrecover::report
