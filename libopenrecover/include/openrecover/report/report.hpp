#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/io/output_sink.hpp"

namespace openrecover::report {

struct SourceSummary {
    std::string description;
    // Set when the source bytes come from inside a container, e.g. "vhd fixed" or "vhdx".
    std::string container;
    uint64_t size_bytes = 0;
    uint32_t sector_size = 0;
    bool shared_write_fallback = false;
    std::vector<uint64_t> bad_sectors;
};

struct PartitionSummary {
    uint32_t index = 0;
    std::string scheme;
    uint64_t start = 0;
    uint64_t length = 0;
    std::string fs;
};

struct FileEntry {
    uint64_t id = 0;
    FileOrigin origin = FileOrigin::FilesystemMetadata;
    std::string path;
    uint64_t size = 0;
    Confidence confidence = Confidence::Low;
    uint32_t flags = 0;
    std::optional<int64_t> mtime_unix;
    // Only present when out-of-band metadata ($Recycle.Bin) recorded when the file was deleted.
    std::optional<int64_t> deleted_unix;
    std::vector<Extent> extents;
    std::string sha256;
    std::string exported_to;
    std::string type;
    std::string note;
};

struct CarvedEntry {
    uint64_t offset = 0;
    uint64_t length = 0;
    std::string type;
    std::string subtype;
    Confidence confidence = Confidence::Low;
    std::string sha256;
    std::string exported_to;
    // Number of device runs when the file was reassembled across a discontinuity; 0 when it is
    // one contiguous run.
    uint32_t fragments = 0;
    // Device runs in file order, filled only for reassembled hits. Never sparse.
    std::vector<Extent> extents;
};

struct AndroidDeviceSummary {
    std::string serial;
    std::string model;
    std::string manufacturer;
    std::string release;
    int sdk = 0;
};

struct AndroidRootSummary {
    std::string id;
    std::string path;
    std::string kind;
    std::string status;
    uint64_t files = 0;
    uint64_t pulled = 0;
};

struct AndroidSummary {
    AndroidDeviceSummary device;
    std::vector<AndroidRootSummary> roots;
    std::vector<std::string> limitations;
};

struct Statistics {
    uint64_t deleted_entries_found = 0;
    uint64_t exported = 0;
    uint64_t carve_hits = 0;
    uint64_t duplicates_skipped = 0;
    uint64_t ads_ignored = 0;
};

struct Report {
    std::string tool = "openrecover";
    std::string version = "1.4.0";
    std::string generated_at;
    SourceSummary source;
    std::vector<PartitionSummary> partitions;
    std::vector<FileEntry> files;
    std::vector<CarvedEntry> carved;
    std::optional<AndroidSummary> android;
    Statistics statistics;
    std::vector<std::string> warnings;
};

// Assigns ids 1..N and sorts files by (origin, first extent offset, path) and carved
// entries by offset, as required by the determinism rule in section 2.
void finalize(Report& report);

std::string to_json(const Report& report);
std::string manifest_csv(const Report& report);
std::string generated_at_utc();

// Writes report.json and (when non-empty) manifest.csv through OutputSink. Both paths
// are '/'-separated and relative to the sink root.
Result<void> write_to_sink(io::OutputSink& sink, const Report& report, std::string_view report_relative,
                   std::string_view manifest_relative);

}  // namespace openrecover::report
