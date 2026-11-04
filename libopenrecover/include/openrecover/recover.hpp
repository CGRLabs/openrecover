#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/carve/carve_engine.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/output_sink.hpp"
#include "openrecover/partition/partition_scanner.hpp"
#include "openrecover/report/report.hpp"

namespace openrecover {

// Names as they appear in report.json: the filesystem of a volume, the scheme of a partition table,
// and the canonical carve type of a file name or a user-supplied token.
const char* fs_kind_name(fs::FsKind kind) noexcept;
const char* scheme_name(partition::PartitionScheme scheme) noexcept;
std::string canonical_type(std::string_view file_name);
std::string canonical_type_token(std::string_view token);

struct SourceRequest {
    std::string source;  // path, \\.\PhysicalDriveN or /dev/...; ignored when `device` is set
    std::shared_ptr<io::BlockDevice> device;  // an already-opened source, e.g. an in-memory fixture
    uint32_t sector_size = 0;                 // 0 = probe or infer
    bool allow_shared_write_sharing = false;
    int partition = -1;                       // pin the volume by table index
    std::optional<uint64_t> offset;           // pin the volume by byte offset; excludes `partition`
    std::optional<fs::FsKind> fs;             // force one filesystem instead of detecting
};

// A source that is open with its volume chosen and its filesystem identified. Copy nothing out of
// it that must outlive it: `scanner()` reads through the view it owns.
class OpenedSource {
public:
    OpenedSource(OpenedSource&&) noexcept = default;
    OpenedSource& operator=(OpenedSource&&) noexcept = default;
    OpenedSource(const OpenedSource&) = delete;
    OpenedSource& operator=(const OpenedSource&) = delete;

    const std::shared_ptr<io::BlockDevice>& root() const noexcept { return root_; }
    const std::shared_ptr<io::BlockDevice>& view() const noexcept { return view_; }
    uint64_t view_offset() const noexcept { return view_offset_; }
    const std::vector<partition::PartitionInfo>& partitions() const noexcept { return partitions_; }
    const std::vector<report::PartitionSummary>& partition_summaries() const noexcept { return summaries_; }
    fs::IFileSystemScanner* scanner() noexcept { return scanner_.get(); }
    const std::vector<std::string>& warnings() const noexcept { return warnings_; }
    const std::optional<Error>& partitions_error() const noexcept { return partitions_error_; }

    // A report seeded with the source, the partition table and the warnings gathered while opening.
    report::Report base_report() const;

private:
    friend Result<OpenedSource> open_volume(const SourceRequest&, bool);

    OpenedSource() = default;

    std::string description_;

    std::shared_ptr<io::BlockDevice> root_;
    std::shared_ptr<io::BlockDevice> view_;
    uint64_t view_offset_ = 0;
    std::vector<partition::PartitionInfo> partitions_;
    std::vector<report::PartitionSummary> summaries_;
    std::optional<Error> partitions_error_;
    std::unique_ptr<fs::IFileSystemScanner> scanner_;
    std::vector<std::string> warnings_;
};

// Open the source, read its partition table, choose the volume to work on and identify its
// filesystem. A missing partition table is recorded as a warning, not an error: the bytes are
// still worth carving. With `need_scanner` a source that has no readable filesystem fails instead
// of coming back without a scanner.
Result<OpenedSource> open_volume(const SourceRequest&, bool need_scanner);

// Which recovered files to write out, applied to metadata and carved hits alike.
struct ExportFilter {
    Confidence min_confidence = Confidence::Low;
    std::set<std::string> types;                 // empty = every type
    std::map<std::string, uint64_t> max_sizes;   // type -> byte cap, absent = uncapped
};

struct CarveRequest {
    carve::CarveOptions options;
    std::string signature_pack;  // JSON pack loaded over the built-ins; empty = built-ins only
    // True when the caller asked for unallocated space explicitly, so a volume without an
    // allocation map is an error rather than a fallback to scanning every byte.
    bool scope_explicit = false;
};

// One recovered file as the report describes it. Extent offsets are relative to the volume, so
// `base_offset` is the volume's offset inside the source.
report::FileEntry make_file_entry(const RecoveredFile& file, uint64_t base_offset);

// Export the files the filesystem metadata still names. Returns how many were written; `accepted`
// collects them so a following carve can call a duplicate what is already on disk.
Result<uint64_t> export_metadata(OpenedSource&, io::OutputSink&, const ExportFilter&, ProgressFn,
                                 report::Report&, std::vector<RecoveredFile>* accepted = nullptr);

// Carve by signature and export the hits, filling in the allocation map the scope needs.
Result<void> carve_and_export(OpenedSource&, io::OutputSink&, const CarveRequest&, const ExportFilter&,
                              ProgressFn, report::Report&, const std::vector<RecoveredFile>* existing);

struct RecoverRequest {
    SourceRequest source;
    io::OutputSink* sink = nullptr;  // the only writer; must outlive the call
    bool metadata = true;
    bool carve = true;
    ExportFilter filter;
    CarveRequest carving;
    ProgressFn metadata_progress;
    ProgressFn carve_progress;
};

// The whole pipeline in one call: open, choose the volume, export what the metadata names, carve
// what it lost, and hand back a finalized report. The caller writes report.json with
// report::write_to_sink, because only the caller knows where it wants it.
Result<report::Report> recover(const RecoverRequest&);

}  // namespace openrecover
