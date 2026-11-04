#include "openrecover/recover.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

#include "openrecover/common/path_util.hpp"
#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/fs/exfat/exfat_scanner.hpp"
#include "openrecover/fs/ext4/ext4_scanner.hpp"
#include "openrecover/fs/fat32.hpp"
#include "openrecover/fs/ntfs.hpp"
#include "openrecover/io/partition_view.hpp"

namespace openrecover {

namespace {

std::string lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        const auto u = static_cast<unsigned char>(c);
        if (u >= 'A' && u <= 'Z') c = static_cast<char>(u - 'A' + 'a');
    }
    return out;
}

std::string trim_ascii(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return std::string(text);
}

// How report.json names the source: a device path verbatim, otherwise the file name alone, so a
// report never records the operator's working directory.
std::string describe_source(std::string_view source) {
    if (source.empty()) return {};
    if (source.rfind("\\\\.\\", 0) == 0 || source.rfind("/dev/", 0) == 0) return std::string(source);
    const auto path = path_from_utf8(source);
    const auto filename = path.filename();
    return filename.empty() ? std::string(source) : path_to_utf8(filename);
}

uint64_t absolute_offset(uint64_t base, uint64_t offset) {
    return offset > UINT64_MAX - base ? UINT64_MAX : base + offset;
}

bool selected_type(const std::set<std::string>& types, const std::string& type) {
    return types.empty() || types.count(type) != 0;
}

uint64_t max_size_for(const std::map<std::string, uint64_t>& limits, const std::string& type) {
    const auto it = limits.find(type);
    return it == limits.end() ? 0 : it->second;
}

// Reads a recovered file as a stream of bytes: from its resident data when the metadata holds the
// content inline, and from the volume otherwise.
class ScannerFileSource final : public io::ByteSource {
public:
    ScannerFileSource(fs::IFileSystemScanner& scanner, const RecoveredFile& file)
        : scanner_(scanner), file_(file) {}

    Result<size_t> read_some(uint8_t* dst, size_t len) override {
        if (position_ >= file_.size_bytes || len == 0) return size_t{0};
        const size_t want = static_cast<size_t>(std::min<uint64_t>(len, file_.size_bytes - position_));
        if (file_.resident_data) {
            if (position_ >= file_.resident_data->size())
                return fail(ErrorCode::CorruptStructure,
                            "resident data is shorter than the declared file size", position_);
            const size_t available = static_cast<size_t>(file_.resident_data->size() - position_);
            const size_t copy = std::min(want, available);
            std::copy(file_.resident_data->begin() + static_cast<std::ptrdiff_t>(position_),
                      file_.resident_data->begin() + static_cast<std::ptrdiff_t>(position_ + copy), dst);
            position_ += copy;
            return copy;
        }
        auto got = scanner_.read_file(file_, position_, dst, want);
        if (!got) return fail(got.error());
        if (*got == 0) return fail(ErrorCode::IoError, "file ended before its declared size", position_);
        position_ += *got;
        return *got;
    }

private:
    fs::IFileSystemScanner& scanner_;
    const RecoveredFile& file_;
    uint64_t position_ = 0;
};

std::string detect_fs_name(const std::shared_ptr<io::BlockDevice>& device) {
    auto scanner = fs::detect_and_open(device);
    if (!scanner) return {};
    return fs_kind_name((*scanner)->kind());
}

// One summary per partition, each labelled with the filesystem its own volume carries. A bare
// volume image is labelled from the whole device, which is what its single summary describes.
std::vector<report::PartitionSummary> summarize_partitions(
    const std::shared_ptr<io::BlockDevice>& root, const std::vector<partition::PartitionInfo>& partitions) {
    std::vector<report::PartitionSummary> summaries;
    for (const partition::PartitionInfo& info : partitions) {
        report::PartitionSummary summary;
        summary.index = info.index;
        summary.scheme = scheme_name(info.scheme);
        summary.start = info.start_byte;
        summary.length = info.length_byte;
        if (info.scheme != partition::PartitionScheme::Superfloppy) {
            auto view = std::make_shared<io::PartitionView>(root, info.start_byte, info.length_byte);
            summary.fs = detect_fs_name(view);
        }
        summaries.push_back(std::move(summary));
    }
    if (summaries.size() == 1 && partitions.front().scheme == partition::PartitionScheme::Superfloppy) {
        summaries.front().fs = detect_fs_name(root);
    }
    return summaries;
}

Result<std::unique_ptr<fs::IFileSystemScanner>> open_forced_scanner(fs::FsKind kind,
                                                                    const std::shared_ptr<io::BlockDevice>& view) {
    // Each scanner opens to its own concrete type, so the conversion is spelled per case.
    switch (kind) {
        case fs::FsKind::Fat32: {
            auto scanner = fs::Fat32Scanner::open(view);
            if (!scanner) return fail(scanner.error());
            return std::unique_ptr<fs::IFileSystemScanner>(std::move(*scanner));
        }
        case fs::FsKind::Ntfs: {
            auto scanner = fs::NtfsScanner::open(view);
            if (!scanner) return fail(scanner.error());
            return std::unique_ptr<fs::IFileSystemScanner>(std::move(*scanner));
        }
        case fs::FsKind::ExFat: {
            auto scanner = fs::ExfatScanner::open(view);
            if (!scanner) return fail(scanner.error());
            return std::unique_ptr<fs::IFileSystemScanner>(std::move(*scanner));
        }
        case fs::FsKind::Ext4: {
            auto scanner = fs::Ext4Scanner::open(view);
            if (!scanner) return fail(scanner.error());
            return std::unique_ptr<fs::IFileSystemScanner>(std::move(*scanner));
        }
    }
    return fail(ErrorCode::InvalidArgument, "unknown filesystem");
}

}  // namespace

const char* fs_kind_name(fs::FsKind kind) noexcept {
    switch (kind) {
        case fs::FsKind::Fat32: return "fat32";
        case fs::FsKind::Ntfs: return "ntfs";
        case fs::FsKind::ExFat: return "exfat";
        case fs::FsKind::Ext4: return "ext4";
    }
    return "unknown";
}

const char* scheme_name(partition::PartitionScheme scheme) noexcept {
    switch (scheme) {
        case partition::PartitionScheme::Mbr: return "mbr";
        case partition::PartitionScheme::Gpt: return "gpt";
        case partition::PartitionScheme::Superfloppy: return "superfloppy";
    }
    return "unknown";
}

std::string canonical_type(std::string_view name) {
    const size_t dot = name.rfind('.');
    if (dot == std::string_view::npos || dot + 1 >= name.size()) return {};
    const std::string ext = lower_ascii(name.substr(dot + 1));
    if (ext == "jpg" || ext == "jpeg") return "jpeg";
    if (ext == "png") return "png";
    if (ext == "pdf") return "pdf";
    if (ext == "zip" || ext == "docx" || ext == "xlsx" || ext == "pptx" || ext == "apk" ||
        ext == "jar" || ext == "odt" || ext == "ods" || ext == "odp" || ext == "epub")
        return "zip";
    if (ext == "tif" || ext == "tiff") return "tiff";
    if (ext == "sqlite" || ext == "sqlite3" || ext == "db") return "sqlite";
    return ext;
}

std::string canonical_type_token(std::string_view token) {
    std::string value = lower_ascii(trim_ascii(token));
    if (value == "jpg") return "jpeg";
    if (value == "docx" || value == "xlsx" || value == "pptx" || value == "apk" || value == "jar" ||
        value == "odt" || value == "ods" || value == "odp" || value == "epub")
        return "zip";
    if (value == "tif") return "tiff";
    if (value == "sqlite3" || value == "db") return "sqlite";
    return value;
}

report::FileEntry make_file_entry(const RecoveredFile& file, uint64_t base_offset) {
    report::FileEntry entry;
    entry.origin = file.origin;
    entry.path = file.path;
    entry.size = file.size_bytes;
    entry.confidence = file.confidence;
    entry.flags = file.flags;
    entry.mtime_unix = file.mtime_unix;
    entry.deleted_unix = file.deleted_unix;
    entry.extents = file.extents;
    for (Extent& extent : entry.extents) {
        extent.offset_bytes = absolute_offset(base_offset, extent.offset_bytes);
    }
    entry.type = file.type_hint.empty() ? canonical_type(file.name) : canonical_type_token(file.type_hint);
    entry.note = file.note;
    return entry;
}

report::Report OpenedSource::base_report() const {
    report::Report result;
    result.generated_at = report::generated_at_utc();
    result.source.description = description_;
    result.source.container = root_->info().container;
    result.source.size_bytes = root_->info().size_bytes;
    result.source.sector_size = root_->info().logical_sector_size;
    result.source.shared_write_fallback = root_->info().shared_write_fallback;
    result.source.bad_sectors = root_->bad_sectors();
    result.partitions = summaries_;
    result.warnings = warnings_;
    return result;
}

Result<OpenedSource> open_volume(const SourceRequest& request, bool need_scanner) {
    io::OpenOptions open_options;
    open_options.sector_size = request.sector_size;
    open_options.allow_shared_write_sharing = request.allow_shared_write_sharing;

    OpenedSource opened;
    if (request.device) {
        opened.root_ = request.device;
    } else {
        auto device = io::open_source(request.source, open_options);
        if (!device) return fail(device.error());
        opened.root_ = std::shared_ptr<io::BlockDevice>(std::move(*device));
    }
    opened.view_ = opened.root_;
    opened.description_ =
        request.source.empty() ? opened.root_->info().description : describe_source(request.source);

    auto partitions = partition::scan_partitions(*opened.root_);
    if (partitions) {
        opened.partitions_ = std::move(*partitions);
        opened.summaries_ = summarize_partitions(opened.root_, opened.partitions_);
    } else if (partitions.error().code != ErrorCode::NoFilesystem &&
               partitions.error().code != ErrorCode::Unsupported) {
        opened.partitions_error_ = partitions.error();
        opened.warnings_.push_back("partition scan failed: " + partitions.error().message);
    }

    if (request.partition >= 0 && request.offset)
        return fail(ErrorCode::InvalidArgument, "a pinned partition and a pinned offset are mutually exclusive");

    if (request.partition >= 0) {
        if (opened.partitions_error_) return fail(*opened.partitions_error_);
        const auto it = std::find_if(opened.partitions_.begin(), opened.partitions_.end(),
                                     [&](const partition::PartitionInfo& info) {
                                         return info.index == static_cast<uint32_t>(request.partition);
                                     });
        if (it == opened.partitions_.end())
            return fail(ErrorCode::InvalidArgument,
                        "partition " + std::to_string(request.partition) + " was not found");
        if (it->length_byte == 0) return fail(ErrorCode::InvalidArgument, "partition has zero length");
        opened.view_ = std::make_shared<io::PartitionView>(opened.root_, it->start_byte, it->length_byte);
        opened.view_offset_ = it->start_byte;
    } else if (request.offset) {
        if (*request.offset >= opened.root_->info().size_bytes)
            return fail(ErrorCode::InvalidArgument, "the pinned offset is beyond the end of the source");
        opened.view_ = std::make_shared<io::PartitionView>(
            opened.root_, *request.offset, opened.root_->info().size_bytes - *request.offset);
        opened.view_offset_ = *request.offset;
    }

    std::optional<Error> scanner_error;
    if (request.fs) {
        auto scanner = open_forced_scanner(*request.fs, opened.view_);
        if (scanner) {
            opened.scanner_ = std::move(*scanner);
        } else {
            scanner_error = scanner.error();
        }
    } else {
        auto scanner = fs::detect_and_open(opened.view_);
        if (scanner) {
            opened.scanner_ = std::move(*scanner);
        } else {
            scanner_error = scanner.error();
        }
    }

    // Nothing at offset 0 and no explicit pin: take the first partition that does carry a volume.
    if (!opened.scanner_ && !request.fs && request.partition < 0 && !request.offset) {
        for (const partition::PartitionInfo& info : opened.partitions_) {
            if (info.scheme == partition::PartitionScheme::Superfloppy || info.length_byte == 0) continue;
            auto view = std::make_shared<io::PartitionView>(opened.root_, info.start_byte, info.length_byte);
            auto scanner = fs::detect_and_open(view);
            if (!scanner) continue;
            opened.view_ = std::move(view);
            opened.view_offset_ = info.start_byte;
            opened.scanner_ = std::move(*scanner);
            opened.warnings_.push_back("no filesystem at offset 0; using partition " +
                                       std::to_string(info.index) + " at byte " +
                                       std::to_string(info.start_byte));
            break;
        }
    }

    if (!opened.scanner_ && request.fs)
        return fail(scanner_error.value_or(
            Error{ErrorCode::Unsupported, "the requested filesystem could not be opened"}));

    if (!opened.scanner_) {
        if (need_scanner)
            return fail(scanner_error.value_or(
                Error{ErrorCode::Unsupported, "no supported filesystem was detected"}));
        opened.warnings_.push_back("no supported filesystem detected; carving the whole source");
    }
    return opened;
}

Result<uint64_t> export_metadata(OpenedSource& opened, io::OutputSink& sink, const ExportFilter& filter,
                                 ProgressFn progress, report::Report& result,
                                 std::vector<RecoveredFile>* accepted) {
    fs::IFileSystemScanner* scanner = opened.scanner();
    if (!scanner) return fail(ErrorCode::Unsupported, "no supported filesystem was detected");

    auto files = scanner->scan_deleted(fs::ScanOptions{}, progress);
    if (!files) return fail(files.error());

    result.statistics.deleted_entries_found = files->size();
    result.files.reserve(files->size());
    for (const RecoveredFile& file : *files) {
        result.files.push_back(make_file_entry(file, opened.view_offset()));
    }

    size_t exported = 0;
    for (size_t i = 0; i < files->size(); ++i) {
        const RecoveredFile& file = (*files)[i];
        report::FileEntry& entry = result.files[i];
        if (file.path.empty()) {
            result.warnings.push_back("skipping a recovered file with an empty path");
            continue;
        }
        if (!meets_confidence(file.confidence, filter.min_confidence)) continue;
        if (!selected_type(filter.types, entry.type)) continue;
        const uint64_t limit = max_size_for(filter.max_sizes, entry.type);
        if (limit != 0 && file.size_bytes > limit) continue;
        if ((file.flags & file_flags::Unsupported) != 0) {
            result.warnings.push_back("skipping unsupported content: " + file.path);
            continue;
        }

        std::unique_ptr<io::ByteSource> source;
        if (file.resident_data) {
            source = std::make_unique<io::MemoryByteSource>(
                std::span<const uint8_t>(file.resident_data->data(), file.resident_data->size()));
        } else {
            source = std::make_unique<ScannerFileSource>(*scanner, file);
        }
        auto written = sink.write_file("files/" + file.path, *source, file.mtime_unix);
        if (!written) {
            result.warnings.push_back("cannot export " + file.path + ": " + written.error().message);
            continue;
        }
        if (written->size != file.size_bytes) {
            result.warnings.push_back("exported size differs for " + file.path + " (expected " +
                                      std::to_string(file.size_bytes) + ", wrote " +
                                      std::to_string(written->size) + ")");
            continue;
        }
        entry.sha256 = written->sha256;
        entry.exported_to = written->relative;
        if (accepted) accepted->push_back(file);
        ++exported;
    }
    result.statistics.exported += exported;
    return exported;
}

Result<void> carve_and_export(OpenedSource& opened, io::OutputSink& sink, const CarveRequest& carving,
                              const ExportFilter& filter, ProgressFn progress, report::Report& result,
                              const std::vector<RecoveredFile>* existing) {
    carve::CarveOptions options = carving.options;
    carve::SignatureRegistry registry = carve::SignatureRegistry::builtins();
    if (!carving.signature_pack.empty()) {
        if (!registry.load_from_file(carving.signature_pack))
            return fail(ErrorCode::InvalidArgument, "cannot load signature pack: " + carving.signature_pack);
    }
    for (const std::string& type : options.types) {
        if (registry.find(type) == nullptr)
            return fail(ErrorCode::InvalidArgument, "unknown carve type: " + type);
    }
    options.existing_files = existing;

    std::unique_ptr<fs::IAllocationMap> allocation;
    if (options.scope == carve::CarveOptions::Scope::UnallocatedOnly) {
        if (!opened.scanner()) {
            if (carving.scope_explicit)
                return fail(ErrorCode::Unsupported,
                            "carving unallocated space requires a supported FAT32, exFAT, NTFS or ext4 volume");
            result.warnings.push_back("no allocation map available; scanning all bytes");
            options.scope = carve::CarveOptions::Scope::All;
        } else {
            auto map = opened.scanner()->allocation_map();
            if (!map) {
                if (carving.scope_explicit) return fail(map.error());
                result.warnings.push_back("cannot read the allocation map (" + map.error().message +
                                          "); scanning all bytes");
                options.scope = carve::CarveOptions::Scope::All;
            } else {
                allocation = std::move(*map);
            }
        }
    }

    auto hits = carve::CarveEngine::run(*opened.view(), allocation.get(), options, progress, registry);
    if (!hits) return fail(hits.error());

    result.statistics.carve_hits = hits->size();
    result.carved.reserve(hits->size());
    for (const carve::CarveHit& hit : *hits) {
        report::CarvedEntry entry;
        entry.offset = absolute_offset(opened.view_offset(), hit.offset);
        entry.length = hit.length;
        entry.type = hit.type;
        entry.subtype = hit.subtype;
        entry.confidence = hit.confidence;
        entry.sha256 = hit.sha256;
        entry.fragments = static_cast<uint32_t>(hit.fragments.size());
        for (const carve::CarveFragment& fragment : hit.fragments) {
            entry.extents.push_back(Extent{absolute_offset(opened.view_offset(), fragment.offset),
                                           fragment.length, false});
        }
        result.carved.push_back(std::move(entry));
    }

    std::vector<size_t> report_index;
    std::vector<carve::CarveHit> to_export;
    size_t oversized = 0;
    for (size_t i = 0; i < hits->size(); ++i) {
        const carve::CarveHit& hit = (*hits)[i];
        if (!hit.duplicate_of.empty()) {
            ++result.statistics.duplicates_skipped;
            continue;
        }
        const uint64_t limit = max_size_for(filter.max_sizes, hit.type);
        if (limit != 0 && hit.length > limit) {
            ++oversized;
            continue;
        }
        report_index.push_back(i);
        to_export.push_back(hit);
    }
    if (oversized != 0) {
        result.warnings.push_back(std::to_string(oversized) +
                                  " carved hit(s) exceeded the size limit and were not exported");
    }

    auto written = carve::export_hits(sink, *opened.view(), to_export, false);
    if (!written) return fail(written.error());
    if (written->size() != to_export.size()) return fail(ErrorCode::IoError, "carved export count mismatch");
    for (size_t i = 0; i < written->size(); ++i) {
        if ((*written)[i].sha256 != to_export[i].sha256)
            return fail(ErrorCode::IoError, "carved file hash mismatch for " + (*written)[i].relative);
        result.carved[report_index[i]].exported_to = (*written)[i].relative;
    }
    result.statistics.exported += written->size();
    return {};
}

Result<report::Report> recover(const RecoverRequest& request) {
    if (!request.sink) return fail(ErrorCode::InvalidArgument, "a recovery needs an output sink");
    if (!request.metadata && !request.carve)
        return fail(ErrorCode::InvalidArgument, "a recovery must run at least one phase");

    auto opened = open_volume(request.source, request.metadata);
    if (!opened) return fail(opened.error());

    report::Report result = opened->base_report();
    std::vector<RecoveredFile> accepted;

    if (request.metadata) {
        auto exported = export_metadata(*opened, *request.sink, request.filter, request.metadata_progress,
                                        result, &accepted);
        if (!exported) return fail(exported.error());
    }
    if (request.carve) {
        auto carved = carve_and_export(*opened, *request.sink, request.carving, request.filter,
                                       request.carve_progress, result, request.metadata ? &accepted : nullptr);
        if (!carved) return fail(carved.error());
    }

    report::finalize(result);
    return result;
}

}  // namespace openrecover
