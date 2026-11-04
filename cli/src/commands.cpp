#include "cli_internal.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "openrecover/android/usb_enumerator.hpp"
#include "openrecover/common/error.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/path_util.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/recover.hpp"

namespace openrecover::cli {

namespace stdfs = std::filesystem;

std::atomic<bool> g_cancelled{false};

namespace {

void on_signal(int) { g_cancelled.store(true); }

bool safe_relative_report_path(std::string_view path) {
    if (path.empty() || path.front() == '/' || path.find('\\') != std::string_view::npos)
        return false;
    size_t start = 0;
    while (start <= path.size()) {
        const size_t slash = path.find('/', start);
        const std::string_view component =
            path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
        if (component.empty() || component == "." || component == "..") return false;
        if (slash == std::string_view::npos) break;
        start = slash + 1;
    }
    return true;
}

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

std::set<std::string> parse_types(const std::string& text) {
    std::set<std::string> out;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t comma = text.find(',', start);
        const std::string token =
            trim_ascii(text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (!token.empty()) out.insert(canonical_type_token(token));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return out;
}

Result<uint64_t> parse_byte_count(std::string_view text) {
    std::string value = trim_ascii(text);
    if (value.empty()) return fail(ErrorCode::InvalidArgument, "empty size value");
    uint64_t multiplier = 1;
    const char suffix = value.back();
    if (suffix == 'k' || suffix == 'K' || suffix == 'm' || suffix == 'M' || suffix == 'g' ||
        suffix == 'G' || suffix == 't' || suffix == 'T') {
        switch (suffix) {
            case 'k':
            case 'K': multiplier = 1024ull; break;
            case 'm':
            case 'M': multiplier = 1024ull * 1024; break;
            case 'g':
            case 'G': multiplier = 1024ull * 1024 * 1024; break;
            case 't':
            case 'T': multiplier = 1024ull * 1024 * 1024 * 1024; break;
        }
        value.pop_back();
    }
    if (value.empty()) return fail(ErrorCode::InvalidArgument, "empty size value");
    int base = 10;
    std::string_view digits = value;
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.remove_prefix(2);
    }
    uint64_t number = 0;
    const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), number, base);
    if (result.ec != std::errc{} || result.ptr != digits.data() + digits.size())
        return fail(ErrorCode::InvalidArgument, "invalid size value: " + std::string(text));
    if (number > UINT64_MAX / multiplier)
        return fail(ErrorCode::InvalidArgument, "size value overflows: " + std::string(text));
    return number * multiplier;
}

Result<std::map<std::string, uint64_t>> parse_max_sizes(const std::string& text) {
    std::map<std::string, uint64_t> out;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t comma = text.find(',', start);
        const std::string item =
            trim_ascii(text.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (!item.empty()) {
            const size_t equals = item.find('=');
            if (equals == std::string::npos)
                return fail(ErrorCode::InvalidArgument,
                            "--max-size requires type=bytes, got: " + item);
            const std::string type = canonical_type_token(item.substr(0, equals));
            if (type.empty())
                return fail(ErrorCode::InvalidArgument, "--max-size has an empty type");
            auto size = parse_byte_count(item.substr(equals + 1));
            if (!size) return fail(size.error());
            out[type] = *size;
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return out;
}

uint64_t max_size_for(const std::map<std::string, uint64_t>& limits, const std::string& type) {
    const auto it = limits.find(type);
    return it == limits.end() ? 0 : it->second;
}

Result<Confidence> parse_confidence(const std::string& text) {
    const std::string value = lower_ascii(text);
    if (value == "high") return Confidence::High;
    if (value == "medium") return Confidence::Medium;
    if (value == "low") return Confidence::Low;
    return fail(ErrorCode::InvalidArgument, "invalid confidence: " + text);
}

Result<uint64_t> parse_offset(const std::string& text) {
    if (text.empty()) return fail(ErrorCode::InvalidArgument, "empty --offset value");
    int base = 10;
    std::string_view digits = text;
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.remove_prefix(2);
    }
    uint64_t value = 0;
    const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), value, base);
    if (result.ec != std::errc{} || result.ptr != digits.data() + digits.size())
        return fail(ErrorCode::InvalidArgument, "invalid --offset value: " + text);
    return value;
}

Result<fs::FsKind> parse_fs_kind(const std::string& text) {
    const std::string value = lower_ascii(text);
    if (value == "fat32") return fs::FsKind::Fat32;
    if (value == "ntfs") return fs::FsKind::Ntfs;
    if (value == "exfat") return fs::FsKind::ExFat;
    if (value == "ext4") return fs::FsKind::Ext4;
    return fail(ErrorCode::Unsupported, "unsupported filesystem: " + text);
}

Result<SourceRequest> make_source_request(const SourceOptions& source) {
    SourceRequest request;
    request.source = source.source;
    request.sector_size = source.sector_size;
    request.allow_shared_write_sharing = source.allow_shared_write_sharing;
    request.partition = source.partition;
    if (!source.offset.empty()) {
        auto offset = parse_offset(source.offset);
        if (!offset) return fail(offset.error());
        request.offset = *offset;
    }
    if (source.fs != "auto") {
        auto kind = parse_fs_kind(source.fs);
        if (!kind) return fail(kind.error());
        request.fs = *kind;
    }
    return request;
}

// --min-confidence, --types and --max-size filter the metadata phase and the carve phase the same
// way, so they are parsed once and shared. The carve engine gets the type list too: restricting
// which signatures are tried is what makes a large scan finish.
Result<ExportFilter> make_filter(const CarveOptions& carve) {
    ExportFilter filter;
    auto minimum = parse_confidence(carve.min_confidence);
    if (!minimum) return fail(minimum.error());
    filter.min_confidence = *minimum;
    filter.types = parse_types(carve.types);
    auto limits = parse_max_sizes(carve.max_size);
    if (!limits) return fail(limits.error());
    filter.max_sizes = std::move(*limits);
    return filter;
}

CarveRequest make_carve_request(const CarveOptions& carve, const ExportFilter& filter) {
    CarveRequest request;
    request.options.scope = carve.scope == "all" ? carve::CarveOptions::Scope::All
                                                 : carve::CarveOptions::Scope::UnallocatedOnly;
    request.options.unaligned = carve.unaligned;
    request.options.nested = carve.nested;
    request.options.deep_validate = carve.deep;
    request.options.reassemble = !carve.no_reassemble;
    request.options.min_confidence = filter.min_confidence;
    request.options.types = filter.types;
    request.signature_pack = carve.signature_pack;
    request.scope_explicit = carve.scope_explicit;
    return request;
}

}  // namespace

void install_signal_handler() {
    std::signal(SIGINT, on_signal);
#if defined(SIGTERM)
    std::signal(SIGTERM, on_signal);
#endif
}

ProgressFn make_progress(const GlobalOptions& global, std::string label) {
    // Silent progress still has to watch for Ctrl-C: the callback returning false is how a scan
    // or a carve is cancelled.
    if (global.no_progress || global.json)
        return [](uint64_t, uint64_t) { return !g_cancelled.load(); };
    auto last = std::make_shared<std::chrono::steady_clock::time_point>(
        std::chrono::steady_clock::now() - std::chrono::seconds(1));
    return [label = std::move(label), last](uint64_t done, uint64_t total) {
        if (g_cancelled.load()) return false;
        const auto now = std::chrono::steady_clock::now();
        const bool finished = total != 0 && done >= total;
        if (!finished && now - *last < std::chrono::milliseconds(500)) return true;
        *last = now;
        const double percent =
            total == 0 ? 0.0 : 100.0 * static_cast<double>(done) / static_cast<double>(total);
        std::fprintf(stderr, "\r%-12s %llu/%llu (%.1f%%)", label.c_str(),
                     static_cast<unsigned long long>(done),
                     static_cast<unsigned long long>(total), percent);
        if (finished) std::fprintf(stderr, "\n");
        return true;
    };
}

Result<ReportDestination> open_report_destination(const GlobalOptions& global,
                                                  const std::string& source,
                                                  const std::string& out_dir,
                                                  bool default_report) {
    ReportDestination destination;
    stdfs::path root;
    std::string relative;

    if (!out_dir.empty()) {
        root = path_from_utf8(out_dir);
        if (global.report.empty()) {
            if (default_report) relative = "report.json";
        } else {
            if (!safe_relative_report_path(global.report))
                return fail(ErrorCode::InvalidArgument,
                            "--report must be a '/'-separated path inside the output directory");
            relative = global.report;
        }
    } else if (!global.report.empty()) {
        const auto report_path = path_from_utf8(global.report);
        if (report_path.filename().empty() || report_path.filename() == ".")
            return fail(ErrorCode::InvalidArgument, "--report must name a file");
        root = report_path.parent_path();
        if (root.empty()) root = path_from_utf8(".");
        relative = path_to_utf8(report_path.filename());
    } else {
        return destination;
    }

    const io::SourceIdentity identity =
        source.empty() ? io::SourceIdentity{} : io::SourceIdentity::from_source_string(source);
    auto sink = io::OutputSink::open(root, identity);
    if (!sink) return fail(sink.error());
    destination.sink = std::move(*sink);
    if (!relative.empty()) {
        destination.report_relative = relative;
        const size_t slash = relative.rfind('/');
        destination.manifest_relative =
            (slash == std::string::npos ? std::string() : relative.substr(0, slash + 1)) +
            "manifest.csv";
    }
    return destination;
}

Result<void> write_report_destination(const ReportDestination& destination,
                                      const report::Report& report) {
    if (!destination.sink || destination.report_relative.empty()) return {};
    auto written = report::write_to_sink(*destination.sink, report, destination.report_relative,
                                 destination.manifest_relative);
    if (!written) return fail(written.error());
    return {};
}

Result<void> run_partitions(const GlobalOptions& global, const SourceOptions& source) {
    auto request = make_source_request(source);
    if (!request) return fail(request.error());
    auto opened = open_volume(*request, false);
    if (!opened) return fail(opened.error());
    if (opened->partitions().empty()) {
        if (opened->partitions_error()) return fail(*opened->partitions_error());
        return fail(ErrorCode::NoFilesystem,
                    "no MBR/GPT partition table or supported filesystem was found");
    }

    report::Report result = opened->base_report();
    auto destination = open_report_destination(global, source.source, "", false);
    if (!destination) return fail(destination.error());
    auto written = write_report_destination(*destination, result);
    if (!written) return fail(written.error());

    if (global.json) {
        std::cout << report::to_json(result);
        return {};
    }
    std::printf("%5s  %-10s %14s %14s  %s\n", "index", "scheme", "start_byte", "length", "fs");
    for (const report::PartitionSummary& part : result.partitions) {
        std::printf("%5u  %-10s %14llu %14llu  %s\n", part.index, part.scheme.c_str(),
                    static_cast<unsigned long long>(part.start),
                    static_cast<unsigned long long>(part.length), part.fs.c_str());
    }
    return {};
}

Result<void> run_scan(const GlobalOptions& global, const SourceOptions& source) {
    auto request = make_source_request(source);
    if (!request) return fail(request.error());
    auto opened = open_volume(*request, true);
    if (!opened) return fail(opened.error());

    report::Report result = opened->base_report();
    auto files = opened->scanner()->scan_deleted(fs::ScanOptions{}, make_progress(global, "metadata"));
    if (!files) return fail(files.error());

    result.statistics.deleted_entries_found = files->size();
    result.files.reserve(files->size());
    for (const RecoveredFile& file : *files) {
        result.files.push_back(make_file_entry(file, opened->view_offset()));
    }
    report::finalize(result);

    auto destination = open_report_destination(global, source.source, "", false);
    if (!destination) return fail(destination.error());
    auto written = write_report_destination(*destination, result);
    if (!written) return fail(written.error());

    if (global.json) {
        std::cout << report::to_json(result);
        return {};
    }
    std::printf("%-8s %10s  %s\n", "confidence", "size", "path");
    for (const report::FileEntry& file : result.files) {
        std::printf("%-8s %10llu  %s\n", confidence_name(file.confidence),
                    static_cast<unsigned long long>(file.size), file.path.c_str());
    }
    std::printf("%llu deleted entr%s found\n",
                static_cast<unsigned long long>(result.statistics.deleted_entries_found),
                result.statistics.deleted_entries_found == 1 ? "y" : "ies");
    return {};
}

Result<void> run_recover(const GlobalOptions& global, const RecoverCommandOptions& options) {
    const bool want_metadata = options.mode == "metadata" || options.mode == "both";
    const bool want_carve = options.mode == "carve" || options.mode == "both";
    if (!want_metadata && !want_carve)
        return fail(ErrorCode::InvalidArgument, "invalid recover mode: " + options.mode);

    auto request = make_source_request(options.source);
    if (!request) return fail(request.error());
    auto opened = open_volume(*request, want_metadata);
    if (!opened) return fail(opened.error());

    auto destination = open_report_destination(global, options.source.source, options.out, true);
    if (!destination) return fail(destination.error());
    if (!destination->sink)
        return fail(ErrorCode::InvalidArgument, "an output directory is required");

    auto filter = make_filter(options.carve);
    if (!filter) return fail(filter.error());

    report::Report result = opened->base_report();
    std::vector<RecoveredFile> accepted;

    if (want_metadata) {
        auto exported = export_metadata(*opened, *destination->sink, *filter,
                                        make_progress(global, "metadata"), result, &accepted);
        if (!exported) return fail(exported.error());
    }

    if (want_carve) {
        const auto carving = make_carve_request(options.carve, *filter);
        auto carved = carve_and_export(*opened, *destination->sink, carving, *filter,
                                       make_progress(global, "carve"), result,
                                       want_metadata ? &accepted : nullptr);
        if (!carved) return fail(carved.error());
    }

    report::finalize(result);
    auto written = write_report_destination(*destination, result);
    if (!written) return fail(written.error());

    if (global.json) {
        std::cout << report::to_json(result);
        return {};
    }
    std::printf("deleted entries found: %llu\n",
                static_cast<unsigned long long>(result.statistics.deleted_entries_found));
    std::printf("files exported:        %llu\n",
                static_cast<unsigned long long>(result.statistics.exported));
    std::printf("carved hits:           %llu\n",
                static_cast<unsigned long long>(result.statistics.carve_hits));
    std::printf("duplicates skipped:    %llu\n",
                static_cast<unsigned long long>(result.statistics.duplicates_skipped));
    std::printf("report: %s\n",
                path_to_utf8(destination->sink->root() /
                             path_from_utf8(destination->report_relative))
                    .c_str());
    for (const std::string& warning : result.warnings) log::warn(warning);
    return {};
}

Result<void> run_carve(const GlobalOptions& global, const RecoverCommandOptions& options) {
    RecoverCommandOptions carve_options = options;
    carve_options.mode = "carve";
    return run_recover(global, carve_options);
}

namespace {

struct DeviceRow {
    std::string path;
    std::string description;
    uint64_t size_bytes = 0;
    uint32_t sector_size = 0;
};

std::vector<DeviceRow> enumerate_physical_devices(std::vector<std::string>& warnings) {
    (void)warnings;
    std::vector<DeviceRow> rows;
#if defined(_WIN32)
    for (uint32_t i = 0; i < 32; ++i) {
        auto device = io::open_physical_drive(i, io::OpenOptions{});
        if (!device) continue;
        DeviceRow row;
        row.path = "\\\\.\\PhysicalDrive" + std::to_string(i);
        row.description = (*device)->info().description;
        row.size_bytes = (*device)->info().size_bytes;
        row.sector_size = (*device)->info().logical_sector_size;
        rows.push_back(std::move(row));
    }
#elif defined(__linux__)
    std::error_code ec;
    stdfs::directory_iterator iterator("/sys/block", ec);
    if (ec) {
        warnings.push_back("cannot list /sys/block: " + ec.message());
        return rows;
    }
    for (const auto& entry : iterator) {
        const std::string name = entry.path().filename().string();
        if (name.rfind("loop", 0) == 0 || name.rfind("ram", 0) == 0 ||
            name.rfind("zram", 0) == 0)
            continue;
        std::ifstream size_file(entry.path() / "size");
        uint64_t sectors = 0;
        if (!(size_file >> sectors) || sectors == 0) continue;
        DeviceRow row;
        row.path = "/dev/" + name;
        row.description = name;
        if (std::ifstream model(entry.path() / "device" / "model"); model) {
            std::string text;
            std::getline(model, text);
            if (!text.empty()) row.description = text;
        }
        row.size_bytes = sectors * 512;
        row.sector_size = 512;
        rows.push_back(std::move(row));
    }
#else
    warnings.push_back("physical device enumeration is not supported on this platform");
#endif
    return rows;
}

}  // namespace

Result<void> run_devices(const GlobalOptions& global) {
    std::vector<std::string> warnings;
    const std::vector<DeviceRow> devices = enumerate_physical_devices(warnings);

    std::vector<android::UsbDeviceInfo> android_devices;
    auto enumerator = android::make_usb_enumerator();
    if (!enumerator) {
        warnings.push_back("Android USB enumeration failed: " + enumerator.error().message);
    } else {
        auto found = (*enumerator)->enumerate();
        if (!found) warnings.push_back("Android USB enumeration failed: " + found.error().message);
        else android_devices = std::move(*found);
    }

    if (!global.report.empty()) {
        report::Report result;
        result.generated_at = report::generated_at_utc();
        result.source.description = "host";
        result.warnings = warnings;
        auto destination = open_report_destination(global, "", "", false);
        if (!destination) return fail(destination.error());
        auto written = write_report_destination(*destination, result);
        if (!written) return fail(written.error());
    }

    if (global.json) {
        nlohmann::ordered_json root;
        nlohmann::ordered_json devices_json = nlohmann::ordered_json::array();
        for (const DeviceRow& device : devices) {
            devices_json.push_back({{"path", device.path},
                                    {"description", device.description},
                                    {"size_bytes", device.size_bytes},
                                    {"sector_size", device.sector_size}});
        }
        nlohmann::ordered_json android_json = nlohmann::ordered_json::array();
        for (const android::UsbDeviceInfo& device : android_devices) {
            android_json.push_back(
                {{"vid", device.vid},
                 {"pid", device.pid},
                 {"serial", device.serial_usb},
                 {"manufacturer", device.manufacturer},
                 {"product", device.product},
                 {"adb_interface", device.has_adb_interface},
                 {"known_android_vid", device.known_android_vid}});
        }
        nlohmann::ordered_json warnings_json = nlohmann::ordered_json::array();
        for (const std::string& warning : warnings) warnings_json.push_back(warning);
        root["devices"] = std::move(devices_json);
        root["android_candidates"] = std::move(android_json);
        root["warnings"] = std::move(warnings_json);
        std::cout << root.dump(2) << "\n";
        return {};
    }

    std::printf("%-24s %14s %7s  %s\n", "device", "size_bytes", "sector", "description");
    for (const DeviceRow& device : devices) {
        std::printf("%-24s %14llu %7u  %s\n", device.path.c_str(),
                    static_cast<unsigned long long>(device.size_bytes), device.sector_size,
                    device.description.c_str());
    }
    if (!android_devices.empty()) {
        std::printf("\nAndroid USB candidates:\n");
        for (const android::UsbDeviceInfo& device : android_devices) {
            std::printf("  %04x:%04x  %-20s %s%s\n", device.vid, device.pid,
                        device.serial_usb.c_str(), device.product.c_str(),
                        device.has_adb_interface ? " [adb]" : "");
        }
    }
    for (const std::string& warning : warnings) log::warn(warning);
    return {};
}

namespace {

Result<std::string> hash_file(const stdfs::path& path, uint64_t& size) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return fail(ErrorCode::NotFound, "cannot open " + path_to_utf8(path));
    Sha256Hasher hasher;
    std::vector<uint8_t> buffer(1u << 20);
    size = 0;
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()),
                   static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = input.gcount();
        if (got > 0) {
            hasher.update(buffer.data(), static_cast<size_t>(got));
            size += static_cast<uint64_t>(got);
        }
    }
    if (!input.eof()) return fail(ErrorCode::IoError, "read failed for " + path_to_utf8(path));
    return hasher.finish_hex();
}

bool report_relative_safe(const std::string& relative) {
    return safe_relative_report_path(relative);
}

}  // namespace

Result<int> run_verify(const GlobalOptions& global, const std::string& report_path) {
    const stdfs::path path = path_from_utf8(report_path);
#if defined(_WIN32)
    std::ifstream input(win_long_path(path), std::ios::binary);
#else
    std::ifstream input(path, std::ios::binary);
#endif
    if (!input) return fail(ErrorCode::NotFound, "cannot open report: " + report_path);
    std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    if (!input.eof() && input.fail())
        return fail(ErrorCode::IoError, "cannot read report: " + report_path);
    const auto parsed = nlohmann::json::parse(text, nullptr, false);
    if (parsed.is_discarded())
        return fail(ErrorCode::CorruptStructure, "report is not valid JSON: " + report_path);

    std::error_code ec;
    stdfs::path base = path.parent_path();
    if (base.empty()) base = path_from_utf8(".");
    base = stdfs::weakly_canonical(stdfs::absolute(base, ec), ec);
    if (ec) return fail(ErrorCode::IoError, "cannot resolve the report directory: " + ec.message());

    uint64_t checked = 0;
    uint64_t verified = 0;
    nlohmann::ordered_json failures = nlohmann::ordered_json::array();

    const auto check_entry = [&](const nlohmann::json& entry, bool check_size) {
        if (!entry.is_object()) return;
        if (!entry.contains("exported_to") || !entry["exported_to"].is_string()) return;
        const std::string relative = entry["exported_to"].get<std::string>();
        if (relative.empty()) return;
        ++checked;
        if (!report_relative_safe(relative)) {
            failures.push_back({{"path", relative}, {"error", "unsafe exported path"}});
            return;
        }
        const stdfs::path file_path = base / path_from_utf8(relative);
        auto canonical = stdfs::weakly_canonical(file_path, ec);
        if (ec || !io::path_is_within(canonical, base)) {
            failures.push_back({{"path", relative}, {"error", "path escapes the report directory"}});
            return;
        }
#if defined(_WIN32)
        const stdfs::path accessible = win_long_path(canonical);
#else
        const stdfs::path& accessible = canonical;
#endif
        if (!stdfs::is_regular_file(accessible, ec)) {
            failures.push_back({{"path", relative}, {"error", "missing file"}});
            return;
        }
        uint64_t size = 0;
        auto digest = hash_file(accessible, size);
        if (!digest) {
            failures.push_back({{"path", relative}, {"error", digest.error().message}});
            return;
        }
        if (entry.contains("sha256") && entry["sha256"].is_string() &&
            !entry["sha256"].get<std::string>().empty() &&
            entry["sha256"].get<std::string>() != *digest) {
            failures.push_back({{"path", relative}, {"error", "sha256 mismatch"}});
            return;
        }
        if (check_size && entry.contains("size") && entry["size"].is_number_unsigned() &&
            entry["size"].get<uint64_t>() != size) {
            failures.push_back({{"path", relative}, {"error", "size mismatch"}});
            return;
        }
        ++verified;
    };

    if (parsed.contains("files") && parsed["files"].is_array()) {
        for (const auto& entry : parsed["files"]) check_entry(entry, true);
    }
    if (parsed.contains("carved") && parsed["carved"].is_array()) {
        for (const auto& entry : parsed["carved"]) check_entry(entry, false);
    }

    if (global.json) {
        nlohmann::ordered_json root;
        root["checked"] = checked;
        root["verified"] = verified;
        root["failures"] = std::move(failures);
        std::cout << root.dump(2) << "\n";
    } else {
        std::printf("checked %llu exported file(s), verified %llu\n",
                    static_cast<unsigned long long>(checked),
                    static_cast<unsigned long long>(verified));
        for (const auto& failure : failures) {
            std::printf("FAILED %s: %s\n", failure["path"].get<std::string>().c_str(),
                        failure["error"].get<std::string>().c_str());
        }
    }
    return verified == checked ? 0 : 1;
}

}  // namespace openrecover::cli
