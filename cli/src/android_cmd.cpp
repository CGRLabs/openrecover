#include "cli_internal.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

#include "openrecover/android/adb_transport.hpp"
#include "openrecover/android/android_bridge.hpp"
#include "openrecover/android/scan_profile.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/path_util.hpp"

namespace openrecover::cli {

namespace stdfs = std::filesystem;

namespace {

stdfs::path executable_directory() {
#if defined(_WIN32)
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                            static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return {};
    return stdfs::path(std::wstring(buffer.data(), length)).parent_path();
#elif defined(__linux__)
    std::vector<char> buffer(4096);
    const ssize_t length = ::readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
    if (length <= 0) return {};
    buffer[static_cast<size_t>(length)] = '\0';
    return stdfs::path(buffer.data()).parent_path();
#else
    return {};
#endif
}

std::string environment_value(const char* name) {
#if defined(_WIN32)
    char* value = nullptr;
    size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) return {};
    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
#endif
}

std::vector<stdfs::path> profile_directories(const stdfs::path& exe_dir) {
    std::vector<stdfs::path> dirs;
    const std::string env = environment_value("OPENRECOVER_PROFILE_DIR");
    if (!env.empty()) dirs.push_back(path_from_utf8(env));
    if (!exe_dir.empty()) {
        dirs.push_back(exe_dir / "profiles");
        dirs.push_back(exe_dir.parent_path() / "profiles");
        dirs.push_back(exe_dir.parent_path() / "share" / "openrecover" / "profiles");
    }
    return dirs;
}

Result<stdfs::path> resolve_profile(const std::string& explicit_path, const stdfs::path& exe_dir) {
    if (!explicit_path.empty()) return path_from_utf8(explicit_path);
    std::error_code ec;
    for (const stdfs::path& dir : profile_directories(exe_dir)) {
        const stdfs::path candidate = dir / "default.json";
        if (stdfs::is_regular_file(candidate, ec)) return candidate;
    }
    return fail(ErrorCode::NotFound,
                "the default Android scan profile was not found; pass --profile <file> or set "
                "OPENRECOVER_PROFILE_DIR");
}

Result<std::unique_ptr<android::IAdbTransport>> make_transport(const AndroidCommandOptions& options,
                                                               const stdfs::path& exe_dir) {
    if (options.backend == "subprocess") {
        auto transport = android::SubprocessAdbTransport::create(exe_dir, options.adb_path);
        if (!transport) return fail(transport.error());
        return std::unique_ptr<android::IAdbTransport>(std::move(*transport));
    }
    if (options.backend == "python") {
        android::PySidecarOptions sidecar;
        sidecar.exe_dir = exe_dir;
        sidecar.adb_path = options.adb_path;
        auto transport = android::PySidecarAdbTransport::create(sidecar);
        if (!transport) return fail(transport.error());
        return std::unique_ptr<android::IAdbTransport>(std::move(*transport));
    }
    return fail(ErrorCode::InvalidArgument,
                "unknown --adb-backend '" + options.backend + "' (expected subprocess or python)");
}

report::Report build_report(const std::string& serial, const android::AndroidScanResult& scan,
                            uint64_t exported) {
    report::Report result;
    result.generated_at = report::generated_at_utc();
    result.source.description = "android:" + serial;

    report::AndroidSummary summary;
    summary.device.serial = scan.probe.serial;
    summary.device.model = scan.probe.model;
    summary.device.manufacturer = scan.probe.manufacturer;
    summary.device.release = scan.probe.release;
    summary.device.sdk = scan.probe.sdk;
    for (const android::AndroidRootResult& root : scan.roots) {
        report::AndroidRootSummary root_summary;
        root_summary.id = root.id;
        root_summary.path = root.path;
        root_summary.kind = root.kind;
        root_summary.status = root.status;
        root_summary.files = root.files;
        root_summary.pulled = root.pulled;
        summary.roots.push_back(std::move(root_summary));
    }
    summary.limitations = scan.limitations;
    result.android = std::move(summary);

    for (const android::AndroidFile& file : scan.files) {
        report::FileEntry entry;
        entry.origin = FileOrigin::AndroidPull;
        entry.path = file.remote_path;
        entry.size = file.size_bytes;
        entry.confidence = file.confidence;
        entry.mtime_unix = file.mtime_unix;
        entry.sha256 = file.sha256;
        entry.exported_to = file.local_relative;
        entry.type = file.type;
        entry.note = file.note;
        if (file.trashed_expires_at) {
            if (!entry.note.empty()) entry.note += "; ";
            entry.note += "trashed_expires_at=" + std::to_string(*file.trashed_expires_at);
        }
        result.files.push_back(std::move(entry));
    }
    result.statistics.exported = exported;
    result.warnings = scan.warnings;
    report::finalize(result);
    return result;
}

void print_table(const report::Report& result) {
    std::printf("%-20s %-14s %8s %8s  %s\n", "root id", "status", "files", "pulled", "path");
    for (const report::AndroidRootSummary& root : result.android->roots) {
        std::printf("%-20s %-14s %8llu %8llu  %s\n", root.id.c_str(), root.status.c_str(),
                    static_cast<unsigned long long>(root.files),
                    static_cast<unsigned long long>(root.pulled), root.path.c_str());
    }
    if (!result.files.empty()) {
        std::printf("\n%-8s %12s  %s\n", "confidence", "size", "remote path");
        for (const report::FileEntry& file : result.files) {
            std::printf("%-8s %12llu  %s\n", confidence_name(file.confidence),
                        static_cast<unsigned long long>(file.size), file.path.c_str());
        }
    }
    std::printf("\n%llu file(s) recorded, %llu pulled\n",
                static_cast<unsigned long long>(result.files.size()),
                static_cast<unsigned long long>(result.statistics.exported));
    for (const std::string& limitation : result.android->limitations)
        log::info(limitation);
    for (const std::string& warning : result.warnings) log::warn(warning);
}

}  // namespace

Result<void> run_android(const GlobalOptions& global, const AndroidCommandOptions& options) {
    if (options.serial.empty())
        return fail(ErrorCode::InvalidArgument, "--serial is required");
    if (options.out.empty())
        return fail(ErrorCode::InvalidArgument, "--out is required");

    const stdfs::path exe_dir = executable_directory();
    auto profile_path = resolve_profile(options.profile, exe_dir);
    if (!profile_path) return fail(profile_path.error());
    auto profile = android::load_scan_profile(*profile_path);
    if (!profile) return fail(profile.error());

    const stdfs::path out_dir = path_from_utf8(options.out);
    auto local = android::ensure_local_output_location(out_dir);
    if (!local) return fail(local.error());

    auto transport = make_transport(options, exe_dir);
    if (!transport) return fail(transport.error());

    android::AndroidBridgeOptions bridge_options;
    bridge_options.out_dir = out_dir;
    if (!options.temp_dir.empty()) bridge_options.temp_dir = path_from_utf8(options.temp_dir);
    bridge_options.validate_media = options.validate;
    android::AndroidBridge bridge(**transport, bridge_options);

    const ProgressFn progress = make_progress(global, options.pull ? "android pull" : "android scan");
    auto scan = options.pull ? bridge.scan_and_pull(options.serial, *profile, progress)
                             : bridge.scan(options.serial, *profile, progress);
    if (!scan) return fail(scan.error());
    if (g_cancelled.load()) return fail(ErrorCode::Cancelled, "android scan cancelled");

    uint64_t exported = 0;
    for (const android::AndroidFile& file : scan->files)
        if (file.pulled) ++exported;
    report::Report result = build_report(options.serial, *scan, exported);

    auto destination = open_report_destination(global, "", options.out, true);
    if (!destination) return fail(destination.error());
    auto written = write_report_destination(*destination, result);
    if (!written) return fail(written.error());

    if (global.json) {
        std::cout << report::to_json(result);
        return {};
    }
    print_table(result);
    if (destination->sink)
        std::printf("report: %s\n",
                    path_to_utf8(destination->sink->root() /
                                 path_from_utf8(destination->report_relative))
                        .c_str());
    return {};
}

}  // namespace openrecover::cli
