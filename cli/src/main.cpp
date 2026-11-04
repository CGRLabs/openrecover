#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

#include <CLI/CLI.hpp>

#include "cli_common.hpp"
#include "openrecover/common/error.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/readonly.hpp"

#ifndef OPENRECOVER_VERSION
#define OPENRECOVER_VERSION "1.4.0"
#endif

namespace {

using openrecover::cli::AndroidCommandOptions;
using openrecover::cli::CarveOptions;
using openrecover::cli::GlobalOptions;
using openrecover::cli::RecoverCommandOptions;
using openrecover::cli::SourceOptions;

void add_source_options(CLI::App* command, SourceOptions& options) {
    command->add_option("--source", options.source, "Device path or disk image")->required();
    command->add_option("--fs", options.fs, "Filesystem: auto, fat32, ntfs, exfat or ext4")
        ->check(CLI::IsMember({"auto", "fat32", "ntfs", "exfat", "ext4"}))
        ->capture_default_str();
    auto* partition = command->add_option("--partition", options.partition,
                                          "Partition index from the partition table");
    auto* offset = command->add_option("--offset", options.offset,
                                       "Absolute byte offset of the filesystem (0x... accepted)");
    partition->excludes(offset);
    command->add_option("--sector-size", options.sector_size,
                        "Override the logical sector size in bytes");
    command->add_flag("--allow-shared-write-sharing", options.allow_shared_write_sharing,
                      "Allow opening a Windows volume shared with a mounted filesystem");
}

void add_carve_options(CLI::App* command, CarveOptions& options) {
    command->add_option("--min-confidence", options.min_confidence,
                        "Minimum confidence: low, medium or high")
        ->check(CLI::IsMember({"low", "medium", "high"}))
        ->capture_default_str();
    command->add_option("--types", options.types,
                        "Comma-separated carve/recovery types "
                        "(jpeg,png,pdf,zip,gif,bmp,tiff,wav,sqlite,mp4,avi,mp3,cfb)");
    command->add_option("--scope", options.scope, "Carving scope: unallocated or all")
        ->check(CLI::IsMember({"unallocated", "all"}))
        ->capture_default_str();
    command->add_flag("--unaligned", options.unaligned,
                      "Also search at sector-unaligned offsets");
    command->add_flag("--deep", options.deep, "Run full structural validation");
    command->add_flag("--nested", options.nested,
                      "Also export signatures nested inside other carved files");
    command->add_flag("--no-reassemble", options.no_reassemble,
                      "Do not join a JPEG or PNG that resumes after a discontinuity");
    command->add_option("--max-size", options.max_size,
                        "Per-type export limit, e.g. jpeg=10M,pdf=2G");
    command->add_option("--signature-pack", options.signature_pack,
                        "JSON file of additional magic-byte signatures");
}

void add_source_flags_only(CLI::App* command, SourceOptions& options) {
    command->add_option("--sector-size", options.sector_size,
                        "Override the logical sector size in bytes");
    command->add_flag("--allow-shared-write-sharing", options.allow_shared_write_sharing,
                      "Allow opening a Windows volume shared with a mounted filesystem");
}

void add_android_options(CLI::App* command, AndroidCommandOptions& options, bool& no_validate) {
    command->add_option("--serial", options.serial, "ADB serial of the device")->required();
    command->add_option("--out", options.out, "Output directory")->required();
    command->add_option("--profile", options.profile, "Android scan profile JSON");
    command->add_option("--adb-backend", options.backend, "ADB backend: subprocess or python")
        ->check(CLI::IsMember({"subprocess", "python"}))
        ->capture_default_str();
    command->add_option("--adb-path", options.adb_path, "Path to the adb executable");
    command->add_option("--temp-dir", options.temp_dir, "Directory for staged pulls");
    command->add_flag("--no-validate", no_validate,
                      "Skip structural validation of pulled media");
}

int fail_with(const openrecover::Error& error) {
    openrecover::log::error(error.to_string());
    return openrecover::exit_code_for_error(error.code);
}

int usage_error(const std::string& message) {
    openrecover::log::error(message);
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace openrecover;

    cli::install_signal_handler();

    CLI::App app{"OpenRecover - read-only deleted-file recovery"};
    app.set_version_flag("--version", std::string("openrecover ") + OPENRECOVER_VERSION);
    app.require_subcommand(1);
    app.fallthrough();

    GlobalOptions global;
    app.add_flag("--json", global.json, "Emit machine-readable JSON on stdout");
    app.add_flag("-v", global.verbose, "Increase verbosity (-v, -vv)");
    app.add_flag("--no-progress", global.no_progress, "Disable progress output");
    app.add_option("--report", global.report,
                   "Report path (with --out: relative to the output directory); also the "
                   "input for verify");

    SourceOptions partitions_source;
    app.add_subcommand("devices", "List physical drives and Android USB candidates");
    auto* partitions = app.add_subcommand("partitions", "Show MBR/GPT partitions and filesystems");
    partitions->add_option("--source", partitions_source.source, "Device path or disk image")
        ->required();
    add_source_flags_only(partitions, partitions_source);

    SourceOptions scan_source;
    auto* scan = app.add_subcommand("scan", "List deleted files from filesystem metadata");
    add_source_options(scan, scan_source);

    RecoverCommandOptions recover_options;
    auto* recover = app.add_subcommand("recover", "Export recoverable files");
    add_source_options(recover, recover_options.source);
    recover->add_option("--out", recover_options.out, "Output directory")->required();
    recover
        ->add_option("--mode", recover_options.mode, "metadata, carve or both")
        ->check(CLI::IsMember({"metadata", "carve", "both"}))
        ->capture_default_str();
    add_carve_options(recover, recover_options.carve);

    RecoverCommandOptions carve_options;
    auto* carve = app.add_subcommand("carve", "Carve files by signature");
    add_source_options(carve, carve_options.source);
    carve->add_option("--out", carve_options.out, "Output directory")->required();
    add_carve_options(carve, carve_options.carve);

    auto* android = app.add_subcommand("android", "Read-only Android scan and pull")->require_subcommand(1);
    android->fallthrough();

    AndroidCommandOptions android_scan_options;
    bool android_scan_no_validate = false;
    auto* android_scan = android->add_subcommand("scan", "List candidate files on the device");
    add_android_options(android_scan, android_scan_options, android_scan_no_validate);

    AndroidCommandOptions android_pull_options;
    android_pull_options.pull = true;
    bool android_pull_no_validate = false;
    auto* android_pull = android->add_subcommand("pull", "Pull candidate files to --out");
    add_android_options(android_pull, android_pull_options, android_pull_no_validate);

    auto* verify = app.add_subcommand("verify", "Re-hash exported files against a report");
    verify->footer("The report path is given with the global --report option.");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& error) {
        const int code = error.get_exit_code();
        app.exit(error);
        return code == 0 ? 0 : 2;
    }

    if (global.verbose >= 2)
        log::set_level(LogLevel::Trace);
    else if (global.verbose == 1)
        log::set_level(LogLevel::Debug);

    try {
        if (app.got_subcommand("partitions")) {
            auto result = cli::run_partitions(global, partitions_source);
            return result ? 0 : fail_with(result.error());
        }
        if (app.got_subcommand("scan")) {
            auto result = cli::run_scan(global, scan_source);
            return result ? 0 : fail_with(result.error());
        }
        if (app.got_subcommand("recover")) {
            auto* command = app.get_subcommand("recover");
            recover_options.carve.scope_explicit = command->get_option("--scope")->count() > 0;
            auto result = cli::run_recover(global, recover_options);
            return result ? 0 : fail_with(result.error());
        }
        if (app.got_subcommand("carve")) {
            auto* command = app.get_subcommand("carve");
            carve_options.carve.scope_explicit = command->get_option("--scope")->count() > 0;
            auto result = cli::run_carve(global, carve_options);
            return result ? 0 : fail_with(result.error());
        }
        if (app.got_subcommand("devices")) {
            auto result = cli::run_devices(global);
            return result ? 0 : fail_with(result.error());
        }
        if (app.got_subcommand("android")) {
            auto* command = app.get_subcommand("android");
            if (command->got_subcommand("scan")) {
                android_scan_options.validate = !android_scan_no_validate;
                auto result = cli::run_android(global, android_scan_options);
                return result ? 0 : fail_with(result.error());
            }
            android_pull_options.validate = !android_pull_no_validate;
            auto result = cli::run_android(global, android_pull_options);
            return result ? 0 : fail_with(result.error());
        }
        if (app.got_subcommand("verify")) {
            if (global.report.empty()) return usage_error("verify requires --report <file>");
            auto result = cli::run_verify(global, global.report);
            if (!result) return fail_with(result.error());
            return *result;
        }
    } catch (const ReadOnlyViolation& violation) {
        log::error(std::string("read-only violation: ") + violation.what());
        return 70;
    } catch (const std::exception& error) {
        log::error(error.what());
        return 1;
    }

    return usage_error("no command was selected");
}
