#pragma once

#include <atomic>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/report/report.hpp"

namespace openrecover::cli {

struct GlobalOptions {
    bool json = false;
    int verbose = 0;
    bool no_progress = false;
    std::string report;
};

struct SourceOptions {
    std::string source;
    std::string fs = "auto";
    int partition = -1;
    std::string offset;
    uint32_t sector_size = 0;
    bool allow_shared_write_sharing = false;
};

struct CarveOptions {
    std::string min_confidence = "low";
    std::string types;
    std::string scope = "unallocated";
    bool scope_explicit = false;
    bool unaligned = false;
    bool deep = false;
    bool nested = false;
    bool no_reassemble = false;
    std::string max_size;
    std::string signature_pack;
};

struct RecoverCommandOptions {
    SourceOptions source;
    std::string out;
    std::string mode = "metadata";
    CarveOptions carve;
};

struct AndroidCommandOptions {
    bool pull = false;
    std::string serial;
    std::string out;
    std::string profile;
    std::string backend = "subprocess";
    std::string adb_path;
    std::string temp_dir;
    bool validate = true;
};

extern std::atomic<bool> g_cancelled;
void install_signal_handler();

Result<void> run_devices(const GlobalOptions& global);
Result<void> run_partitions(const GlobalOptions& global, const SourceOptions& source);
Result<void> run_scan(const GlobalOptions& global, const SourceOptions& source);
Result<void> run_recover(const GlobalOptions& global, const RecoverCommandOptions& options);
Result<void> run_carve(const GlobalOptions& global, const RecoverCommandOptions& options);
Result<int> run_verify(const GlobalOptions& global, const std::string& report_path);
Result<void> run_android(const GlobalOptions& global, const AndroidCommandOptions& options);

}  // namespace openrecover::cli
