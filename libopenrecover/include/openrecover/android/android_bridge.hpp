#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "openrecover/android/adb_transport.hpp"
#include "openrecover/android/scan_profile.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"

namespace openrecover::io {
class OutputSink;
}

namespace openrecover::android {

struct AndroidProbeInfo {
    std::string serial;
    std::string model;
    std::string manufacturer;
    std::string release;
    std::string sdk_raw;
    int sdk = 0;
    std::string crypto_state;
};

struct AndroidRootResult {
    std::string id;
    std::string path;
    std::string kind;
    // "ok" | "absent" | "access_denied"
    std::string status;
    size_t files = 0;
    size_t pulled = 0;
};

struct AndroidFile {
    std::string remote_path;
    std::string local_relative;  // empty for scan-only runs
    std::string sha256;          // empty for scan-only runs
    uint64_t size_bytes = 0;
    int64_t mtime_unix = 0;
    Confidence confidence = Confidence::Low;
    std::string root_id;
    std::string kind;
    std::string type;
    std::string note;
    std::optional<uint64_t> trashed_expires_at;
    bool pulled = false;
};

struct AndroidScanResult {
    AndroidProbeInfo probe;
    std::vector<AndroidRootResult> roots;
    std::vector<AndroidFile> files;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations;
};

struct AndroidBridgeOptions {
    std::filesystem::path out_dir;   // required by scan_and_pull
    std::filesystem::path temp_dir;  // empty = system temporary directory
    bool validate_media = true;
};

// Read-only Android scan/pull pipeline (section 6.4). Files reach the output tree only
// through OutputSink, and only allowlisted transport commands are issued.
class AndroidBridge {
public:
    AndroidBridge(IAdbTransport& transport, AndroidBridgeOptions options);

    Result<AndroidProbeInfo> probe(const std::string& serial);
    // Enumerates and stats candidate files without writing anything.
    Result<AndroidScanResult> scan(const std::string& serial, const AndroidScanProfile& profile,
                                   const ProgressFn& progress = {});
    // Same enumeration, then pulls every accepted file into out_dir.
    Result<AndroidScanResult> scan_and_pull(const std::string& serial,
                                            const AndroidScanProfile& profile,
                                            const ProgressFn& progress = {});

private:
    Result<AndroidScanResult> scan_impl(const std::string& serial, const AndroidScanProfile& profile,
                                        const ProgressFn& progress, io::OutputSink* sink);

    IAdbTransport& transport_;
    AndroidBridgeOptions options_;
};

// Limitations every Android report must state (section 6.0), plus the scoped-storage
// note when the device reports SDK >= 30.
std::vector<std::string> android_limitations(int sdk);

// Refuses output locations on MTP/gvfs mounts. Exposed so every Android command
// (including scan-only report writing) applies the guard before creating anything.
Result<void> ensure_local_output_location(const std::filesystem::path& out_dir);

}  // namespace openrecover::android
