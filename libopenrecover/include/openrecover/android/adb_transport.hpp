#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/android/adb_command_policy.hpp"
#include "openrecover/common/result.hpp"

namespace openrecover::android {

class ChildSession;

enum class AdbState { Device, Unauthorized, Offline, NoPermissions, Recovery, Sideload, Unknown };

const char* adb_state_name(AdbState state) noexcept;
AdbState adb_state_from_string(std::string_view raw) noexcept;
bool adb_state_ready(AdbState state) noexcept;

struct AdbDevice {
    std::string serial;
    AdbState state = AdbState::Unknown;
    std::string state_raw;
    std::string model;
    std::string product;
    std::string transport_id;
};

struct AdbTimeouts {
    std::chrono::milliseconds server{30000};
    std::chrono::milliseconds shell{30000};
    std::chrono::milliseconds pull{900000};
};

struct RemoteStat {
    std::string path;
    uint64_t size = 0;
    int64_t mtime = 0;
};

// Transport used by the scan pipeline. Implementations: subprocess (default),
// Python sidecar (optional) and the in-memory fake used by tests.
class IAdbTransport {
public:
    virtual ~IAdbTransport() = default;
    virtual Result<std::vector<AdbDevice>> list_devices() = 0;
    // Returns stdout. For TestDir the transport returns "1" when the directory exists
    // and "0" when it does not; a permission failure yields Error{AccessDenied}.
    virtual Result<std::string> shell_readonly(const std::string& serial, const AdbShellCmd&) = 0;
    virtual Result<void> pull(const std::string& serial, const std::string& remote,
                              const std::filesystem::path& local_tmp) = 0;
};

// Searches explicit_path, OPENRECOVER_ADB, <exe_dir>/platform-tools/adb(.exe), then PATH.
Result<std::string> locate_adb(const std::filesystem::path& exe_dir,
                               const std::string& explicit_path);

Result<std::vector<AdbDevice>> parse_adb_devices_output(std::string_view text);
Result<std::vector<std::string>> parse_find_output(std::string_view text);
Result<std::vector<RemoteStat>> parse_stat_output(std::string_view text);

class SubprocessAdbTransport final : public IAdbTransport {
public:
    static Result<std::unique_ptr<SubprocessAdbTransport>> create(
        const std::filesystem::path& exe_dir = {}, const std::string& explicit_adb_path = {},
        AdbTimeouts timeouts = {});

    Result<std::vector<AdbDevice>> list_devices() override;
    Result<std::string> shell_readonly(const std::string& serial, const AdbShellCmd&) override;
    Result<void> pull(const std::string& serial, const std::string& remote,
                      const std::filesystem::path& local_tmp) override;

    const std::string& adb_path() const noexcept { return adb_path_; }

private:
    SubprocessAdbTransport(std::string adb_path, AdbTimeouts timeouts)
        : adb_path_(std::move(adb_path)), timeouts_(timeouts) {}

    Result<std::string> shell_stdout(const std::vector<std::string>& argv,
                                     std::chrono::milliseconds timeout);

    std::string adb_path_;
    AdbTimeouts timeouts_;
};

struct PySidecarOptions {
    std::filesystem::path exe_dir;
    std::string adb_path;  // --adb-path
    std::filesystem::path python;
    std::filesystem::path sidecar_script;
    std::filesystem::path policy_path;
    AdbTimeouts timeouts;
};

// Resolves the Python interpreter from an explicit value, OPENRECOVER_PYTHON, then
// `python3`/`python`, verifying each candidate by running `--version`.
Result<std::string> locate_python(const std::string& explicit_path);

// Optional backend that talks JSON Lines to tools/adb_sidecar/sidecar.py, which uses
// pure-python-adb. The adb server is still started through the adb executable.
class PySidecarAdbTransport final : public IAdbTransport {
public:
    static Result<std::unique_ptr<PySidecarAdbTransport>> create(const PySidecarOptions& options);
    ~PySidecarAdbTransport() override;

    PySidecarAdbTransport(const PySidecarAdbTransport&) = delete;
    PySidecarAdbTransport& operator=(const PySidecarAdbTransport&) = delete;

    Result<std::vector<AdbDevice>> list_devices() override;
    Result<std::string> shell_readonly(const std::string& serial, const AdbShellCmd&) override;
    Result<void> pull(const std::string& serial, const std::string& remote,
                      const std::filesystem::path& local_tmp) override;

    const std::string& python_path() const noexcept { return python_path_; }
    const std::string& ppadb_version() const noexcept { return ppadb_version_; }

private:
    PySidecarAdbTransport(std::unique_ptr<ChildSession> session, AdbTimeouts timeouts,
                          std::string python_path, std::string ppadb_version);

    std::unique_ptr<ChildSession> session_;
    AdbTimeouts timeouts_;
    std::string python_path_;
    std::string ppadb_version_;
    uint64_t next_id_ = 1;
};

}  // namespace openrecover::android
