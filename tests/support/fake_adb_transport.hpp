#pragma once

#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "openrecover/android/adb_transport.hpp"

namespace openrecover::test {

// In-memory-backed adb transport for the scan/pull tests. Device paths under
// /sdcard (and /storage/emulated/0) map onto a fixture directory; every command
// goes through the real allowlist helpers first.
class FakeAdbTransport final : public android::IAdbTransport {
public:
    explicit FakeAdbTransport(std::filesystem::path sdcard_root,
                              std::string serial = "FAKE1234");

    Result<std::vector<android::AdbDevice>> list_devices() override;
    Result<std::string> shell_readonly(const std::string& serial,
                                       const android::AdbShellCmd& cmd) override;
    Result<void> pull(const std::string& serial, const std::string& remote,
                      const std::filesystem::path& local_tmp) override;

    void set_state(android::AdbState state) { state_ = state; }
    void remove_device() { has_device_ = false; }
    void set_sdcard_present(bool present) { sdcard_present_ = present; }
    void set_shell_timeout(bool enabled) { shell_timeout_ = enabled; }
    void set_pull_timeout(bool enabled) { pull_timeout_ = enabled; }
    void set_truncate_pull(bool enabled) { truncate_pull_ = enabled; }
    void deny_path(std::string prefix) { denied_.insert(std::move(prefix)); }
    void deny_stat_path(std::string prefix) { denied_stats_.insert(std::move(prefix)); }
    void clear_denied_paths() {
        denied_.clear();
        denied_stats_.clear();
    }
    void set_property(std::string key, std::string value) {
        properties_[std::move(key)] = std::move(value);
    }

    int shell_calls() const noexcept { return shell_calls_; }
    int pull_calls() const noexcept { return pull_calls_; }
    int list_files_calls() const noexcept { return list_files_calls_; }
    const std::string& serial() const noexcept { return serial_; }
    const std::vector<std::string>& pulled_paths() const noexcept { return pulled_paths_; }

private:
    Result<std::filesystem::path> local_path_for(const std::string& remote) const;
    bool is_denied(const std::string& remote) const;
    void collect_files(const std::filesystem::path& local_dir, const std::string& remote_dir,
                       std::vector<std::string>& files) const;

    std::filesystem::path root_;
    std::string serial_;
    android::AdbState state_ = android::AdbState::Device;
    bool has_device_ = true;
    bool sdcard_present_ = true;
    bool shell_timeout_ = false;
    bool pull_timeout_ = false;
    bool truncate_pull_ = false;
    std::set<std::string> denied_;
    std::set<std::string> denied_stats_;
    std::map<std::string, std::string> properties_;
    int shell_calls_ = 0;
    int pull_calls_ = 0;
    int list_files_calls_ = 0;
    std::vector<std::string> pulled_paths_;
};

}  // namespace openrecover::test
