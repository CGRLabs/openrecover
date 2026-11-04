#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/result.hpp"

namespace openrecover::android {

inline constexpr size_t kMaxRemotePathBytes = 4096;
inline constexpr size_t kMaxStatFiles = 64;
inline constexpr std::string_view kStatFormat = "%s|%Y|%n";
// Shell metacharacters refused in remote paths; backslash and control characters are
// rejected separately. Kept in sync with tools/adb_sidecar/policy.json via adb_policy_dump.
inline constexpr std::string_view kForbiddenRemotePathChars = "\"$`;&|<>(){}[]*?!#";

// A closed set of device-side commands. There is deliberately no way to pass a free
// string to `adb shell`.
class AdbShellCmd {
public:
    enum class Kind { GetProp, ListFiles, StatBatch, TestDir };

    static Result<AdbShellCmd> get_prop(std::string key);
    static Result<AdbShellCmd> list_files(std::string dir);
    static Result<AdbShellCmd> stat_batch(std::vector<std::string> files);
    static Result<AdbShellCmd> test_dir(std::string dir);

    Kind kind() const noexcept { return kind_; }
    const std::string& key() const noexcept { return key_; }
    const std::string& dir() const noexcept { return dir_; }
    const std::vector<std::string>& files() const noexcept { return files_; }

    // Unquoted device-side argv, e.g. {"find", "/sdcard/DCIM", "-type", "f"}.
    std::vector<std::string> device_argv() const;
    // The single argument passed after `adb shell`, with every dynamic value quoted
    // for the device shell.
    std::string shell_command_line() const;

private:
    Kind kind_ = Kind::GetProp;
    std::string key_;
    std::string dir_;
    std::vector<std::string> files_;
};

// Shared-storage path validation (section 6.2.1). `/sdcard`, `/storage/emulated/0`
// and a `/storage/XXXX-XXXX` mount root are accepted exactly as well as subtrees.
Result<void> validate_remote_path(std::string_view path);
Result<void> validate_prop_key(std::string_view key);
Result<void> validate_adb_serial(std::string_view serial);

// Wraps `arg` in single quotes, replacing each `'` with `'\''`.
std::string shell_quote(std::string_view arg);

bool is_denied_adb_verb(std::string_view verb);
const std::vector<std::string>& denied_adb_verbs();

// Splits a POSIX command line the way the device shell would for our quoted forms.
Result<std::vector<std::string>> parse_shell_command_line(std::string_view line);

std::vector<std::string> start_server_argv();
std::vector<std::string> devices_argv();
Result<std::vector<std::string>> shell_argv(const std::string& serial, const AdbShellCmd& cmd);
Result<std::vector<std::string>> pull_argv(const std::string& serial, const std::string& remote,
                                           const std::filesystem::path& local_tmp);

// Defense in depth for argv built outside the helpers above. Throws ReadOnlyViolation
// when a deny-listed verb or a private device path is present; returns PolicyViolation
// for any invocation outside the allowlist. `argv` excludes the adb executable path.
Result<void> validate_adb_argv(std::span<const std::string> argv);

}  // namespace openrecover::android
