#include "openrecover/android/adb_transport.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <optional>
#include <string>

#include "openrecover/android/child_process.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/path_util.hpp"

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace openrecover::android {

namespace {

std::string_view trim_view(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

std::string lower_copy(std::string_view s) {
    std::string out(s);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

// adb.exe writes CRLF on Windows; the device-side output is LF only.
std::string normalize_newlines(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') continue;
        out.push_back(text[i]);
    }
    return out;
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

AdbState parse_state(std::string_view raw) { return adb_state_from_string(raw); }

Error map_failure(int exit_code, const std::string& out, const std::string& err) {
    const std::string text = lower_copy(out + "\n" + err);
    const std::string_view detail_view = trim_view(err).empty() ? trim_view(out) : trim_view(err);
    const std::string detail(detail_view);
    if (contains(text, "unauthorized"))
        return make_error(ErrorCode::DeviceUnauthorized,
                          "device is unauthorized; accept the USB debugging prompt on the phone");
    if (contains(text, "offline")) return make_error(ErrorCode::DeviceOffline, "device is offline");
    if (contains(text, "permission denied") || contains(text, "operation not permitted"))
        return make_error(ErrorCode::AccessDenied, "adb was denied access: " + std::string(detail));
    if (contains(text, "no devices/emulators found") || contains(text, "device not found") ||
        contains(text, "not found"))
        return make_error(ErrorCode::NotFound, "adb device not found: " + std::string(detail));
    if (contains(text, "cannot connect to daemon") || contains(text, "failed to start daemon"))
        return make_error(ErrorCode::AdbNotFound, "cannot start the adb server: " + std::string(detail));
    return make_error(ErrorCode::IoError,
                      "adb exited with code " + std::to_string(exit_code) + ": " + std::string(detail));
}

std::string adb_executable_name() {
#if defined(_WIN32)
    return "adb.exe";
#else
    return "adb";
#endif
}

bool is_executable_file(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return false;
#if !defined(_WIN32)
    return ::access(path.c_str(), X_OK) == 0;
#else
    return true;
#endif
}

std::optional<std::string> environment_value(const char* name) {
#if defined(_WIN32)
    char* buffer = nullptr;
    size_t length = 0;
    if (_dupenv_s(&buffer, &length, name) != 0 || buffer == nullptr) return std::nullopt;
    std::string value(buffer);
    std::free(buffer);
    return value;
#else
    const char* value = std::getenv(name);
    if (value == nullptr) return std::nullopt;
    return std::string(value);
#endif
}

}  // namespace

const char* adb_state_name(AdbState state) noexcept {
    switch (state) {
        case AdbState::Device: return "device";
        case AdbState::Unauthorized: return "unauthorized";
        case AdbState::Offline: return "offline";
        case AdbState::NoPermissions: return "no_permissions";
        case AdbState::Recovery: return "recovery";
        case AdbState::Sideload: return "sideload";
        case AdbState::Unknown: return "unknown";
    }
    return "unknown";
}

bool adb_state_ready(AdbState state) noexcept { return state == AdbState::Device; }

AdbState adb_state_from_string(std::string_view raw) noexcept {
    if (raw == "device") return AdbState::Device;
    if (raw == "unauthorized") return AdbState::Unauthorized;
    if (raw == "offline") return AdbState::Offline;
    if (raw == "no permissions") return AdbState::NoPermissions;
    if (raw == "recovery") return AdbState::Recovery;
    if (raw == "sideload") return AdbState::Sideload;
    return AdbState::Unknown;
}

Result<std::string> locate_adb(const std::filesystem::path& exe_dir,
                               const std::string& explicit_path) {
    if (!explicit_path.empty()) {
        const std::filesystem::path candidate = path_from_utf8(explicit_path);
        if (is_executable_file(candidate)) return path_to_utf8(candidate);
        return fail(ErrorCode::AdbNotFound, "adb not found at the path given by --adb-path: " + explicit_path);
    }
    if (auto env = environment_value("OPENRECOVER_ADB"); env && !env->empty()) {
        const std::filesystem::path candidate = path_from_utf8(*env);
        if (is_executable_file(candidate)) return path_to_utf8(candidate);
        return fail(ErrorCode::AdbNotFound, "adb not found at OPENRECOVER_ADB: " + *env);
    }
    if (!exe_dir.empty()) {
        const std::filesystem::path candidate = exe_dir / "platform-tools" / adb_executable_name();
        if (is_executable_file(candidate)) return path_to_utf8(candidate);
    }
    if (auto path_env = environment_value("PATH"); path_env && !path_env->empty()) {
        const std::string& path_text = *path_env;
        const char separator =
#if defined(_WIN32)
            ';';
#else
            ':';
#endif
        size_t start = 0;
        while (start <= path_text.size()) {
            const size_t end = path_text.find(separator, start);
            const std::string_view entry =
                std::string_view(path_text).substr(start, end == std::string::npos ? std::string::npos : end - start);
            if (!entry.empty()) {
                const std::filesystem::path candidate =
                    path_from_utf8(std::string(entry)) / adb_executable_name();
                if (is_executable_file(candidate)) return path_to_utf8(candidate);
            }
            if (end == std::string::npos) break;
            start = end + 1;
        }
    }
    return fail(ErrorCode::AdbNotFound,
                "adb was not found; install Android platform-tools and put adb on PATH, or pass "
                "--adb-path. Download: https://developer.android.com/tools/releases/platform-tools");
}

Result<std::vector<AdbDevice>> parse_adb_devices_output(std::string_view text) {
    std::vector<AdbDevice> devices;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t newline = text.find('\n', pos);
        std::string_view line =
            text.substr(pos, newline == std::string_view::npos ? std::string_view::npos : newline - pos);
        pos = newline == std::string_view::npos ? text.size() + 1 : newline + 1;
        line = trim_view(line);
        if (line.empty()) continue;
        if (line.front() == '*') continue;  // daemon status noise
        if (line == "List of devices attached") continue;
        if (line.rfind("adb server", 0) == 0) continue;

        const size_t separator = line.find_first_of(" \t");
        if (separator == std::string_view::npos) continue;

        AdbDevice device;
        device.serial = std::string(line.substr(0, separator));
        std::string_view rest = trim_view(line.substr(separator));
        if (rest.empty()) continue;

        if (rest.rfind("no permissions", 0) == 0) {
            device.state = AdbState::NoPermissions;
            device.state_raw = "no permissions";
            rest = trim_view(rest.substr(14));
        } else {
            const size_t state_end = rest.find_first_of(" \t");
            const std::string_view state =
                rest.substr(0, state_end == std::string_view::npos ? std::string_view::npos : state_end);
            device.state_raw = std::string(state);
            device.state = parse_state(state);
            rest = state_end == std::string_view::npos ? std::string_view{} : trim_view(rest.substr(state_end));
        }

        while (!rest.empty()) {
            const size_t end = rest.find_first_of(" \t");
            const std::string_view token =
                rest.substr(0, end == std::string_view::npos ? std::string_view::npos : end);
            if (token.rfind("model:", 0) == 0) device.model = std::string(token.substr(6));
            else if (token.rfind("product:", 0) == 0) device.product = std::string(token.substr(8));
            else if (token.rfind("transport_id:", 0) == 0) device.transport_id = std::string(token.substr(13));
            rest = end == std::string_view::npos ? std::string_view{} : trim_view(rest.substr(end));
        }
        devices.push_back(std::move(device));
    }
    return devices;
}

Result<std::vector<std::string>> parse_find_output(std::string_view text) {
    std::vector<std::string> files;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t newline = text.find('\n', pos);
        std::string_view line =
            text.substr(pos, newline == std::string_view::npos ? std::string_view::npos : newline - pos);
        pos = newline == std::string_view::npos ? text.size() + 1 : newline + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (!line.empty()) files.emplace_back(line);
    }
    return files;
}

Result<std::vector<RemoteStat>> parse_stat_output(std::string_view text) {
    std::vector<RemoteStat> stats;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t newline = text.find('\n', pos);
        std::string_view line =
            text.substr(pos, newline == std::string_view::npos ? std::string_view::npos : newline - pos);
        pos = newline == std::string_view::npos ? text.size() + 1 : newline + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) continue;

        const size_t first = line.find('|');
        const size_t second = first == std::string_view::npos ? std::string_view::npos
                                                              : line.find('|', first + 1);
        if (first == std::string_view::npos || second == std::string_view::npos) {
            log::warn("android: skipping malformed stat line");
            continue;
        }
        RemoteStat stat;
        const std::string_view size_text = line.substr(0, first);
        const std::string_view mtime_text = line.substr(first + 1, second - first - 1);
        stat.path = std::string(line.substr(second + 1));
        const auto size_parsed = std::from_chars(size_text.data(), size_text.data() + size_text.size(), stat.size);
        const auto mtime_parsed =
            std::from_chars(mtime_text.data(), mtime_text.data() + mtime_text.size(), stat.mtime);
        if (size_parsed.ec != std::errc{} || size_parsed.ptr != size_text.data() + size_text.size() ||
            mtime_parsed.ec != std::errc{} || mtime_parsed.ptr != mtime_text.data() + mtime_text.size() ||
            stat.path.empty() || stat.path.front() != '/') {
            log::warn("android: skipping malformed stat line");
            continue;
        }
        stats.push_back(std::move(stat));
    }
    return stats;
}

Result<std::unique_ptr<SubprocessAdbTransport>> SubprocessAdbTransport::create(
    const std::filesystem::path& exe_dir, const std::string& explicit_adb_path, AdbTimeouts timeouts) {
    auto adb = locate_adb(exe_dir, explicit_adb_path);
    if (!adb) return fail(adb.error());
    auto transport = std::unique_ptr<SubprocessAdbTransport>(
        new SubprocessAdbTransport(std::move(*adb), timeouts));
    auto started = transport->shell_stdout(start_server_argv(), timeouts.server);
    if (!started) return fail(started.error());
    return transport;
}

Result<std::string> SubprocessAdbTransport::shell_stdout(const std::vector<std::string>& argv,
                                                         std::chrono::milliseconds timeout) {
    std::vector<std::string> full{adb_path_};
    full.insert(full.end(), argv.begin(), argv.end());
    ProcessOptions options;
    options.timeout = timeout;
    auto result = run_child_process(full, options);
    if (!result) return fail(result.error());
    if (result->timed_out)
        return fail(ErrorCode::Timeout, "adb command timed out after " +
                                            std::to_string(timeout.count()) + " ms");
    if (result->exit_code != 0)
        return fail(map_failure(result->exit_code, result->stdout_text, result->stderr_text));
    return result->stdout_text;
}

Result<std::vector<AdbDevice>> SubprocessAdbTransport::list_devices() {
    auto output = shell_stdout(devices_argv(), timeouts_.shell);
    if (!output) return fail(output.error());
    return parse_adb_devices_output(*output);
}

Result<std::string> SubprocessAdbTransport::shell_readonly(const std::string& serial,
                                                           const AdbShellCmd& cmd) {
    auto argv = shell_argv(serial, cmd);
    if (!argv) return fail(argv.error());

    std::vector<std::string> full{adb_path_};
    full.insert(full.end(), argv->begin(), argv->end());
    ProcessOptions options;
    options.timeout = timeouts_.shell;
    auto result = run_child_process(full, options);
    if (!result) return fail(result.error());
    if (result->timed_out)
        return fail(ErrorCode::Timeout, "adb shell command timed out after " +
                                            std::to_string(timeouts_.shell.count()) + " ms");
    if (result->exit_code == 0) {
        if (cmd.kind() == AdbShellCmd::Kind::TestDir) return std::string("1");
        return normalize_newlines(result->stdout_text);
    }
    if (cmd.kind() == AdbShellCmd::Kind::TestDir && result->exit_code == 1 &&
        trim_view(result->stdout_text).empty()) {
        const std::string err = lower_copy(result->stderr_text);
        if (!contains(err, "permission denied") && !contains(err, "operation not permitted"))
            return std::string("0");
    }
    if ((cmd.kind() == AdbShellCmd::Kind::ListFiles || cmd.kind() == AdbShellCmd::Kind::StatBatch) &&
        !trim_view(result->stdout_text).empty()) {
        log::warn("android: adb reported an error but returned partial output");
        return normalize_newlines(result->stdout_text);
    }
    return fail(map_failure(result->exit_code, result->stdout_text, result->stderr_text));
}

Result<void> SubprocessAdbTransport::pull(const std::string& serial, const std::string& remote,
                                          const std::filesystem::path& local_tmp) {
    auto argv = pull_argv(serial, remote, local_tmp);
    if (!argv) return fail(argv.error());
    std::vector<std::string> full{adb_path_};
    full.insert(full.end(), argv->begin(), argv->end());
    ProcessOptions options;
    options.timeout = timeouts_.pull;
    auto result = run_child_process(full, options);
    if (!result) return fail(result.error());
    if (result->timed_out)
        return fail(ErrorCode::Timeout, "adb pull timed out after " +
                                            std::to_string(timeouts_.pull.count()) + " ms");
    if (result->exit_code != 0)
        return fail(map_failure(result->exit_code, result->stdout_text, result->stderr_text));
    return {};
}

}  // namespace openrecover::android
