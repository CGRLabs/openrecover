#include "openrecover/android/adb_command_policy.hpp"

#include <algorithm>
#include <array>
#include <cctype>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/path_util.hpp"
#include "openrecover/common/readonly.hpp"

namespace openrecover::android {

namespace {

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Returns the length of the shared-storage prefix, or 0 when the path is outside it.
size_t shared_storage_prefix(std::string_view path) {
    if (path == "/sdcard") return path.size();
    if (starts_with(path, "/sdcard/")) return 7;
    if (path == "/storage/emulated/0") return path.size();
    if (starts_with(path, "/storage/emulated/0/")) return 19;
    if (path.size() >= 18 && starts_with(path, "/storage/") && is_hex(path[9]) && is_hex(path[10]) &&
        is_hex(path[11]) && is_hex(path[12]) && path[13] == '-' && is_hex(path[14]) &&
        is_hex(path[15]) && is_hex(path[16]) && is_hex(path[17]) &&
        (path.size() == 18 || path[18] == '/')) {
        return 18;
    }
    return 0;
}

std::string short_path(std::string_view path) {
    constexpr size_t kMax = 80;
    if (path.size() <= kMax) return std::string(path);
    return std::string(path.substr(0, kMax)) + "...";
}

bool is_control_or_forbidden(char c) {
    const auto u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7F || c == '\\') return true;
    // Apostrophes and spaces are legal in filenames; shell_quote neutralizes them.
    // Everything else with shell meaning is refused before it reaches adb.
    return kForbiddenRemotePathChars.find(c) != std::string_view::npos;
}

// Private device locations the bridge must never read.
bool is_private_device_path(std::string_view token) {
    static constexpr std::array<std::string_view, 7> kDenied = {
        "/dev/block", "/dev/", "/data", "/system", "/vendor", "/proc", "/sys"};
    for (std::string_view prefix : kDenied) {
        if (token == prefix) return true;
        if (prefix.back() == '/' ? starts_with(token, prefix) : starts_with(token, prefix) && token.size() > prefix.size() &&
                                                                         token[prefix.size()] == '/')
            return true;
    }
    return false;
}

Result<void> validate_device_argv(const std::vector<std::string>& argv) {
    if (argv.empty()) return fail(ErrorCode::PolicyViolation, "empty device command");
    const std::string& command = argv[0];
    if (command == "getprop") {
        if (argv.size() != 2)
            return fail(ErrorCode::PolicyViolation, "getprop takes exactly one key");
        return validate_prop_key(argv[1]);
    }
    if (command == "find") {
        if (argv.size() != 4 || argv[2] != "-type" || argv[3] != "f")
            return fail(ErrorCode::PolicyViolation, "find is limited to: find <dir> -type f");
        return validate_remote_path(argv[1]);
    }
    if (command == "test") {
        if (argv.size() != 3 || argv[1] != "-d")
            return fail(ErrorCode::PolicyViolation, "test is limited to: test -d <dir>");
        return validate_remote_path(argv[2]);
    }
    if (command == "stat") {
        if (argv.size() < 4 || argv.size() > 3 + kMaxStatFiles)
            return fail(ErrorCode::PolicyViolation, "stat accepts 1..64 files");
        if (argv[1] != "-c" || argv[2] != kStatFormat)
            return fail(ErrorCode::PolicyViolation, "stat format may not be changed");
        for (size_t i = 3; i < argv.size(); ++i) {
            auto ok = validate_remote_path(argv[i]);
            if (!ok) return ok;
        }
        return {};
    }
    return fail(ErrorCode::PolicyViolation, "device command is not allowlisted: " + short_path(command));
}

}  // namespace

Result<AdbShellCmd> AdbShellCmd::get_prop(std::string key) {
    auto ok = validate_prop_key(key);
    if (!ok) return fail(ok.error());
    AdbShellCmd cmd;
    cmd.kind_ = Kind::GetProp;
    cmd.key_ = std::move(key);
    return cmd;
}

Result<AdbShellCmd> AdbShellCmd::list_files(std::string dir) {
    auto ok = validate_remote_path(dir);
    if (!ok) return fail(ok.error());
    AdbShellCmd cmd;
    cmd.kind_ = Kind::ListFiles;
    cmd.dir_ = std::move(dir);
    return cmd;
}

Result<AdbShellCmd> AdbShellCmd::stat_batch(std::vector<std::string> files) {
    if (files.empty() || files.size() > kMaxStatFiles)
        return fail(ErrorCode::InvalidArgument, "stat batch requires 1..64 files");
    for (const std::string& file : files) {
        auto ok = validate_remote_path(file);
        if (!ok) return fail(ok.error());
    }
    AdbShellCmd cmd;
    cmd.kind_ = Kind::StatBatch;
    cmd.files_ = std::move(files);
    return cmd;
}

Result<AdbShellCmd> AdbShellCmd::test_dir(std::string dir) {
    auto ok = validate_remote_path(dir);
    if (!ok) return fail(ok.error());
    AdbShellCmd cmd;
    cmd.kind_ = Kind::TestDir;
    cmd.dir_ = std::move(dir);
    return cmd;
}

std::vector<std::string> AdbShellCmd::device_argv() const {
    switch (kind_) {
        case Kind::GetProp:
            return {"getprop", key_};
        case Kind::ListFiles:
            return {"find", dir_, "-type", "f"};
        case Kind::StatBatch: {
            std::vector<std::string> argv{"stat", "-c", std::string(kStatFormat)};
            argv.insert(argv.end(), files_.begin(), files_.end());
            return argv;
        }
        case Kind::TestDir:
            return {"test", "-d", dir_};
    }
    return {};
}

std::string AdbShellCmd::shell_command_line() const {
    switch (kind_) {
        case Kind::GetProp:
            return "getprop " + shell_quote(key_);
        case Kind::ListFiles:
            return "find " + shell_quote(dir_) + " -type f";
        case Kind::StatBatch: {
            std::string line = "stat -c " + shell_quote(kStatFormat);
            for (const std::string& file : files_) line += " " + shell_quote(file);
            return line;
        }
        case Kind::TestDir:
            return "test -d " + shell_quote(dir_);
    }
    return {};
}

Result<void> validate_remote_path(std::string_view path) {
    if (path.empty()) return fail(ErrorCode::PolicyViolation, "remote path is empty");
    if (path.size() > kMaxRemotePathBytes)
        return fail(ErrorCode::PolicyViolation, "remote path exceeds 4096 bytes");
    if (!is_valid_utf8(path))
        return fail(ErrorCode::PolicyViolation, "remote path is not valid UTF-8");
    for (char c : path) {
        if (is_control_or_forbidden(c))
            return fail(ErrorCode::PolicyViolation,
                        "remote path contains a control character or backslash: " + short_path(path));
    }
    if (path.back() == '/')
        return fail(ErrorCode::PolicyViolation, "remote path has a trailing slash: " + short_path(path));
    if (shared_storage_prefix(path) == 0)
        return fail(ErrorCode::PolicyViolation,
                    "remote path is outside shared storage: " + short_path(path));

    size_t start = 1;
    while (start <= path.size()) {
        const size_t slash = path.find('/', start);
        const std::string_view component =
            path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
        if (component.empty())
            return fail(ErrorCode::PolicyViolation, "remote path has an empty component: " + short_path(path));
        if (component == "." || component == "..")
            return fail(ErrorCode::PolicyViolation,
                        "remote path contains a relative component: " + short_path(path));
        if (slash == std::string_view::npos) break;
        start = slash + 1;
    }
    return {};
}

Result<void> validate_prop_key(std::string_view key) {
    if (key.empty() || key.size() > 64)
        return fail(ErrorCode::PolicyViolation, "property key must be 1..64 characters");
    for (char c : key) {
        const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-';
        if (!ok) return fail(ErrorCode::PolicyViolation, "invalid property key: " + short_path(key));
    }
    return {};
}

Result<void> validate_adb_serial(std::string_view serial) {
    if (serial.empty() || serial.size() > 128)
        return fail(ErrorCode::PolicyViolation, "adb serial must be 1..128 characters");
    for (char c : serial) {
        const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' ||
                        c == '-' || c == ':';
        if (!ok) return fail(ErrorCode::PolicyViolation, "invalid adb serial: " + short_path(serial));
    }
    return {};
}

std::string shell_quote(std::string_view arg) {
    std::string out;
    out.reserve(arg.size() + 2);
    out.push_back('\'');
    for (char c : arg) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out.push_back(c);
        }
    }
    out.push_back('\'');
    return out;
}

bool is_denied_adb_verb(std::string_view verb) {
    const auto& verbs = denied_adb_verbs();
    return std::find(verbs.begin(), verbs.end(), verb) != verbs.end();
}

const std::vector<std::string>& denied_adb_verbs() {
    // Every verb that could modify the device, escalate privileges or read private
    // storage. `adb pull` reads; everything below is refused at the policy layer.
    static const std::vector<std::string> kDenied = {
        "push",       "install",    "uninstall", "root",      "unroot",   "remount",
        "reboot",     "sideload",   "disable-verity", "enable-verity", "rm",  "mv",
        "cp",         "su",         "settings",  "pm",        "am",       "dd",
        "mkfs",       "format",     "wipe",      "restorecon", "chmod",   "chown",
        "ln",         "touch",      "mkdir",     "rmdir",     "setprop",  "svc",
        "input",      "stop",       "start",     "kill",      "fastboot", "shell-with-su"};
    return kDenied;
}

Result<std::vector<std::string>> parse_shell_command_line(std::string_view line) {
    std::vector<std::string> tokens;
    std::string current;
    bool have_token = false;
    bool in_single_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (in_single_quotes) {
            if (c == '\'') {
                in_single_quotes = false;
            } else {
                current.push_back(c);
            }
            have_token = true;
            continue;
        }
        if (c == '\'') {
            in_single_quotes = true;
            have_token = true;
            continue;
        }
        if (c == '\\') {
            if (++i >= line.size())
                return fail(ErrorCode::PolicyViolation, "dangling backslash in device command");
            current.push_back(line[i]);
            have_token = true;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            if (have_token) {
                tokens.push_back(current);
                current.clear();
                have_token = false;
            }
            continue;
        }
        current.push_back(c);
        have_token = true;
    }
    if (in_single_quotes)
        return fail(ErrorCode::PolicyViolation, "unterminated quote in device command");
    if (have_token) tokens.push_back(current);
    if (tokens.empty()) return fail(ErrorCode::PolicyViolation, "empty device command");
    return tokens;
}

std::vector<std::string> start_server_argv() { return {"start-server"}; }

std::vector<std::string> devices_argv() { return {"devices", "-l"}; }

Result<std::vector<std::string>> shell_argv(const std::string& serial, const AdbShellCmd& cmd) {
    auto ok = validate_adb_serial(serial);
    if (!ok) return fail(ok.error());
    std::vector<std::string> argv{"-s", serial, "shell", cmd.shell_command_line()};
    auto allowed = validate_adb_argv(argv);
    if (!allowed) return fail(allowed.error());
    return argv;
}

Result<std::vector<std::string>> pull_argv(const std::string& serial, const std::string& remote,
                                           const std::filesystem::path& local_tmp) {
    auto ok = validate_adb_serial(serial);
    if (!ok) return fail(ok.error());
    ok = validate_remote_path(remote);
    if (!ok) return fail(ok.error());
    const std::string local = path_to_utf8(local_tmp);
    if (local.empty()) return fail(ErrorCode::InvalidArgument, "empty local pull destination");
    std::vector<std::string> argv{"-s", serial, "pull", remote, local};
    auto allowed = validate_adb_argv(argv);
    if (!allowed) return fail(allowed.error());
    return argv;
}

Result<void> validate_adb_argv(std::span<const std::string> argv) {
    if (argv.empty()) return fail(ErrorCode::PolicyViolation, "empty adb invocation");

    // `adb shell` receives one string that the device shell re-parses, so denied
    // verbs are only visible after splitting it.
    std::vector<std::string> shell_tokens;
    if (argv.size() == 4 && argv[0] == "-s" && argv[2] == "shell") {
        auto tokens = parse_shell_command_line(argv[3]);
        if (!tokens) return fail(tokens.error());
        shell_tokens = std::move(*tokens);
    }

    const auto check_denied = [](const std::string& token) {
        if (is_denied_adb_verb(token))
            throw ReadOnlyViolation("adb verb is forbidden by the read-only policy: " + token);
        if (is_private_device_path(token))
            throw ReadOnlyViolation("adb argument targets private device storage: " + short_path(token));
    };
    for (const std::string& token : argv) check_denied(token);
    for (const std::string& token : shell_tokens) check_denied(token);

    const std::string& first = argv[0];
    if (first == "start-server") {
        if (argv.size() != 1)
            return fail(ErrorCode::PolicyViolation, "start-server takes no arguments");
        return {};
    }
    if (first == "devices") {
        if (argv.size() != 2 || argv[1] != "-l")
            return fail(ErrorCode::PolicyViolation, "devices is limited to: devices -l");
        return {};
    }
    if (first == "-s") {
        if (argv.size() < 4)
            return fail(ErrorCode::PolicyViolation, "adb -s requires a serial and a command");
        auto ok = validate_adb_serial(argv[1]);
        if (!ok) return ok;
        if (argv[2] == "shell") {
            if (argv.size() != 4)
                return fail(ErrorCode::PolicyViolation, "shell takes exactly one command argument");
            return validate_device_argv(shell_tokens);
        }
        if (argv[2] == "pull") {
            if (argv.size() != 5)
                return fail(ErrorCode::PolicyViolation, "pull takes a remote and a local path");
            ok = validate_remote_path(argv[3]);
            if (!ok) return ok;
            if (argv[4].empty())
                return fail(ErrorCode::InvalidArgument, "empty local pull destination");
            return {};
        }
        return fail(ErrorCode::PolicyViolation, "adb subcommand is not allowlisted: " + short_path(argv[2]));
    }
    return fail(ErrorCode::PolicyViolation, "adb verb is not allowlisted: " + short_path(first));
}

}  // namespace openrecover::android
