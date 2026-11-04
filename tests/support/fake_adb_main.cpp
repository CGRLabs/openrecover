// Test double for the adb executable. It emulates only the allowlisted commands the
// transport issues, against a fake shared-storage tree, and injects faults via env vars.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string env_or(const char* name, const std::string& fallback) {
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : fallback;
}

fs::path utf8_path(const std::string& text) {
    return fs::path(std::u8string(text.begin(), text.end()));
}

std::vector<std::string> split_command(const std::string& line) {
    std::vector<std::string> tokens;
    std::string current;
    bool have = false;
    bool quoted = false;
    for (char c : line) {
        if (quoted) {
            if (c == '\'') quoted = false;
            else current.push_back(c);
            have = true;
            continue;
        }
        if (c == '\'') {
            quoted = true;
            have = true;
            continue;
        }
        if (c == ' ') {
            if (have) {
                tokens.push_back(current);
                current.clear();
                have = false;
            }
            continue;
        }
        current.push_back(c);
        have = true;
    }
    if (have) tokens.push_back(current);
    return tokens;
}

bool is_under(const std::string& path, const std::string& root) {
    if (path == root) return true;
    return path.size() > root.size() && path.compare(0, root.size(), root) == 0 && path[root.size()] == '/';
}

fs::path to_local(const std::string& remote) {
    const fs::path root = utf8_path(env_or("FAKE_ADB_ROOT", ""));
    if (remote == "/sdcard") return root / "sdcard";
    if (remote.rfind("/sdcard/", 0) == 0) return root / "sdcard" / utf8_path(remote.substr(8));
    if (remote == "/storage/emulated/0") return root / "sdcard";
    if (remote.rfind("/storage/emulated/0/", 0) == 0)
        return root / "sdcard" / utf8_path(remote.substr(20));
    if (remote.rfind("/storage/", 0) == 0 && remote.size() >= 18)
        return root / "storage" / utf8_path(remote.substr(9, 9)) / utf8_path(remote.substr(19));
    return root / utf8_path(remote);
}

std::string to_remote(const std::string& base, const fs::path& local) {
    const fs::path root = utf8_path(env_or("FAKE_ADB_ROOT", ""));
    const fs::path base_local = to_local(base);
    std::error_code ec;
    const fs::path relative = fs::relative(local, base_local, ec);
    if (ec) return base;
    const std::u8string relative_u8 = relative.generic_u8string();
    const std::string rel(reinterpret_cast<const char*>(relative_u8.data()), relative_u8.size());
    return rel.empty() ? base : base + "/" + rel;
}

bool denied(const std::string& remote) {
    const std::string rule = env_or("FAKE_ADB_DENIED", "");
    return !rule.empty() && is_under(remote, rule);
}

int fail(const std::string& message) {
    std::cerr << message << "\n";
    return 1;
}

int command_find(const std::string& dir) {
    if (denied(dir)) return fail("find: " + dir + ": Permission denied");
    const fs::path local = to_local(dir);
    std::error_code ec;
    if (!fs::is_directory(local, ec)) return fail("find: " + dir + ": No such file or directory");
    std::vector<std::string> files;
    for (fs::recursive_directory_iterator it(local, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code type_ec;
        if (it->is_regular_file(type_ec)) files.push_back(to_remote(dir, it->path()));
    }
    std::sort(files.begin(), files.end());
    for (const std::string& file : files) std::cout << file << "\n";
    return 0;
}

int command_stat(const std::vector<std::string>& files) {
    const std::string fixed_mtime = env_or("FAKE_ADB_MTIME", "1700000000");
    int status = 0;
    for (const std::string& file : files) {
        if (denied(file)) {
            std::cerr << "stat: " << file << ": Permission denied\n";
            status = 1;
            continue;
        }
        const fs::path local = to_local(file);
        std::error_code ec;
        const auto size = fs::file_size(local, ec);
        if (ec) {
            std::cerr << "stat: " << file << ": No such file or directory\n";
            status = 1;
            continue;
        }
        std::cout << size << "|" << fixed_mtime << "|" << file << "\n";
    }
    return status;
}

int command_pull(const std::string& remote, const std::string& local_text) {
    if (denied(remote)) return fail("adb: error: failed to stat remote object '" + remote + "': Permission denied");
    const fs::path source = to_local(remote);
    const fs::path destination = utf8_path(local_text);
    std::error_code ec;
    if (!fs::is_regular_file(source, ec))
        return fail("adb: error: failed to stat remote object '" + remote + "': No such file or directory");
    std::ifstream in(source, std::ios::binary);
    if (!in) return fail("adb: error: cannot read remote object");
    std::ofstream out(destination, std::ios::binary | std::ios::trunc);
    if (!out) return fail("adb: error: cannot open local destination");
    const std::string truncate = env_or("FAKE_ADB_TRUNCATE_PULL", "");
    uint64_t limit = UINT64_MAX;
    if (!truncate.empty()) limit = std::stoull(truncate);
    std::vector<char> buffer(64 * 1024);
    uint64_t written = 0;
    while (in && written < limit) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(buffer.size(), limit - written));
        in.read(buffer.data(), static_cast<std::streamsize>(want));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        out.write(buffer.data(), got);
        written += static_cast<uint64_t>(got);
    }
    out.flush();
    return 0;
}

std::string property(const std::string& key) {
    if (key == "ro.product.model") return env_or("FAKE_ADB_MODEL", "Pixel_7");
    if (key == "ro.product.manufacturer") return env_or("FAKE_ADB_MANUFACTURER", "Google");
    if (key == "ro.build.version.release") return env_or("FAKE_ADB_RELEASE", "14");
    if (key == "ro.build.version.sdk") return env_or("FAKE_ADB_SDK", "34");
    if (key == "ro.crypto.state") return env_or("FAKE_ADB_CRYPTO", "encrypted");
    return env_or("FAKE_ADB_UNKNOWN_PROP", "");
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) return fail("fake_adb: missing arguments");

    if (args[0] == "argv") {
        for (size_t i = 1; i < args.size(); ++i)
            std::cout << args[i].size() << ":" << args[i] << "\n";
        return 0;
    }
    if (args[0] == "start-server") return 0;
    if (args[0] == "devices") {
        if (args.size() != 2 || args[1] != "-l") return fail("fake_adb: devices requires -l");
        std::cout << "List of devices attached\n";
        if (!env_or("FAKE_ADB_NOISE", "").empty()) std::cout << "* daemon started successfully\n";
        const std::string state = env_or("FAKE_ADB_STATE", "device");
        if (state == "empty") {
            std::cout.flush();
            return 0;
        }
        std::cout << env_or("FAKE_ADB_SERIAL", "FAKE123") << "\t" << state;
        if (state == "device") std::cout << " product:panther model:Pixel_7 device:panther transport_id:1";
        std::cout << "\n";
        return 0;
    }
    if (args.size() >= 2 && args[0] == "-s") {
        if (const char* sleep_ms = std::getenv("FAKE_ADB_SLEEP_MS"); sleep_ms != nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(std::stoll(sleep_ms)));
        }
        const std::string expected = env_or("FAKE_ADB_SERIAL", "FAKE123");
        if (args[1] != expected) return fail("adb: device '" + args[1] + "' not found");
        if (args.size() < 3) return fail("fake_adb: missing command");
        if (args[2] == "shell") {
            if (args.size() != 4) return fail("adb: shell requires one command string");
            const std::vector<std::string> tokens = split_command(args[3]);
            if (tokens.empty()) return fail("fake_adb: empty shell command");
            if (tokens[0] == "getprop") {
                if (tokens.size() != 2) return fail("fake_adb: getprop requires a key");
                std::cout << property(tokens[1]) << "\n";
                return 0;
            }
            if (tokens[0] == "find") {
                if (tokens.size() != 4 || tokens[2] != "-type" || tokens[3] != "f")
                    return fail("fake_adb: unsupported find");
                return command_find(tokens[1]);
            }
            if (tokens[0] == "test") {
                if (tokens.size() != 3 || tokens[1] != "-d") return fail("fake_adb: unsupported test");
                if (denied(tokens[2])) return fail("test: " + tokens[2] + ": Permission denied");
                std::error_code ec;
                return fs::is_directory(to_local(tokens[2]), ec) ? 0 : 1;
            }
            if (tokens[0] == "stat") {
                if (tokens.size() < 4 || tokens[1] != "-c" || tokens[2] != "%s|%Y|%n")
                    return fail("fake_adb: unsupported stat");
                return command_stat(std::vector<std::string>(tokens.begin() + 3, tokens.end()));
            }
            return fail("fake_adb: command not allowlisted");
        }
        if (args[2] == "pull") {
            if (args.size() != 5) return fail("adb: pull requires remote and local");
            return command_pull(args[3], args[4]);
        }
        return fail("fake_adb: subcommand not allowlisted");
    }
    return fail("fake_adb: invocation not allowlisted");
}
