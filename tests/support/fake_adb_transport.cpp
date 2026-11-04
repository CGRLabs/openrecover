#include "fake_adb_transport.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <system_error>
#include <utility>

#include "openrecover/common/path_util.hpp"
#include "openrecover/io/output_sink.hpp"

namespace fs = std::filesystem;

namespace openrecover::test {

namespace {

int64_t unix_seconds(fs::file_time_type time) {
#if defined(_MSC_VER)
    const auto sys = std::chrono::clock_cast<std::chrono::system_clock>(time);
#else
    const auto sys = std::chrono::file_clock::to_sys(time);
#endif
    return std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count();
}

bool under_prefix(const std::string& path, const std::string& prefix) {
    if (path == prefix) return true;
    return path.size() > prefix.size() && path.compare(0, prefix.size(), prefix) == 0 &&
           path[prefix.size()] == '/';
}

}  // namespace

FakeAdbTransport::FakeAdbTransport(fs::path sdcard_root, std::string serial)
    : root_(std::move(sdcard_root)), serial_(std::move(serial)) {
    properties_["ro.product.model"] = "Pixel Fake";
    properties_["ro.product.manufacturer"] = "Google";
    properties_["ro.build.version.release"] = "14";
    properties_["ro.build.version.sdk"] = "34";
    properties_["ro.crypto.state"] = "encrypted";
}

Result<std::vector<android::AdbDevice>> FakeAdbTransport::list_devices() {
    std::vector<android::AdbDevice> devices;
    if (!has_device_) return devices;
    android::AdbDevice device;
    device.serial = serial_;
    device.state = state_;
    device.state_raw = state_ == android::AdbState::NoPermissions
                           ? "no permissions"
                           : android::adb_state_name(state_);
    device.model = properties_["ro.product.model"];
    device.product = "fake";
    device.transport_id = "1";
    devices.push_back(std::move(device));
    return devices;
}

Result<fs::path> FakeAdbTransport::local_path_for(const std::string& remote) const {
    std::string_view rest;
    if (remote == "/sdcard") {
        rest = {};
    } else if (remote.rfind("/sdcard/", 0) == 0) {
        rest = std::string_view(remote).substr(7);
    } else if (remote == "/storage/emulated/0") {
        rest = {};
    } else if (remote.rfind("/storage/emulated/0/", 0) == 0) {
        rest = std::string_view(remote).substr(19);
    } else {
        return fail(ErrorCode::NotFound, "fake adb: remote path is not mapped: " + remote);
    }

    fs::path local = root_;
    size_t start = 0;
    while (start < rest.size()) {
        const size_t slash = rest.find('/', start);
        const std::string_view component =
            rest.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
        local /= path_from_utf8(std::string(component));
        if (slash == std::string_view::npos) break;
        start = slash + 1;
    }
    if (!io::path_is_within(local, root_)) {
        return fail(ErrorCode::PolicyViolation, "fake adb: path escapes the fixture root: " + remote);
    }
    return local;
}

bool FakeAdbTransport::is_denied(const std::string& remote) const {
    for (const std::string& prefix : denied_) {
        if (under_prefix(remote, prefix)) return true;
    }
    return false;
}

void FakeAdbTransport::collect_files(const fs::path& local_dir, const std::string& remote_dir,
                                     std::vector<std::string>& files) const {
    std::error_code ec;
    for (fs::directory_iterator it(local_dir, ec), end; !ec && it != end; it.increment(ec)) {
        const fs::path& path = it->path();
        const std::string name = path_to_utf8(path.filename());
        const std::string remote = remote_dir + "/" + name;
        if (is_denied(remote)) continue;
        std::error_code entry_ec;
        if (it->is_symlink(entry_ec)) continue;
        if (it->is_directory(entry_ec)) {
            if (!entry_ec) collect_files(path, remote, files);
        } else if (it->is_regular_file(entry_ec)) {
            files.push_back(remote);
        }
    }
}

Result<std::string> FakeAdbTransport::shell_readonly(const std::string& serial,
                                                     const android::AdbShellCmd& cmd) {
    ++shell_calls_;
    if (serial != serial_) {
        return fail(ErrorCode::NotFound, "fake adb: unknown device " + serial);
    }
    auto argv = android::shell_argv(serial_, cmd);
    if (!argv) return fail(argv.error());
    if (shell_timeout_) return fail(ErrorCode::Timeout, "fake adb shell command timed out");

    switch (cmd.kind()) {
        case android::AdbShellCmd::Kind::GetProp: {
            const auto it = properties_.find(cmd.key());
            return it == properties_.end() ? std::string() : it->second;
        }
        case android::AdbShellCmd::Kind::TestDir: {
            if (!sdcard_present_) return std::string("0");
            if (is_denied(cmd.dir())) return fail(ErrorCode::AccessDenied, "fake adb: permission denied");
            auto local = local_path_for(cmd.dir());
            if (!local) return fail(local.error());
            std::error_code ec;
            return fs::is_directory(*local, ec) ? std::string("1") : std::string("0");
        }
        case android::AdbShellCmd::Kind::ListFiles: {
            ++list_files_calls_;
            if (is_denied(cmd.dir())) return fail(ErrorCode::AccessDenied, "fake adb: permission denied");
            auto local = local_path_for(cmd.dir());
            if (!local) return fail(local.error());
            std::error_code ec;
            if (!fs::is_directory(*local, ec)) {
                return fail(ErrorCode::NotFound, "fake adb: no such directory: " + cmd.dir());
            }
            std::vector<std::string> files;
            collect_files(*local, cmd.dir(), files);
            std::sort(files.begin(), files.end());
            std::string out;
            for (const std::string& file : files) {
                out += file;
                out += '\n';
            }
            return out;
        }
        case android::AdbShellCmd::Kind::StatBatch: {
            std::string out;
            for (const std::string& remote : cmd.files()) {
                if (is_denied(remote)) {
                    return fail(ErrorCode::AccessDenied, "fake adb: permission denied");
                }
                for (const std::string& prefix : denied_stats_) {
                    if (under_prefix(remote, prefix)) {
                        return fail(ErrorCode::AccessDenied, "fake adb: permission denied");
                    }
                }
                auto local = local_path_for(remote);
                if (!local) return fail(local.error());
                std::error_code ec;
                if (!fs::is_regular_file(*local, ec)) continue;
                const uint64_t size = fs::file_size(*local, ec);
                if (ec) continue;
                const int64_t mtime = unix_seconds(fs::last_write_time(*local, ec));
                if (ec) continue;
                out += std::to_string(size);
                out += '|';
                out += std::to_string(mtime);
                out += '|';
                out += remote;
                out += '\n';
            }
            return out;
        }
    }
    return fail(ErrorCode::ProtocolError, "fake adb: unsupported command");
}

Result<void> FakeAdbTransport::pull(const std::string& serial, const std::string& remote,
                                    const fs::path& local_tmp) {
    ++pull_calls_;
    if (serial != serial_) {
        return fail(ErrorCode::NotFound, "fake adb: unknown device " + serial);
    }
    auto argv = android::pull_argv(serial_, remote, local_tmp);
    if (!argv) return fail(argv.error());
    if (pull_timeout_) return fail(ErrorCode::Timeout, "fake adb pull timed out");
    if (is_denied(remote)) return fail(ErrorCode::AccessDenied, "fake adb: permission denied");
    auto local = local_path_for(remote);
    if (!local) return fail(local.error());

    std::error_code ec;
    if (!fs::is_regular_file(*local, ec)) {
        return fail(ErrorCode::NotFound, "fake adb: no such file: " + remote);
    }
    std::ifstream in(*local, std::ios::binary);
    if (!in) return fail(ErrorCode::IoError, "fake adb: cannot open " + remote);
    const uint64_t size = fs::file_size(*local, ec);
    if (ec) return fail(ErrorCode::IoError, "fake adb: cannot stat " + remote);
    const uint64_t limit = truncate_pull_ ? size / 2 : size;

    std::fstream out(local_tmp, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!out) {
        return fail(ErrorCode::IoError, "fake adb: cannot create " + path_to_utf8(local_tmp));
    }
    std::vector<char> buffer(64u << 10);
    uint64_t copied = 0;
    while (copied < limit) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(buffer.size(), limit - copied));
        in.read(buffer.data(), static_cast<std::streamsize>(want));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        out.write(buffer.data(), got);
        if (!out) return fail(ErrorCode::IoError, "fake adb: write failed");
        copied += static_cast<uint64_t>(got);
    }
    pulled_paths_.push_back(remote);
    return {};
}

}  // namespace openrecover::test
