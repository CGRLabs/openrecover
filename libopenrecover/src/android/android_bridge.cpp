#include "openrecover/android/android_bridge.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <regex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/signature.hpp"
#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/path_util.hpp"
#include "openrecover/io/image_device.hpp"
#include "openrecover/io/output_sink.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace openrecover::android {

namespace {

constexpr const char* kSdcardRoot = "/sdcard";

std::string_view trim_view(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1);
    }
    return text;
}

std::string lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        const auto u = static_cast<unsigned char>(c);
        if (u >= 'A' && u <= 'Z') c = static_cast<char>(u - 'A' + 'a');
    }
    return out;
}

bool starts_with(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::string_view extension_of(std::string_view filename) {
    const size_t dot = filename.rfind('.');
    if (dot == std::string_view::npos || dot + 1 >= filename.size()) return {};
    return filename.substr(dot + 1);
}

std::string type_for_extension(std::string_view extension) {
    if (extension == "jpg" || extension == "jpeg") return "jpeg";
    if (extension == "png") return "png";
    if (extension == "pdf") return "pdf";
    if (extension == "gif") return "gif";
    if (extension == "bmp" || extension == "dib") return "bmp";
    if (extension == "zip" || extension == "docx" || extension == "xlsx" || extension == "pptx") {
        return extension == "zip" ? "zip" : std::string(extension);
    }
    return std::string(extension);
}

std::string_view signature_for_extension(std::string_view extension) {
    if (extension == "jpg" || extension == "jpeg") return "jpeg";
    if (extension == "png") return "png";
    if (extension == "pdf") return "pdf";
    if (extension == "gif") return "gif";
    if (extension == "bmp" || extension == "dib") return "bmp";
    if (extension == "zip" || extension == "docx" || extension == "xlsx" || extension == "pptx") {
        return "zip";
    }
    return {};
}

void append_note(std::string& note, std::string_view extra) {
    if (extra.empty()) return;
    if (!note.empty()) note += "; ";
    note += extra;
}

std::string remote_directory(const std::string& path) {
    const size_t slash = path.rfind('/');
    if (slash == std::string::npos || slash == 0) return "/";
    return path.substr(0, slash);
}

struct Candidate {
    std::string remote_path;
    std::string relative;  // path below the scan root, '/'-separated
    std::string filename;
    size_t root_index = 0;
    std::optional<uint64_t> trashed_expires_at;
};

struct FilteredFiles {
    std::vector<Candidate> candidates;
};

Result<FilteredFiles> enumerate_root(IAdbTransport& transport, const std::string& serial,
                                     const AndroidScanProfile& profile, size_t root_index,
                                     AndroidRootResult& root_result,
                                     std::vector<std::string>& warnings) {
    const AndroidScanRoot& root = profile.roots[root_index];
    FilteredFiles result;

    auto test_cmd = AdbShellCmd::test_dir(root.path);
    if (!test_cmd) return fail(test_cmd.error());
    auto present = transport.shell_readonly(serial, *test_cmd);
    if (!present) {
        if (present.error().code == ErrorCode::AccessDenied) {
            root_result.status = "access_denied";
            if (!root.optional) {
                warnings.push_back("android: root '" + root.id + "' is not accessible (" +
                                   root.path + ")");
            }
            return result;
        }
        return fail(present.error());
    }
    const std::string present_text = std::string(trim_view(*present));
    if (present_text == "0") {
        root_result.status = "absent";
        return result;
    }
    if (present_text != "1") {
        return fail(ErrorCode::ProtocolError,
                    "test -d returned unexpected output for " + root.path + ": " + present_text);
    }

    auto list_cmd = AdbShellCmd::list_files(root.path);
    if (!list_cmd) return fail(list_cmd.error());
    auto listing = transport.shell_readonly(serial, *list_cmd);
    if (!listing) {
        if (listing.error().code == ErrorCode::AccessDenied) {
            root_result.status = "access_denied";
            if (!root.optional) {
                warnings.push_back("android: cannot list root '" + root.id + "' (" + root.path +
                                   "): access denied");
            }
            return result;
        }
        return fail(listing.error());
    }
    root_result.status = "ok";

    auto listed = parse_find_output(*listing);
    if (!listed) return fail(listed.error());
    const std::string prefix = root.path + "/";
    for (const std::string& remote_path : *listed) {
        if (!starts_with(remote_path, prefix)) {
            warnings.push_back("android: skipping path outside root '" + root.id + "': " +
                               (remote_path.size() > 200 ? remote_path.substr(0, 200) + "..." : remote_path));
            continue;
        }
        auto valid = validate_remote_path(remote_path);
        if (!valid) {
            warnings.push_back("android: skipping invalid path under root '" + root.id + "': " +
                               valid.error().message);
            continue;
        }

        const std::string relative = remote_path.substr(prefix.size());
        if (relative.empty()) continue;
        const bool nested = relative.find('/') != std::string::npos;
        if (!root.recursive && nested) continue;

        size_t depth = 1;
        for (char c : relative) {
            if (c == '/') ++depth;
        }
        if (root.max_depth > 0 && depth > static_cast<size_t>(root.max_depth)) continue;

        const size_t slash = relative.rfind('/');
        const std::string_view filename =
            slash == std::string_view::npos ? std::string_view(relative)
                                            : std::string_view(relative).substr(slash + 1);

        if (root.name_pattern &&
            !std::regex_match(filename.begin(), filename.end(), *root.name_pattern)) {
            continue;
        }
        if (root.dir_pattern &&
            !std::regex_search(remote_directory(remote_path), *root.dir_pattern)) {
            continue;
        }

        const std::string extension = lower_ascii(extension_of(filename));
        if (!profile.type_filter.empty() &&
            std::find(profile.type_filter.begin(), profile.type_filter.end(), extension) ==
                profile.type_filter.end()) {
            continue;
        }

        Candidate candidate;
        candidate.remote_path = remote_path;
        candidate.relative = relative;
        candidate.filename = std::string(filename);
        candidate.root_index = root_index;
        if (root.kind == AndroidRootKind::Trash) {
            if (auto trashed = parse_trashed_name(filename)) {
                candidate.trashed_expires_at = trashed->expires_at;
            }
        }
        result.candidates.push_back(std::move(candidate));
    }
    return result;
}

Result<void> stat_range(IAdbTransport& transport, const std::string& serial,
                        const std::vector<const Candidate*>& candidates, size_t begin, size_t end,
                        std::map<std::string, RemoteStat>& stats,
                        std::vector<std::string>& warnings) {
    if (begin >= end) return {};
    std::vector<std::string> paths;
    paths.reserve(end - begin);
    for (size_t i = begin; i < end; ++i) paths.push_back(candidates[i]->remote_path);

    auto cmd = AdbShellCmd::stat_batch(std::move(paths));
    if (!cmd) return fail(cmd.error());
    auto output = transport.shell_readonly(serial, *cmd);
    if (!output) {
        if (output.error().code == ErrorCode::AccessDenied) {
            if (end - begin == 1) {
                warnings.push_back("android: cannot stat " + candidates[begin]->remote_path +
                                   ": access denied");
                return {};
            }
            const size_t middle = begin + (end - begin) / 2;
            auto left = stat_range(transport, serial, candidates, begin, middle, stats, warnings);
            if (!left) return fail(left.error());
            return stat_range(transport, serial, candidates, middle, end, stats, warnings);
        }
        return fail(output.error());
    }
    auto parsed = parse_stat_output(*output);
    if (!parsed) return fail(parsed.error());
    for (RemoteStat& stat : *parsed) {
        stats[stat.path] = std::move(stat);
    }
    return {};
}

Result<carve::ValidationResult> validate_media(const fs::path& path, uint64_t size,
                                               std::string_view signature_name) {
    io::OpenOptions options;
    auto device = io::open_image_raw(path, options);
    if (!device) return fail(device.error());
    const carve::ISignature* signature = carve::SignatureRegistry::builtins().find(signature_name);
    if (signature == nullptr) {
        return fail(ErrorCode::Unsupported,
                    "no structural validator for this media type: " + std::string(signature_name));
    }
    carve::BoundedReader reader(**device, 0, size);
    carve::ValidationResult validation = signature->validate(reader);
    if (reader.error()) return fail(*reader.error());
    return validation;
}

class FileByteSource final : public io::ByteSource {
public:
    explicit FileByteSource(const fs::path& path) : stream_(path, std::ios::binary) {}
    bool is_open() const { return stream_.is_open(); }

    Result<size_t> read_some(uint8_t* dst, size_t len) override {
        stream_.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(len));
        const std::streamsize got = stream_.gcount();
        if (stream_.bad()) return fail(ErrorCode::IoError, "cannot read staged pull file");
        return static_cast<size_t>(got);
    }

private:
    std::ifstream stream_;
};

class ScopedPullDir {
public:
    explicit ScopedPullDir(fs::path path) : path_(std::move(path)) {}
    ~ScopedPullDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    ScopedPullDir(const ScopedPullDir&) = delete;
    ScopedPullDir& operator=(const ScopedPullDir&) = delete;

    const fs::path& path() const noexcept { return path_; }

private:
    fs::path path_;
};

Result<std::unique_ptr<ScopedPullDir>> make_pull_dir(const fs::path& configured_base) {
    std::error_code ec;
    fs::path base = configured_base;
    if (base.empty()) {
        base = fs::temp_directory_path(ec);
        if (ec) return fail(ErrorCode::IoError, "cannot locate the temporary directory: " + ec.message());
    } else {
        fs::create_directories(base, ec);
        if (ec) {
            return fail(ErrorCode::IoError,
                        "cannot create the temporary pull directory " + path_to_utf8(base) + ": " +
                            ec.message());
        }
    }

    std::random_device random;
    const uint64_t stamp =
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    for (int attempt = 0; attempt < 32; ++attempt) {
        const uint64_t token = (static_cast<uint64_t>(random()) << 32) ^ random() ^ stamp ^
                               static_cast<uint64_t>(attempt);
        fs::path candidate = base / ("openrecover-pull-" + std::to_string(token));
        ec.clear();
        if (fs::create_directory(candidate, ec)) {
            return std::make_unique<ScopedPullDir>(std::move(candidate));
        }
    }
    return fail(ErrorCode::IoError,
                "cannot create a unique temporary pull directory under " + path_to_utf8(base));
}

#if defined(__linux__)
bool mount_path_contains(std::string_view mount_point, std::string_view target) {
    if (mount_point == "/") return !target.empty() && target.front() == '/';
    if (target.size() < mount_point.size()) return false;
    if (target.compare(0, mount_point.size(), mount_point) != 0) return false;
    return target.size() == mount_point.size() || target[mount_point.size()] == '/';
}

std::string unescape_mount_field(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 3 < text.size() && text[i + 1] >= '0' && text[i + 1] <= '3' &&
            text[i + 2] >= '0' && text[i + 2] <= '7' && text[i + 3] >= '0' && text[i + 3] <= '7') {
            out.push_back(static_cast<char>(((text[i + 1] - '0') << 6) | ((text[i + 2] - '0') << 3) |
                                            (text[i + 3] - '0')));
            i += 3;
        } else {
            out.push_back(text[i]);
        }
    }
    return out;
}
#endif

// Refuses output locations on MTP/gvfs mounts: those are the phone's own storage,
// and writing there would violate the read-only mandate.
Result<void> ensure_output_is_local(const fs::path& out_dir) {
    std::error_code ec;
    const fs::path absolute = fs::absolute(out_dir, ec).lexically_normal();
    if (ec) return fail(ErrorCode::InvalidArgument, "cannot resolve the output directory: " + ec.message());

#if defined(_WIN32)
    const std::wstring root = absolute.root_name().wstring();
    if (root.empty()) {
        return fail(ErrorCode::InvalidArgument, "output directory must be an absolute path");
    }
    std::wstring probe = root;
    if (probe.size() == 2 && probe[1] == L':') probe += L'\\';
    const UINT type = ::GetDriveTypeW(probe.c_str());
    if (type == DRIVE_REMOTE || type == DRIVE_NO_ROOT_DIR || type == DRIVE_UNKNOWN) {
        return fail(ErrorCode::OutputOnSourceDevice,
                    "output directory is on a remote or shell-namespace volume (" +
                        path_to_utf8(absolute) +
                        "); choose a local fixed drive, not an MTP-mounted phone");
    }
    return {};
#elif defined(__linux__)
    std::ifstream mountinfo("/proc/self/mountinfo");
    if (!mountinfo) {
        return fail(ErrorCode::OutputOnSourceDevice,
                    "cannot inspect mount points; refusing to write output without an MTP check");
    }
    const std::string target = path_to_utf8(absolute);
    std::string best_point;
    std::string best_fstype;
    std::string best_source;
    std::string line;
    while (std::getline(mountinfo, line)) {
        std::vector<std::string> fields;
        size_t pos = 0;
        while (pos <= line.size()) {
            const size_t space = line.find(' ', pos);
            fields.push_back(line.substr(pos, space == std::string::npos ? std::string::npos : space - pos));
            if (space == std::string::npos) break;
            pos = space + 1;
        }
        const auto separator = std::find(fields.begin(), fields.end(), "-");
        if (fields.size() < 7 || separator == fields.end()) continue;
        const size_t sep_index = static_cast<size_t>(separator - fields.begin());
        if (sep_index < 5 || sep_index + 2 >= fields.size()) continue;
        const std::string mount_point = unescape_mount_field(fields[4]);
        if (!mount_path_contains(mount_point, target)) continue;
        if (mount_point.size() < best_point.size()) continue;
        best_point = mount_point;
        best_fstype = lower_ascii(fields[sep_index + 1]);
        best_source = lower_ascii(unescape_mount_field(fields[sep_index + 2]));
    }
    if (best_point.empty()) {
        return fail(ErrorCode::OutputOnSourceDevice,
                    "cannot determine the filesystem backing the output directory; refusing to write");
    }
    const bool mtp = best_fstype.find("mtp") != std::string::npos ||
                     best_fstype.find("gvfs") != std::string::npos ||
                     best_source.find("mtp") != std::string::npos ||
                     best_source.find("gvfs") != std::string::npos ||
                     best_point.find("/gvfs") != std::string::npos;
    if (mtp) {
        return fail(ErrorCode::OutputOnSourceDevice,
                    "output directory is inside an MTP/gvfs mount (" + best_point +
                        "); choose a local filesystem path");
    }
    return {};
#else
    (void)out_dir;
    return fail(ErrorCode::Unsupported, "Android output location checks are not supported on this platform");
#endif
}

std::string local_relative_path(const std::string& serial, const AndroidScanRoot& root,
                                const Candidate& candidate) {
    std::string out = "android/";
    out += sanitize_component(serial);
    out += "/";
    out += root.id;
    out += "/";
    out += candidate.relative;
    return out;
}

}  // namespace

std::vector<std::string> android_limitations(int sdk) {
    std::vector<std::string> limitations = {
        "Without root, only shared storage and directories accessible to the adb shell user "
        "can be read; app-private data is inaccessible.",
        "Encrypted /data cannot be decrypted or read by this tool.",
        "True low-level undelete of deleted files requires root or a physical device image "
        "and is out of scope for the Android bridge.",
    };
    if (sdk >= 30) {
        limitations.push_back(
            "scoped_storage_restricts_android_data: Android 11+ restricts access to other "
            "apps' Android/data directories, so cache recovery may be incomplete.");
    }
    return limitations;
}

AndroidBridge::AndroidBridge(IAdbTransport& transport, AndroidBridgeOptions options)
    : transport_(transport), options_(std::move(options)) {}

Result<AndroidProbeInfo> AndroidBridge::probe(const std::string& serial) {
    auto valid = validate_adb_serial(serial);
    if (!valid) return fail(valid.error());

    auto devices = transport_.list_devices();
    if (!devices) return fail(devices.error());
    const AdbDevice* device = nullptr;
    for (const AdbDevice& candidate : *devices) {
        if (candidate.serial == serial) {
            device = &candidate;
            break;
        }
    }
    if (device == nullptr) {
        return fail(ErrorCode::NotFound, "adb device not found: " + serial);
    }
    switch (device->state) {
        case AdbState::Device: break;
        case AdbState::Unauthorized:
            return fail(ErrorCode::DeviceUnauthorized,
                        "device is unauthorized; unlock the phone and accept the USB debugging prompt");
        case AdbState::NoPermissions:
            return fail(ErrorCode::AccessDenied,
                        "adb reports 'no permissions'; check the udev rules for this device");
        case AdbState::Offline:
        case AdbState::Recovery:
        case AdbState::Sideload:
        case AdbState::Unknown:
            return fail(ErrorCode::DeviceOffline,
                        "device is not ready for shell access (state: " + device->state_raw + ")");
    }

    auto sdcard_cmd = AdbShellCmd::test_dir(kSdcardRoot);
    if (!sdcard_cmd) return fail(sdcard_cmd.error());
    auto sdcard = transport_.shell_readonly(serial, *sdcard_cmd);
    if (!sdcard) return fail(sdcard.error());
    if (std::string(trim_view(*sdcard)) != "1") {
        return fail(ErrorCode::StorageUnavailable,
                    "shared storage is not available at " + std::string(kSdcardRoot));
    }

    const auto read_prop = [&](const char* key) -> Result<std::string> {
        auto cmd = AdbShellCmd::get_prop(key);
        if (!cmd) return fail(cmd.error());
        auto value = transport_.shell_readonly(serial, *cmd);
        if (!value) return fail(value.error());
        return std::string(trim_view(*value));
    };

    AndroidProbeInfo info;
    info.serial = serial;
    auto model = read_prop("ro.product.model");
    if (!model) return fail(model.error());
    info.model = std::move(*model);
    auto manufacturer = read_prop("ro.product.manufacturer");
    if (!manufacturer) return fail(manufacturer.error());
    info.manufacturer = std::move(*manufacturer);
    auto release = read_prop("ro.build.version.release");
    if (!release) return fail(release.error());
    info.release = std::move(*release);
    auto sdk_raw = read_prop("ro.build.version.sdk");
    if (!sdk_raw) return fail(sdk_raw.error());
    info.sdk_raw = std::move(*sdk_raw);
    auto crypto = read_prop("ro.crypto.state");
    if (!crypto) return fail(crypto.error());
    info.crypto_state = std::move(*crypto);

    int sdk = 0;
    const auto parsed = std::from_chars(info.sdk_raw.data(), info.sdk_raw.data() + info.sdk_raw.size(), sdk);
    if (parsed.ec == std::errc{} && parsed.ptr == info.sdk_raw.data() + info.sdk_raw.size() && sdk >= 1 &&
        sdk <= 1000) {
        info.sdk = sdk;
    }
    return info;
}

Result<AndroidScanResult> AndroidBridge::scan(const std::string& serial,
                                              const AndroidScanProfile& profile,
                                              const ProgressFn& progress) {
    return scan_impl(serial, profile, progress, nullptr);
}

Result<AndroidScanResult> AndroidBridge::scan_and_pull(const std::string& serial,
                                                       const AndroidScanProfile& profile,
                                                       const ProgressFn& progress) {
    if (options_.out_dir.empty()) {
        return fail(ErrorCode::InvalidArgument, "an output directory is required to pull files");
    }
    auto local = ensure_output_is_local(options_.out_dir);
    if (!local) return fail(local.error());
    auto sink = io::OutputSink::open(options_.out_dir, io::SourceIdentity{});
    if (!sink) return fail(sink.error());
    return scan_impl(serial, profile, progress, sink->get());
}

Result<AndroidScanResult> AndroidBridge::scan_impl(const std::string& serial,
                                                   const AndroidScanProfile& profile,
                                                   const ProgressFn& progress, io::OutputSink* sink) {    AndroidScanResult result;
    auto probe_info = probe(serial);
    if (!probe_info) return fail(probe_info.error());
    result.probe = std::move(*probe_info);
    result.limitations = android_limitations(result.probe.sdk);

    result.roots.reserve(profile.roots.size());
    for (const AndroidScanRoot& root : profile.roots) {
        AndroidRootResult root_result;
        root_result.id = root.id;
        root_result.path = root.path;
        root_result.kind = android_root_kind_name(root.kind);
        result.roots.push_back(std::move(root_result));
    }

    std::vector<Candidate> candidates;
    for (size_t i = 0; i < profile.roots.size(); ++i) {
        auto filtered =
            enumerate_root(transport_, serial, profile, i, result.roots[i], result.warnings);
        if (!filtered) return fail(filtered.error());
        candidates.insert(candidates.end(),
                          std::make_move_iterator(filtered->candidates.begin()),
                          std::make_move_iterator(filtered->candidates.end()));
    }

    std::sort(candidates.begin(), candidates.end(), [&](const Candidate& a, const Candidate& b) {
        const std::string& root_a = profile.roots[a.root_index].id;
        const std::string& root_b = profile.roots[b.root_index].id;
        if (root_a != root_b) return root_a < root_b;
        if (a.remote_path != b.remote_path) return a.remote_path < b.remote_path;
        return a.root_index < b.root_index;
    });

    std::map<std::string, RemoteStat> stats;
    std::vector<const Candidate*> ordered;
    ordered.reserve(candidates.size());
    for (const Candidate& candidate : candidates) ordered.push_back(&candidate);
    for (size_t begin = 0; begin < ordered.size(); begin += kMaxStatFiles) {
        const size_t end = std::min(begin + kMaxStatFiles, ordered.size());
        auto ok = stat_range(transport_, serial, ordered, begin, end, stats, result.warnings);
        if (!ok) return fail(ok.error());
    }

    std::unique_ptr<ScopedPullDir> pull_dir;
    if (sink != nullptr) {
        auto created = make_pull_dir(options_.temp_dir);
        if (!created) return fail(created.error());
        pull_dir = std::move(*created);
    }

    uint64_t done = 0;
    const uint64_t total = static_cast<uint64_t>(candidates.size());
    uint64_t pull_seq = 0;
    for (Candidate& candidate : candidates) {
        const AndroidScanRoot& root = profile.roots[candidate.root_index];
        const auto stat_it = stats.find(candidate.remote_path);
        if (stat_it == stats.end()) {
            result.warnings.push_back("android: cannot stat " + candidate.remote_path +
                                      " (file may have disappeared); skipping");
        } else if (stat_it->second.size > profile.max_file_size) {
            result.warnings.push_back("android: skipping " + candidate.remote_path + " (" +
                                      std::to_string(stat_it->second.size) +
                                      " bytes exceeds max_file_size " +
                                      std::to_string(profile.max_file_size) + ")");
        } else if (stat_it->second.size != 0) {
            const RemoteStat& stat = stat_it->second;
            AndroidFile file;
            file.remote_path = candidate.remote_path;
            file.size_bytes = stat.size;
            file.mtime_unix = stat.mtime;
            file.root_id = root.id;
            file.kind = android_root_kind_name(root.kind);
            const std::string extension = lower_ascii(extension_of(candidate.filename));
            file.type = type_for_extension(extension);
            file.trashed_expires_at = candidate.trashed_expires_at;

            switch (root.kind) {
                case AndroidRootKind::Trash: file.confidence = Confidence::High; break;
                case AndroidRootKind::Thumbnail:
                    file.confidence = Confidence::Medium;
                    append_note(file.note, "low-resolution derivative");
                    break;
                case AndroidRootKind::Cache: file.confidence = Confidence::Low; break;
            }

            if (sink != nullptr) {
                const fs::path staged =
                    pull_dir->path() / ("payload-" + std::to_string(pull_seq++) + ".bin");
                auto pulled = transport_.pull(serial, candidate.remote_path, staged);
                if (!pulled && pulled.error().code != ErrorCode::AccessDenied) {
                    return fail(pulled.error());
                }
                if (!pulled) {
                    result.warnings.push_back("android: cannot pull " + candidate.remote_path +
                                              ": access denied");
                } else {
                    std::error_code ec;
                    const uint64_t staged_size = fs::file_size(staged, ec);
                    if (ec) {
                        return fail(ErrorCode::IoError, "pulled file is missing for " +
                                                            candidate.remote_path + ": " +
                                                            ec.message());
                    }
                    if (staged_size != stat.size) {
                        return fail(ErrorCode::IoError,
                                    "pulled size mismatch for " + candidate.remote_path + " (expected " +
                                        std::to_string(stat.size) + ", got " +
                                        std::to_string(staged_size) + ")");
                    }

                    const std::string_view signature_name = signature_for_extension(extension);
                    if (options_.validate_media && !signature_name.empty()) {
                        auto validation = validate_media(staged, staged_size, signature_name);
                        if (!validation) {
                            result.warnings.push_back("android: cannot validate " +
                                                      candidate.remote_path + ": " +
                                                      validation.error().message);
                        } else {
                            switch (validation->verdict) {
                                case carve::ValidationResult::Verdict::Valid:
                                    if (root.kind == AndroidRootKind::Cache) {
                                        file.confidence = Confidence::Medium;
                                    }
                                    break;
                                case carve::ValidationResult::Verdict::ValidTruncated:
                                    file.confidence = Confidence::Low;
                                    append_note(file.note, "truncated");
                                    break;
                                case carve::ValidationResult::Verdict::Invalid:
                                    file.confidence = Confidence::Low;
                                    append_note(file.note, "corrupt");
                                    break;
                            }
                        }
                    }

                    {
                        FileByteSource source(staged);
                        if (!source.is_open()) {
                            return fail(ErrorCode::IoError,
                                        "cannot reopen the staged pull file for " +
                                            candidate.remote_path);
                        }
                        const std::string relative = local_relative_path(serial, root, candidate);
                        auto written = sink->write_file(relative, source, stat.mtime);
                        if (!written) return fail(written.error());
                        if (written->size != stat.size) {
                            return fail(ErrorCode::IoError,
                                        "exported size mismatch for " + candidate.remote_path +
                                            " (expected " + std::to_string(stat.size) + ", wrote " +
                                            std::to_string(written->size) + ")");
                        }
                        file.sha256 = written->sha256;
                        file.local_relative = written->relative;
                    }
                    file.pulled = true;
                    result.roots[candidate.root_index].pulled++;

                    std::error_code remove_ec;
                    fs::remove(staged, remove_ec);
                }
            }

            result.roots[candidate.root_index].files++;
            result.files.push_back(std::move(file));
        }

        ++done;
        if (progress && !progress(done, total)) {
            return fail(ErrorCode::Cancelled, "android scan cancelled");
        }
    }
    return result;
}

Result<void> ensure_local_output_location(const std::filesystem::path& out_dir) {
    return ensure_output_is_local(out_dir);
}

}  // namespace openrecover::android
