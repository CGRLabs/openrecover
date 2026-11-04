// The ONLY writer in the project. Every file created by OpenRecover goes through here.
#include "openrecover/io/output_sink.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cwctype>
#include <fstream>
#include <set>
#include <system_error>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/path_util.hpp"
#include "openrecover/io/win_physical_device.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#endif

namespace fs = std::filesystem;

namespace openrecover::io {

namespace {

#if defined(_WIN32)
fs::path os_path(const fs::path& p) { return win_long_path(p); }

bool component_equal(const fs::path& a, const fs::path& b) {
    std::wstring x = a.wstring(), y = b.wstring();
    if (x.size() != y.size()) return false;
    for (size_t i = 0; i < x.size(); ++i)
        if (std::towlower(x[i]) != std::towlower(y[i])) return false;
    return true;
}
#else
fs::path os_path(const fs::path& p) { return p; }
bool component_equal(const fs::path& a, const fs::path& b) { return a == b; }
#endif

// Canonical form of `p` even if its tail does not exist yet; also returns the deepest existing ancestor.
Result<fs::path> resolve_future_dir(const fs::path& p, fs::path& existing_ancestor) {
    std::error_code ec;
    fs::path abs = fs::absolute(p, ec).lexically_normal();
    if (ec) return fail(ErrorCode::InvalidArgument, "cannot resolve output path: " + ec.message());
    fs::path cur = abs;
    std::vector<fs::path> tail;
    while (!fs::exists(cur, ec)) {
        if (!cur.has_relative_path()) return fail(ErrorCode::NotFound, "output path has no existing ancestor");
        tail.push_back(cur.filename());
        cur = cur.parent_path();
    }
    if (!fs::is_directory(cur, ec))
        return fail(ErrorCode::InvalidArgument, path_to_utf8(cur) + " exists and is not a directory");
    fs::path canon = fs::canonical(cur, ec);
    if (ec) return fail(ErrorCode::IoError, "cannot canonicalize " + path_to_utf8(cur) + ": " + ec.message());
    existing_ancestor = canon;
    for (auto it = tail.rbegin(); it != tail.rend(); ++it) canon /= *it;
    return canon.lexically_normal();
}

#if defined(__linux__)

// Whole-disk names (e.g. "sda") backing a block device number, following dm/md slaves.
void disks_for_devnum(dev_t dev, std::set<std::string>& out, int depth = 0) {
    if (depth > 16) return;
    std::error_code ec;
    fs::path sys = "/sys/dev/block/" + std::to_string(major(dev)) + ":" + std::to_string(minor(dev));
    fs::path real = fs::canonical(sys, ec);
    if (ec) return;
    fs::path disk = fs::exists(real / "partition", ec) ? real.parent_path() : real;
    fs::path slaves = disk / "slaves";
    bool had_slaves = false;
    if (fs::is_directory(slaves, ec)) {
        for (const auto& e : fs::directory_iterator(slaves, ec)) {
            std::ifstream in(e.path() / "dev");
            unsigned maj = 0, min = 0;
            char colon = 0;
            if (in >> maj >> colon >> min) {
                had_slaves = true;
                disks_for_devnum(makedev(maj, min), out, depth + 1);
            }
        }
    }
    if (!had_slaves) out.insert(disk.filename().string());
}

std::string unescape_mountinfo(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size()) {
            out.push_back(static_cast<char>(((s[i + 1] - '0') << 6) | ((s[i + 2] - '0') << 3) | (s[i + 3] - '0')));
            i += 3;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

// Disks backing the filesystem that contains `dir`. Sets `unknown` if it is block-backed but unresolvable.
std::set<std::string> disks_for_directory(const fs::path& dir, bool& unknown) {
    unknown = false;
    std::set<std::string> disks;
    std::ifstream mi("/proc/self/mountinfo");
    std::string line, best_point, best_source;
    unsigned best_maj = 0, best_min = 0;
    const std::string target = dir.string();
    while (std::getline(mi, line)) {
        std::vector<std::string> f;
        size_t pos = 0;
        while (pos < line.size()) {
            size_t sp = line.find(' ', pos);
            if (sp == std::string::npos) sp = line.size();
            f.push_back(line.substr(pos, sp - pos));
            pos = sp + 1;
        }
        auto dash = std::find(f.begin(), f.end(), "-");
        if (f.size() < 5 || dash == f.end() || dash + 2 >= f.end()) continue;
        std::string point = unescape_mountinfo(f[4]);
        bool prefix = target == point || point == "/" ||
                      (target.rfind(point, 0) == 0 && target.size() > point.size() && target[point.size()] == '/');
        if (!prefix || point.size() < best_point.size()) continue;
        best_point = point;
        best_source = unescape_mountinfo(*(dash + 2));
        unsigned maj = 0, min = 0;
        if (std::sscanf(f[2].c_str(), "%u:%u", &maj, &min) == 2) {
            best_maj = maj;
            best_min = min;
        }
    }
    if (best_source.rfind("/dev/", 0) == 0) {
        struct stat st {};
        if (::stat(best_source.c_str(), &st) == 0 && S_ISBLK(st.st_mode)) disks_for_devnum(st.st_rdev, disks);
        if (disks.empty()) unknown = true;
        return disks;
    }
    if (best_maj != 0) disks_for_devnum(makedev(best_maj, best_min), disks);
    return disks;
}

#endif

Result<void> check_not_on_source(const fs::path& target_root, const fs::path& existing, const SourceIdentity& source,
                                 const std::shared_ptr<win::IWin32Api>& api) {
    (void)existing;
    (void)api;
    switch (source.kind) {
        case SourceIdentity::Kind::None: return {};
        case SourceIdentity::Kind::ImageFile: {
            std::error_code ec;
            fs::path img = fs::weakly_canonical(fs::absolute(source.path, ec), ec);
            if (ec) return fail(ErrorCode::OutputOnSourceDevice, "cannot resolve source image path; refusing output");
            if (path_is_within(img, target_root))
                return fail(ErrorCode::OutputOnSourceDevice,
                            "output directory " + path_to_utf8(target_root) + " contains the source image " +
                                path_to_utf8(img));
            return {};
        }
        case SourceIdentity::Kind::WindowsPhysicalDrive: {
#if defined(_WIN32)
            auto disk = api->DiskNumberForPath(existing.wstring());
            if (!disk)
                return fail(ErrorCode::OutputOnSourceDevice,
                            "cannot determine which disk holds the output directory; refusing to write");
            if (*disk == source.drive_number)
                return fail(ErrorCode::OutputOnSourceDevice, "output directory is on the source disk PhysicalDrive" +
                                                                 std::to_string(source.drive_number));
            return {};
#else
            return fail(ErrorCode::Unsupported, "Windows physical drive sources are only supported on Windows");
#endif
        }
        case SourceIdentity::Kind::WindowsVolume: {
#if defined(_WIN32)
            // A volume source names one filesystem, so another volume on the same disk is safe
            // to write: recovered bytes land in different clusters than the ones being scanned.
            // Same-volume output is what could overwrite the evidence. Volume identity is
            // compared by GUID path, which survives mount-point aliasing.
            std::wstring vol = source.path.wstring();
            const std::wstring prefix = L"\\\\.\\";
            if (vol.rfind(prefix, 0) == 0) vol.erase(0, prefix.size());
            if (!vol.empty() && vol.back() != L'\\') vol.push_back(L'\\');
            const auto source_volume = api->VolumeGuidForPath(vol);
            const auto output_volume = api->VolumeGuidForPath(existing.wstring());
            if (!source_volume || !output_volume)
                return fail(ErrorCode::OutputOnSourceDevice,
                            "cannot determine which volume holds the output directory; refusing to write");
            if (*source_volume == *output_volume)
                return fail(ErrorCode::OutputOnSourceDevice,
                            "output directory is on the source volume " + path_to_utf8(source.path));
            return {};
#else
            (void)api;
            return fail(ErrorCode::Unsupported, "Windows volume sources are only supported on Windows");
#endif
        }
        case SourceIdentity::Kind::BlockNode: {
#if defined(__linux__)
            struct stat st {};
            if (::stat(source.path.c_str(), &st) != 0 || !S_ISBLK(st.st_mode))
                return fail(ErrorCode::OutputOnSourceDevice, "cannot stat source block device; refusing output");
            std::set<std::string> src_disks;
            disks_for_devnum(st.st_rdev, src_disks);
            if (src_disks.empty())
                return fail(ErrorCode::OutputOnSourceDevice, "cannot resolve source disk in sysfs; refusing output");
            bool unknown = false;
            auto out_disks = disks_for_directory(existing, unknown);
            if (unknown)
                return fail(ErrorCode::OutputOnSourceDevice,
                            "cannot resolve the disk backing the output directory; refusing output");
            for (const auto& d : out_disks)
                if (src_disks.count(d))
                    return fail(ErrorCode::OutputOnSourceDevice,
                                "output directory resides on a filesystem backed by source disk " + d);
            return {};
#else
            return fail(ErrorCode::Unsupported, "block device sources are only supported on Linux");
#endif
        }
    }
    return {};
}

Result<void> commit_no_replace(const fs::path& temp, const fs::path& final_path, bool& exists) {
    exists = false;
#if defined(_WIN32)
    if (::MoveFileExW(os_path(temp).c_str(), os_path(final_path).c_str(), MOVEFILE_WRITE_THROUGH)) return {};
    DWORD e = ::GetLastError();
    if (e == ERROR_ALREADY_EXISTS || e == ERROR_FILE_EXISTS) {
        exists = true;
        return {};
    }
    return fail(ErrorCode::IoError, "rename failed: Win32 error " + std::to_string(e));
#else
    if (::link(temp.c_str(), final_path.c_str()) == 0) {
        std::error_code ec;
        fs::remove(temp, ec);
        return {};
    }
    if (errno == EEXIST) {
        exists = true;
        return {};
    }
    // Filesystems without hard links: check-then-rename (single writer per output root).
    std::error_code ec;
    if (fs::exists(final_path, ec)) {
        exists = true;
        return {};
    }
    fs::rename(temp, final_path, ec);
    if (ec) return fail(ErrorCode::IoError, "rename failed: " + ec.message());
    return {};
#endif
}

}  // namespace

bool path_is_within(const fs::path& child, const fs::path& root) {
    fs::path c = child.lexically_normal(), r = root.lexically_normal();
    auto ci = c.begin();
    for (auto ri = r.begin(); ri != r.end(); ++ri) {
        if (ri->empty()) continue;  // trailing separator
        if (ci == c.end() || !component_equal(*ci, *ri)) return false;
        ++ci;
    }
    return true;
}

SourceIdentity SourceIdentity::from_source_string(const std::string& source) {
    if (is_valid_physical_drive_path(source))
        return physical_drive(static_cast<uint32_t>(std::stoul(source.substr(17))));
#if defined(_WIN32)
    if (is_valid_volume_path(source)) return windows_volume(path_from_utf8(source));
#endif
#if defined(__linux__)
    std::error_code ec;
    if (source.rfind("/dev/", 0) == 0 && fs::is_block_file(source, ec)) return block_node(source);
#endif
    return image(path_from_utf8(source));
}

Result<size_t> MemoryByteSource::read_some(uint8_t* dst, size_t len) {
    size_t n = std::min(len, data_.size() - pos_);
    if (n) std::copy(data_.begin() + static_cast<std::ptrdiff_t>(pos_),
                     data_.begin() + static_cast<std::ptrdiff_t>(pos_ + n), dst);
    pos_ += n;
    return n;
}

std::vector<std::string> OutputSink::sanitize_relative(std::string_view rel) {
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos <= rel.size()) {
        size_t slash = rel.find('/', pos);
        if (slash == std::string_view::npos) slash = rel.size();
        std::string_view comp = rel.substr(pos, slash - pos);
        if (!comp.empty()) parts.push_back(sanitize_component(std::string(comp)));
        pos = slash + 1;
    }
    return parts;
}

Result<std::unique_ptr<OutputSink>> OutputSink::open(const fs::path& out_dir, const SourceIdentity& source,
                                                     std::shared_ptr<win::IWin32Api> api) {
    if (out_dir.empty()) return fail(ErrorCode::InvalidArgument, "output directory is empty");
#if defined(_WIN32)
    if (!api) api = win::real_api();
#endif
    fs::path existing;
    auto target = resolve_future_dir(out_dir, existing);
    if (!target) return fail(target.error());

    // The check runs before any directory is created, so nothing is ever created on the source.
    auto ok = check_not_on_source(*target, existing, source, api);
    if (!ok) return fail(ok.error());

    std::error_code ec;
    fs::create_directories(os_path(*target), ec);
    if (ec) return fail(ErrorCode::IoError, "cannot create output directory: " + ec.message());
    fs::path root = fs::canonical(*target, ec);
    if (ec) return fail(ErrorCode::IoError, "cannot canonicalize output directory: " + ec.message());
    return std::unique_ptr<OutputSink>(new OutputSink(std::move(root)));
}

Result<WrittenFile> OutputSink::write_file(std::string_view relative_path, ByteSource& src,
                                           std::optional<int64_t> mtime_unix) {
    auto parts = sanitize_relative(relative_path);
    if (parts.empty()) return fail(ErrorCode::InvalidArgument, "empty relative output path");

    fs::path dir = root_;
    for (size_t i = 0; i + 1 < parts.size(); ++i) dir /= path_from_utf8(parts[i]);
    if (!path_is_within(dir, root_)) return fail(ErrorCode::PolicyViolation, "path escapes output root");
    std::error_code ec;
    fs::create_directories(os_path(dir), ec);
    if (ec) return fail(ErrorCode::IoError, "cannot create directory " + path_to_utf8(dir) + ": " + ec.message());
    fs::path real_dir = fs::canonical(os_path(dir), ec);
    if (ec || !path_is_within(fs::canonical(dir, ec), root_))
        return fail(ErrorCode::PolicyViolation, "directory resolves outside the output root (symlink?)");
    (void)real_dir;

    const std::string& name = parts.back();
    std::string stem = name, ext;
    size_t dot = name.rfind('.');
    if (dot != std::string::npos && dot > 0) {
        stem = name.substr(0, dot);
        ext = name.substr(dot);
    }

    fs::path temp;
    for (;;) {
        temp = dir / path_from_utf8(".~" + std::to_string(++temp_counter_) + ".part");
        if (!fs::exists(os_path(temp), ec)) break;
    }

    Sha256Hasher hasher;
    uint64_t total = 0;
    {
        std::ofstream os(os_path(temp), std::ios::binary | std::ios::trunc);
        if (!os) return fail(ErrorCode::IoError, "cannot create " + path_to_utf8(temp));
        std::vector<uint8_t> buf(1u << 20);
        for (;;) {
            auto n = src.read_some(buf.data(), buf.size());
            if (!n) {
                os.close();
                fs::remove(os_path(temp), ec);
                return fail(n.error());
            }
            if (*n == 0) break;
            hasher.update(buf.data(), *n);
            os.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(*n));
            if (!os) break;
            total += *n;
        }
        os.close();
        if (!os) {
            fs::remove(os_path(temp), ec);
            return fail(ErrorCode::IoError, "write failed for " + path_to_utf8(temp));
        }
    }

    fs::path final_path;
    std::string final_name;
    for (uint32_t i = 0;; ++i) {
        if (i > 100000) {
            fs::remove(os_path(temp), ec);
            return fail(ErrorCode::AlreadyExists, "too many name collisions for " + name);
        }
        final_name = i == 0 ? name : stem + " (" + std::to_string(i) + ")" + ext;
        final_path = dir / path_from_utf8(final_name);
        bool exists = false;
        auto c = commit_no_replace(temp, final_path, exists);
        if (!c) {
            fs::remove(os_path(temp), ec);
            return fail(c.error());
        }
        if (!exists) break;
    }

    if (mtime_unix) {
        const std::chrono::sys_seconds sys_tp{std::chrono::seconds(*mtime_unix)};
#if defined(_MSC_VER)
        auto tp = std::chrono::clock_cast<std::chrono::file_clock>(sys_tp);
#else
        auto tp = std::chrono::file_clock::from_sys(sys_tp);
#endif
        fs::last_write_time(os_path(final_path), tp, ec);
        if (ec) log::warn("cannot set mtime on " + path_to_utf8(final_path) + ": " + ec.message());
    }

    WrittenFile wf;
    wf.path = final_path;
    for (size_t i = 0; i + 1 < parts.size(); ++i) wf.relative += parts[i] + "/";
    wf.relative += final_name;
    wf.sha256 = hasher.finish_hex();
    wf.size = total;
    return wf;
}

}  // namespace openrecover::io
