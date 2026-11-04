#include "openrecover/android/usb_enumerator.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace openrecover::android {

namespace {

constexpr KnownAndroidVid kAndroidVids[] = {
#define OR_ANDROID_VID(name, vid) {static_cast<uint16_t>(vid), name},
#include "vid_table.inc"
#undef OR_ANDROID_VID
};

constexpr size_t kVidTableSize = sizeof(kAndroidVids) / sizeof(kAndroidVids[0]);
static_assert(kVidTableSize == 12, "section 6.1.3 lists twelve vendors");

bool ascii_iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb)) return false;
    }
    return true;
}

bool ascii_istarts_with(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size() && ascii_iequals(text.substr(0, prefix.size()), prefix);
}

bool ascii_alnum(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parse_hex(std::string_view text, uint32_t& out, size_t min_digits, size_t max_digits) {
    if (text.size() < min_digits || text.size() > max_digits) return false;
    uint32_t value = 0;
    for (char c : text) {
        const int digit = hex_digit(c);
        if (digit < 0) return false;
        value = value * 16 + static_cast<uint32_t>(digit);
    }
    out = value;
    return true;
}

bool is_trim_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

bool has_control(std::string_view text) {
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) return true;
    }
    return false;
}

std::optional<std::string> read_attribute(const std::filesystem::path& dir, const char* name) {
    std::ifstream in(dir / name, std::ios::binary);
    if (!in) return std::nullopt;
    std::string text;
    char buffer[1024];
    while (in && text.size() < 4096) {
        in.read(buffer, sizeof(buffer));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        text.append(buffer, static_cast<size_t>(got));
    }
    if (text.size() > 1024) return std::nullopt;
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && is_trim_space(text[begin])) ++begin;
    while (end > begin && is_trim_space(text[end - 1])) --end;
    return text.substr(begin, end - begin);
}

std::string read_text_attribute(const std::filesystem::path& dir, const char* name) {
    const auto raw = read_attribute(dir, name);
    if (!raw || raw->empty() || has_control(*raw)) return {};
    return *raw;
}

std::optional<uint16_t> read_hex16_attribute(const std::filesystem::path& dir, const char* name) {
    const auto raw = read_attribute(dir, name);
    if (!raw) return std::nullopt;
    uint32_t value = 0;
    if (!parse_hex(*raw, value, 4, 4)) return std::nullopt;
    return static_cast<uint16_t>(value);
}

std::optional<uint8_t> read_hex8_attribute(const std::filesystem::path& dir, const char* name) {
    const auto raw = read_attribute(dir, name);
    if (!raw) return std::nullopt;
    uint32_t value = 0;
    if (!parse_hex(*raw, value, 1, 2)) return std::nullopt;
    return static_cast<uint8_t>(value);
}

bool is_adb_interface_dir(const std::filesystem::path& dir) {
    const auto cls = read_hex8_attribute(dir, "bInterfaceClass");
    const auto sub = read_hex8_attribute(dir, "bInterfaceSubClass");
    const auto proto = read_hex8_attribute(dir, "bInterfaceProtocol");
    return cls && sub && proto && *cls == 0xFF && *sub == 0x42 && *proto == 0x01;
}

bool has_adb_interface(const std::filesystem::path& device_dir, std::string_view device_name) {
    std::error_code ec;
    std::filesystem::directory_iterator it(device_dir, ec);
    const std::filesystem::directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code type_ec;
        if (!it->is_directory(type_ec)) continue;
        const std::string name = it->path().filename().string();
        if (name.size() <= device_name.size()) continue;
        if (name.compare(0, device_name.size(), device_name) != 0) continue;
        if (name[device_name.size()] != ':') continue;
        if (is_adb_interface_dir(it->path())) return true;
    }
    return false;
}

}  // namespace

std::span<const KnownAndroidVid> known_android_vids() noexcept { return kAndroidVids; }

bool is_adb_interface_directory(const std::filesystem::path& interface_dir) {
    return is_adb_interface_dir(interface_dir);
}

bool is_known_android_vid(uint16_t vid) noexcept {
    return std::find_if(std::begin(kAndroidVids), std::end(kAndroidVids),
                        [vid](const KnownAndroidVid& entry) { return entry.vid == vid; }) !=
           std::end(kAndroidVids);
}

std::string_view android_vendor_name(uint16_t vid) noexcept {
    for (const KnownAndroidVid& entry : kAndroidVids) {
        if (entry.vid == vid) return entry.vendor;
    }
    return {};
}

std::optional<UsbInterfacePath> parse_usb_interface_path(std::string_view path) {
    if (path.empty() || has_control(path)) return std::nullopt;
    if (path.size() >= 4 && path.substr(0, 4) == "\\\\?\\") path.remove_prefix(4);

    std::vector<std::string_view> segments;
    size_t start = 0;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i != path.size() && path[i] != '#' && path[i] != '\\') continue;
        if (i > start) segments.push_back(path.substr(start, i - start));
        start = i + 1;
    }
    if (segments.size() < 3) return std::nullopt;
    if (!ascii_iequals(segments[0], "usb")) return std::nullopt;

    const std::string_view ids = segments[1];
    // "vid_XXXX&pid_XXXX" occupies the first 17 bytes.
    if (ids.size() < 17 || !ascii_istarts_with(ids, "vid_")) return std::nullopt;
    uint32_t vid = 0;
    uint32_t pid = 0;
    if (!parse_hex(ids.substr(4, 4), vid, 4, 4)) return std::nullopt;
    if (!ascii_istarts_with(ids.substr(8), "&pid_")) return std::nullopt;
    if (!parse_hex(ids.substr(13, 4), pid, 4, 4)) return std::nullopt;

    UsbInterfacePath parsed;
    parsed.vid = static_cast<uint16_t>(vid);
    parsed.pid = static_cast<uint16_t>(pid);

    size_t pos = 17;
    while (pos < ids.size()) {
        if (ids[pos] != '&') return std::nullopt;
        ++pos;
        const size_t next = ids.find('&', pos);
        const std::string_view token = ids.substr(pos, next == std::string_view::npos
                                                          ? std::string_view::npos
                                                          : next - pos);
        if (token.empty()) return std::nullopt;
        const size_t underscore = token.find('_');
        if (underscore == std::string_view::npos || underscore == 0 || underscore + 1 >= token.size())
            return std::nullopt;
        const std::string_view key = token.substr(0, underscore);
        const std::string_view value = token.substr(underscore + 1);
        for (char c : value) {
            if (!ascii_alnum(c)) return std::nullopt;
        }
        if (ascii_iequals(key, "mi")) {
            uint32_t mi = 0;
            if (!parse_hex(value, mi, 2, 2)) return std::nullopt;
            parsed.interface_number = static_cast<uint8_t>(mi);
            parsed.composite = true;
        }
        if (next == std::string_view::npos) break;
        pos = next;
    }

    const std::string_view serial = segments[2];
    if (serial.size() > 256) return std::nullopt;
    // A GUID in the serial slot means the path is truncated.
    if (serial.front() == '{' && serial.back() == '}') return std::nullopt;
    // Synthetic instance ids embed '&'; only a real iSerialNumber is reported.
    if (serial.find('&') == std::string_view::npos) parsed.serial = std::string(serial);
    return parsed;
}

Result<std::vector<UsbDeviceInfo>> enumerate_sysfs_usb(const std::filesystem::path& sysfs_root) {
    std::error_code ec;
    if (!std::filesystem::is_directory(sysfs_root, ec)) {
        return fail(ErrorCode::IoError,
                    "USB sysfs root is not a directory: " + sysfs_root.string());
    }

    std::vector<UsbDeviceInfo> devices;
    std::filesystem::directory_iterator it(sysfs_root, ec);
    if (ec) {
        return fail(ErrorCode::IoError,
                    "cannot enumerate " + sysfs_root.string() + ": " + ec.message());
    }
    const std::filesystem::directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code type_ec;
        if (!it->is_directory(type_ec)) continue;
        const std::string name = it->path().filename().string();
        if (name.empty() || name.find(':') != std::string::npos) continue;

        const auto vid = read_hex16_attribute(it->path(), "idVendor");
        const auto pid = read_hex16_attribute(it->path(), "idProduct");
        if (!vid || !pid) continue;

        UsbDeviceInfo info;
        info.vid = *vid;
        info.pid = *pid;
        info.serial_usb = read_text_attribute(it->path(), "serial");
        info.manufacturer = read_text_attribute(it->path(), "manufacturer");
        info.product = read_text_attribute(it->path(), "product");
        info.instance_id = it->path().generic_string();
        info.has_adb_interface = has_adb_interface(it->path(), name);
        info.known_android_vid = is_known_android_vid(info.vid);
        devices.push_back(std::move(info));
    }
    if (ec) {
        return fail(ErrorCode::IoError,
                    "error while enumerating " + sysfs_root.string() + ": " + ec.message());
    }
    std::sort(devices.begin(), devices.end(),
              [](const UsbDeviceInfo& a, const UsbDeviceInfo& b) {
                  return a.instance_id < b.instance_id;
              });
    return devices;
}

#if !defined(_WIN32) && !defined(__linux__)
Result<std::unique_ptr<IUsbEnumerator>> make_usb_enumerator() {
    return fail(ErrorCode::Unsupported, "USB enumeration is not implemented on this platform");
}
#endif

}  // namespace openrecover::android
