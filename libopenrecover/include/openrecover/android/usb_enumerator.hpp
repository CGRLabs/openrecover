#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/result.hpp"

namespace openrecover::android {

struct UsbDeviceInfo {
    uint16_t vid = 0;
    uint16_t pid = 0;
    std::string serial_usb;
    std::string manufacturer;
    std::string product;
    std::string instance_id;
    bool has_adb_interface = false;
    bool known_android_vid = false;
};

class IUsbEnumerator {
public:
    virtual ~IUsbEnumerator() = default;
    virtual Result<std::vector<UsbDeviceInfo>> enumerate() = 0;
};

struct KnownAndroidVid {
    uint16_t vid = 0;
    std::string_view vendor;
};

// Non-exhaustive hint table from section 6.1.3; a VID match is never authoritative.
std::span<const KnownAndroidVid> known_android_vids() noexcept;
bool is_known_android_vid(uint16_t vid) noexcept;
std::string_view android_vendor_name(uint16_t vid) noexcept;

// Components of a Windows device interface path such as
//   \\?\usb#vid_18d1&pid_4ee7&mi_01#SERIAL#{a5dcbf10-...}
// `serial` stays empty when the third segment is a synthetic instance id (contains '&').
struct UsbInterfacePath {
    uint16_t vid = 0;
    uint16_t pid = 0;
    std::string serial;
    uint8_t interface_number = 0;
    bool composite = false;
};

std::optional<UsbInterfacePath> parse_usb_interface_path(std::string_view path);

// Portable sysfs reader (section 6.1.4). Exposed so the parser can be exercised
// against a fake tree on every platform.
Result<std::vector<UsbDeviceInfo>> enumerate_sysfs_usb(const std::filesystem::path& sysfs_root);

// True when bInterfaceClass/SubClass/Protocol are ff/42/01 (the ADB interface).
bool is_adb_interface_directory(const std::filesystem::path& interface_dir);

// SetupAPI on Windows, sysfs on Linux; unsupported elsewhere.
Result<std::unique_ptr<IUsbEnumerator>> make_usb_enumerator();

}  // namespace openrecover::android
