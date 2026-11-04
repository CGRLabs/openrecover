#include "openrecover/android/usb_enumerator.hpp"

#include <windows.h>

#include <setupapi.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/log.hpp"

namespace openrecover::android {

namespace {

constexpr GUID kUsbDeviceInterfaceGuid = {
    0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED}};

class DeviceInfoSet {
public:
    explicit DeviceInfoSet(HDEVINFO handle) : handle_(handle) {}
    ~DeviceInfoSet() {
        if (handle_ != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(handle_);
    }
    DeviceInfoSet(const DeviceInfoSet&) = delete;
    DeviceInfoSet& operator=(const DeviceInfoSet&) = delete;
    HDEVINFO get() const noexcept { return handle_; }

private:
    HDEVINFO handle_ = INVALID_HANDLE_VALUE;
};

std::string last_error_text(const char* what) {
    return std::string(what) + " failed (Win32 error " +
           std::to_string(static_cast<unsigned long>(GetLastError())) + ")";
}

std::optional<std::string> to_utf8(const std::wstring& text) {
    if (text.empty()) return std::string();
    if (text.size() > static_cast<size_t>(std::numeric_limits<int>::max())) return std::nullopt;
    const int length = static_cast<int>(text.size());
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), length,
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::nullopt;
    std::string out(static_cast<size_t>(needed), '\0');
    const int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), length,
                                            out.data(), needed, nullptr, nullptr);
    if (written != needed) return std::nullopt;
    return out;
}

std::wstring property_string(HDEVINFO set, SP_DEVINFO_DATA& info, DWORD property) {
    DWORD type = 0;
    DWORD required = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type, nullptr, 0, &required);
    if (required == 0) return {};
    std::vector<wchar_t> buffer(required / sizeof(wchar_t) + 2, L'\0');
    if (!SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type,
                                           reinterpret_cast<PBYTE>(buffer.data()),
                                           static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                                           nullptr)) {
        return {};
    }
    buffer.back() = L'\0';
    return std::wstring(buffer.data());
}

std::vector<std::wstring> property_multi_string(HDEVINFO set, SP_DEVINFO_DATA& info,
                                                DWORD property) {
    DWORD type = 0;
    DWORD required = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type, nullptr, 0, &required);
    if (required == 0) return {};
    std::vector<wchar_t> buffer(required / sizeof(wchar_t) + 2, L'\0');
    if (!SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type,
                                           reinterpret_cast<PBYTE>(buffer.data()),
                                           static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                                           nullptr)) {
        return {};
    }
    buffer.back() = L'\0';

    std::vector<std::wstring> values;
    size_t begin = 0;
    while (begin < buffer.size() && buffer[begin] != L'\0') {
        size_t end = begin;
        while (end < buffer.size() && buffer[end] != L'\0') ++end;
        values.emplace_back(buffer.data() + begin, end - begin);
        begin = end + 1;
    }
    return values;
}

std::wstring ascii_lower(std::wstring text) {
    for (wchar_t& c : text) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    }
    return text;
}

bool ids_contain_adb_triplet(const std::vector<std::wstring>& ids) {
    static constexpr std::wstring_view kAdbClass = L"class_ff&subclass_42&prot_01";
    for (const std::wstring& id : ids) {
        if (ascii_lower(id).find(kAdbClass) != std::wstring::npos) return true;
    }
    return false;
}

bool node_has_adb_interface(HDEVINFO set, SP_DEVINFO_DATA& info) {
    return ids_contain_adb_triplet(property_multi_string(set, info, SPDRP_COMPATIBLEIDS)) ||
           ids_contain_adb_triplet(property_multi_string(set, info, SPDRP_HARDWAREID));
}

std::wstring device_instance_id(HDEVINFO set, SP_DEVINFO_DATA& info) {
    DWORD required = 0;
    SetupDiGetDeviceInstanceIdW(set, &info, nullptr, 0, &required);
    if (required == 0) return {};
    std::wstring id(required, L'\0');
    if (!SetupDiGetDeviceInstanceIdW(set, &info, id.data(), required, nullptr)) return {};
    while (!id.empty() && id.back() == L'\0') id.pop_back();
    return id;
}

struct UsbIdentity {
    uint16_t vid = 0;
    uint16_t pid = 0;
};

// Composite devices expose the ADB function as a child MI node; scan every USB
// devnode once and remember which vendor/product pairs carry the class triplet.
std::vector<UsbIdentity> adb_usb_nodes() {
    std::vector<UsbIdentity> nodes;
    HDEVINFO raw =
        SetupDiGetClassDevsW(nullptr, L"USB", nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (raw == INVALID_HANDLE_VALUE) {
        log::warn(last_error_text("SetupDiGetClassDevsW(USB)"));
        return nodes;
    }
    DeviceInfoSet set(raw);
    for (DWORD index = 0;; ++index) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!SetupDiEnumDeviceInfo(set.get(), index, &info)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                log::warn(last_error_text("SetupDiEnumDeviceInfo"));
            }
            break;
        }
        const auto instance = to_utf8(device_instance_id(set.get(), info));
        if (!instance) continue;
        const auto parsed = parse_usb_interface_path(*instance);
        if (!parsed) continue;
        if (node_has_adb_interface(set.get(), info)) {
            nodes.push_back(UsbIdentity{parsed->vid, parsed->pid});
        }
    }
    return nodes;
}

Result<std::vector<UsbDeviceInfo>> enumerate_setupapi() {
    const GUID guid = kUsbDeviceInterfaceGuid;
    HDEVINFO raw =
        SetupDiGetClassDevsW(&guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (raw == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::IoError, last_error_text("SetupDiGetClassDevsW(USB devices)"));
    }
    DeviceInfoSet set(raw);
    const std::vector<UsbIdentity> adb_nodes = adb_usb_nodes();

    std::vector<UsbDeviceInfo> devices;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interface_data{};
        interface_data.cbSize = sizeof(interface_data);
        if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &guid, index, &interface_data)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
            return fail(ErrorCode::IoError, last_error_text("SetupDiEnumDeviceInterfaces"));
        }

        DWORD required = 0;
        SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, nullptr, 0, &required,
                                         nullptr);
        if (required == 0) continue;

        std::vector<BYTE> buffer(required);
        auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, detail, required, nullptr,
                                              &info)) {
            log::debug(last_error_text("SetupDiGetDeviceInterfaceDetailW"));
            continue;
        }

        const auto path = to_utf8(std::wstring(detail->DevicePath));
        if (!path) continue;
        const auto parsed = parse_usb_interface_path(*path);
        if (!parsed) {
            log::debug("skipping unrecognised USB device interface path");
            continue;
        }

        UsbDeviceInfo device;
        device.vid = parsed->vid;
        device.pid = parsed->pid;
        device.serial_usb = parsed->serial;
        const auto manufacturer = to_utf8(property_string(set.get(), info, SPDRP_MFG));
        if (manufacturer) device.manufacturer = *manufacturer;
        const auto friendly = to_utf8(property_string(set.get(), info, SPDRP_FRIENDLYNAME));
        if (friendly) device.product = *friendly;
        if (device.product.empty()) {
            const auto description =
                to_utf8(property_string(set.get(), info, SPDRP_DEVICEDESC));
            if (description) device.product = *description;
        }
        const auto instance = to_utf8(device_instance_id(set.get(), info));
        if (instance) device.instance_id = *instance;
        device.has_adb_interface =
            node_has_adb_interface(set.get(), info) ||
            std::any_of(adb_nodes.begin(), adb_nodes.end(), [&device](const UsbIdentity& node) {
                return node.vid == device.vid && node.pid == device.pid;
            });
        device.known_android_vid = is_known_android_vid(device.vid);
        devices.push_back(std::move(device));
    }

    std::stable_sort(devices.begin(), devices.end(),
                     [](const UsbDeviceInfo& a, const UsbDeviceInfo& b) {
                         return a.instance_id < b.instance_id;
                     });
    return devices;
}

class SetupApiUsbEnumerator final : public IUsbEnumerator {
public:
    Result<std::vector<UsbDeviceInfo>> enumerate() override { return enumerate_setupapi(); }
};

}  // namespace

Result<std::unique_ptr<IUsbEnumerator>> make_usb_enumerator() {
    return std::unique_ptr<IUsbEnumerator>(new SetupApiUsbEnumerator());
}

}  // namespace openrecover::android
