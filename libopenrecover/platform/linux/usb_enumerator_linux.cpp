#include "openrecover/android/usb_enumerator.hpp"

#include <memory>

namespace openrecover::android {

namespace {

constexpr const char* kSysfsUsbDevices = "/sys/bus/usb/devices";

class SysfsUsbEnumerator final : public IUsbEnumerator {
public:
    Result<std::vector<UsbDeviceInfo>> enumerate() override {
        return enumerate_sysfs_usb(kSysfsUsbDevices);
    }
};

}  // namespace

Result<std::unique_ptr<IUsbEnumerator>> make_usb_enumerator() {
    return std::unique_ptr<IUsbEnumerator>(new SysfsUsbEnumerator());
}

}  // namespace openrecover::android
