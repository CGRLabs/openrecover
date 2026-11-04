#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/android/usb_enumerator.hpp"
#include "test_util.hpp"

using namespace openrecover;
using namespace openrecover::android;

namespace {

void put_file(const std::filesystem::path& path, std::string_view text) {
    std::filesystem::create_directories(path.parent_path());
    test::create_test_file(path, std::vector<uint8_t>(text.begin(), text.end()));
}

struct ParsedPathCase {
    std::string path;
    uint16_t vid;
    uint16_t pid;
    const char* serial;
    bool composite;
    uint8_t interface_number;
};

}  // namespace

TEST_CASE("USB interface paths parse vendor, product, serial and interface",
          "[android][usb]") {
    const std::string guid = "#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
    const std::vector<ParsedPathCase> cases = {
        {"\\\\?\\usb#vid_18d1&pid_4ee7#39241FDH2004J4" + guid, 0x18D1, 0x4EE7,
         "39241FDH2004J4", false, 0},
        {"\\\\?\\usb#vid_04e8&pid_6860#R58M12ABC" + guid, 0x04E8, 0x6860, "R58M12ABC",
         false, 0},
        {"\\\\?\\USB#VID_0BB4&PID_0FFF#HT1234567890" + guid, 0x0BB4, 0x0FFF,
         "HT1234567890", false, 0},
        {"\\\\?\\usb#vid_12d1&pid_107e#ABCDEF123456" + guid, 0x12D1, 0x107E,
         "ABCDEF123456", false, 0},
        {"\\\\?\\usb#vid_22b8&pid_2e82#ZY3228PLMC" + guid, 0x22B8, 0x2E82,
         "ZY3228PLMC", false, 0},
        {"\\\\?\\usb#vid_1004&pid_633e#LG123456789" + guid, 0x1004, 0x633E,
         "LG123456789", false, 0},
        {"\\\\?\\usb#vid_0fce&pid_51a2#CB5123ABCD" + guid, 0x0FCE, 0x51A2,
         "CB5123ABCD", false, 0},
        {"\\\\?\\usb#vid_0b05&pid_5480#A1B2C3D4" + guid, 0x0B05, 0x5480, "A1B2C3D4",
         false, 0},
        {"\\\\?\\usb#vid_2717&pid_ff48#a1b2c3d4" + guid, 0x2717, 0xFF48, "a1b2c3d4",
         false, 0},
        {"\\\\?\\usb#vid_2a70&pid_f003#1234567890abcdef" + guid, 0x2A70, 0xF003,
         "1234567890abcdef", false, 0},
        {"\\\\?\\usb#vid_22d9&pid_2769#OP1234567890" + guid, 0x22D9, 0x2769,
         "OP1234567890", false, 0},
        {"\\\\?\\usb#vid_17ef&pid_7a39#ABCD1234" + guid, 0x17EF, 0x7A39, "ABCD1234",
         false, 0},
        {"\\\\?\\usb#vid_18d1&pid_4ee7&mi_01#7&1a2b3c4d&0&0000" + guid, 0x18D1, 0x4EE7,
         "", true, 1},
        {"\\\\?\\USB#VID_04E8&PID_6860&MI_00#5&2B5D0D3&0&0000" + guid, 0x04E8, 0x6860,
         "", true, 0},
        {"USB\\VID_18D1&PID_4EE7\\39241FDH2004J4", 0x18D1, 0x4EE7, "39241FDH2004J4",
         false, 0},
    };

    for (const ParsedPathCase& expected : cases) {
        INFO(expected.path);
        const auto parsed = parse_usb_interface_path(expected.path);
        REQUIRE(parsed.has_value());
        CHECK(parsed->vid == expected.vid);
        CHECK(parsed->pid == expected.pid);
        CHECK(parsed->serial == expected.serial);
        CHECK(parsed->composite == expected.composite);
        CHECK(parsed->interface_number == expected.interface_number);
    }
}

TEST_CASE("USB interface path parser rejects malformed paths", "[android][usb]") {
    const std::string guid = "#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
    std::string control_serial = "\\\\?\\usb#vid_18d1&pid_4ee7#AB";
    control_serial.push_back('\x01');
    control_serial += "CD" + guid;
    const std::string long_serial =
        "\\\\?\\usb#vid_18d1&pid_4ee7#" + std::string(300, 'A') + guid;

    const std::vector<std::string> rejected = {
        "",
        "usb",
        "\\\\?\\usb#vid_18d1&pid_4ee7#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
        "\\\\?\\usb#vid_18d1#SERIAL" + guid,
        "\\\\?\\usb#vid_18d&pid_4ee7#SERIAL" + guid,
        "\\\\?\\usb#vid_18d1&pid_4ee#SERIAL" + guid,
        "\\\\?\\usb#vid_18zz&pid_4ee7#SERIAL" + guid,
        "\\\\?\\usb#vid_18d1&pid_4ee7&mi_0#SERIAL" + guid,
        "\\\\?\\usb#vid_18d1&pid_4ee7&mi_001#SERIAL" + guid,
        "\\\\?\\usb#vid_18d1&pid_4ee7&foo#SERIAL" + guid,
        "\\\\?\\acpi#vid_18d1&pid_4ee7#SERIAL" + guid,
        "\\\\?\\usb#18d1&pid_4ee7#SERIAL" + guid,
        "\\\\?\\usb#vid_18d1&pid_4ee7",
        long_serial,
        control_serial,
    };
    for (const std::string& path : rejected) {
        INFO(path);
        CHECK_FALSE(parse_usb_interface_path(path).has_value());
    }
}

TEST_CASE("known Android vendor table matches section 6.1.3", "[android][usb]") {
    const auto vids = known_android_vids();
    REQUIRE(vids.size() == 12);
    CHECK(is_known_android_vid(0x18D1));
    CHECK(android_vendor_name(0x18D1) == "Google");
    CHECK(android_vendor_name(0x04E8) == "Samsung");
    CHECK(android_vendor_name(0x0BB4) == "HTC");
    CHECK(android_vendor_name(0x12D1) == "Huawei");
    CHECK(android_vendor_name(0x22B8) == "Motorola");
    CHECK(android_vendor_name(0x1004) == "LG");
    CHECK(android_vendor_name(0x0FCE) == "Sony");
    CHECK(android_vendor_name(0x0B05) == "ASUS");
    CHECK(android_vendor_name(0x2717) == "Xiaomi");
    CHECK(android_vendor_name(0x2A70) == "OnePlus");
    CHECK(android_vendor_name(0x22D9) == "Oppo");
    CHECK(android_vendor_name(0x17EF) == "Lenovo");
    CHECK_FALSE(is_known_android_vid(0x1D6B));
    CHECK(android_vendor_name(0x1D6B).empty());
}

TEST_CASE("sysfs enumerator reads attributes and skips invalid entries", "[android][usb]") {
    test::TempDir tmp;
    const std::filesystem::path sys = tmp.path() / "sys";

    put_file(sys / "1-1" / "idVendor", "18D1\n");
    put_file(sys / "1-1" / "idProduct", "4EE7\n");
    put_file(sys / "1-1" / "serial", "  SERIAL WITH SPACES  \n");
    put_file(sys / "1-1" / "manufacturer", "Google\n");
    put_file(sys / "1-1" / "product", "Pixel 7\n");

    put_file(sys / "1-2" / "idVendor", "1234\n");
    put_file(sys / "1-2" / "idProduct", "5678\n");

    put_file(sys / "2-1" / "idVendor", "zzzz\n");
    put_file(sys / "2-1" / "idProduct", "0001\n");
    std::filesystem::create_directories(sys / "3-1");
    put_file(sys / "3-1" / "product", "no ids\n");

    auto enumerated = enumerate_sysfs_usb(sys);
    REQUIRE(enumerated.has_value());
    REQUIRE(enumerated->size() == 2);
    CHECK((*enumerated)[0].instance_id == (sys / "1-1").generic_string());
    CHECK((*enumerated)[0].serial_usb == "SERIAL WITH SPACES");
    CHECK((*enumerated)[0].product == "Pixel 7");
    CHECK((*enumerated)[0].known_android_vid);
    CHECK_FALSE((*enumerated)[0].has_adb_interface);
    CHECK((*enumerated)[1].instance_id == (sys / "1-2").generic_string());
    CHECK_FALSE((*enumerated)[1].known_android_vid);
}

TEST_CASE("ADB interface directories require class ff subclass 42 protocol 01",
          "[android][usb]") {
    test::TempDir tmp;
    const auto make = [&tmp](const char* name, const char* cls, const char* sub,
                             const char* proto) {
        const std::filesystem::path dir = tmp.path() / name;
        put_file(dir / "bInterfaceClass", std::string(cls) + "\n");
        put_file(dir / "bInterfaceSubClass", std::string(sub) + "\n");
        put_file(dir / "bInterfaceProtocol", std::string(proto) + "\n");
        return dir;
    };

    CHECK(is_adb_interface_directory(make("adb-lower", "ff", "42", "01")));
    CHECK(is_adb_interface_directory(make("adb-upper", "FF", "42", "01")));
    CHECK_FALSE(is_adb_interface_directory(make("mtp", "06", "01", "01")));
    CHECK_FALSE(is_adb_interface_directory(make("fastboot", "ff", "42", "03")));
    CHECK_FALSE(is_adb_interface_directory(make("vendor", "ff", "ff", "01")));

    const std::filesystem::path incomplete = tmp.path() / "incomplete";
    put_file(incomplete / "bInterfaceClass", "ff\n");
    put_file(incomplete / "bInterfaceSubClass", "42\n");
    CHECK_FALSE(is_adb_interface_directory(incomplete));

    const std::filesystem::path invalid = tmp.path() / "invalid";
    put_file(invalid / "bInterfaceClass", "ff\n");
    put_file(invalid / "bInterfaceSubClass", "42\n");
    put_file(invalid / "bInterfaceProtocol", "zz\n");
    CHECK_FALSE(is_adb_interface_directory(invalid));
}

#if !defined(_WIN32)
TEST_CASE("sysfs enumerator reads devices and detects ADB interfaces", "[android][usb]") {
    test::TempDir tmp;
    const std::filesystem::path sys = tmp.path() / "usb" / "devices";

    const auto device = [&sys](const char* name, const char* vid, const char* pid,
                               const char* serial = nullptr, const char* manufacturer = nullptr,
                               const char* product = nullptr) {
        const std::filesystem::path dir = sys / name;
        put_file(dir / "idVendor", std::string(vid) + "\n");
        put_file(dir / "idProduct", std::string(pid) + "\n");
        if (serial) put_file(dir / "serial", std::string(serial) + "\n");
        if (manufacturer) put_file(dir / "manufacturer", std::string(manufacturer) + "\n");
        if (product) put_file(dir / "product", std::string(product) + "\n");
        return dir;
    };
    const auto interface_dir = [](const std::filesystem::path& parent, const char* name,
                                  const char* cls, const char* sub, const char* proto) {
        const std::filesystem::path dir = parent / name;
        put_file(dir / "bInterfaceClass", std::string(cls) + "\n");
        put_file(dir / "bInterfaceSubClass", std::string(sub) + "\n");
        put_file(dir / "bInterfaceProtocol", std::string(proto) + "\n");
    };

    const auto google = device("1-1", "18D1", "4EE7", "39241FDH2004J4", "Google", "Pixel 7");
    interface_dir(google, "1-1:1.0", "ff", "42", "01");

    const auto samsung = device("1-2", "04e8", "6860", "R58M12ABC", "Samsung", "Galaxy S21");
    interface_dir(samsung, "1-2:1.0", "08", "06", "50");

    device("1-3", "1234", "5678");

    const auto xiaomi = device("1-4", "2717", "ff48", "a1b2c3d4", "Xiaomi", "MI 11");
    interface_dir(xiaomi, "1-4:1.0", "ff", "42", "02");
    interface_dir(xiaomi, "1-4:1.1", "FF", "42", "01");

    device("usb1", "1d6b", "0002", nullptr, "Linux Foundation", "xHCI Host Controller");

    std::filesystem::create_directories(sys / "notadevice");
    put_file(sys / "notadevice" / "product", "no ids here\n");
    device("2-1", "zzzz", "0001");

    auto enumerated = enumerate_sysfs_usb(sys);
    REQUIRE(enumerated.has_value());
    const std::vector<UsbDeviceInfo>& devices = *enumerated;
    REQUIRE(devices.size() == 5);

    CHECK(devices[0].instance_id == (sys / "1-1").generic_string());
    CHECK(devices[0].vid == 0x18D1);
    CHECK(devices[0].pid == 0x4EE7);
    CHECK(devices[0].serial_usb == "39241FDH2004J4");
    CHECK(devices[0].manufacturer == "Google");
    CHECK(devices[0].product == "Pixel 7");
    CHECK(devices[0].has_adb_interface);
    CHECK(devices[0].known_android_vid);

    CHECK(devices[1].instance_id == (sys / "1-2").generic_string());
    CHECK(devices[1].vid == 0x04E8);
    CHECK(devices[1].pid == 0x6860);
    CHECK(devices[1].serial_usb == "R58M12ABC");
    CHECK_FALSE(devices[1].has_adb_interface);
    CHECK(devices[1].known_android_vid);

    CHECK(devices[2].instance_id == (sys / "1-3").generic_string());
    CHECK(devices[2].serial_usb.empty());
    CHECK(devices[2].manufacturer.empty());
    CHECK_FALSE(devices[2].has_adb_interface);
    CHECK_FALSE(devices[2].known_android_vid);

    CHECK(devices[3].instance_id == (sys / "1-4").generic_string());
    CHECK(devices[3].has_adb_interface);
    CHECK(devices[3].known_android_vid);

    CHECK(devices[4].instance_id == (sys / "usb1").generic_string());
    CHECK(devices[4].manufacturer == "Linux Foundation");
    CHECK_FALSE(devices[4].has_adb_interface);
    CHECK_FALSE(devices[4].known_android_vid);
}
#endif  // !_WIN32

TEST_CASE("sysfs enumerator reports an unusable root", "[android][usb]") {
    test::TempDir tmp;
    auto missing = enumerate_sysfs_usb(tmp.path() / "missing");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == ErrorCode::IoError);

    const std::filesystem::path file = tmp.path() / "not-a-directory";
    test::create_test_file(file, {'x'});
    auto regular_file = enumerate_sysfs_usb(file);
    REQUIRE_FALSE(regular_file.has_value());
}

TEST_CASE("platform USB enumerator is available where supported", "[android][usb]") {
#if defined(_WIN32) || defined(__linux__)
    auto enumerator = make_usb_enumerator();
    REQUIRE(enumerator.has_value());
    auto devices = (*enumerator)->enumerate();
    REQUIRE(devices.has_value());
    for (const UsbDeviceInfo& device : *devices) {
        CHECK(device.known_android_vid == is_known_android_vid(device.vid));
        CHECK_FALSE(device.instance_id.empty());
    }
#else
    auto enumerator = make_usb_enumerator();
    REQUIRE_FALSE(enumerator.has_value());
    CHECK(enumerator.error().code == ErrorCode::Unsupported);
#endif
}
