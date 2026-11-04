#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdio>
#include <string>
#include <vector>

#include "openrecover/android/adb_command_policy.hpp"
#include "openrecover/common/readonly.hpp"

#if !defined(_WIN32)
#include <cstdio>
#endif

using namespace openrecover;
using namespace openrecover::android;

namespace {

std::vector<std::string> stat_files(size_t n) {
    std::vector<std::string> files;
    for (size_t i = 0; i < n; ++i) files.push_back("/sdcard/f" + std::to_string(i));
    return files;
}

void expect_path_ok(const std::string& path) {
    INFO("path: " << path);
    auto result = validate_remote_path(path);
    REQUIRE(result.has_value());
}

void expect_path_rejected(const std::string& path) {
    INFO("path bytes: " << path.size());
    auto result = validate_remote_path(path);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == ErrorCode::PolicyViolation);
}

}  // namespace

TEST_CASE("Remote paths inside shared storage are accepted", "[android][policy]") {
    const std::vector<std::string> valid = {
        "/sdcard",
        "/sdcard/DCIM",
        "/sdcard/DCIM/IMG_0001.jpg",
        "/sdcard/DCIM/.thumbnails/thumb1.jpg",
        "/sdcard/a'b.jpg",
        "/sdcard/holiday photo 2024.jpg",
        "/sdcard/Android/data/com.x/cache/a.png",
        "/storage/emulated/0",
        "/storage/emulated/0/Pictures/holiday.png",
        "/storage/ABCD-1234",
        "/storage/abcd-1234/DCIM/x.jpg",
        "/sdcard/\xD0\xA4\xD0\xBE\xD1\x82\xD0\xBE/\xD0\xBA\xD0\xBE\xD1\x82.jpg",
    };
    for (const std::string& path : valid) expect_path_ok(path);
}

TEST_CASE("Remote paths outside shared storage are rejected", "[android][policy]") {
    const std::vector<std::string> invalid = {
        "",
        "/",
        "/sdcard/",
        "/sdcard//x",
        "/sdcard/./x",
        "/sdcard/../etc/passwd",
        "/sdcard/a/../../b",
        "/sdcardx/file",
        "/storage/emulated/0/../0/x",
        "/storage/XYZ-1234/x",
        "/storage/ABCD_1234/x",
        "/data",
        "/data/data/com.example/db",
        "/dev/block/sda1",
        "/system/build.prop",
        "/sdcard/x/",
        "/sdcard/a\\b",
        "/sdcard/'; rm -rf /sdcard #",
        "/sdcard/$(id)",
        "/sdcard/`id`",
        "/sdcard/a\nb",
        "/sdcard/a\rb",
        std::string("/sdcard/\xC3\x28"),
    };
    for (const std::string& path : invalid) expect_path_rejected(path);
    expect_path_rejected("/sdcard/" + std::string(5000, 'a'));
}

TEST_CASE("Property keys and adb serials are validated", "[android][policy]") {
    for (const char* key : {"ro.product.model", "ro.build.version.sdk", "a", "a.b_c-d0"}) {
        INFO(key);
        CHECK(validate_prop_key(key).has_value());
    }
    for (const char* key : {"", "ro product", "ro;product", "ro$(id)", "ro/product"}) {
        INFO(key);
        auto r = validate_prop_key(key);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == ErrorCode::PolicyViolation);
    }
    CHECK_FALSE(validate_prop_key(std::string(65, 'a')).has_value());

    for (const char* serial : {"emulator-5554", "0123456789ABCDEF", "192.168.1.5:5555", "R58M12ABC"}) {
        INFO(serial);
        CHECK(validate_adb_serial(serial).has_value());
    }
    for (const char* serial : {"", "abc def", "abc;rm", "a'b", "a/b", "a\nb"}) {
        INFO(serial);
        auto r = validate_adb_serial(serial);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == ErrorCode::PolicyViolation);
    }
    CHECK_FALSE(validate_adb_serial(std::string(129, 'a')).has_value());
}

TEST_CASE("Shell quoting preserves apostrophes and metacharacters", "[android][policy]") {
    CHECK(shell_quote("abc") == "'abc'");
    CHECK(shell_quote("a'b") == "'a'\\''b'");
    CHECK(shell_quote("$(id); rm -rf /sdcard") == "'$(id); rm -rf /sdcard'");

    const std::vector<std::string> values = {"plain", "a'b", "it's 'quoted'", "$(id) `id` ; & | > <",
                                             "two words", "/sdcard/a'b.jpg"};
    for (const std::string& value : values) {
        auto tokens = parse_shell_command_line("echo " + shell_quote(value));
        INFO(value);
        REQUIRE(tokens.has_value());
        REQUIRE(tokens->size() == 2);
        CHECK((*tokens)[1] == value);
    }

#if !defined(_WIN32)
    for (const std::string& value : values) {
        const std::string command = "printf %s " + shell_quote(value);
        FILE* pipe = popen(command.c_str(), "r");
        INFO(value);
        REQUIRE(pipe != nullptr);
        std::string out;
        std::array<char, 256> buffer{};
        size_t got = 0;
        while ((got = std::fread(buffer.data(), 1, buffer.size(), pipe)) > 0)
            out.append(buffer.data(), got);
        const int status = pclose(pipe);
        CHECK(status == 0);
        CHECK(out == value);
    }
#endif
}

TEST_CASE("AdbShellCmd builds exact allowlisted command lines", "[android][policy]") {
    auto prop = AdbShellCmd::get_prop("ro.product.model");
    REQUIRE(prop.has_value());
    CHECK(prop->shell_command_line() == "getprop 'ro.product.model'");
    CHECK(prop->device_argv() == std::vector<std::string>{"getprop", "ro.product.model"});

    auto find = AdbShellCmd::list_files("/sdcard/DCIM");
    REQUIRE(find.has_value());
    CHECK(find->shell_command_line() == "find '/sdcard/DCIM' -type f");

    auto test = AdbShellCmd::test_dir("/sdcard");
    REQUIRE(test.has_value());
    CHECK(test->shell_command_line() == "test -d '/sdcard'");

    auto stat = AdbShellCmd::stat_batch({"/sdcard/a b.jpg", "/sdcard/x'y.png"});
    REQUIRE(stat.has_value());
    CHECK(stat->shell_command_line() ==
          "stat -c '%s|%Y|%n' '/sdcard/a b.jpg' '/sdcard/x'\\''y.png'");
    CHECK(stat->device_argv() ==
          std::vector<std::string>{"stat", "-c", "%s|%Y|%n", "/sdcard/a b.jpg", "/sdcard/x'y.png"});

    CHECK_FALSE(AdbShellCmd::get_prop("ro product").has_value());
    CHECK_FALSE(AdbShellCmd::list_files("/data/data/x").has_value());
    CHECK_FALSE(AdbShellCmd::test_dir("../sdcard").has_value());
    CHECK_FALSE(AdbShellCmd::stat_batch({}).has_value());
    CHECK_FALSE(AdbShellCmd::stat_batch(stat_files(65)).has_value());
    CHECK(AdbShellCmd::stat_batch(stat_files(64)).has_value());
}

TEST_CASE("Allowed adb invocations pass policy", "[android][policy]") {
    CHECK(validate_adb_argv(start_server_argv()).has_value());
    CHECK(validate_adb_argv(devices_argv()).has_value());

    auto prop = AdbShellCmd::get_prop("ro.product.model");
    REQUIRE(prop.has_value());
    auto shell = shell_argv("emulator-5554", *prop);
    REQUIRE(shell.has_value());
    CHECK(*shell == std::vector<std::string>{"-s", "emulator-5554", "shell",
                                             "getprop 'ro.product.model'"});
    CHECK(validate_adb_argv(*shell).has_value());

    auto stat = AdbShellCmd::stat_batch({"/sdcard/a.jpg"});
    REQUIRE(stat.has_value());
    auto stat_argv = shell_argv("R58M12ABC", *stat);
    REQUIRE(stat_argv.has_value());
    CHECK(validate_adb_argv(*stat_argv).has_value());

    auto pull = pull_argv("emulator-5554", "/sdcard/DCIM/a.jpg", "/tmp/a.jpg");
    REQUIRE(pull.has_value());
    CHECK(*pull == std::vector<std::string>{"-s", "emulator-5554", "pull", "/sdcard/DCIM/a.jpg",
                                            "/tmp/a.jpg"});
    CHECK(validate_adb_argv(*pull).has_value());
}

TEST_CASE("Non-allowlisted adb invocations are rejected with PolicyViolation", "[android][policy]") {
    const std::vector<std::vector<std::string>> cases = {
        {},
        {"devices"},
        {"devices", "-l", "extra"},
        {"start-server", "x"},
        {"shell", "getprop 'ro.product.model'"},
        {"-s", "emulator-5554"},
        {"-s", "emulator-5554", "shell"},
        {"-s", "emulator-5554", "shell", "cat '/sdcard/a.jpg'"},
        {"-s", "emulator-5554", "shell", "find '/sdcard/DCIM' -name '*'"},
        {"-s", "emulator-5554", "shell", "test -f '/sdcard/a.jpg'"},
        {"-s", "emulator-5554", "shell", "stat '/sdcard/a.jpg'"},
        {"-s", "emulator-5554", "shell", "getprop 'ro.product.model' extra"},
        {"-s", "emulator-5554", "pull", "/sdcard/a.jpg"},
        {"-s", "emulator-5554", "pull", "/sdcard/a.jpg", "/tmp/a.jpg", "extra"},
        {"-s", "bad serial", "shell", "getprop 'ro.product.model'"},
        {"-s", "emulator-5554", "wait-for-device"},
        {"forward", "tcp:1234", "tcp:1234"},
    };
    for (const auto& argv : cases) {
        INFO("argv[0]: " << (argv.empty() ? "<empty>" : argv[0]));
        auto result = validate_adb_argv(argv);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code != ErrorCode::IoError);
    }
}

TEST_CASE("Deny-listed adb verbs and private paths throw ReadOnlyViolation", "[android][policy]") {
    const std::vector<std::vector<std::string>> cases = {
        {"push", "/tmp/x", "/sdcard/x"},
        {"install", "x.apk"},
        {"uninstall", "com.x"},
        {"root"},
        {"remount"},
        {"reboot"},
        {"sideload", "x.zip"},
        {"disable-verity"},
        {"-s", "emulator-5554", "shell", "rm -rf '/sdcard/x'"},
        {"-s", "emulator-5554", "shell", "su -c 'id'"},
        {"-s", "emulator-5554", "shell", "mv '/sdcard/a' '/sdcard/b'"},
        {"-s", "emulator-5554", "shell", "settings put global x 1"},
        {"-s", "emulator-5554", "shell", "pm list packages"},
        {"-s", "emulator-5554", "shell", "am start -a x"},
        {"-s", "emulator-5554", "pull", "/data/data/com.x/db", "/tmp/db"},
        {"-s", "emulator-5554", "pull", "/dev/block/sda1", "/tmp/sda1"},
        {"-s", "emulator-5554", "pull", "/sdcard/a.jpg", "/data/tmp/a.jpg"},
    };
    for (const auto& argv : cases) {
        INFO("argv[0]: " << (argv.empty() ? "<empty>" : argv[0]));
        CHECK_THROWS_AS(validate_adb_argv(argv), ReadOnlyViolation);
    }
}
