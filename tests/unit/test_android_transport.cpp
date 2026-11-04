#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "openrecover/android/adb_transport.hpp"
#include "openrecover/android/child_process.hpp"
#include "test_util.hpp"

#ifndef OPENRECOVER_FAKE_ADB
#error "OPENRECOVER_FAKE_ADB must point at the fake adb executable"
#endif

using namespace openrecover;
using namespace openrecover::android;

namespace {

const std::string kFakeAdb = OPENRECOVER_FAKE_ADB;

class ScopedEnv {
public:
    ScopedEnv(const char* name, const std::string& value) : name_(name) {
        if (const char* old = std::getenv(name)) old_ = std::string(old);
#if defined(_WIN32)
        _putenv_s(name, value.c_str());
#else
        setenv(name, value.c_str(), 1);
#endif
    }
    ~ScopedEnv() {
#if defined(_WIN32)
        _putenv_s(name_, old_ ? old_->c_str() : "");
#else
        if (old_) setenv(name_, old_->c_str(), 1);
        else unsetenv(name_);
#endif
    }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    const char* name_;
    std::optional<std::string> old_;
};

std::filesystem::path make_fake_root(const test::TempDir& tmp) {
    const std::filesystem::path root = tmp.path() / "device";
    const auto put = [](const std::filesystem::path& path, std::vector<uint8_t> bytes) {
        std::filesystem::create_directories(path.parent_path());
        test::create_test_file(path, bytes);
    };
    put(root / "sdcard" / "DCIM" / "a.jpg", {'a', 'a', 'a'});
    put(root / "sdcard" / "DCIM" / "sub dir" / "b png.png", {'b', 'b'});
    put(root / "sdcard" / "Pictures" / ".thumbnails" / "t.jpg", {'t'});
    put(root / "sdcard" / "denied" / "secret.jpg", {'s', 'e', 'c'});
    return root;
}

std::vector<std::string> lines_of(const std::string& text) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t nl = text.find('\n', start);
        std::string line = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (nl == std::string::npos) {
            if (!line.empty()) lines.push_back(std::move(line));
            break;
        }
        lines.push_back(std::move(line));
        start = nl + 1;
    }
    return lines;
}

}  // namespace

TEST_CASE("adb devices -l parser understands every state and noise", "[android][transport]") {
    const std::string text =
        "List of devices attached\n"
        "* daemon started successfully\n"
        "R58M12ABC\tdevice product:panther model:Pixel_7 device:panther transport_id:1\n"
        "emulator-5554\toffline\n"
        "XYZ\tunauthorized usb:1-2\n"
        "PERM\tno permissions (missing udev rules? user is in the plugdev group); see "
        "[http://developer.android.com/tools/device.html]\n"
        "REC\trecovery\n"
        "SIDE\tsideload\n"
        "BOOT\tbootloader\n"
        "adb server version (41) doesn't match this client (39); killing...\n";
    auto parsed = parse_adb_devices_output(text);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->size() == 7);

    CHECK((*parsed)[0].serial == "R58M12ABC");
    CHECK((*parsed)[0].state == AdbState::Device);
    CHECK((*parsed)[0].model == "Pixel_7");
    CHECK((*parsed)[0].product == "panther");
    CHECK((*parsed)[0].transport_id == "1");
    CHECK((*parsed)[1].state == AdbState::Offline);
    CHECK((*parsed)[2].state == AdbState::Unauthorized);
    CHECK((*parsed)[3].state == AdbState::NoPermissions);
    CHECK((*parsed)[3].state_raw == "no permissions");
    CHECK((*parsed)[4].state == AdbState::Recovery);
    CHECK((*parsed)[5].state == AdbState::Sideload);
    CHECK((*parsed)[6].state == AdbState::Unknown);
    CHECK(std::string(adb_state_name(AdbState::Device)) == "device");
}

TEST_CASE("find and stat output parsers preserve spaces, unicode and pipes", "[android][transport]") {
    auto files = parse_find_output(
        "/sdcard/DCIM/a b.jpg\r\n/sdcard/DCIM/\xD0\xA4\xD0\xBE\xD1\x82\xD0\xBE.png\n\n");
    REQUIRE(files.has_value());
    REQUIRE(files->size() == 2);
    CHECK((*files)[0] == "/sdcard/DCIM/a b.jpg");
    CHECK((*files)[1] == "/sdcard/DCIM/\xD0\xA4\xD0\xBE\xD1\x82\xD0\xBE.png");

    auto stats = parse_stat_output(
        "123|1700000000|/sdcard/a b.jpg\n"
        "0|1|/sdcard/\xD0\xA4\xD0\xBE\xD1\x82\xD0\xBE/x.png\n"
        "7|1700000001|/sdcard/a|b.jpg\n"
        "garbage line\n"
        "9|12|relative/path\n");
    REQUIRE(stats.has_value());
    REQUIRE(stats->size() == 3);
    CHECK((*stats)[0].size == 123);
    CHECK((*stats)[0].mtime == 1700000000);
    CHECK((*stats)[0].path == "/sdcard/a b.jpg");
    CHECK((*stats)[1].size == 0);
    CHECK((*stats)[2].path == "/sdcard/a|b.jpg");
}

TEST_CASE("locate_adb honours explicit paths, the environment and platform-tools", "[android][transport]") {
    test::TempDir tmp;
    auto missing = locate_adb({}, (tmp.path() / "nope" / "adb").string());
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == ErrorCode::AdbNotFound);

#if defined(_WIN32)
    const std::string name = "adb.exe";
#else
    const std::string name = "adb";
#endif
    const std::filesystem::path platform_tools = tmp.path() / "platform-tools";
    std::filesystem::create_directories(platform_tools);
    test::create_test_file(platform_tools / name, {'x'});
#if !defined(_WIN32)
    std::filesystem::permissions(platform_tools / name,
                                 std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::add);
#endif
    auto from_exe_dir = locate_adb(tmp.path(), {});
    REQUIRE(from_exe_dir.has_value());
    CHECK(*from_exe_dir == (platform_tools / name).string());

    {
        ScopedEnv env("OPENRECOVER_ADB", (platform_tools / name).string());
        auto from_env = locate_adb({}, {});
        REQUIRE(from_env.has_value());
        CHECK(*from_env == (platform_tools / name).string());
    }
}

TEST_CASE("run_child_process preserves argv boundaries", "[android][transport]") {
    const std::vector<std::string> args = {"plain", "a b", "a'b", "", "C:\\dir\\x y\\", "\"quoted\""};
    std::vector<std::string> argv{kFakeAdb, "argv"};
    argv.insert(argv.end(), args.begin(), args.end());

    ProcessOptions options;
    options.timeout = std::chrono::seconds(10);
    auto result = run_child_process(argv, options);
    REQUIRE(result.has_value());
    CHECK_FALSE(result->timed_out);
    CHECK(result->exit_code == 0);

    const std::vector<std::string> lines = lines_of(result->stdout_text);
    REQUIRE(lines.size() == args.size());
    for (size_t i = 0; i < args.size(); ++i) {
        INFO("argument " << i);
        CHECK(lines[i] == std::to_string(args[i].size()) + ":" + args[i]);
    }
}

TEST_CASE("run_child_process kills a child that exceeds its timeout", "[android][transport]") {
    ScopedEnv sleep("FAKE_ADB_SLEEP_MS", "5000");
    ProcessOptions options;
    options.timeout = std::chrono::milliseconds(200);
    const auto start = std::chrono::steady_clock::now();
    auto result = run_child_process(
        {kFakeAdb, "-s", "FAKE123", "shell", "getprop 'ro.product.model'"}, options);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    REQUIRE(result.has_value());
    CHECK(result->timed_out);
    CHECK(elapsed < std::chrono::seconds(4));
}

TEST_CASE("SubprocessAdbTransport executes allowlisted commands", "[android][transport]") {
    test::TempDir tmp;
    const std::filesystem::path root = make_fake_root(tmp);
    ScopedEnv root_env("FAKE_ADB_ROOT", root.string());

    auto created = SubprocessAdbTransport::create({}, kFakeAdb);
    REQUIRE(created.has_value());
    SubprocessAdbTransport& transport = **created;
    CHECK(transport.adb_path() == kFakeAdb);

    auto devices = transport.list_devices();
    REQUIRE(devices.has_value());
    REQUIRE(devices->size() == 1);
    CHECK((*devices)[0].serial == "FAKE123");
    CHECK((*devices)[0].state == AdbState::Device);
    CHECK((*devices)[0].model == "Pixel_7");

    {
        ScopedEnv state("FAKE_ADB_STATE", "unauthorized");
        auto unauthorized = transport.list_devices();
        REQUIRE(unauthorized.has_value());
        REQUIRE(unauthorized->size() == 1);
        CHECK((*unauthorized)[0].state == AdbState::Unauthorized);
    }

    auto prop = AdbShellCmd::get_prop("ro.product.model");
    REQUIRE(prop.has_value());
    auto model = transport.shell_readonly("FAKE123", *prop);
    REQUIRE(model.has_value());
    CHECK(*model == "Pixel_7\n");

    auto present = AdbShellCmd::test_dir("/sdcard");
    REQUIRE(present.has_value());
    auto present_result = transport.shell_readonly("FAKE123", *present);
    REQUIRE(present_result.has_value());
    CHECK(*present_result == "1");

    auto absent = AdbShellCmd::test_dir("/sdcard/does-not-exist");
    REQUIRE(absent.has_value());
    auto absent_result = transport.shell_readonly("FAKE123", *absent);
    REQUIRE(absent_result.has_value());
    CHECK(*absent_result == "0");

    auto list = AdbShellCmd::list_files("/sdcard");
    REQUIRE(list.has_value());
    auto files = transport.shell_readonly("FAKE123", *list);
    REQUIRE(files.has_value());
    const std::vector<std::string> file_lines = lines_of(*files);
    REQUIRE(file_lines.size() == 4);
    CHECK(file_lines[0] == "/sdcard/DCIM/a.jpg");
    CHECK(std::find(file_lines.begin(), file_lines.end(), "/sdcard/DCIM/sub dir/b png.png") !=
          file_lines.end());
    CHECK(std::find(file_lines.begin(), file_lines.end(),
                    "/sdcard/Pictures/.thumbnails/t.jpg") != file_lines.end());

    auto stat = AdbShellCmd::stat_batch(
        {"/sdcard/DCIM/a.jpg", "/sdcard/DCIM/sub dir/b png.png", "/sdcard/DCIM/missing.jpg"});
    REQUIRE(stat.has_value());
    auto stat_output = transport.shell_readonly("FAKE123", *stat);
    REQUIRE(stat_output.has_value());
    auto stats = parse_stat_output(*stat_output);
    REQUIRE(stats.has_value());
    REQUIRE(stats->size() == 2);
    CHECK((*stats)[0].size == 3);
    CHECK((*stats)[0].mtime == 1700000000);

    const std::filesystem::path pulled = tmp.path() / "pulled.jpg";
    auto pull = transport.pull("FAKE123", "/sdcard/DCIM/a.jpg", pulled);
    REQUIRE(pull.has_value());
    CHECK(test::load_test_file(pulled) == std::vector<uint8_t>({'a', 'a', 'a'}));

    auto missing_device = AdbShellCmd::get_prop("ro.product.model");
    REQUIRE(missing_device.has_value());
    auto missing = transport.shell_readonly("OTHER", *missing_device);
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == ErrorCode::NotFound);
}

TEST_CASE("SubprocessAdbTransport reports access denial and timeouts", "[android][transport]") {
    test::TempDir tmp;
    const std::filesystem::path root = make_fake_root(tmp);
    ScopedEnv root_env("FAKE_ADB_ROOT", root.string());
    ScopedEnv denied("FAKE_ADB_DENIED", "/sdcard/denied");

    AdbTimeouts timeouts;
    timeouts.shell = std::chrono::milliseconds(500);
    auto created = SubprocessAdbTransport::create({}, kFakeAdb, timeouts);
    REQUIRE(created.has_value());
    SubprocessAdbTransport& transport = **created;

    auto list = AdbShellCmd::list_files("/sdcard/denied");
    REQUIRE(list.has_value());
    auto files = transport.shell_readonly("FAKE123", *list);
    REQUIRE_FALSE(files.has_value());
    CHECK(files.error().code == ErrorCode::AccessDenied);

    auto test = AdbShellCmd::test_dir("/sdcard/denied");
    REQUIRE(test.has_value());
    auto test_result = transport.shell_readonly("FAKE123", *test);
    REQUIRE_FALSE(test_result.has_value());
    CHECK(test_result.error().code == ErrorCode::AccessDenied);

    auto pull = transport.pull("FAKE123", "/sdcard/denied/secret.jpg", tmp.path() / "x.jpg");
    REQUIRE_FALSE(pull.has_value());
    CHECK(pull.error().code == ErrorCode::AccessDenied);

    {
        ScopedEnv sleep("FAKE_ADB_SLEEP_MS", "5000");
        auto prop = AdbShellCmd::get_prop("ro.product.model");
        REQUIRE(prop.has_value());
        const auto start = std::chrono::steady_clock::now();
        auto timed = transport.shell_readonly("FAKE123", *prop);
        const auto elapsed = std::chrono::steady_clock::now() - start;
        REQUIRE_FALSE(timed.has_value());
        CHECK(timed.error().code == ErrorCode::Timeout);
        CHECK(elapsed < std::chrono::seconds(4));
    }
}

TEST_CASE("SubprocessAdbTransport surfaces truncated pulls to the caller", "[android][transport]") {
    test::TempDir tmp;
    const std::filesystem::path root = make_fake_root(tmp);
    ScopedEnv root_env("FAKE_ADB_ROOT", root.string());
    ScopedEnv truncate("FAKE_ADB_TRUNCATE_PULL", "1");

    auto created = SubprocessAdbTransport::create({}, kFakeAdb);
    REQUIRE(created.has_value());
    const std::filesystem::path pulled = tmp.path() / "short.jpg";
    auto pull = (*created)->pull("FAKE123", "/sdcard/DCIM/a.jpg", pulled);
    REQUIRE(pull.has_value());
    CHECK(test::load_test_file(pulled).size() == 1);
}
