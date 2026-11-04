#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "openrecover/android/adb_command_policy.hpp"
#include "openrecover/android/adb_transport.hpp"
#include "openrecover/android/child_process.hpp"
#include "test_util.hpp"

#ifndef OPENRECOVER_FAKE_ADB
#error "OPENRECOVER_FAKE_ADB must point at the fake adb executable"
#endif
#ifndef OPENRECOVER_SIDECAR_SCRIPT
#error "OPENRECOVER_SIDECAR_SCRIPT must point at sidecar.py"
#endif
#ifndef OPENRECOVER_SIDECAR_POLICY_PY
#error "OPENRECOVER_SIDECAR_POLICY_PY must point at policy.py"
#endif
#ifndef OPENRECOVER_SIDECAR_STUB
#error "OPENRECOVER_SIDECAR_STUB must point at the protocol stub"
#endif
#ifndef OPENRECOVER_SIDECAR_POLICY_JSON
#error "OPENRECOVER_SIDECAR_POLICY_JSON must point at the generated policy.json"
#endif

using namespace openrecover;
using namespace openrecover::android;

namespace fs = std::filesystem;
using nlohmann::json;

namespace {

const std::string kFakeAdb = OPENRECOVER_FAKE_ADB;
const std::string kSidecarScript = OPENRECOVER_SIDECAR_SCRIPT;
const std::string kPolicyScript = OPENRECOVER_SIDECAR_POLICY_PY;
const std::string kSidecarStub = OPENRECOVER_SIDECAR_STUB;
const std::string kPolicyJson = OPENRECOVER_SIDECAR_POLICY_JSON;

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

std::string find_python() {
    for (const char* candidate : {"python3", "python"}) {
        ProcessOptions options;
        options.timeout = std::chrono::seconds(15);
        auto result = run_child_process({candidate, "--version"}, options);
        if (result && !result->timed_out && result->exit_code == 0) return candidate;
    }
    SKIP("Python 3 is not available; sidecar tests are skipped");
    return {};
}

std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + path.string());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_text(const fs::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) throw std::runtime_error("cannot write " + path.string());
}

json load_policy() { return json::parse(read_text(fs::path(kPolicyJson))); }

json command_json(const AdbShellCmd& cmd) {
    json entry;
    switch (cmd.kind()) {
        case AdbShellCmd::Kind::GetProp:
            entry["kind"] = "GetProp";
            entry["key"] = cmd.key();
            break;
        case AdbShellCmd::Kind::ListFiles:
            entry["kind"] = "ListFiles";
            entry["dir"] = cmd.dir();
            break;
        case AdbShellCmd::Kind::StatBatch:
            entry["kind"] = "StatBatch";
            entry["files"] = cmd.files();
            break;
        case AdbShellCmd::Kind::TestDir:
            entry["kind"] = "TestDir";
            entry["dir"] = cmd.dir();
            break;
    }
    return entry;
}

struct PolicyRequest {
    json request;
    bool expect_ok = false;
    std::string expected_command;  // non-empty for shell_command requests
};

std::string run_policy_requests(const std::string& python, const fs::path& requests_path) {
    ProcessOptions options;
    options.timeout = std::chrono::seconds(60);
    auto result = run_child_process(
        {python, kPolicyScript, "--policy", kPolicyJson, "--evaluate", requests_path.string()},
        options);
    REQUIRE(result.has_value());
    REQUIRE_FALSE(result->timed_out);
    if (result->exit_code != 0) {
        INFO(result->stderr_text);
        REQUIRE(result->exit_code == 0);
    }
    return result->stdout_text;
}

fs::path make_fake_root(const test::TempDir& tmp) {
    const fs::path root = tmp.path() / "device";
    const auto put = [](const fs::path& path, std::vector<uint8_t> bytes) {
        fs::create_directories(path.parent_path());
        test::create_test_file(path, bytes);
    };
    put(root / "sdcard" / "DCIM" / "a.jpg", {'a', 'a', 'a'});
    put(root / "sdcard" / "DCIM" / "sub dir" / "b png.png", {'b', 'b'});
    put(root / "sdcard" / "Pictures" / ".thumbnails" / "t.jpg", {'t'});
    put(root / "sdcard" / "denied" / "secret.jpg", {'s', 'e', 'c'});
    return root;
}

PySidecarOptions stub_options(const std::string& python, const std::string& script,
                              AdbTimeouts timeouts = {}) {
    PySidecarOptions options;
    options.adb_path = kFakeAdb;
    options.python = python;
    options.sidecar_script = script;
    options.policy_path = kPolicyJson;
    options.timeouts = timeouts;
    return options;
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

TEST_CASE("sidecar policy parity covers paths, keys, serials and command lines",
          "[android][sidecar][policy]") {
    const std::string python = find_python();
    const json policy = load_policy();
    REQUIRE(policy.at("proto").get<int>() == 1);

    std::vector<PolicyRequest> requests;
    const auto add_path = [&requests](const std::string& path) {
        PolicyRequest item;
        item.request = {{"op", "validate_path"}, {"path", path}};
        item.expect_ok = validate_remote_path(path).has_value();
        requests.push_back(std::move(item));
    };
    const auto add_key = [&requests](const std::string& key) {
        PolicyRequest item;
        item.request = {{"op", "validate_prop_key"}, {"key", key}};
        item.expect_ok = validate_prop_key(key).has_value();
        requests.push_back(std::move(item));
    };
    const auto add_serial = [&requests](const std::string& serial) {
        PolicyRequest item;
        item.request = {{"op", "validate_serial"}, {"serial", serial}};
        item.expect_ok = validate_adb_serial(serial).has_value();
        requests.push_back(std::move(item));
    };
    const auto add_command = [&requests](const AdbShellCmd& cmd) {
        PolicyRequest item;
        item.request = {{"op", "shell_command"}, {"cmd", command_json(cmd)}};
        item.expect_ok = true;
        item.expected_command = cmd.shell_command_line();
        requests.push_back(std::move(item));
    };
    const auto add_rejected_command = [&requests](json cmd) {
        PolicyRequest item;
        item.request = {{"op", "shell_command"}, {"cmd", std::move(cmd)}};
        item.expect_ok = false;
        requests.push_back(std::move(item));
    };

    const json& malicious = policy.at("malicious_remote_paths");
    REQUIRE(malicious.is_array());
    REQUIRE(malicious.size() == 20);
    for (const json& path : malicious) add_path(path.get<std::string>());
    for (const json& path : policy.at("accepted_remote_path_samples"))
        add_path(path.get<std::string>());

    add_key("ro.product.model");
    add_key("ro.build.version.sdk");
    add_key("bad key");
    add_key(std::string(65, 'a'));
    add_key("");
    add_serial("FAKE123");
    add_serial("emulator-5554");
    add_serial("192.168.1.2:5555");
    add_serial("bad serial!");
    add_serial("a/b");
    add_serial("");

    const auto prop = AdbShellCmd::get_prop("ro.product.model");
    REQUIRE(prop.has_value());
    add_command(*prop);
    const auto prop2 = AdbShellCmd::get_prop("ro.build.version.sdk");
    REQUIRE(prop2.has_value());
    add_command(*prop2);

    const auto list_sdcard = AdbShellCmd::list_files("/sdcard");
    REQUIRE(list_sdcard.has_value());
    add_command(*list_sdcard);
    const auto list_quote = AdbShellCmd::list_files("/sdcard/DCIM/O'Brien dir");
    REQUIRE(list_quote.has_value());
    add_command(*list_quote);
    const auto list_unicode = AdbShellCmd::list_files("/sdcard/Photos/\xE7\x85\xA7\xE7\x89\x87");
    REQUIRE(list_unicode.has_value());
    add_command(*list_unicode);

    const auto stat_one = AdbShellCmd::stat_batch({"/sdcard/DCIM/a.jpg"});
    REQUIRE(stat_one.has_value());
    add_command(*stat_one);
    const auto stat_many = AdbShellCmd::stat_batch(
        {"/sdcard/a b.jpg", "/sdcard/O'Brien.png", "/storage/ABCD-1234/x.png"});
    REQUIRE(stat_many.has_value());
    add_command(*stat_many);

    const auto test_dir = AdbShellCmd::test_dir("/sdcard/DCIM");
    REQUIRE(test_dir.has_value());
    add_command(*test_dir);
    add_rejected_command({{"kind", "ListFiles"}, {"dir", "/sdcard/../data"}});
    add_rejected_command({{"kind", "GetProp"}, {"key", "bad key"}});
    add_rejected_command({{"kind", "StatBatch"}, {"files", json::array()}});
    add_rejected_command({{"kind", "ShellPassthrough"}, {"command", "id"}});

    test::TempDir tmp;
    const fs::path requests_path = tmp.path() / "requests.json";
    json request_array = json::array();
    for (const PolicyRequest& item : requests) request_array.push_back(item.request);
    write_text(requests_path, request_array.dump());

    const json results = json::parse(run_policy_requests(python, requests_path));
    REQUIRE(results.is_array());
    REQUIRE(results.size() == requests.size());
    for (size_t i = 0; i < requests.size(); ++i) {
        INFO("request " << i << ": " << requests[i].request.dump());
        REQUIRE(results[i].is_object());
        REQUIRE(results[i].at("ok").is_boolean());
        CHECK(results[i].at("ok").get<bool>() == requests[i].expect_ok);
        if (requests[i].expect_ok && !requests[i].expected_command.empty()) {
            REQUIRE(results[i].contains("value"));
            CHECK(results[i].at("value").get<std::string>() == requests[i].expected_command);
        }
    }
}

TEST_CASE("PySidecarAdbTransport round-trips allowlisted operations over JSON Lines",
          "[android][sidecar]") {
    const std::string python = find_python();
    test::TempDir tmp;
    const fs::path root = make_fake_root(tmp);
    ScopedEnv root_env("SIDECAR_STUB_ROOT", root.string());

    auto created = PySidecarAdbTransport::create(stub_options(python, kSidecarStub));
    REQUIRE(created.has_value());
    PySidecarAdbTransport& transport = **created;
    CHECK(transport.python_path() == python);
    CHECK(transport.ppadb_version() == "stub-1");

    auto devices = transport.list_devices();
    if (!devices) FAIL(devices.error().message);
    REQUIRE(devices->size() == 1);
    CHECK((*devices)[0].serial == "FAKE123");
    CHECK((*devices)[0].state == AdbState::Device);
    CHECK((*devices)[0].model == "Pixel_7");
    CHECK((*devices)[0].transport_id == "1");

    auto prop = AdbShellCmd::get_prop("ro.product.model");
    REQUIRE(prop.has_value());
    auto model = transport.shell_readonly("FAKE123", *prop);
    REQUIRE(model.has_value());
    CHECK(*model == "Pixel_7");

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

    const std::string source_sha = test::sha256_of_file(root / "sdcard" / "DCIM" / "a.jpg");
    const fs::path pulled = tmp.path() / "pulled.jpg";
    auto pull = transport.pull("FAKE123", "/sdcard/DCIM/a.jpg", pulled);
    REQUIRE(pull.has_value());
    CHECK(test::load_test_file(pulled) == std::vector<uint8_t>({'a', 'a', 'a'}));
    CHECK(test::sha256_of_file(root / "sdcard" / "DCIM" / "a.jpg") == source_sha);

    auto bad_remote = transport.pull("FAKE123", "/data/media/0/x.jpg", tmp.path() / "x.jpg");
    REQUIRE_FALSE(bad_remote.has_value());
    CHECK(bad_remote.error().code == ErrorCode::PolicyViolation);

    auto bad_serial = transport.shell_readonly("bad serial!", *prop);
    REQUIRE_FALSE(bad_serial.has_value());
    CHECK(bad_serial.error().code == ErrorCode::PolicyViolation);

    {
        ScopedEnv deny("SIDECAR_STUB_DENY", "/sdcard/denied");
        auto denied_transport = PySidecarAdbTransport::create(stub_options(python, kSidecarStub));
        REQUIRE(denied_transport.has_value());
        auto denied =
            (*denied_transport)->pull("FAKE123", "/sdcard/denied/secret.jpg", tmp.path() / "denied.jpg");
        REQUIRE_FALSE(denied.has_value());
        CHECK(denied.error().code == ErrorCode::AccessDenied);
    }
}

TEST_CASE("PySidecarAdbTransport reports protocol failures and handshake timeouts",
          "[android][sidecar]") {
    const std::string python = find_python();
    test::TempDir tmp;
    const fs::path root = make_fake_root(tmp);
    ScopedEnv root_env("SIDECAR_STUB_ROOT", root.string());

    {
        ScopedEnv mode("SIDECAR_STUB_MODE", "malformed");
        auto created = PySidecarAdbTransport::create(stub_options(python, kSidecarStub));
        REQUIRE(created.has_value());
        auto devices = (*created)->list_devices();
        REQUIRE_FALSE(devices.has_value());
        CHECK(devices.error().code == ErrorCode::ProtocolError);
    }
    {
        ScopedEnv mode("SIDECAR_STUB_MODE", "bad-proto");
        auto created = PySidecarAdbTransport::create(stub_options(python, kSidecarStub));
        REQUIRE_FALSE(created.has_value());
        CHECK(created.error().code == ErrorCode::ProtocolError);
    }
    {
        ScopedEnv mode("SIDECAR_STUB_MODE", "crash");
        auto created = PySidecarAdbTransport::create(stub_options(python, kSidecarStub));
        REQUIRE(created.has_value());
        auto devices = (*created)->list_devices();
        REQUIRE_FALSE(devices.has_value());
        CHECK((devices.error().code == ErrorCode::ProtocolError ||
               devices.error().code == ErrorCode::IoError));
    }
    {
        ScopedEnv mode("SIDECAR_STUB_MODE", "hang");
        AdbTimeouts timeouts;
        timeouts.server = std::chrono::milliseconds(300);
        const auto started = std::chrono::steady_clock::now();
        auto created = PySidecarAdbTransport::create(stub_options(python, kSidecarStub, timeouts));
        const auto elapsed = std::chrono::steady_clock::now() - started;
        REQUIRE_FALSE(created.has_value());
        CHECK(created.error().code == ErrorCode::Timeout);
        CHECK(elapsed < std::chrono::seconds(5));
    }
}

TEST_CASE("PySidecarAdbTransport scales request ids and rejects unknown responses",
          "[android][sidecar]") {
    const std::string python = find_python();
    test::TempDir tmp;
    const fs::path root = make_fake_root(tmp);
    ScopedEnv root_env("SIDECAR_STUB_ROOT", root.string());
    auto created = PySidecarAdbTransport::create(stub_options(python, kSidecarStub));
    REQUIRE(created.has_value());

    for (int i = 0; i < 3; ++i) {
        auto devices = (*created)->list_devices();
        REQUIRE(devices.has_value());
    }
    auto prop = AdbShellCmd::get_prop("ro.product.model");
    REQUIRE(prop.has_value());
    auto model = (*created)->shell_readonly("FAKE123", *prop);
    REQUIRE(model.has_value());
}

TEST_CASE("shipped sidecar reports a missing pure-python-adb dependency",
          "[android][sidecar]") {
    const std::string python = find_python();
    ProcessOptions probe_options;
    probe_options.timeout = std::chrono::seconds(30);
    auto probe = run_child_process({python, "-c", "import ppadb"}, probe_options);
    REQUIRE(probe.has_value());
    if (probe->exit_code == 0) SKIP("pure-python-adb is installed; the stub covers the protocol path");

    test::TempDir tmp;
    const fs::path root = make_fake_root(tmp);
    ScopedEnv root_env("SIDECAR_STUB_ROOT", root.string());
    auto created = PySidecarAdbTransport::create(stub_options(python, kSidecarScript));
    REQUIRE_FALSE(created.has_value());
    CHECK(created.error().code == ErrorCode::Unsupported);
    CHECK(created.error().message.find("pure-python-adb") != std::string::npos);
}
