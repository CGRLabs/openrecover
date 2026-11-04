#include <chrono>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "nlohmann/json.hpp"
#include "openrecover/android/adb_transport.hpp"
#include "openrecover/android/child_process.hpp"
#include "openrecover/common/path_util.hpp"

namespace openrecover::android {

namespace {

using json = nlohmann::json;

std::optional<std::string> environment_value(const char* name) {
#if defined(_WIN32)
    char* buffer = nullptr;
    size_t length = 0;
    if (_dupenv_s(&buffer, &length, name) != 0 || buffer == nullptr) return std::nullopt;
    std::string value(buffer);
    std::free(buffer);
    return value;
#else
    const char* value = std::getenv(name);
    if (value == nullptr) return std::nullopt;
    return std::string(value);
#endif
}

std::string summarized(std::string_view text) {
    constexpr size_t kMax = 300;
    std::string out;
    const size_t take = text.size() < kMax ? text.size() : kMax;
    out.reserve(take + 3);
    for (size_t i = 0; i < take; ++i) {
        const char c = text[i];
        out.push_back(c == '\n' || c == '\r' ? ' ' : c);
    }
    if (take < text.size()) out += "...";
    return out;
}

ErrorCode error_code_from_name(std::string_view name) {
    static const std::pair<std::string_view, ErrorCode> kMap[] = {
        {"IoError", ErrorCode::IoError},
        {"NotFound", ErrorCode::NotFound},
        {"PermissionDenied", ErrorCode::PermissionDenied},
        {"DeviceBusy", ErrorCode::DeviceBusy},
        {"Unsupported", ErrorCode::Unsupported},
        {"NoFilesystem", ErrorCode::NoFilesystem},
        {"CorruptStructure", ErrorCode::CorruptStructure},
        {"InvalidArgument", ErrorCode::InvalidArgument},
        {"OutputOnSourceDevice", ErrorCode::OutputOnSourceDevice},
        {"AlreadyExists", ErrorCode::AlreadyExists},
        {"Cancelled", ErrorCode::Cancelled},
        {"Timeout", ErrorCode::Timeout},
        {"PolicyViolation", ErrorCode::PolicyViolation},
        {"AdbNotFound", ErrorCode::AdbNotFound},
        {"DeviceUnauthorized", ErrorCode::DeviceUnauthorized},
        {"DeviceOffline", ErrorCode::DeviceOffline},
        {"ProtocolError", ErrorCode::ProtocolError},
        {"StorageUnavailable", ErrorCode::StorageUnavailable},
        {"AccessDenied", ErrorCode::AccessDenied},
    };
    for (const auto& [key, code] : kMap) {
        if (key == name) return code;
    }
    return ErrorCode::IoError;
}

Error response_error(const json& response, const std::string& operation) {
    const auto error = response.find("error");
    if (error == response.end() || !error->is_object())
        return make_error(ErrorCode::ProtocolError,
                          "sidecar rejected '" + operation + "' without an error object");
    const std::string code = error->value("code", std::string());
    std::string message = error->value("message", std::string());
    if (message.empty()) message = "sidecar reported a failure";
    return make_error(error_code_from_name(code), operation + ": " + message);
}

Result<json> exchange(ChildSession& session, const json& request, std::chrono::milliseconds timeout,
                      std::optional<uint64_t> expected_id) {
    const std::string operation = request.value("op", std::string("request"));
    auto wrote = session.write_line(request.dump());
    if (!wrote) return fail(wrote.error());

    auto line = session.read_line(timeout);
    if (!line) return fail(line.error());
    if (!line->has_value()) {
        session.terminate();
        return fail(ErrorCode::Timeout, "sidecar did not respond to '" + operation + "' within " +
                                            std::to_string(timeout.count()) + " ms");
    }

    json response = json::parse(**line, nullptr, false);
    if (response.is_discarded() || !response.is_object())
        return fail(ErrorCode::ProtocolError,
                    "malformed sidecar response to '" + operation + "': " + summarized(**line));

    if (expected_id) {
        const auto id = response.find("id");
        if (id == response.end() || !id->is_number_integer() || id->get<int64_t>() < 0 ||
            static_cast<uint64_t>(id->get<int64_t>()) != *expected_id) {
            return fail(ErrorCode::ProtocolError,
                        "sidecar response id does not match request id " + std::to_string(*expected_id) +
                            ": " + summarized(response.dump()));
        }
    }

    const auto ok = response.find("ok");
    if (ok == response.end() || !ok->is_boolean())
        return fail(ErrorCode::ProtocolError, "sidecar response to '" + operation + "' has no ok flag");
    if (!ok->get<bool>()) return fail(response_error(response, operation));
    return response;
}

Result<std::string> string_data(const json& response, const std::string& operation) {
    const auto data = response.find("data");
    if (data == response.end() || !data->is_string())
        return fail(ErrorCode::ProtocolError, "sidecar response to '" + operation + "' has no string data");
    return data->get<std::string>();
}

Result<std::vector<AdbDevice>> parse_device_list(const json& data) {
    if (!data.is_array())
        return fail(ErrorCode::ProtocolError, "sidecar list_devices data is not an array");
    std::vector<AdbDevice> devices;
    for (const json& item : data) {
        if (!item.is_object())
            return fail(ErrorCode::ProtocolError, "sidecar device entry is not an object");
        const auto serial = item.find("serial");
        if (serial == item.end() || !serial->is_string() || serial->get<std::string>().empty())
            return fail(ErrorCode::ProtocolError, "sidecar device entry has no serial");
        const auto state = item.find("state");
        if (state == item.end() || !state->is_string())
            return fail(ErrorCode::ProtocolError, "sidecar device entry has no state");

        AdbDevice device;
        device.serial = serial->get<std::string>();
        device.state_raw = state->get<std::string>();
        device.state = adb_state_from_string(device.state_raw);
        const auto optional_string = [&item](const char* key) {
            const auto it = item.find(key);
            return it != item.end() && it->is_string() ? it->get<std::string>() : std::string();
        };
        device.model = optional_string("model");
        device.product = optional_string("product");
        device.transport_id = optional_string("transport_id");
        devices.push_back(std::move(device));
    }
    return devices;
}

bool interpreter_works(const std::string& candidate, std::string& detail) {
    ProcessOptions options;
    options.timeout = std::chrono::seconds(10);
    auto result = run_child_process({candidate, "--version"}, options);
    if (!result) {
        detail = result.error().message;
        return false;
    }
    if (result->timed_out) {
        detail = "timed out";
        return false;
    }
    if (result->exit_code != 0) {
        detail = summarized(result->stderr_text);
        return false;
    }
    return true;
}

}  // namespace

Result<std::string> locate_python(const std::string& explicit_path) {
    std::string detail;
    if (!explicit_path.empty()) {
        if (interpreter_works(explicit_path, detail)) return explicit_path;
        return fail(ErrorCode::NotFound,
                    "Python interpreter is not usable at '" + explicit_path + "': " + detail);
    }
    if (auto env = environment_value("OPENRECOVER_PYTHON"); env && !env->empty()) {
        if (interpreter_works(*env, detail)) return *env;
        return fail(ErrorCode::NotFound,
                    "Python interpreter is not usable at OPENRECOVER_PYTHON='" + *env + "': " + detail);
    }
    for (const char* candidate : {"python3", "python"}) {
        detail.clear();
        if (interpreter_works(candidate, detail)) return std::string(candidate);
    }
    return fail(ErrorCode::NotFound,
                "Python 3 was not found; install it, put it on PATH, or pass --python. The sidecar "
                "also needs the 'pure-python-adb' package (tools/adb_sidecar/requirements.txt)");
}

PySidecarAdbTransport::PySidecarAdbTransport(std::unique_ptr<ChildSession> session, AdbTimeouts timeouts,
                                             std::string python_path, std::string ppadb_version)
    : session_(std::move(session)),
      timeouts_(timeouts),
      python_path_(std::move(python_path)),
      ppadb_version_(std::move(ppadb_version)) {}

PySidecarAdbTransport::~PySidecarAdbTransport() = default;

Result<std::unique_ptr<PySidecarAdbTransport>> PySidecarAdbTransport::create(
    const PySidecarOptions& options) {
    auto adb = locate_adb(options.exe_dir, options.adb_path);
    if (!adb) return fail(adb.error());

    ProcessOptions server_options;
    server_options.timeout = options.timeouts.server;
    auto started = run_child_process({*adb, "start-server"}, server_options);
    if (!started) return fail(started.error());
    if (started->timed_out)
        return fail(ErrorCode::Timeout, "adb start-server timed out after " +
                                            std::to_string(options.timeouts.server.count()) + " ms");
    if (started->exit_code != 0) {
        const std::string detail =
            summarized(started->stderr_text.empty() ? started->stdout_text : started->stderr_text);
        return fail(ErrorCode::AdbNotFound, "cannot start the adb server: " + detail);
    }

    std::filesystem::path script = options.sidecar_script;
    if (script.empty()) {
        if (auto env = environment_value("OPENRECOVER_SIDECAR"); env && !env->empty())
            script = path_from_utf8(*env);
        else if (!options.exe_dir.empty())
            script = options.exe_dir / "tools" / "adb_sidecar" / "sidecar.py";
    }
    if (script.empty())
        return fail(ErrorCode::NotFound,
                    "sidecar script was not specified; pass its path or set OPENRECOVER_SIDECAR");
    std::error_code ec;
    if (!std::filesystem::is_regular_file(script, ec))
        return fail(ErrorCode::NotFound, "sidecar script not found: " + path_to_utf8(script));
    const std::string script_text = path_to_utf8(script);

    auto python = locate_python(path_to_utf8(options.python));
    if (!python) return fail(python.error());

    std::filesystem::path policy = options.policy_path;
    if (policy.empty()) {
        if (auto env = environment_value("OPENRECOVER_SIDECAR_POLICY"); env && !env->empty())
            policy = path_from_utf8(*env);
        else
            policy = script.parent_path() / "policy.json";
    }
    if (!std::filesystem::is_regular_file(policy, ec))
        return fail(ErrorCode::NotFound, "sidecar policy file not found: " + path_to_utf8(policy) +
                                             " (it is generated from C++ at build time)");

    auto session = ChildSession::start({*python, script_text, "--policy", path_to_utf8(policy)});
    if (!session) return fail(session.error());

    json hello{{"op", "hello"}};
    auto response = exchange(**session, hello, options.timeouts.server, std::nullopt);
    if (!response) return fail(response.error());

    const auto data = response->find("data");
    if (data == response->end() || !data->is_object())
        return fail(ErrorCode::ProtocolError, "sidecar hello response is missing data");
    const auto proto = data->find("proto");
    if (proto == data->end() || !proto->is_number_integer() || proto->get<int64_t>() != 1)
        return fail(ErrorCode::ProtocolError, "sidecar protocol version is not 1");
    std::string version = "unknown";
    if (const auto ppadb = data->find("ppadb"); ppadb != data->end() && ppadb->is_string())
        version = ppadb->get<std::string>();

    std::unique_ptr<PySidecarAdbTransport> transport(
        new PySidecarAdbTransport(std::move(*session), options.timeouts, *python, std::move(version)));
    return transport;
}

Result<std::vector<AdbDevice>> PySidecarAdbTransport::list_devices() {
    const uint64_t id = next_id_++;
    json request{{"id", id}, {"op", "list_devices"}};
    auto response = exchange(*session_, request, timeouts_.shell, id);
    if (!response) return fail(response.error());
    const auto data = response->find("data");
    if (data == response->end())
        return fail(ErrorCode::ProtocolError, "sidecar list_devices response has no data");
    return parse_device_list(*data);
}

Result<std::string> PySidecarAdbTransport::shell_readonly(const std::string& serial,
                                                          const AdbShellCmd& cmd) {
    auto ok = validate_adb_serial(serial);
    if (!ok) return fail(ok.error());

    const uint64_t id = next_id_++;
    json request{{"id", id}, {"op", "shell"}, {"serial", serial}};
    json device_cmd;
    switch (cmd.kind()) {
        case AdbShellCmd::Kind::GetProp:
            device_cmd["kind"] = "GetProp";
            device_cmd["key"] = cmd.key();
            break;
        case AdbShellCmd::Kind::ListFiles:
            device_cmd["kind"] = "ListFiles";
            device_cmd["dir"] = cmd.dir();
            break;
        case AdbShellCmd::Kind::StatBatch:
            device_cmd["kind"] = "StatBatch";
            device_cmd["files"] = cmd.files();
            break;
        case AdbShellCmd::Kind::TestDir:
            device_cmd["kind"] = "TestDir";
            device_cmd["dir"] = cmd.dir();
            break;
    }
    request["cmd"] = std::move(device_cmd);

    auto response = exchange(*session_, request, timeouts_.shell, id);
    if (!response) return fail(response.error());
    auto data = string_data(*response, "shell");
    if (!data) return fail(data.error());
    if (cmd.kind() == AdbShellCmd::Kind::TestDir && *data != "0" && *data != "1")
        return fail(ErrorCode::ProtocolError,
                    "sidecar returned an invalid test -d result: " + summarized(*data));
    return data;
}

Result<void> PySidecarAdbTransport::pull(const std::string& serial, const std::string& remote,
                                         const std::filesystem::path& local_tmp) {
    auto ok = validate_adb_serial(serial);
    if (!ok) return fail(ok.error());
    ok = validate_remote_path(remote);
    if (!ok) return fail(ok.error());
    const std::string local = path_to_utf8(local_tmp);
    if (local.empty()) return fail(ErrorCode::InvalidArgument, "empty local pull destination");

    const uint64_t id = next_id_++;
    json request{
        {"id", id}, {"op", "pull"}, {"serial", serial}, {"remote", remote}, {"local", local}};
    auto response = exchange(*session_, request, timeouts_.pull, id);
    if (!response) return fail(response.error());

    std::error_code ec;
    if (!std::filesystem::is_regular_file(local_tmp, ec))
        return fail(ErrorCode::ProtocolError,
                    "sidecar reported a successful pull but the local file is missing: " + local);
    return {};
}

}  // namespace openrecover::android
