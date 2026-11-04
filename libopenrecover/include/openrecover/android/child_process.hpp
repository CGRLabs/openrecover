#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/result.hpp"

namespace openrecover::android {

struct ProcessOptions {
    std::chrono::milliseconds timeout{30000};
    size_t max_stdout_bytes = 8u << 20;
    size_t max_stderr_bytes = 1u << 20;
};

struct ProcessResult {
    int exit_code = 0;
    bool timed_out = false;
    bool stdout_truncated = false;
    bool stderr_truncated = false;
    std::string stdout_text;
    std::string stderr_text;
};

// Runs `argv` directly (no shell) and captures stdout/stderr. On timeout the child is
// killed and `timed_out` is set. I/O failures to create the process return an Error.
Result<ProcessResult> run_child_process(const std::vector<std::string>& argv,
                                        const ProcessOptions& options);

// Long-lived child process for line-oriented protocols (the Python adb sidecar).
// stdout is split into LF-terminated lines; stderr is kept as a bounded tail for
// diagnostics. Destructor kills the child if it is still running.
class ChildSession {
public:
    static Result<std::unique_ptr<ChildSession>> start(const std::vector<std::string>& argv);
    ~ChildSession();

    ChildSession(const ChildSession&) = delete;
    ChildSession& operator=(const ChildSession&) = delete;

    Result<void> write_line(std::string_view line);
    // std::nullopt on deadline; an exited child yields Error{ProtocolError}.
    Result<std::optional<std::string>> read_line(std::chrono::milliseconds timeout);

    bool running();
    void terminate();
    std::string stderr_tail() const;

private:
    ChildSession();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace openrecover::android
