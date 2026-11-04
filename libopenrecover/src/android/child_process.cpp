#include "openrecover/android/child_process.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

extern char** environ;
#endif

namespace openrecover::android {

namespace {

#if defined(_WIN32)

std::wstring utf8_to_wide(const std::string& text) {
    if (text.empty()) return {};
    const int needed = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed);
    return out;
}

std::string wide_to_utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed,
                        nullptr, nullptr);
    return out;
}

std::string format_last_error(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<wchar_t*>(&buffer),
        0, nullptr);
    std::string text;
    if (len != 0 && buffer != nullptr) {
        text = wide_to_utf8(std::wstring(buffer, len));
        LocalFree(buffer);
    }
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
    return text.empty() ? "Win32 error " + std::to_string(code)
                        : "Win32 error " + std::to_string(code) + ": " + text;
}

// MSVCRT command-line quoting, as expected by CreateProcessW.
std::wstring quote_windows_arg(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
    std::wstring result = L"\"";
    size_t backslashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        if (c == L'"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(c);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

struct PipeRead {
    std::string data;
    bool truncated = false;
};

void read_pipe(HANDLE pipe, size_t max_bytes, PipeRead& out) {
    char buffer[8192];
    DWORD got = 0;
    while (ReadFile(pipe, buffer, static_cast<DWORD>(sizeof buffer), &got, nullptr) && got > 0) {
        if (out.data.size() < max_bytes) {
            const size_t take = std::min<size_t>(got, max_bytes - out.data.size());
            out.data.append(buffer, take);
            if (take < got) out.truncated = true;
        } else {
            out.truncated = true;
        }
    }
}

#else

struct PipeRead {
    std::string data;
    bool truncated = false;
};

void read_pipe(int fd, size_t max_bytes, PipeRead& out) {
    char buffer[8192];
    for (;;) {
        const ssize_t got = ::read(fd, buffer, sizeof buffer);
        if (got > 0) {
            if (out.data.size() < max_bytes) {
                const size_t take = std::min<size_t>(static_cast<size_t>(got), max_bytes - out.data.size());
                out.data.append(buffer, take);
                if (take < static_cast<size_t>(got)) out.truncated = true;
            } else {
                out.truncated = true;
            }
            continue;
        }
        if (got < 0 && errno == EINTR) continue;
        break;
    }
}

#endif

}  // namespace

Result<ProcessResult> run_child_process(const std::vector<std::string>& argv,
                                        const ProcessOptions& options) {
    if (argv.empty()) return fail(ErrorCode::InvalidArgument, "empty child process argv");
    if (options.timeout.count() <= 0)
        return fail(ErrorCode::InvalidArgument, "child process timeout must be positive");

#if defined(_WIN32)
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;

    HANDLE out_read = nullptr;
    HANDLE out_write = nullptr;
    HANDLE err_read = nullptr;
    HANDLE err_write = nullptr;
    HANDLE in_read = nullptr;
    HANDLE in_write = nullptr;
    if (!CreatePipe(&out_read, &out_write, &sa, 0) || !CreatePipe(&err_read, &err_write, &sa, 0) ||
        !CreatePipe(&in_read, &in_write, &sa, 0)) {
        const DWORD code = GetLastError();
        for (HANDLE h : {out_read, out_write, err_read, err_write, in_read, in_write}) {
            if (h != nullptr) CloseHandle(h);
        }
        return fail(ErrorCode::IoError, "failed to create child process pipes: " + format_last_error(code));
    }
    SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);

    std::wstring command_line;
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i != 0) command_line.push_back(L' ');
        command_line += quote_windows_arg(utf8_to_wide(argv[i]));
    }

    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_read;
    si.hStdOutput = out_write;
    si.hStdError = err_write;
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');
    // A null application name lets CreateProcessW resolve argv[0] through PATH.
    const BOOL created =
        CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi);
    const DWORD create_error = created ? 0 : GetLastError();

    CloseHandle(in_read);
    CloseHandle(out_write);
    CloseHandle(err_write);
    CloseHandle(in_write);
    if (!created) {
        CloseHandle(out_read);
        CloseHandle(err_read);
        return fail(ErrorCode::IoError,
                    "failed to start child process '" + argv[0] + "': " + format_last_error(create_error));
    }
    CloseHandle(pi.hThread);

    PipeRead out;
    PipeRead err;
    std::thread out_thread(read_pipe, out_read, options.max_stdout_bytes, std::ref(out));
    std::thread err_thread(read_pipe, err_read, options.max_stderr_bytes, std::ref(err));

    ProcessResult result;
    const DWORD waited = WaitForSingleObject(pi.hProcess, static_cast<DWORD>(options.timeout.count()));
    if (waited == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
        result.timed_out = true;
    } else if (waited != WAIT_OBJECT_0) {
        const DWORD code = GetLastError();
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
        out_thread.join();
        err_thread.join();
        CloseHandle(out_read);
        CloseHandle(err_read);
        CloseHandle(pi.hProcess);
        return fail(ErrorCode::IoError, "failed to wait for child process: " + format_last_error(code));
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    out_thread.join();
    err_thread.join();
    CloseHandle(out_read);
    CloseHandle(err_read);
    CloseHandle(pi.hProcess);

    result.exit_code = static_cast<int>(exit_code);
    result.stdout_text = std::move(out.data);
    result.stderr_text = std::move(err.data);
    result.stdout_truncated = out.truncated;
    result.stderr_truncated = err.truncated;
    return result;
#else
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        if (out_pipe[0] >= 0) {
            close(out_pipe[0]);
            close(out_pipe[1]);
        }
        return fail(ErrorCode::IoError,
                    std::string("failed to create child process pipes: ") + std::strerror(errno));
    }

    const int devnull = open("/dev/null", O_RDONLY);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (devnull >= 0) posix_spawn_file_actions_adddup2(&actions, devnull, STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, err_pipe[0]);

    std::vector<char*> raw_argv;
    raw_argv.reserve(argv.size() + 1);
    for (const std::string& arg : argv) raw_argv.push_back(const_cast<char*>(arg.c_str()));
    raw_argv.push_back(nullptr);

    pid_t pid = 0;
    const int spawn_error =
        posix_spawnp(&pid, raw_argv[0], &actions, nullptr, raw_argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    close(out_pipe[1]);
    close(err_pipe[1]);
    if (devnull >= 0) close(devnull);
    if (spawn_error != 0) {
        close(out_pipe[0]);
        close(err_pipe[0]);
        return fail(ErrorCode::IoError,
                    "failed to start child process '" + argv[0] + "': " + std::strerror(spawn_error));
    }

    PipeRead out;
    PipeRead err;
    std::thread out_thread(read_pipe, out_pipe[0], options.max_stdout_bytes, std::ref(out));
    std::thread err_thread(read_pipe, err_pipe[0], options.max_stderr_bytes, std::ref(err));

    ProcessResult result;
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    for (;;) {
        const pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) break;
        if (done < 0 && errno != EINTR) {
            const int wait_error = errno;
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            out_thread.join();
            err_thread.join();
            close(out_pipe[0]);
            close(err_pipe[0]);
            return fail(ErrorCode::IoError,
                        std::string("failed to wait for child process: ") + std::strerror(wait_error));
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            result.timed_out = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    out_thread.join();
    err_thread.join();
    close(out_pipe[0]);
    close(err_pipe[0]);

    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exit_code = 128 + WTERMSIG(status);
    } else {
        result.exit_code = 1;
    }
    result.stdout_text = std::move(out.data);
    result.stderr_text = std::move(err.data);
    result.stdout_truncated = out.truncated;
    result.stderr_truncated = err.truncated;
    return result;
#endif
}

namespace {

constexpr size_t kMaxProtocolLineBytes = 16u << 20;
constexpr size_t kMaxQueuedLines = 1024;
constexpr size_t kMaxStderrTailBytes = 64u << 10;

struct SessionState {
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::string> lines;
    std::string stderr_data;
    size_t queued_bytes = 0;
    bool eof = false;

    // Returns false when the queue limit was hit and the reader should stop.
    bool push_line(std::string line) {
        bool keep_going = true;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (lines.size() >= kMaxQueuedLines || queued_bytes + line.size() > kMaxProtocolLineBytes) {
                eof = true;
                keep_going = false;
            } else {
                queued_bytes += line.size();
                lines.push_back(std::move(line));
            }
        }
        cv.notify_all();
        return keep_going;
    }

    void push_stderr(const char* data, size_t size) {
        std::lock_guard<std::mutex> lock(mutex);
        stderr_data.append(data, size);
        if (stderr_data.size() > kMaxStderrTailBytes)
            stderr_data.erase(0, stderr_data.size() - kMaxStderrTailBytes);
    }

    void mark_eof() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            eof = true;
        }
        cv.notify_all();
    }

    std::string tail_locked() const {
        constexpr size_t kTail = 2048;
        return stderr_data.size() > kTail ? stderr_data.substr(stderr_data.size() - kTail) : stderr_data;
    }
};

// Returns false when the caller should stop reading (line too long or queue full).
bool consume_chunks(std::string& buffer, const char* chunk, size_t size, SessionState& state) {
    buffer.append(chunk, size);
    size_t start = 0;
    for (;;) {
        const size_t newline = buffer.find('\n', start);
        if (newline == std::string::npos) break;
        std::string line = buffer.substr(start, newline - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        start = newline + 1;
        if (!state.push_line(std::move(line))) return false;
    }
    buffer.erase(0, start);
    return buffer.size() <= kMaxProtocolLineBytes;
}

#if defined(_WIN32)

void session_stdout_reader(HANDLE pipe, SessionState& state) {
    std::string buffer;
    char chunk[8192];
    DWORD got = 0;
    while (ReadFile(pipe, chunk, static_cast<DWORD>(sizeof chunk), &got, nullptr) && got > 0) {
        if (!consume_chunks(buffer, chunk, static_cast<size_t>(got), state)) break;
    }
    CloseHandle(pipe);
    state.mark_eof();
}

void session_stderr_reader(HANDLE pipe, SessionState& state) {
    char chunk[4096];
    DWORD got = 0;
    while (ReadFile(pipe, chunk, static_cast<DWORD>(sizeof chunk), &got, nullptr) && got > 0)
        state.push_stderr(chunk, static_cast<size_t>(got));
    CloseHandle(pipe);
}

#else

void session_stdout_reader(int fd, SessionState& state) {
    std::string buffer;
    char chunk[8192];
    for (;;) {
        const ssize_t got = ::read(fd, chunk, sizeof chunk);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        if (!consume_chunks(buffer, chunk, static_cast<size_t>(got), state)) break;
    }
    close(fd);
    state.mark_eof();
}

void session_stderr_reader(int fd, SessionState& state) {
    char chunk[4096];
    for (;;) {
        const ssize_t got = ::read(fd, chunk, sizeof chunk);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        state.push_stderr(chunk, static_cast<size_t>(got));
    }
    close(fd);
}

#endif

}  // namespace

struct ChildSession::Impl {
#if defined(_WIN32)
    HANDLE in_write = nullptr;
    HANDLE process = nullptr;
#else
    int in_write = -1;
    pid_t pid = -1;
    int exit_status = 0;
    bool reaped = false;
#endif
    SessionState state;
    std::thread out_thread;
    std::thread err_thread;
    bool terminated = false;
};

ChildSession::ChildSession() : impl_(std::make_unique<Impl>()) {}

ChildSession::~ChildSession() {
    if (!impl_) return;
    terminate();
    if (impl_->out_thread.joinable()) impl_->out_thread.join();
    if (impl_->err_thread.joinable()) impl_->err_thread.join();
#if defined(_WIN32)
    if (impl_->in_write != nullptr) CloseHandle(impl_->in_write);
    if (impl_->process != nullptr) CloseHandle(impl_->process);
#else
    if (impl_->in_write >= 0) close(impl_->in_write);
#endif
}

Result<std::unique_ptr<ChildSession>> ChildSession::start(const std::vector<std::string>& argv) {
    if (argv.empty()) return fail(ErrorCode::InvalidArgument, "empty child process argv");

#if defined(_WIN32)
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;

    HANDLE in_read = nullptr;
    HANDLE in_write = nullptr;
    HANDLE out_read = nullptr;
    HANDLE out_write = nullptr;
    HANDLE err_read = nullptr;
    HANDLE err_write = nullptr;
    if (!CreatePipe(&in_read, &in_write, &sa, 0) || !CreatePipe(&out_read, &out_write, &sa, 0) ||
        !CreatePipe(&err_read, &err_write, &sa, 0)) {
        const DWORD code = GetLastError();
        for (HANDLE h : {in_read, in_write, out_read, out_write, err_read, err_write}) {
            if (h != nullptr) CloseHandle(h);
        }
        return fail(ErrorCode::IoError, "failed to create child process pipes: " + format_last_error(code));
    }
    SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);

    std::wstring command_line;
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i != 0) command_line.push_back(L' ');
        command_line += quote_windows_arg(utf8_to_wide(argv[i]));
    }

    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_read;
    si.hStdOutput = out_write;
    si.hStdError = err_write;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');
    const BOOL created =
        CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi);
    const DWORD create_error = created ? 0 : GetLastError();
    CloseHandle(in_read);
    CloseHandle(out_write);
    CloseHandle(err_write);
    if (!created) {
        CloseHandle(in_write);
        CloseHandle(out_read);
        CloseHandle(err_read);
        return fail(ErrorCode::IoError,
                    "failed to start child process '" + argv[0] + "': " + format_last_error(create_error));
    }
    CloseHandle(pi.hThread);

    std::unique_ptr<ChildSession> session(new ChildSession());
    session->impl_->in_write = in_write;
    session->impl_->process = pi.hProcess;
    Impl* impl = session->impl_.get();
    impl->out_thread = std::thread(session_stdout_reader, out_read, std::ref(impl->state));
    impl->err_thread = std::thread(session_stderr_reader, err_read, std::ref(impl->state));
    return std::move(session);
#else
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        const int pipe_error = errno;
        for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]}) {
            if (fd >= 0) close(fd);
        }
        return fail(ErrorCode::IoError,
                    std::string("failed to create child process pipes: ") + std::strerror(pipe_error));
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in_pipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
    for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]})
        posix_spawn_file_actions_addclose(&actions, fd);

    std::vector<char*> raw_argv;
    raw_argv.reserve(argv.size() + 1);
    for (const std::string& arg : argv) raw_argv.push_back(const_cast<char*>(arg.c_str()));
    raw_argv.push_back(nullptr);

    pid_t pid = 0;
    const int spawn_error = posix_spawnp(&pid, raw_argv[0], &actions, nullptr, raw_argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) {
        for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]}) close(fd);
        return fail(ErrorCode::IoError,
                    "failed to start child process '" + argv[0] + "': " + std::strerror(spawn_error));
    }
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);
    for (int fd : {in_pipe[1], out_pipe[0], err_pipe[0]}) fcntl(fd, F_SETFD, FD_CLOEXEC);

    std::unique_ptr<ChildSession> session(new ChildSession());
    session->impl_->in_write = in_pipe[1];
    session->impl_->pid = pid;
    Impl* impl = session->impl_.get();
    impl->out_thread = std::thread(session_stdout_reader, out_pipe[0], std::ref(impl->state));
    impl->err_thread = std::thread(session_stderr_reader, err_pipe[0], std::ref(impl->state));
    return std::move(session);
#endif
}

Result<void> ChildSession::write_line(std::string_view line) {
    if (!impl_) return fail(ErrorCode::InvalidArgument, "child session is not open");
    if (line.find_first_of("\r\n") != std::string_view::npos)
        return fail(ErrorCode::InvalidArgument, "protocol line must not contain CR or LF");
    std::string payload(line);
    payload.push_back('\n');
    const auto tail_suffix = [this]() {
        const std::string tail = stderr_tail();
        return tail.empty() ? std::string() : ": " + tail;
    };

#if defined(_WIN32)
    if (impl_->in_write == nullptr) return fail(ErrorCode::InvalidArgument, "child stdin is closed");
    size_t written = 0;
    while (written < payload.size()) {
        const DWORD want =
            static_cast<DWORD>(std::min<size_t>(payload.size() - written, 1u << 20));
        DWORD wrote = 0;
        if (!WriteFile(impl_->in_write, payload.data() + written, want, &wrote, nullptr) || wrote == 0) {
            const DWORD code = GetLastError();
            return fail(ErrorCode::IoError,
                        "failed to write to child process: " + format_last_error(code) + tail_suffix());
        }
        written += wrote;
    }
#else
    if (impl_->in_write < 0) return fail(ErrorCode::InvalidArgument, "child stdin is closed");
    size_t written = 0;
    while (written < payload.size()) {
        const ssize_t wrote = ::write(impl_->in_write, payload.data() + written, payload.size() - written);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0)
            return fail(ErrorCode::IoError,
                        "failed to write to child process: " + std::string(std::strerror(errno)) +
                            tail_suffix());
        written += static_cast<size_t>(wrote);
    }
#endif
    return {};
}

Result<std::optional<std::string>> ChildSession::read_line(std::chrono::milliseconds timeout) {
    if (!impl_) return fail(ErrorCode::InvalidArgument, "child session is not open");
    std::unique_lock<std::mutex> lock(impl_->state.mutex);
    const bool ready = impl_->state.cv.wait_for(lock, timeout, [&] {
        return !impl_->state.lines.empty() || impl_->state.eof;
    });
    if (!ready) return std::optional<std::string>{};
    if (!impl_->state.lines.empty()) {
        std::string line = std::move(impl_->state.lines.front());
        impl_->state.lines.pop_front();
        const size_t size = line.size();
        impl_->state.queued_bytes =
            impl_->state.queued_bytes >= size ? impl_->state.queued_bytes - size : 0;
        return std::optional<std::string>(std::move(line));
    }
    const std::string tail = impl_->state.tail_locked();
    return fail(ErrorCode::ProtocolError,
                std::string("child process exited before sending a response") +
                    (tail.empty() ? "" : ": " + tail));
}

bool ChildSession::running() {
    if (!impl_) return false;
#if defined(_WIN32)
    if (impl_->process == nullptr) return false;
    return WaitForSingleObject(impl_->process, 0) == WAIT_TIMEOUT;
#else
    if (impl_->pid <= 0 || impl_->reaped) return false;
    int status = 0;
    const pid_t done = waitpid(impl_->pid, &status, WNOHANG);
    if (done == impl_->pid) {
        impl_->reaped = true;
        impl_->exit_status = status;
        return false;
    }
    if (done < 0 && errno == ECHILD) {
        impl_->reaped = true;
        return false;
    }
    return done == 0;
#endif
}

void ChildSession::terminate() {
    if (!impl_ || impl_->terminated) return;
    impl_->terminated = true;
#if defined(_WIN32)
    if (impl_->process == nullptr) return;
    DWORD code = 0;
    if (GetExitCodeProcess(impl_->process, &code) && code == STILL_ACTIVE) {
        TerminateProcess(impl_->process, 1);
        WaitForSingleObject(impl_->process, 5000);
    }
#else
    if (impl_->pid <= 0 || impl_->reaped) return;
    if (running()) kill(impl_->pid, SIGKILL);
    if (!impl_->reaped) {
        int status = 0;
        while (waitpid(impl_->pid, &status, 0) < 0 && errno == EINTR) {
        }
        impl_->reaped = true;
        impl_->exit_status = status;
    }
#endif
}

std::string ChildSession::stderr_tail() const {
    if (!impl_) return {};
    std::lock_guard<std::mutex> lock(impl_->state.mutex);
    return impl_->state.tail_locked();
}

}  // namespace openrecover::android
