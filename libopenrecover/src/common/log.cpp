#include "openrecover/common/log.hpp"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>

namespace openrecover::log {

namespace {

std::atomic<int> g_level{static_cast<int>(LogLevel::Warn)};
std::mutex g_mutex;
Sink g_sink;

const char* level_tag(LogLevel l) {
    switch (l) {
        case LogLevel::Error: return "error";
        case LogLevel::Warn: return "warn";
        case LogLevel::Info: return "info";
        case LogLevel::Debug: return "debug";
        case LogLevel::Trace: return "trace";
    }
    return "?";
}

}  // namespace

void set_level(LogLevel level) noexcept { g_level.store(static_cast<int>(level)); }
LogLevel level() noexcept { return static_cast<LogLevel>(g_level.load()); }
bool enabled(LogLevel level) noexcept { return static_cast<int>(level) <= g_level.load(); }

void set_sink(Sink sink) {
    std::lock_guard lock(g_mutex);
    g_sink = std::move(sink);
}

void emit(LogLevel level, std::string_view message) {
    if (!enabled(level)) return;
    std::lock_guard lock(g_mutex);
    if (g_sink) {
        g_sink(level, message);
        return;
    }
    std::string line = "[";
    line += level_tag(level);
    line += "] ";
    line += message;
    line += '\n';
    std::fputs(line.c_str(), stderr);
}

}  // namespace openrecover::log
