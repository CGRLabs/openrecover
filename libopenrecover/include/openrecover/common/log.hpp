#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace openrecover {

enum class LogLevel { Error = 0, Warn = 1, Info = 2, Debug = 3, Trace = 4 };

namespace log {

void set_level(LogLevel level) noexcept;
LogLevel level() noexcept;
bool enabled(LogLevel level) noexcept;

using Sink = std::function<void(LogLevel, std::string_view)>;
// Replaces the output sink (default: stderr). Pass nullptr to restore the default.
void set_sink(Sink sink);

void emit(LogLevel level, std::string_view message);
inline void error(std::string_view m) { emit(LogLevel::Error, m); }
inline void warn(std::string_view m) { emit(LogLevel::Warn, m); }
inline void info(std::string_view m) { emit(LogLevel::Info, m); }
inline void debug(std::string_view m) { emit(LogLevel::Debug, m); }
inline void trace(std::string_view m) { emit(LogLevel::Trace, m); }

}  // namespace log

using ProgressFn = std::function<bool(uint64_t done, uint64_t total)>;

}  // namespace openrecover
