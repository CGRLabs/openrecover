#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace openrecover {

enum class ErrorCode {
    IoError,
    NotFound,
    PermissionDenied,
    DeviceBusy,
    Unsupported,
    NoFilesystem,
    CorruptStructure,
    InvalidArgument,
    OutputOnSourceDevice,
    AlreadyExists,
    Cancelled,
    Timeout,
    PolicyViolation,
    AdbNotFound,
    DeviceUnauthorized,
    DeviceOffline,
    ProtocolError,
    StorageUnavailable,
    AccessDenied,
};

std::string_view error_code_name(ErrorCode code) noexcept;

// Process exit code for a failure (spec 7.2). ReadOnlyViolation is not an ErrorCode;
// the CLI maps that exception to 70 directly.
int exit_code_for_error(ErrorCode code) noexcept;

struct Error {
    ErrorCode code = ErrorCode::IoError;
    std::string message;
    uint64_t offset = 0;

    std::string to_string() const;
};

inline Error make_error(ErrorCode code, std::string message, uint64_t offset = 0) {
    return Error{code, std::move(message), offset};
}

}  // namespace openrecover
