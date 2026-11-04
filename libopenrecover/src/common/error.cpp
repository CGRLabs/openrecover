#include "openrecover/common/error.hpp"
#include "openrecover/common/types.hpp"

namespace openrecover {

std::string_view error_code_name(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::IoError: return "IoError";
        case ErrorCode::NotFound: return "NotFound";
        case ErrorCode::PermissionDenied: return "PermissionDenied";
        case ErrorCode::DeviceBusy: return "DeviceBusy";
        case ErrorCode::Unsupported: return "Unsupported";
        case ErrorCode::NoFilesystem: return "NoFilesystem";
        case ErrorCode::CorruptStructure: return "CorruptStructure";
        case ErrorCode::InvalidArgument: return "InvalidArgument";
        case ErrorCode::OutputOnSourceDevice: return "OutputOnSourceDevice";
        case ErrorCode::AlreadyExists: return "AlreadyExists";
        case ErrorCode::Cancelled: return "Cancelled";
        case ErrorCode::Timeout: return "Timeout";
        case ErrorCode::PolicyViolation: return "PolicyViolation";
        case ErrorCode::AdbNotFound: return "AdbNotFound";
        case ErrorCode::DeviceUnauthorized: return "DeviceUnauthorized";
        case ErrorCode::DeviceOffline: return "DeviceOffline";
        case ErrorCode::ProtocolError: return "ProtocolError";
        case ErrorCode::StorageUnavailable: return "StorageUnavailable";
        case ErrorCode::AccessDenied: return "AccessDenied";
    }
    return "Unknown";
}

int exit_code_for_error(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::InvalidArgument:
        case ErrorCode::PolicyViolation: return 2;
        case ErrorCode::PermissionDenied:
        case ErrorCode::AccessDenied: return 3;
        case ErrorCode::DeviceBusy: return 4;
        case ErrorCode::Unsupported:
        case ErrorCode::NoFilesystem: return 5;
        case ErrorCode::OutputOnSourceDevice: return 6;
        case ErrorCode::DeviceUnauthorized: return 7;
        case ErrorCode::IoError:
        case ErrorCode::NotFound:
        case ErrorCode::CorruptStructure:
        case ErrorCode::AlreadyExists:
        case ErrorCode::Cancelled:
        case ErrorCode::Timeout:
        case ErrorCode::AdbNotFound:
        case ErrorCode::DeviceOffline:
        case ErrorCode::ProtocolError:
        case ErrorCode::StorageUnavailable: return 1;
    }
    return 1;
}

std::string Error::to_string() const {
    std::string s(error_code_name(code));
    if (!message.empty()) {
        s += ": ";
        s += message;
    }
    if (offset != 0) {
        s += " (at offset ";
        s += std::to_string(offset);
        s += ")";
    }
    return s;
}

const char* confidence_name(Confidence c) noexcept {
    switch (c) {
        case Confidence::High: return "high";
        case Confidence::Medium: return "medium";
        case Confidence::Low: return "low";
    }
    return "low";
}

const char* origin_name(FileOrigin o) noexcept {
    switch (o) {
        case FileOrigin::FilesystemMetadata: return "filesystem_metadata";
        case FileOrigin::Carved: return "carved";
        case FileOrigin::AndroidPull: return "android_pull";
    }
    return "carved";
}

std::vector<std::string> flag_names(uint32_t flags) {
    static const std::pair<uint32_t, const char*> table[] = {
        {file_flags::PathUncertain, "PathUncertain"},
        {file_flags::Truncated, "Truncated"},
        {file_flags::ClustersReallocated, "ClustersReallocated"},
        {file_flags::NameFirstCharGuessed, "NameFirstCharGuessed"},
        {file_flags::Fragmented, "Fragmented"},
        {file_flags::Unsupported, "Unsupported"},
        {file_flags::OriginalPathRestored, "OriginalPathRestored"},
    };
    std::vector<std::string> out;
    for (const auto& [bit, name] : table)
        if (flags & bit) out.emplace_back(name);
    return out;
}

}  // namespace openrecover
