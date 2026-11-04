#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/result.hpp"
#include "openrecover/io/win32_api.hpp"

namespace openrecover::io {

// Identifies the evidence source so the sink can refuse output locations backed by it.
struct SourceIdentity {
    enum class Kind { None, ImageFile, WindowsPhysicalDrive, WindowsVolume, BlockNode };
    Kind kind = Kind::None;
    std::filesystem::path path;
    uint32_t drive_number = 0;

    static SourceIdentity image(std::filesystem::path p) { return {Kind::ImageFile, std::move(p), 0}; }
    static SourceIdentity physical_drive(uint32_t n) { return {Kind::WindowsPhysicalDrive, {}, n}; }
    static SourceIdentity windows_volume(std::filesystem::path p) { return {Kind::WindowsVolume, std::move(p), 0}; }
    static SourceIdentity block_node(std::filesystem::path p) { return {Kind::BlockNode, std::move(p), 0}; }
    static SourceIdentity from_source_string(const std::string& source);
};

class ByteSource {
public:
    virtual ~ByteSource() = default;
    // Returns 0 at end of stream.
    virtual Result<size_t> read_some(uint8_t* dst, size_t len) = 0;
};

class MemoryByteSource final : public ByteSource {
public:
    explicit MemoryByteSource(std::span<const uint8_t> data) : data_(data) {}
    explicit MemoryByteSource(std::string_view text)
        : data_(reinterpret_cast<const uint8_t*>(text.data()), text.size()) {}
    Result<size_t> read_some(uint8_t* dst, size_t len) override;

private:
    std::span<const uint8_t> data_;
    size_t pos_ = 0;
};

struct WrittenFile {
    std::filesystem::path path;
    std::string relative;  // '/'-separated, relative to the sink root
    std::string sha256;
    uint64_t size = 0;
};

// The only component in the project that creates or writes files.
class OutputSink {
public:
    static Result<std::unique_ptr<OutputSink>> open(const std::filesystem::path& out_dir, const SourceIdentity& source,
                                                    std::shared_ptr<win::IWin32Api> api = nullptr);

    // Writes a new file under the root. Never overwrites: collisions get " (1)", " (2)", ... before the extension.
    Result<WrittenFile> write_file(std::string_view relative_path, ByteSource& src,
                                   std::optional<int64_t> mtime_unix = std::nullopt);

    const std::filesystem::path& root() const noexcept { return root_; }

    // Splits a '/'-separated path and sanitizes each component.
    static std::vector<std::string> sanitize_relative(std::string_view relative_path);

private:
    explicit OutputSink(std::filesystem::path root) : root_(std::move(root)) {}

    std::filesystem::path root_;
    uint64_t temp_counter_ = 0;
};

// True if `child` equals `root` or lies beneath it (both must be absolute and normalized).
bool path_is_within(const std::filesystem::path& child, const std::filesystem::path& root);

}  // namespace openrecover::io
