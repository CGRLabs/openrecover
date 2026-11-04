#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace openrecover::test {

// Unique temporary directory removed on destruction.
class TempDir {
public:
    TempDir();
    ~TempDir();
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

// Deterministic, position-dependent test pattern.
std::vector<uint8_t> patterned_bytes(size_t n, uint32_t seed = 0);

// Test fixtures only: the library never creates files outside OutputSink.
void create_test_file(const std::filesystem::path& p, const std::vector<uint8_t>& data);
std::vector<uint8_t> load_test_file(const std::filesystem::path& p);
std::string sha256_of_file(const std::filesystem::path& p);

}  // namespace openrecover::test
