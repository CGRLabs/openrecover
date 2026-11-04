#include "test_util.hpp"

#include <atomic>
#include <chrono>
#include <fstream>
#include <iterator>
#include <random>
#include <stdexcept>

#include "openrecover/common/hash.hpp"

namespace fs = std::filesystem;

namespace openrecover::test {

TempDir::TempDir() {
    static std::atomic<uint64_t> counter{0};
    std::random_device rd;
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    for (int attempt = 0; attempt < 100; ++attempt) {
        fs::path p = fs::temp_directory_path() /
                     ("openrecover_test_" + std::to_string(stamp) + "_" + std::to_string(rd()) + "_" +
                      std::to_string(counter++));
        if (fs::create_directory(p)) {
            path_ = fs::canonical(p);
            return;
        }
    }
    throw std::runtime_error("cannot create temp dir");
}

TempDir::~TempDir() {
    std::error_code ec;
    fs::permissions(path_, fs::perms::owner_all, fs::perm_options::add, ec);
    for (auto it = fs::recursive_directory_iterator(path_, ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec))
        fs::permissions(it->path(), fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::add, ec);
    fs::remove_all(path_, ec);
}

std::vector<uint8_t> patterned_bytes(size_t n, uint32_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i)
        v[i] = static_cast<uint8_t>((i * 131u + (i >> 9) * 7u + (i >> 17) + seed * 17u) & 0xFF);
    return v;
}

void create_test_file(const fs::path& p, const std::vector<uint8_t>& data) {
    std::ofstream os(p, std::ios::binary | std::ios::trunc);
    os.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!os) throw std::runtime_error("cannot create test file " + p.string());
}

std::vector<uint8_t> load_test_file(const fs::path& p) {
    std::ifstream is(p, std::ios::binary);
    if (!is) throw std::runtime_error("cannot open " + p.string());
    return {std::istreambuf_iterator<char>(is), std::istreambuf_iterator<char>()};
}

std::string sha256_of_file(const fs::path& p) { return sha256_hex(load_test_file(p)); }

}  // namespace openrecover::test
