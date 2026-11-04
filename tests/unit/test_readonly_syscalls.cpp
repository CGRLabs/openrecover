// Linux only: runs readonly_probe under strace and proves the source image is opened O_RDONLY
// and never targeted by write/pwrite64/ftruncate.
#include <catch2/catch_test_macros.hpp>

#include <sys/stat.h>

#include <cstdlib>
#include <fstream>
#include <regex>
#include <set>
#include <string>

#include "test_util.hpp"

#ifndef OPENRECOVER_PROBE_PATH
#error "OPENRECOVER_PROBE_PATH must be defined"
#endif

namespace fs = std::filesystem;
using openrecover::test::TempDir;

namespace {

std::string quote(const std::string& s) {
    std::string q = "'";
    for (char c : s) {
        if (c == '\'') q += "'\\''";
        else q += c;
    }
    return q + "'";
}

}  // namespace

TEST_CASE("source image is opened O_RDONLY and never written (strace)", "[readonly][syscalls]") {
    if (std::system("command -v strace >/dev/null 2>&1") != 0) SKIP("strace not installed");

    TempDir tmp;
    const fs::path image = tmp.path() / "src" / "disk.img";
    fs::create_directories(image.parent_path());
    openrecover::test::create_test_file(image, openrecover::test::patterned_bytes(3u << 20, 77));
    REQUIRE(::chmod(image.c_str(), 0444) == 0);
    const std::string before = openrecover::test::sha256_of_file(image);

    const fs::path trace = tmp.path() / "trace.txt";
    const fs::path out = tmp.path() / "out";
    const std::string cmd = "strace -f -s 4096 -e trace=open,openat,openat2,creat,write,pwrite64,pwritev,pwritev2,"
                            "writev,ftruncate,truncate,fallocate,close,dup,dup2,dup3 -o " +
                            quote(trace.string()) + " " + quote(OPENRECOVER_PROBE_PATH) + " " +
                            quote(image.string()) + " " + quote(out.string()) + " >/dev/null";
    const int rc = std::system(cmd.c_str());
    REQUIRE(rc == 0);
    REQUIRE(fs::exists(out / "probe" / "hash.txt"));

    std::ifstream in(trace);
    REQUIRE(in);
    const std::string img = image.string();
    const std::regex open_re(R"re((open|openat|openat2)\((?:[^,]*, )?"([^"]*)", ([A-Z_|0-9x]+)[^=]*= (-?\d+))re");
    const std::regex fd_re(R"re(\b(write|pwrite64|pwritev|pwritev2|writev|ftruncate|fallocate|close|dup|dup2|dup3)\((\d+)(?:, (\d+))?[^=]*= (-?\d+))re");
    const std::regex path_re(R"re(\b(creat|truncate)\("([^"]*)")re");

    std::set<int> image_fds;
    int image_opens = 0;
    std::string line;
    while (std::getline(in, line)) {
        INFO(line);
        std::smatch m;
        if (std::regex_search(line, m, open_re)) {
            if (m[2].str() == img) {
                const std::string flags = m[3].str();
                CHECK(flags.find("O_RDONLY") != std::string::npos);
                CHECK(flags.find("O_WRONLY") == std::string::npos);
                CHECK(flags.find("O_RDWR") == std::string::npos);
                CHECK(flags.find("O_CREAT") == std::string::npos);
                CHECK(flags.find("O_TRUNC") == std::string::npos);
                CHECK(flags.find("O_APPEND") == std::string::npos);
                const int fd = std::stoi(m[4].str());
                if (fd >= 0) {
                    image_fds.insert(fd);
                    ++image_opens;
                }
            }
            continue;
        }
        if (std::regex_search(line, m, path_re)) {
            CHECK(m[2].str() != img);
            continue;
        }
        if (std::regex_search(line, m, fd_re)) {
            const std::string call = m[1].str();
            const int fd = std::stoi(m[2].str());
            const int ret = std::stoi(m[4].str());
            if (call == "close") {
                image_fds.erase(fd);
            } else if (call == "dup" || call == "dup2" || call == "dup3") {
                if (call != "dup" && m[3].matched) image_fds.erase(std::stoi(m[3].str()));
                if (image_fds.count(fd) && ret >= 0) image_fds.insert(ret);
            } else {
                CHECK(image_fds.count(fd) == 0);
            }
        }
    }
    CHECK(image_opens >= 1);

    CHECK(openrecover::test::sha256_of_file(image) == before);
    struct stat st {};
    REQUIRE(::stat(image.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0444);
}
