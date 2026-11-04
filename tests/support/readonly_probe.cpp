// Minimal driver used by test_readonly_syscalls: opens a source, reads it fully and unaligned,
// then exports one file through OutputSink. Run under strace to prove the source is never written.
#include <cstdio>
#include <string>
#include <vector>

#include "openrecover/io/block_device.hpp"
#include "openrecover/io/output_sink.hpp"
#include "openrecover/io/readonly_guard.hpp"

using namespace openrecover;
using namespace openrecover::io;

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: readonly_probe <source> <out-dir>\n");
        return 2;
    }
    const std::string source = argv[1];
    auto dev = open_source(source, OpenOptions{});
    if (!dev) {
        std::fprintf(stderr, "open failed: %s\n", dev.error().to_string().c_str());
        return 3;
    }
    auto hash = sha256_of_device(**dev);
    if (!hash) {
        std::fprintf(stderr, "read failed: %s\n", hash.error().to_string().c_str());
        return 3;
    }
    std::vector<uint8_t> buf(1000);
    for (uint64_t off : {uint64_t{513}, uint64_t{1}, (*dev)->info().size_bytes / 2 + 7}) {
        if (!(*dev)->read(off, buf.data(), buf.size())) return 3;
    }
    auto sink = OutputSink::open(argv[2], SourceIdentity::from_source_string(source));
    if (!sink) {
        std::fprintf(stderr, "sink failed: %s\n", sink.error().to_string().c_str());
        return 6;
    }
    MemoryByteSource content(std::string_view(*hash));
    auto w = (*sink)->write_file("probe/hash.txt", content);
    if (!w) {
        std::fprintf(stderr, "export failed: %s\n", w.error().to_string().c_str());
        return 3;
    }
    std::printf("%s\n", hash->c_str());
    return 0;
}
