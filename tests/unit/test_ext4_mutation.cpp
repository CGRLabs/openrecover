#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/ext4/ext4_scanner.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "test_util.hpp"

namespace {

using namespace openrecover;
using openrecover::test::MemoryDevice;
namespace fsys = openrecover::fs;
namespace stdfs = std::filesystem;

constexpr int kMutations = 600;

// Deterministic: the same image always gets the same set of single-byte flips, so a
// regression here reproduces on the next run instead of on a lucky seed.
class Lcg {
public:
    explicit Lcg(uint64_t seed) : state_(seed) {}
    uint64_t next() {
        state_ = state_ * 6364136223846793005ull + 1442695040888963407ull;
        return state_ >> 11;
    }

private:
    uint64_t state_;
};

// Names come off a corrupted volume, and a path that escapes the output directory is a
// bug in the reader, not a property of the image.
bool component_ok(const std::string& component) {
    if (component.empty() || component == "." || component == "..") return false;
    for (const char ch : component) {
        const unsigned char raw = static_cast<unsigned char>(ch);
        if (raw < 0x20 || raw == 0x7F) return false;
        if (std::string("<>:\"/\\|?*").find(ch) != std::string::npos) return false;
    }
    return true;
}

void check_invariants(fsys::Ext4Scanner& scanner, io::BlockDevice& dev,
                      const std::vector<RecoveredFile>& files, uint64_t at, uint8_t delta) {
    std::set<std::string> seen;
    const uint64_t volume_bytes = dev.info().size_bytes;
    for (const RecoveredFile& file : files) {
        INFO("mutation: offset " << at << " xor " << static_cast<int>(delta)
                                 << ", reported path " << file.path);
        REQUIRE_FALSE(file.path.empty());
        CHECK(seen.insert(file.path).second);

        size_t from = 0;
        while (from <= file.path.size()) {
            const size_t slash = file.path.find('/', from);
            const std::string part = file.path.substr(
                from, (slash == std::string::npos ? file.path.size() : slash) - from);
            INFO("component '" << part << "' of path '" << file.path << "'");
            CHECK(component_ok(part));
            if (slash == std::string::npos) break;
            from = slash + 1;
        }

        const bool reallocated = (file.flags & file_flags::ClustersReallocated) != 0;
        if (reallocated) {
            // The scanner's only promise about taken blocks is that it says so, loudly.
            CHECK(file.confidence == Confidence::Low);
            continue;
        }
        if ((file.flags & file_flags::Unsupported) != 0) {
            std::vector<uint8_t> buf(1);
            auto got = scanner.read_file(file, 0, buf.data(), buf.size());
            CHECK_FALSE(got.has_value());
            if (!got) CHECK(got.error().code == ErrorCode::Unsupported);
            continue;
        }
        for (const Extent& extent : file.extents) {
            if (extent.sparse) continue;
            CHECK(extent.offset_bytes + extent.length_bytes <= volume_bytes);
        }
        // A file the scanner reports as readable has to read back, even when its block map
        // turned to garbage; an empty result is honest, an error is not.
        const size_t want = static_cast<size_t>(std::min<uint64_t>(file.size_bytes, 4096));
        std::vector<uint8_t> buf(want);
        auto got = scanner.read_file(file, 0, buf.data(), want);
        CHECK(got.has_value());
        if (got) CHECK(*got <= want);
    }
}

}  // namespace

TEST_CASE("ext4 scanner survives single-byte corruption of a real image",
          "[ext4][mutation]") {
    const stdfs::path image = stdfs::path(OPENRECOVER_FIXTURE_DIR) / "ext4_basic.img";
    if (!stdfs::exists(image)) SKIP("ext4 fixture images are missing from " << OPENRECOVER_FIXTURE_DIR);
    const std::vector<uint8_t> base = test::load_test_file(image);
    REQUIRE(base.size() > 4096);

    // Corrupt volumes are chatty; the count is a coverage stat, not console noise.
    uint64_t warnings = 0;
    log::set_sink([&](LogLevel level, std::string_view) {
        if (level <= LogLevel::Warn) ++warnings;
    });
    struct Restore {
        ~Restore() { log::set_sink(nullptr); }
    } restore;

    int opened = 0, scanned = 0, reported = 0;
    Lcg rng(0x5EED1234ull);
    for (int i = 0; i < kMutations; ++i) {
        std::vector<uint8_t> bytes = base;
        const uint64_t at = rng.next() % bytes.size();
        uint8_t delta = static_cast<uint8_t>(rng.next() & 0xFF);
        while (delta == 0) delta = static_cast<uint8_t>(rng.next() & 0xFF);
        bytes[static_cast<size_t>(at)] ^= delta;

        INFO("mutation " << i << ": offset " << at << " xor " << static_cast<int>(delta));
        auto dev = std::make_shared<MemoryDevice>(bytes, 512);
        auto scanner = fsys::Ext4Scanner::open(dev);
        if (!scanner.has_value()) continue;
        ++opened;
        auto files = (*scanner)->scan_deleted(fsys::ScanOptions{}, nullptr);
        if (!files.has_value()) continue;
        ++scanned;
        if (!files->empty()) ++reported;
        check_invariants(**scanner, *dev, *files, at, delta);
    }

    // A sweep where nothing opens means the mutations missed the filesystem rather than
    // that the reader is robust, so the floors below are coverage, not tolerance. On this
    // image all 600 mutations open, scan and report at least one file; 19/20 leaves room
    // for the superblock to be hit dead-on without the check turning into a tautology.
    INFO("of " << kMutations << " mutations -- opens: " << opened << ", scans: " << scanned
         << ", reports: " << reported << ", warnings: " << warnings);
    CHECK(opened * 20 >= kMutations * 19);
    CHECK(scanned * 20 >= kMutations * 19);
    CHECK(reported * 20 >= kMutations * 19);
}
