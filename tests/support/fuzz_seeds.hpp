#pragma once

// Shared check that a committed libFuzzer seed corpus still parses the way its name says.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory_device.hpp"
#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/carve/signature.hpp"
#include "test_util.hpp"

namespace openrecover::test {

// A seed named "invalid_*" must be rejected by the validator, every other seed must be
// accepted and report a non-empty length. This keeps the corpora meaningful on hosts that
// cannot build the libFuzzer targets.
//
// `allowed_subtypes` is the set a family signature may report; empty means the subtype has to
// equal the signature's own name, which is true for every format except the ones where one
// container holds several named families.
inline void check_signature_seed_corpus(std::string_view seed_dir,
                                        const carve::ISignature& signature,
                                        std::span<const std::string_view> allowed_subtypes = {}) {
    const std::filesystem::path root{std::string(seed_dir)};
    REQUIRE(std::filesystem::is_directory(root));

    std::vector<std::filesystem::path> seeds;
    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        if (entry.is_regular_file()) seeds.push_back(entry.path());
    }
    std::sort(seeds.begin(), seeds.end());
    REQUIRE_FALSE(seeds.empty());

    for (const auto& path : seeds) {
        INFO("seed: " << path.filename().string());
        const std::vector<uint8_t> bytes = load_test_file(path);
        const bool expect_valid = path.filename().string().rfind("invalid_", 0) != 0;

        carve::ValidationResult result;
        {
            // A BoundedReader carries a 256 KiB block cache; keep it out of the caller's frame.
            test::MemoryDevice device(bytes);
            carve::BoundedReader reader(device, 0, bytes.size());
            result = signature.validate(reader);
        }

        CHECK(result.is_valid() == expect_valid);
        if (!expect_valid) continue;
        CHECK(result.length_bytes > 0);
        CHECK(result.length_bytes <= bytes.size());
        if (allowed_subtypes.empty()) {
            CHECK(result.subtype == signature.name());
        } else {
            CHECK(std::find(allowed_subtypes.begin(), allowed_subtypes.end(),
                            std::string_view(result.subtype)) != allowed_subtypes.end());
        }
    }
}

}  // namespace openrecover::test
