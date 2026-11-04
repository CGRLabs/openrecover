#pragma once

#include <string_view>

#include "openrecover/common/log.hpp"

namespace openrecover::fuzz {

// Parser warnings are expected for most mutated inputs; printing them would dominate the
// fuzzing loop and the CI log.
inline void silence_logs() {
    static const bool once = [] {
        log::set_sink([](LogLevel, std::string_view) {});
        return true;
    }();
    (void)once;
}

}  // namespace openrecover::fuzz
