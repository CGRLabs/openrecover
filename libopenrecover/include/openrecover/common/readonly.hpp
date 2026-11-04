#pragma once

#include <stdexcept>

namespace openrecover {

// Thrown whenever a code path attempts something the read-only mandate forbids.
// Kept in common/ so every module (including android/, which cannot include io/
// block-device headers) reports the same violation type.
struct ReadOnlyViolation : std::logic_error {
    using std::logic_error::logic_error;
};

}  // namespace openrecover
