#pragma once

#include <tl/expected.hpp>

#include "openrecover/common/error.hpp"

namespace openrecover {

template <typename T>
using Result = tl::expected<T, Error>;

inline tl::unexpected<Error> fail(ErrorCode code, std::string message, uint64_t offset = 0) {
    return tl::unexpected<Error>(Error{code, std::move(message), offset});
}

inline tl::unexpected<Error> fail(Error e) { return tl::unexpected<Error>(std::move(e)); }

}  // namespace openrecover
