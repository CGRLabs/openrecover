#include "openrecover/io/readonly_guard.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "openrecover/common/hash.hpp"
#include "openrecover/common/log.hpp"

namespace openrecover::io {

void fatal_write_attempt(const char* what, const char* file, int line) {
    std::string msg = "read-only violation: ";
    msg += what ? what : "(unknown)";
    msg += " at ";
    msg += file ? file : "?";
    msg += ":";
    msg += std::to_string(line);
    log::error(msg);
    throw ReadOnlyViolation(msg);
}

GuardedDevice::GuardedDevice(std::shared_ptr<BlockDevice> inner) : inner_(std::move(inner)) {
    if (!inner_) throw std::invalid_argument("GuardedDevice: null inner device");
}

Result<ReadResult> GuardedDevice::read(uint64_t offset, uint8_t* dst, size_t len) {
    reads_.fetch_add(1, std::memory_order_relaxed);
    return inner_->read(offset, dst, len);
}

void GuardedDevice::assert_untouched(const std::string& sha256_before) {
    auto now = sha256_of_device(*inner_);
    if (!now) throw ReadOnlyViolation("assert_untouched: cannot re-read device: " + now.error().to_string());
    if (*now != sha256_before)
        OR_FATAL_WRITE("source content changed between open and assert_untouched()");
}

Result<std::string> sha256_of_device(BlockDevice& dev) {
    Sha256Hasher h;
    std::vector<uint8_t> buf(1u << 20);
    const uint64_t size = dev.info().size_bytes;
    uint64_t off = 0;
    while (off < size) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(buf.size(), size - off));
        auto n = read_fully(dev, off, buf.data(), want);
        if (!n) return fail(n.error());
        if (*n == 0) break;
        h.update(buf.data(), *n);
        off += *n;
    }
    return h.finish_hex();
}

}  // namespace openrecover::io
