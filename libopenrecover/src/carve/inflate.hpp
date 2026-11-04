#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include <miniz.h>

#include "openrecover/common/crc32.hpp"

namespace openrecover::carve::detail {

// Streaming inflater with a 32 KiB dictionary ring; output is counted and CRC-32 hashed.
class Inflator {
public:
    explicit Inflator(bool zlib_wrapper)
        : flags_(zlib_wrapper ? TINFL_FLAG_PARSE_ZLIB_HEADER : 0u) {
        tinfl_init(&decompressor_);
    }

    bool feed(const uint8_t* data, size_t len) {
        if (failed_) return false;
        if (done_) {
            if (len != 0) failed_ = true;
            return !failed_;
        }
        size_t pos = 0;
        for (;;) {
            if (ring_pos_ == ring_.size()) ring_pos_ = 0;
            size_t in_bytes = len - pos;
            size_t out_bytes = ring_.size() - ring_pos_;
            const size_t out_start = ring_pos_;
            const tinfl_status status = tinfl_decompress(
                &decompressor_, data + pos, &in_bytes, ring_.data(), ring_.data() + ring_pos_,
                &out_bytes, flags_ | TINFL_FLAG_HAS_MORE_INPUT);
            pos += in_bytes;
            crc_ = crc32_update(crc_, ring_.data() + out_start, out_bytes);
            output_ += out_bytes;
            ring_pos_ += out_bytes;
            if (status == TINFL_STATUS_DONE) {
                done_ = true;
                if (pos != len) failed_ = true;
                return !failed_;
            }
            if (status == TINFL_STATUS_NEEDS_MORE_INPUT) {
                if (pos != len) {
                    failed_ = true;
                    return false;
                }
                return true;
            }
            if (status == TINFL_STATUS_HAS_MORE_OUTPUT) {
                if (in_bytes == 0 && out_bytes == 0) {
                    failed_ = true;
                    return false;
                }
                continue;
            }
            failed_ = true;
            return false;
        }
    }

    bool finish() {
        if (failed_) return false;
        if (done_) return true;
        uint8_t dummy = 0;
        for (;;) {
            if (ring_pos_ == ring_.size()) ring_pos_ = 0;
            size_t consumed = 0;
            size_t out_bytes = ring_.size() - ring_pos_;
            const size_t out_start = ring_pos_;
            const tinfl_status status = tinfl_decompress(&decompressor_, &dummy, &consumed,
                                                         ring_.data(), ring_.data() + ring_pos_,
                                                         &out_bytes, flags_);
            crc_ = crc32_update(crc_, ring_.data() + out_start, out_bytes);
            output_ += out_bytes;
            ring_pos_ += out_bytes;
            if (status == TINFL_STATUS_DONE) {
                done_ = true;
                return true;
            }
            if (status == TINFL_STATUS_HAS_MORE_OUTPUT && (consumed != 0 || out_bytes != 0))
                continue;
            failed_ = true;
            return false;
        }
    }

    uint64_t output() const noexcept { return output_; }
    uint32_t crc() const noexcept { return crc_; }

private:
    tinfl_decompressor decompressor_{};
    uint32_t flags_ = 0;
    std::array<uint8_t, TINFL_LZ_DICT_SIZE> ring_{};
    size_t ring_pos_ = 0;
    uint64_t output_ = 0;
    uint32_t crc_ = 0;
    bool done_ = false;
    bool failed_ = false;
};

}  // namespace openrecover::carve::detail
