#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/common/types.hpp"

namespace openrecover::carve {

class BoundedReader;

struct ValidationResult {
    enum class Verdict { Valid, ValidTruncated, Invalid };

    Verdict verdict = Verdict::Invalid;
    uint64_t length_bytes = 0;  // exact length (Valid) or validated bytes (ValidTruncated)
    std::string subtype;
    Confidence confidence = Confidence::Low;
    std::vector<std::string> notes;

    static ValidationResult invalid() { return {}; }
    bool is_valid() const noexcept { return verdict != Verdict::Invalid; }
};

// The tail of a file whose bytes resume after a discontinuity. Offsets are relative to the
// reader the signature was handed, which starts at the first allocation-unit boundary after
// the validated prefix.
struct Continuation {
    uint64_t start = 0;
    uint64_t length = 0;
    // True when [start, start+length) ends at the format's terminator. False when the bytes
    // stopped making sense again at offset start+length, so another continuation may follow it.
    bool complete = true;
};

class ISignature {
public:
    virtual ~ISignature() = default;
    virtual std::string_view name() const = 0;
    virtual std::span<const std::span<const uint8_t>> magics() const = 0;
    // Offset of the magic from the start of a candidate. A format whose first bytes are a length
    // field -- an ISO media file opens with the size of its first box -- anchors further in.
    virtual size_t magic_offset() const { return 0; }
    virtual size_t min_header_bytes() const = 0;
    virtual uint64_t max_file_size() const = 0;
    virtual std::string_view default_extension() const = 0;
    // `r` is positioned at the candidate start (offset 0).
    virtual ValidationResult validate(BoundedReader& r) const = 0;
    // A format that can recognise its own trailer from an arbitrary resume point may claim the
    // rest of a run that ended at a discontinuity. `r` starts at the first alignment boundary
    // after the bytes already attributed to the file and is bounded by the reassembly gap.
    // Returning a continuation is a promise that [start, start+length) is structurally valid
    // content of this format: it either ends at the terminator (`complete`) or at another
    // discontinuity, in which case the engine may ask again from the new cut. The engine exports
    // the prefix and every joined continuation concatenated, and only accepts a set that ends at
    // the terminator.
    virtual std::optional<Continuation> find_continuation(BoundedReader& /*r*/) const {
        return std::nullopt;
    }
};

// Deterministic registration order; adding a signature is one line here (spec 5.9).
class SignatureRegistry {
public:
    void add(const ISignature& signature) { signatures_.push_back(&signature); }

    const std::vector<const ISignature*>& signatures() const noexcept { return signatures_; }
    const ISignature* find(std::string_view name) const noexcept;

    static const SignatureRegistry& builtins();

    // Load additional signatures from a JSON signature pack file.
    // Format: array of { "name", "magic" (hex), "extension", "max_size" }.
    bool load_from_file(const std::string& path);

private:
    std::vector<const ISignature*> signatures_;
};

}  // namespace openrecover::carve
