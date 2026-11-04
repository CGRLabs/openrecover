#include "openrecover/carve/carve_engine.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <set>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"
#include "openrecover/common/bytes.hpp"
#include "openrecover/common/hash.hpp"
#include "openrecover/common/log.hpp"

namespace openrecover::carve {

namespace {

constexpr uint64_t kWindowBytes = 4ull << 20;
constexpr uint64_t kOverlapBytes = 64ull << 10;
// A joined file is a chain of runs, not a pile: more pieces than this is a sign the walk is
// stitching unrelated data together, so the chain is dropped and the head stands on its own.
constexpr size_t kMaxReassemblyPieces = 8;
// Bounds the number of times the walk may resume inside short marker-only runs.
constexpr size_t kMaxReassemblyAttempts = 256;

struct AllocationGeometry {
    bool valid = false;
    uint64_t cluster_size = 0;
    uint64_t anchor_offset = 0;  // byte offset of cluster 2

    static AllocationGeometry from(const fs::IAllocationMap* map) {
        AllocationGeometry geometry;
        if (!map || map->cluster_count() <= 2) return geometry;
        const uint64_t first = map->cluster_to_byte_offset(1);
        const uint64_t second = map->cluster_to_byte_offset(2);
        if (second <= first) return geometry;
        geometry.cluster_size = second - first;
        geometry.anchor_offset = second;
        geometry.valid = geometry.cluster_size != 0;
        return geometry;
    }

    bool is_allocated(const fs::IAllocationMap& map, uint64_t byte) const {
        if (!valid) return true;
        if (byte < anchor_offset) return true;
        const uint64_t cluster = 2 + (byte - anchor_offset) / cluster_size;
        if (cluster >= map.cluster_count()) return true;
        return map.is_cluster_allocated(cluster);
    }

    // True when any allocation unit touched by [begin, end) is marked allocated. A piece found
    // beyond a gap is only part of the deleted file if the clusters holding it are free too;
    // bytes in a cluster in use belong to whatever file owns it now.
    bool overlaps_allocated(const fs::IAllocationMap& map, uint64_t begin, uint64_t end) const {
        if (!valid) return true;
        if (end <= begin) return false;
        if (begin < anchor_offset) return true;
        const uint64_t last_cluster = 2 + ((end - 1) - anchor_offset) / cluster_size;
        if (last_cluster >= map.cluster_count()) return true;
        for (uint64_t cluster = 2 + (begin - anchor_offset) / cluster_size;; ++cluster) {
            if (map.is_cluster_allocated(cluster)) return true;
            if (cluster == last_cluster) return false;
        }
    }
};

uint64_t saturating_add(uint64_t a, uint64_t b) {
    const uint64_t max = UINT64_MAX;
    return a > max - b ? max : a + b;
}

std::vector<CarveFragment> ranges_of(const CarveHit& hit) {
    if (!hit.fragments.empty()) return hit.fragments;
    return {{hit.offset, hit.length}};
}

bool ranges_overlap(const std::vector<CarveFragment>& a, const std::vector<CarveFragment>& b) {
    for (const CarveFragment& x : a) {
        const uint64_t x_end = saturating_add(x.offset, x.length);
        for (const CarveFragment& y : b) {
            const uint64_t y_end = saturating_add(y.offset, y.length);
            if (x.offset < y_end && y.offset < x_end) return true;
        }
    }
    return false;
}

// True when every byte of `inner` falls inside `outer`'s runs.
bool ranges_cover(const std::vector<CarveFragment>& outer,
                  const std::vector<CarveFragment>& inner) {
    for (const CarveFragment& y : inner) {
        const uint64_t y_end = saturating_add(y.offset, y.length);
        bool covered = false;
        for (const CarveFragment& x : outer) {
            const uint64_t x_end = saturating_add(x.offset, x.length);
            if (x.offset <= y.offset && x_end >= y_end) {
                covered = true;
                break;
            }
        }
        if (!covered) return false;
    }
    return true;
}

void resolve_overlaps(std::vector<CarveHit>& hits) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < hits.size() && !changed; ++i) {
            for (size_t j = i + 1; j < hits.size(); ++j) {
                const std::vector<CarveFragment> ranges_i = ranges_of(hits[i]);
                const std::vector<CarveFragment> ranges_j = ranges_of(hits[j]);
                if (!ranges_overlap(ranges_i, ranges_j)) continue;

                const bool i_contains_j = ranges_cover(ranges_i, ranges_j);
                const bool j_contains_i = ranges_cover(ranges_j, ranges_i);
                if (i_contains_j) {
                    hits.erase(hits.begin() + static_cast<std::ptrdiff_t>(j));
                } else if (j_contains_i) {
                    hits.erase(hits.begin() + static_cast<std::ptrdiff_t>(i));
                } else {
                    const int i_rank = confidence_rank(hits[i].confidence);
                    const int j_rank = confidence_rank(hits[j].confidence);
                    const bool keep_i =
                        i_rank < j_rank || (i_rank == j_rank && hits[i].length >= hits[j].length);
                    hits.erase(hits.begin() + static_cast<std::ptrdiff_t>(keep_i ? j : i));
                }
                changed = true;
                break;
            }
        }
    }
    std::sort(hits.begin(), hits.end(), [](const CarveHit& a, const CarveHit& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.length > b.length;
    });
}

Result<std::string> hash_fragments(io::BlockDevice& device,
                                   const std::vector<CarveFragment>& ranges, uint64_t total) {
    Sha256Hasher hasher;
    std::vector<uint8_t> buffer(1u << 20);
    uint64_t hashed = 0;
    for (const CarveFragment& range : ranges) {
        uint64_t done = 0;
        while (done < range.length) {
            const size_t want =
                static_cast<size_t>(std::min<uint64_t>(buffer.size(), range.length - done));
            auto got = io::read_fully(device, range.offset + done, buffer.data(), want);
            if (!got) return fail(got.error());
            if (*got == 0)
                return fail(ErrorCode::IoError, "short read while hashing a carved hit",
                            range.offset + done);
            hasher.update(buffer.data(), *got);
            done += *got;
        }
        hashed += range.length;
    }
    if (hashed != total)
        return fail(ErrorCode::IoError, "carved fragments do not add up to the file length");
    return hasher.finish_hex();
}

const char* extension_for(const std::string& type, const std::string& subtype,
                          const SignatureRegistry& registry) {
    if (type == "jpeg") return "jpg";
    if (type == "png") return "png";
    if (type == "pdf") return "pdf";
    if (type == "zip") {
        if (subtype == "docx" || subtype == "xlsx" || subtype == "pptx" || subtype == "odt" ||
            subtype == "ods" || subtype == "odp" || subtype == "apk" || subtype == "jar" ||
            subtype == "epub") {
            return nullptr;  // caller uses the subtype itself
        }
        return "zip";
    }
    // An ISO media file is named by its brand, so the subtype the validator picked is the
    // extension: mp4, mov, m4a, 3gp and heic all come out of one signature.
    if (type == "mp4") return nullptr;
    // A compound file is named by the application stream it holds, so a Word document comes out as
    // .doc and an Excel workbook as .xls while anything else keeps the container's own extension.
    if (type == "cfb") return nullptr;
    const ISignature* signature = registry.find(type);
    if (signature && !signature->default_extension().empty()) {
        static thread_local std::string extension;
        extension.assign(signature->default_extension());
        return extension.c_str();
    }
    return "bin";
}

class DeviceRangesSource final : public io::ByteSource {
public:
    DeviceRangesSource(io::BlockDevice& device, std::vector<CarveFragment> ranges)
        : device_(device), ranges_(std::move(ranges)) {}

    Result<size_t> read_some(uint8_t* dst, size_t len) override {
        while (index_ < ranges_.size() && pos_ == ranges_[index_].length) {
            ++index_;
            pos_ = 0;
        }
        if (index_ >= ranges_.size() || len == 0) return size_t{0};
        const CarveFragment& range = ranges_[index_];
        const size_t want = static_cast<size_t>(std::min<uint64_t>(len, range.length - pos_));
        auto got = io::read_fully(device_, range.offset + pos_, dst, want);
        if (!got) return fail(got.error());
        pos_ += *got;
        return *got;
    }

private:
    io::BlockDevice& device_;
    std::vector<CarveFragment> ranges_;
    size_t index_ = 0;
    uint64_t pos_ = 0;
};

void mark_duplicates(std::vector<CarveHit>& hits,
                     const std::vector<RecoveredFile>* recovered) {
    if (!recovered) return;
    for (CarveHit& hit : hits) {
        const std::vector<CarveFragment> ranges = ranges_of(hit);
        for (const RecoveredFile& file : *recovered) {
            if (file.confidence != Confidence::High || file.extents.empty()) continue;
            const Extent& first = file.extents.front();
            if (first.sparse) continue;
            if (first.offset_bytes == ranges.front().offset &&
                first.length_bytes >= ranges.front().length) {
                hit.duplicate_of = file.path;
                break;
            }
        }
    }
}

}  // namespace

Result<std::vector<CarveHit>> CarveEngine::run(io::BlockDevice& device,
                                               const fs::IAllocationMap* allocation,
                                               const CarveOptions& options, ProgressFn progress) {
    return run(device, allocation, options, std::move(progress), SignatureRegistry::builtins());
}

Result<std::vector<CarveHit>> CarveEngine::run(io::BlockDevice& device,
                                               const fs::IAllocationMap* allocation,
                                               const CarveOptions& options, ProgressFn progress,
                                               const SignatureRegistry& registry) {
    for (const std::string& type : options.types) {
        if (registry.find(type) == nullptr)
            return fail(ErrorCode::InvalidArgument, "unknown carve type: " + type);
    }

    std::vector<const ISignature*> signatures;
    for (const ISignature* signature : registry.signatures()) {
        if (!options.types.empty() && options.types.count(std::string(signature->name())) == 0)
            continue;
        signatures.push_back(signature);
    }

    const uint64_t device_size = device.info().size_bytes;
    const uint64_t scan_start = std::min<uint64_t>(options.start_byte, device_size);
    const uint64_t scan_end = std::min<uint64_t>(options.end_byte, device_size);
    if (scan_start >= scan_end || signatures.empty()) return std::vector<CarveHit>{};

    const AllocationGeometry geometry = AllocationGeometry::from(allocation);
    bool restrict_allocation = options.scope == CarveOptions::Scope::UnallocatedOnly;
    if (restrict_allocation && !allocation) {
        log::warn("carve: UnallocatedOnly without an allocation map; scanning all bytes");
        restrict_allocation = false;
    } else if (restrict_allocation && !geometry.valid) {
        log::warn("carve: allocation-map geometry is unusable; treating every cluster as allocated");
    }

    uint64_t alignment = options.alignment;
    if (alignment == 0 && geometry.valid) alignment = geometry.cluster_size;
    if (alignment == 0) alignment = device.info().logical_sector_size;
    if (alignment == 0) alignment = 1;

    uint64_t pos = scan_start;
    if (!options.unaligned) {
        if (!align_up(scan_start, alignment, pos)) return std::vector<CarveHit>{};
    }
    const uint64_t step = options.unaligned ? 1 : alignment;

    const uint64_t total = scan_end > scan_start ? scan_end - scan_start : 1;
    if (progress && !progress(0, total)) return fail(ErrorCode::Cancelled, "carve cancelled");

    std::vector<CarveHit> hits;
    std::vector<uint8_t> window(
        static_cast<size_t>(std::min<uint64_t>(kWindowBytes + kOverlapBytes, scan_end - pos)));

    while (pos < scan_end) {
        const uint64_t window_base = pos;
        const uint64_t read_len =
            std::min<uint64_t>(kWindowBytes + kOverlapBytes, scan_end - window_base);
        window.resize(static_cast<size_t>(read_len));
        auto got = io::read_fully(device, window_base, window.data(), window.size());
        if (!got) return fail(got.error());
        if (*got != window.size())
            return fail(ErrorCode::IoError, "short read while scanning for carved files",
                        window_base + *got);

        const uint64_t window_scan_end = std::min<uint64_t>(window_base + kWindowBytes, scan_end);
        uint64_t p = window_base;
        while (p < window_scan_end) {
            const size_t rel = static_cast<size_t>(p - window_base);
            bool emitted = false;
            uint64_t emitted_scan_end = 0;

            for (const ISignature* signature : signatures) {
                const size_t magic_offset = signature->magic_offset();
                bool matches = false;
                for (const std::span<const uint8_t>& magic : signature->magics()) {
                    if (magic.empty()) continue;
                    if (magic.size() + magic_offset > window.size() - rel) continue;
                    const uint8_t* at = window.data() + rel + magic_offset;
                    if (at[0] != magic[0]) continue;
                    if (std::memcmp(at, magic.data(), magic.size()) != 0) continue;
                    matches = true;
                    break;
                }
                if (!matches) continue;

                if (restrict_allocation && geometry.is_allocated(*allocation, p)) continue;

                const uint64_t limit =
                    std::min<uint64_t>(signature->max_file_size(), scan_end - p);
                BoundedReader reader(device, p, limit);
                reader.set_deep_validate(options.deep_validate);
                const ValidationResult validation = signature->validate(reader);
                if (reader.error()) return fail(*reader.error());
                if (!validation.is_valid()) continue;
                if (validation.length_bytes == 0 || validation.length_bytes > reader.limit())
                    continue;
                if (!meets_confidence(validation.confidence, options.min_confidence)) continue;

                std::vector<CarveFragment> fragments;
                uint64_t logical_length = validation.length_bytes;
                uint64_t scan_resume = saturating_add(p, validation.length_bytes);

                // A truncated run may be the head of a file whose remainder resumes at an
                // allocation-unit boundary beyond the gap. The signature stays responsible for
                // recognising its own content, so the engine walks from cut to cut and keeps the
                // chain only when it reaches the format's terminator; a chain that never gets
                // there is discarded as junk and the head is reported on its own.
                if (options.reassemble &&
                    validation.verdict == ValidationResult::Verdict::ValidTruncated) {
                    std::vector<CarveFragment> pieces;
                    uint64_t chain_end = scan_resume;
                    uint64_t chain_length = logical_length;
                    uint64_t attempt_start = 0;
                    bool complete = false;
                    if (align_up(scan_resume, alignment, attempt_start)) {
                        for (size_t attempt = 0; attempt < kMaxReassemblyAttempts; ++attempt) {
                            if (attempt_start >= scan_end) break;
                            if (attempt_start - chain_end > options.max_reassembly_gap) break;
                            const uint64_t room = chain_length < signature->max_file_size()
                                                      ? signature->max_file_size() - chain_length
                                                      : 0;
                            const uint64_t reach = std::min(
                                {scan_end - attempt_start, room, options.max_reassembly_gap});
                            if (reach == 0) break;
                            BoundedReader tail_reader(device, attempt_start, reach);
                            tail_reader.set_deep_validate(options.deep_validate);
                            const auto tail = signature->find_continuation(tail_reader);
                            if (tail_reader.error()) return fail(*tail_reader.error());
                            if (!tail || tail->start > reach || tail->length > reach - tail->start)
                                break;
                            const uint64_t piece_start = attempt_start + tail->start;
                            const uint64_t piece_end = piece_start + tail->length;
                            if (restrict_allocation &&
                                geometry.overlaps_allocated(*allocation, piece_start, piece_end))
                                break;
                            if (tail->complete) {
                                if (tail->length == 0) break;
                                pieces.push_back({piece_start, tail->length});
                                chain_length += tail->length;
                                chain_end = piece_end;
                                complete = true;
                                break;
                            }
                            // A cut inside the first allocation unit holds no usable run: skip
                            // past it and look again from the next boundary.
                            if (tail->length >= alignment) {
                                if (pieces.size() + 2 > kMaxReassemblyPieces) break;
                                pieces.push_back({piece_start, tail->length});
                                chain_length += tail->length;
                                chain_end = piece_end;
                            }
                            uint64_t next = 0;
                            if (!align_up(piece_end, alignment, next) || next <= attempt_start)
                                break;
                            attempt_start = next;
                        }
                    }
                    if (complete && !pieces.empty()) {
                        fragments.push_back({p, validation.length_bytes});
                        fragments.insert(fragments.end(), pieces.begin(), pieces.end());
                        logical_length = chain_length;
                        scan_resume = chain_end;
                    }
                }

                const std::vector<CarveFragment> ranges =
                    fragments.empty() ? std::vector<CarveFragment>{{p, logical_length}}
                                      : fragments;
                auto digest = hash_fragments(device, ranges, logical_length);
                if (!digest) return fail(digest.error());

                CarveHit hit;
                hit.offset = p;
                hit.length = logical_length;
                hit.type = std::string(signature->name());
                hit.subtype = validation.subtype;
                hit.confidence = validation.confidence;
                // A chain that reached its terminator is the whole file: the head alone was
                // truncated, the reassembled bytes are not.
                if (validation.verdict == ValidationResult::Verdict::ValidTruncated &&
                    fragments.empty())
                    hit.flags |= file_flags::Truncated;
                if (!fragments.empty()) {
                    hit.fragments = std::move(fragments);
                    hit.flags |= file_flags::Fragmented;
                }

                hit.sha256 = std::move(*digest);
                hits.push_back(std::move(hit));
                emitted = true;
                emitted_scan_end = scan_resume;
                break;
            }

            uint64_t next = p + step;
            if (emitted && !options.nested) {
                uint64_t skip = 0;
                if (align_up(emitted_scan_end, alignment, skip) && skip > next)
                    next = skip;
            }
            p = next;
        }

        if (progress && !progress(std::min<uint64_t>(p, scan_end) - scan_start, total))
            return fail(ErrorCode::Cancelled, "carve cancelled");
        pos = p > window_base ? p : window_scan_end;
    }

    if (!options.nested) resolve_overlaps(hits);
    std::sort(hits.begin(), hits.end(), [](const CarveHit& a, const CarveHit& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.length > b.length;
    });
    mark_duplicates(hits, options.existing_files);

    if (progress && !progress(scan_end - scan_start, total))
        return fail(ErrorCode::Cancelled, "carve cancelled");
    return hits;
}

Result<std::vector<io::WrittenFile>> export_hits(io::OutputSink& sink, io::BlockDevice& device,
                                                 const std::vector<CarveHit>& hits,
                                                 bool skip_duplicates) {
    std::vector<io::WrittenFile> written;
    for (const CarveHit& hit : hits) {
        if (skip_duplicates && !hit.duplicate_of.empty()) continue;

        const char* extension = extension_for(hit.type, hit.subtype, SignatureRegistry::builtins());
        std::string ext = extension ? extension : hit.subtype;
        char offset_text[17]{};
        std::snprintf(offset_text, sizeof offset_text, "%016llx",
                      static_cast<unsigned long long>(hit.offset));
        const std::string relative = "carved/" + hit.type + "/" + offset_text + "_" +
                                     std::to_string(hit.length) + "." + ext;

        DeviceRangesSource source(device, ranges_of(hit));
        auto file = sink.write_file(relative, source);
        if (!file) return fail(file.error());
        written.push_back(std::move(*file));
    }
    return written;
}

}  // namespace openrecover::carve
