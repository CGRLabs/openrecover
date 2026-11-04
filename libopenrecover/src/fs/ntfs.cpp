#include "openrecover/fs/ntfs.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/fs/lznt1.hpp"
#include "openrecover/fs/ntfs_recyclebin.hpp"

namespace openrecover::fs {

namespace {

constexpr uint64_t kMaxMetadataAttributeBytes = 16ull << 20;
constexpr size_t kBitmapWindowBytes = 64 * 1024;
constexpr size_t kMaxAttributeListExtensions = 64;
// A compressed file is expanded while its record is being examined, so the library holds the
// result in memory. Anything past this size is reported as unsupported rather than buffered.
constexpr uint64_t kMaxCompressedDataBytes = 256ull << 20;
// One compression unit is the granule the decoder expands, so a unit larger than this cannot be
// decoded without unbounded buffering. Windows writes 16 clusters, which is far below it.
constexpr uint64_t kMaxCompressedUnitBytes = 1ull << 20;

Result<std::vector<uint8_t>> read_bytes(io::BlockDevice& dev, uint64_t offset, size_t len,
                                        std::string_view what) {
    std::vector<uint8_t> buffer(len);
    auto got = io::read_fully(dev, offset, buffer.data(), buffer.size());
    if (!got) return fail(got.error());
    if (*got != buffer.size())
        return fail(ErrorCode::CorruptStructure, "short read while reading " + std::string(what));
    return buffer;
}

const NtfsAttribute* find_attribute(const NtfsRecord& record, uint32_t type,
                                    bool unnamed_only = false) {
    for (const auto& attr : record.attributes) {
        if (attr.type != type) continue;
        if (unnamed_only && !attr.name.empty()) continue;
        return &attr;
    }
    return nullptr;
}

Result<std::vector<DataRun>> decode_attribute_runs(const NtfsBoot& boot,
                                                   const NtfsAttribute& attr) {
    if (!attr.non_resident)
        return fail(ErrorCode::CorruptStructure, "expected a non-resident NTFS attribute");
    return decode_runlist(attr.runlist, attr.start_vcn, boot.total_clusters);
}

Result<std::vector<uint8_t>> read_attribute_fully(io::BlockDevice& dev, const NtfsBoot& boot,
                                                  const NtfsAttribute& attr,
                                                  uint64_t max_bytes) {
    if (!attr.non_resident) return attr.resident_data;
    if (attr.compressed() || attr.encrypted())
        return fail(ErrorCode::Unsupported, "compressed or encrypted NTFS metadata");
    if (attr.real_size > max_bytes)
        return fail(ErrorCode::CorruptStructure, "NTFS metadata attribute is too large");
    if (attr.start_vcn != 0)
        return fail(ErrorCode::CorruptStructure, "NTFS metadata attribute does not start at VCN 0");

    auto runs = decode_attribute_runs(boot, attr);
    if (!runs) return fail(runs.error());

    std::vector<uint8_t> data(static_cast<size_t>(attr.real_size), 0);
    size_t done = 0;
    uint64_t expected_vcn = 0;
    for (const DataRun& run : *runs) {
        if (run.vcn != expected_vcn)
            return fail(ErrorCode::CorruptStructure, "NTFS metadata runlist has a VCN gap");
        uint64_t run_bytes = 0;
        if (!checked_mul<uint64_t>(run.length_clusters, boot.bytes_per_cluster, run_bytes))
            return fail(ErrorCode::CorruptStructure, "NTFS metadata run length overflows");
        const size_t take = static_cast<size_t>(
            std::min<uint64_t>(run_bytes, data.size() - done));
        if (take != 0) {
            if (run.is_sparse()) {
                std::memset(data.data() + done, 0, take);
            } else {
                const uint64_t offset = static_cast<uint64_t>(run.lcn) * boot.bytes_per_cluster;
                auto got = io::read_fully(dev, offset, data.data() + done, take);
                if (!got) return fail(got.error());
                if (*got != take)
                    return fail(ErrorCode::CorruptStructure,
                                "short read while reading NTFS metadata");
            }
            done += take;
        }
        if (!checked_add<uint64_t>(expected_vcn, run.length_clusters, expected_vcn))
            return fail(ErrorCode::CorruptStructure, "NTFS metadata VCN overflows");
        if (done == data.size()) break;
    }
    if (done != data.size())
        return fail(ErrorCode::CorruptStructure, "NTFS metadata runlist is truncated");
    return data;
}

std::string lowercase_ascii(std::string text) {
    for (char& ch : text) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return text;
}

std::string type_hint_for_name(const std::string& name) {
    const size_t dot = name.rfind('.');
    if (dot == std::string::npos || dot + 1 == name.size()) return {};
    const std::string ext = lowercase_ascii(name.substr(dot + 1));
    if (ext == "jpg" || ext == "jpeg") return "jpeg";
    if (ext == "png") return "png";
    if (ext == "pdf") return "pdf";
    if (ext == "zip" || ext == "docx" || ext == "xlsx" || ext == "pptx" || ext == "apk" ||
        ext == "jar")
        return "zip";
    return {};
}

bool magic_matches(const std::string& hint, const uint8_t* data) {
    if (hint == "jpeg") {
        return data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF &&
               (data[3] == 0xE0 || data[3] == 0xE1 || data[3] == 0xE2 || data[3] == 0xE8 ||
                data[3] == 0xDB || data[3] == 0xC0 || data[3] == 0xC2 || data[3] == 0xEE ||
                data[3] == 0xFE);
    }
    if (hint == "png") {
        static constexpr std::array<uint8_t, 8> kPng = {0x89, 0x50, 0x4E, 0x47,
                                                       0x0D, 0x0A, 0x1A, 0x0A};
        return std::memcmp(data, kPng.data(), kPng.size()) == 0;
    }
    if (hint == "pdf") {
        return data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F' &&
               data[4] == '-' &&
               ((data[5] == '1' && data[6] == '.' && data[7] >= '0' && data[7] <= '7') ||
                (data[5] == '2' && data[6] == '.' && data[7] == '0'));
    }
    if (hint == "zip") {
        return data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04;
    }
    return true;
}

struct GatheredFileAttributes {
    std::vector<NtfsFileName> names;
    std::vector<NtfsAttribute> data;
    std::optional<NtfsStandardInformation> standard;
};

Result<GatheredFileAttributes> gather_file_attributes(io::BlockDevice& dev, const NtfsBoot& boot,
                                                      const NtfsRecord& base,
                                                      NtfsMftReader& mft) {
    GatheredFileAttributes out;
    std::vector<NtfsAttribute> base_names;
    std::vector<NtfsAttribute> base_data;
    const NtfsAttribute* list_attr = nullptr;

    for (const auto& attr : base.attributes) {
        if (attr.type == kNtfsAttrStandardInformation && !attr.non_resident && !out.standard) {
            auto info = parse_standard_information(attr.resident_data);
            if (info) out.standard = *info;
        } else if (attr.type == kNtfsAttrFileName && !attr.non_resident) {
            base_names.push_back(attr);
        } else if (attr.type == kNtfsAttrData && attr.name.empty()) {
            base_data.push_back(attr);
        } else if (attr.type == kNtfsAttrAttributeList && !list_attr) {
            list_attr = &attr;
        }
    }

    std::vector<NtfsAttribute> listed_names;
    std::vector<NtfsAttribute> listed_data;

    if (list_attr) {
        std::optional<std::vector<uint8_t>> list_bytes;
        if (!list_attr->non_resident) {
            list_bytes = list_attr->resident_data;
        } else {
            auto bytes = read_attribute_fully(dev, boot, *list_attr, kMaxMetadataAttributeBytes);
            if (bytes) {
                list_bytes = std::move(*bytes);
            } else if (bytes.error().code == ErrorCode::IoError) {
                return fail(bytes.error());
            }
        }

        if (list_bytes) {
            auto entries = parse_attribute_list(*list_bytes);
            if (entries) {
                std::set<std::tuple<uint64_t, uint16_t, uint64_t>> seen;
                std::vector<std::optional<NtfsRecord>> extensions;
                std::unordered_map<uint64_t, size_t> extension_index;

                for (const NtfsAttributeListEntry& entry : *entries) {
                    if (entry.type != kNtfsAttrFileName && entry.type != kNtfsAttrData) continue;

                    const uint64_t source_number = entry.mft_record();
                    const NtfsRecord* source = &base;
                    if (source_number != base.record_number) {
                        auto it = extension_index.find(source_number);
                        if (it == extension_index.end()) {
                            if (extensions.size() >= kMaxAttributeListExtensions) continue;
                            auto loaded = mft.load_record(source_number);
                            if (!loaded) return fail(loaded.error());
                            std::optional<NtfsRecord> stored;
                            if (*loaded &&
                                ntfs_record_index((*loaded)->base_record_ref) ==
                                    base.record_number) {
                                stored = std::move(**loaded);
                            }
                            extension_index.emplace(source_number, extensions.size());
                            extensions.push_back(std::move(stored));
                            it = extension_index.find(source_number);
                        }
                        if (it == extension_index.end() || !extensions[it->second]) continue;
                        source = &*extensions[it->second];
                    }

                    for (const auto& attr : source->attributes) {
                        if (attr.type != entry.type || attr.attr_id != entry.attr_id ||
                            attr.name != entry.name)
                            continue;
                        if (entry.type == kNtfsAttrData && attr.start_vcn != entry.start_vcn)
                            continue;
                        const auto key = std::make_tuple(source_number, attr.attr_id,
                                                         attr.start_vcn);
                        if (!seen.insert(key).second) continue;
                        if (entry.type == kNtfsAttrFileName) {
                            if (!attr.non_resident) listed_names.push_back(attr);
                        } else if (attr.name.empty()) {
                            listed_data.push_back(attr);
                        }
                    }
                }
            }
        }
    }

    const std::vector<NtfsAttribute>& name_attrs =
        listed_names.empty() ? base_names : listed_names;
    const std::vector<NtfsAttribute>& data_attrs =
        listed_data.empty() ? base_data : listed_data;

    for (const auto& attr : name_attrs) {
        auto name = parse_file_name(attr.resident_data);
        if (name) out.names.push_back(std::move(*name));
    }
    out.data = data_attrs;
    return out;
}

struct AssembledData {
    bool unsupported = false;
    bool truncated = false;
    std::string reason;
    std::optional<std::vector<uint8_t>> resident;
    std::vector<Extent> extents;
    // The clusters a compressed file was stored in. They are not reported as extents because the
    // content has already been expanded, but they still say whether the data was overwritten.
    std::vector<Extent> stored;
    uint64_t size = 0;
};

std::vector<Extent> clip_extents(const std::vector<Extent>& input, uint64_t logical_size,
                                 bool& truncated) {
    std::vector<Extent> out;
    uint64_t remaining = logical_size;
    for (const Extent& extent : input) {
        if (remaining == 0) break;
        const uint64_t take = std::min<uint64_t>(extent.length_bytes, remaining);
        out.push_back(Extent{extent.offset_bytes, take, extent.sparse});
        remaining -= take;
    }
    if (remaining != 0) truncated = true;
    return out;
}

std::vector<Extent> zero_initialized_tail(const std::vector<Extent>& input,
                                          uint64_t initialized_bytes) {
    std::vector<Extent> out;
    uint64_t position = 0;
    for (const Extent& extent : input) {
        const uint64_t end = position + extent.length_bytes;
        if (position >= initialized_bytes) {
            out.push_back(Extent{0, extent.length_bytes, true});
        } else if (end <= initialized_bytes) {
            out.push_back(extent);
        } else {
            const uint64_t actual = initialized_bytes - position;
            out.push_back(Extent{extent.sparse ? 0 : extent.offset_bytes, actual, extent.sparse});
            out.push_back(Extent{0, end - initialized_bytes, true});
        }
        position = end;
    }
    return out;
}

std::optional<AssembledData> unsupported_data(std::string reason,
                                              const std::vector<NtfsAttribute>& attributes) {
    AssembledData out;
    out.unsupported = true;
    out.reason = std::move(reason);
    const auto base = std::find_if(attributes.begin(), attributes.end(),
                                   [](const NtfsAttribute& a) { return a.start_vcn == 0; });
    const NtfsAttribute& source = base != attributes.end() ? *base : attributes.front();
    out.size = source.non_resident ? source.real_size : source.resident_data.size();
    return out;
}

// A compression unit is the block of LZNT1 chunks Windows writes and reads as one piece. Its
// width in clusters comes from the attribute's log2 field, and it has to be small enough to
// buffer, because the whole unit is what the decoder expands.
Result<uint64_t> unit_cluster_count(const NtfsAttribute& attr, uint32_t bytes_per_cluster) {
    const uint16_t bits = attr.compression_unit;
    if (bits == 0 || bits > 16)
        return fail(ErrorCode::Unsupported, "NTFS compression unit field holds " + std::to_string(bits));
    const uint64_t clusters = uint64_t{1} << bits;
    uint64_t unit_bytes = 0;
    if (!checked_mul<uint64_t>(clusters, bytes_per_cluster, unit_bytes) ||
        unit_bytes > kMaxCompressedUnitBytes)
        return fail(ErrorCode::Unsupported, "NTFS compression unit is too large to buffer");
    return clusters;
}

struct CompressedExtraction {
    bool usable = false;
    std::string reason;
    std::vector<uint8_t> data;
    std::vector<Extent> stored;
};

// Expands a compressed $DATA. A compressed attribute counts VCNs in the uncompressed space, so
// the clusters its compressed form did not need show up as a sparse run after each unit: a unit
// with all of its clusters allocated was stored verbatim, a unit that is one sparse run is all
// zeros, and anything in between is a stream of LZNT1 chunks.
CompressedExtraction extract_compressed_data(io::BlockDevice& dev, const NtfsBoot& boot,
                                             const std::vector<const NtfsAttribute*>& fragments,
                                             const std::vector<DataRun>& runs) {
    CompressedExtraction result;
    const NtfsAttribute& base = *fragments.front();
    const uint64_t size = base.real_size;
    if (size > kMaxCompressedDataBytes) {
        result.reason = "ntfs_compressed_too_large";
        return result;
    }
    auto clusters = unit_cluster_count(base, boot.bytes_per_cluster);
    if (!clusters) {
        result.reason = "ntfs_compressed_unsupported: " + clusters.error().message;
        return result;
    }
    for (const NtfsAttribute* attr : fragments) {
        if (attr->compression_unit != base.compression_unit) {
            result.reason = "ntfs_compressed_unsupported: the fragments disagree about the unit size";
            return result;
        }
    }

    const uint64_t unit_clusters = *clusters;
    const uint64_t unit_bytes = unit_clusters * boot.bytes_per_cluster;
    const uint64_t cluster_count =
        (size + boot.bytes_per_cluster - 1) / boot.bytes_per_cluster;

    result.data.assign(static_cast<size_t>(std::min<uint64_t>(size, cluster_count * boot.bytes_per_cluster)),
                       0);
    std::vector<uint8_t> stored(static_cast<size_t>(unit_bytes), 0);

    size_t cursor = 0;
    for (uint64_t unit_vcn = 0; unit_vcn < cluster_count; unit_vcn += unit_clusters) {
        while (cursor + 1 < runs.size() &&
               runs[cursor].vcn + runs[cursor].length_clusters <= unit_vcn)
            ++cursor;
        if (cursor >= runs.size() || runs[cursor].vcn > unit_vcn || runs[cursor].is_sparse())
            continue;  // nothing stored for this unit

        std::fill(stored.begin(), stored.end(), uint8_t{0});
        uint64_t covered = 0;
        uint64_t vcn = unit_vcn;
        for (size_t index = cursor; index < runs.size() && covered < unit_clusters; ++index) {
            const DataRun& run = runs[index];
            if (run.vcn + run.length_clusters <= vcn) continue;
            // A sparse run or a gap ends the unit's stored data: nothing past it belongs to the
            // unit, so only what precedes it can be fed to the decoder.
            if (run.is_sparse() || run.vcn > vcn) break;
            const uint64_t within = vcn - run.vcn;
            const uint64_t take =
                std::min<uint64_t>(run.length_clusters - within, unit_clusters - covered);
            uint64_t physical = 0;
            uint64_t into = 0;
            uint64_t bytes = 0;
            if (!checked_mul<uint64_t>(static_cast<uint64_t>(run.lcn) + within, boot.bytes_per_cluster,
                                       physical) ||
                !checked_mul<uint64_t>(covered, boot.bytes_per_cluster, into) ||
                !checked_mul<uint64_t>(take, boot.bytes_per_cluster, bytes)) {
                result.reason = "ntfs_compressed_corrupt: the unit run overflows";
                return result;
            }
            auto got = io::read_fully(dev, physical, stored.data() + into, static_cast<size_t>(bytes));
            if (!got || *got != bytes) {
                result.reason = "ntfs_compressed_corrupt: the stored clusters could not be read";
                return result;
            }
            covered += take;
            vcn += take;
            result.stored.push_back(Extent{physical, bytes, false});
        }

        const uint64_t unit_start = unit_vcn * boot.bytes_per_cluster;
        const uint64_t slice = std::min<uint64_t>(unit_bytes, result.data.size() - unit_start);
        uint8_t* target = result.data.data() + static_cast<std::ptrdiff_t>(unit_start);
        if (covered == unit_clusters) {
            // A unit that occupies all of its clusters was stored verbatim: no chunk headers,
            // nothing to decode.
            std::copy_n(stored.begin(), static_cast<std::ptrdiff_t>(slice), target);
        } else {
            // The decoder stages each chunk on its own, so the unit expands straight into the file
            // image and a short tail unit just stops where the image stops.
            std::fill_n(target, static_cast<std::ptrdiff_t>(slice), uint8_t{0});
            auto produced = decompress_lznt1(
                std::span<const uint8_t>(stored.data(),
                                         static_cast<size_t>(covered * boot.bytes_per_cluster)),
                std::span<uint8_t>(target, static_cast<size_t>(slice)));
            if (!produced) {
                result.reason = "ntfs_compressed_corrupt: " + produced.error().message;
                return result;
            }
        }
    }

    const uint64_t initialized = std::min<uint64_t>(base.initialized_size, size);
    std::fill(result.data.begin() + static_cast<std::ptrdiff_t>(initialized), result.data.end(),
              uint8_t{0});
    result.data.resize(static_cast<size_t>(size));
    result.usable = true;
    return result;
}

std::optional<AssembledData> assemble_data(io::BlockDevice& dev, const NtfsBoot& boot,
                                           const std::vector<NtfsAttribute>& attributes) {
    AssembledData out;
    if (attributes.empty()) return std::nullopt;

    bool compressed = false;
    for (const auto& attr : attributes) {
        if (attr.encrypted()) return unsupported_data("ntfs_encrypted", attributes);
        if (attr.compressed()) compressed = true;
    }

    std::vector<const NtfsAttribute*> non_resident;
    std::vector<const NtfsAttribute*> resident;
    for (const auto& attr : attributes) {
        (attr.non_resident ? non_resident : resident).push_back(&attr);
    }

    if (compressed) {
        if (!resident.empty())
            return unsupported_data("ntfs_compressed_unsupported: a resident attribute cannot be "
                                    "compressed",
                                    attributes);
        std::vector<const NtfsAttribute*> fragments = non_resident;
        std::sort(fragments.begin(), fragments.end(),
                  [](const NtfsAttribute* a, const NtfsAttribute* b) {
                      return a->start_vcn < b->start_vcn;
                  });
        if (fragments.empty() || fragments.front()->start_vcn != 0)
            return unsupported_data("ntfs_compressed_unsupported: the fragments do not start at VCN 0",
                                    attributes);

        std::vector<DataRun> runs;
        for (const NtfsAttribute* attr : fragments) {
            auto decoded = decode_attribute_runs(boot, *attr);
            if (!decoded)
                return unsupported_data("ntfs_compressed_corrupt: the runlist could not be decoded",
                                        attributes);
            runs.insert(runs.end(), decoded->begin(), decoded->end());
        }
        std::sort(runs.begin(), runs.end(),
                  [](const DataRun& a, const DataRun& b) { return a.vcn < b.vcn; });

        auto extracted = extract_compressed_data(dev, boot, fragments, runs);
        if (!extracted.usable) return unsupported_data(std::move(extracted.reason), attributes);
        out.resident = std::move(extracted.data);
        out.stored = std::move(extracted.stored);
        out.size = fragments.front()->real_size;
        return out;
    }

    if (!resident.empty()) {
        if (resident.size() != 1 || !non_resident.empty()) return std::nullopt;
        out.resident = resident.front()->resident_data;
        out.size = out.resident->size();
        return out;
    }

    if (non_resident.empty()) return std::nullopt;

    std::vector<const NtfsAttribute*> ordered = non_resident;
    std::sort(ordered.begin(), ordered.end(), [](const NtfsAttribute* a, const NtfsAttribute* b) {
        return a->start_vcn < b->start_vcn;
    });
    if (ordered.front()->start_vcn != 0) return std::nullopt;

    const NtfsAttribute& base = *ordered.front();
    out.size = base.real_size;
    const uint64_t initialized = std::min<uint64_t>(base.initialized_size, out.size);

    std::vector<DataRun> runs;
    for (const NtfsAttribute* attr : ordered) {
        auto decoded = decode_attribute_runs(boot, *attr);
        if (!decoded) return std::nullopt;
        runs.insert(runs.end(), decoded->begin(), decoded->end());
    }
    std::sort(runs.begin(), runs.end(), [](const DataRun& a, const DataRun& b) {
        return a.vcn < b.vcn;
    });

    std::vector<Extent> logical_extents;
    uint64_t logical_bytes = 0;
    for (const DataRun& run : runs) {
        uint64_t run_start = 0;
        uint64_t run_bytes = 0;
        if (!checked_mul<uint64_t>(run.vcn, boot.bytes_per_cluster, run_start) ||
            !checked_mul<uint64_t>(run.length_clusters, boot.bytes_per_cluster, run_bytes))
            return std::nullopt;
        if (run_start < logical_bytes) return std::nullopt;
        if (run_start > logical_bytes)
            logical_extents.push_back(Extent{0, run_start - logical_bytes, true});
        if (run.is_sparse()) {
            logical_extents.push_back(Extent{0, run_bytes, true});
        } else {
            uint64_t offset = 0;
            if (!checked_mul<uint64_t>(static_cast<uint64_t>(run.lcn), boot.bytes_per_cluster,
                                       offset))
                return std::nullopt;
            logical_extents.push_back(Extent{offset, run_bytes, false});
        }
        uint64_t run_end = 0;
        if (!checked_add<uint64_t>(run_start, run_bytes, run_end)) return std::nullopt;
        logical_bytes = run_end;
        if (logical_bytes >= out.size) break;
    }

    bool truncated = false;
    std::vector<Extent> clipped = clip_extents(logical_extents, out.size, truncated);
    out.truncated = truncated || logical_bytes < out.size;
    out.extents = zero_initialized_tail(clipped, initialized);
    return out;
}

bool extents_reused(const std::vector<Extent>& extents, const IAllocationMap& map,
                    uint32_t bytes_per_cluster) {
    for (const Extent& extent : extents) {
        if (extent.sparse || extent.length_bytes == 0) continue;
        const uint64_t first = extent.offset_bytes / bytes_per_cluster;
        uint64_t last = 0;
        if (!checked_add<uint64_t>(extent.offset_bytes, extent.length_bytes, last))
            return true;
        last = (last + bytes_per_cluster - 1) / bytes_per_cluster;
        for (uint64_t cluster = first; cluster < last; ++cluster) {
            if (map.is_cluster_allocated(cluster)) return true;
        }
    }
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// NtfsMftReader
// ---------------------------------------------------------------------------

NtfsMftReader::NtfsMftReader(std::shared_ptr<io::BlockDevice> dev, NtfsBoot boot,
                             std::vector<DataRun> runs, uint64_t coverage_bytes,
                             uint64_t record_count)
    : dev_(std::move(dev)),
      boot_(boot),
      runs_(std::move(runs)),
      coverage_bytes_(coverage_bytes),
      record_count_(record_count),
      record_size_(boot.record_size) {}

Result<std::unique_ptr<NtfsMftReader>> NtfsMftReader::open(
    std::shared_ptr<io::BlockDevice> dev, const NtfsBoot& boot) {
    if (!dev) return fail(ErrorCode::InvalidArgument, "null device");

    auto load_zero = [&](uint64_t offset) -> Result<std::optional<NtfsRecord>> {
        auto raw = read_bytes(*dev, offset, boot.record_size, "$MFT record 0");
        if (!raw) return fail(raw.error());
        auto parsed = parse_mft_record(*raw, 0);
        if (!parsed) return fail(parsed.error());
        if (parsed->kind != NtfsRecordKind::File) return std::optional<NtfsRecord>{};
        return std::optional<NtfsRecord>{std::move(parsed->record)};
    };

    std::optional<NtfsRecord> mft_record;
    std::string primary_error;
    auto primary = load_zero(boot.mft_byte_offset());
    if (primary) {
        mft_record = std::move(*primary);
    } else {
        primary_error = primary.error().message;
    }

    if (!mft_record) {
        auto mirror = load_zero(boot.mft_mirror_byte_offset());
        if (mirror) {
            mft_record = std::move(*mirror);
        } else if (!primary_error.empty()) {
            return fail(ErrorCode::CorruptStructure,
                        "cannot read $MFT record 0: " + primary_error +
                            "; mirror: " + mirror.error().message);
        } else {
            return fail(ErrorCode::CorruptStructure,
                        "cannot read $MFT record 0 from the mirror: " + mirror.error().message);
        }
    }
    if (!mft_record)
        return fail(ErrorCode::CorruptStructure, "$MFT record 0 is unused or corrupt");

    const NtfsAttribute* data = find_attribute(*mft_record, kNtfsAttrData, true);
    if (!data || !data->non_resident)
        return fail(ErrorCode::CorruptStructure, "$MFT has no unnamed non-resident $DATA");
    if (data->compressed() || data->encrypted())
        return fail(ErrorCode::CorruptStructure, "$MFT is compressed or encrypted");
    if (data->start_vcn != 0)
        return fail(ErrorCode::CorruptStructure, "$MFT $DATA does not start at VCN 0");
    if (data->real_size == 0)
        return fail(ErrorCode::CorruptStructure, "$MFT is empty");

    auto runs = decode_attribute_runs(boot, *data);
    if (!runs) return fail(runs.error());
    if (runs->empty()) return fail(ErrorCode::CorruptStructure, "$MFT runlist is empty");

    uint64_t coverage = 0;
    uint64_t expected_vcn = 0;
    for (const DataRun& run : *runs) {
        if (run.vcn != expected_vcn)
            return fail(ErrorCode::CorruptStructure, "$MFT runlist has a VCN gap");
        if (run.is_sparse())
            return fail(ErrorCode::CorruptStructure, "$MFT runlist is sparse");
        uint64_t run_bytes = 0;
        if (!checked_mul<uint64_t>(run.length_clusters, boot.bytes_per_cluster, run_bytes))
            return fail(ErrorCode::CorruptStructure, "$MFT run length overflows");
        uint64_t next = 0;
        if (!checked_add<uint64_t>(coverage, run_bytes, next))
            return fail(ErrorCode::CorruptStructure, "$MFT size overflows");
        coverage = next;
        expected_vcn = run.vcn + run.length_clusters;
    }
    if (coverage < data->real_size)
        return fail(ErrorCode::CorruptStructure, "$MFT runlist is shorter than its real size");

    const uint64_t record_count = data->real_size / boot.record_size;
    if (record_count == 0)
        return fail(ErrorCode::CorruptStructure, "$MFT has no records");

    return std::unique_ptr<NtfsMftReader>(
        new NtfsMftReader(std::move(dev), boot, std::move(*runs), coverage, record_count));
}

Result<size_t> NtfsMftReader::read_logical(uint64_t offset, uint8_t* dst, size_t len) {
    if (offset >= coverage_bytes_) return size_t{0};

    size_t done = 0;
    uint64_t run_start = 0;
    for (const DataRun& run : runs_) {
        uint64_t run_bytes = 0;
        if (!checked_mul<uint64_t>(run.length_clusters, boot_.bytes_per_cluster, run_bytes))
            return fail(ErrorCode::CorruptStructure, "invalid $MFT run length");
        uint64_t run_end = 0;
        if (!checked_add<uint64_t>(run_start, run_bytes, run_end))
            return fail(ErrorCode::CorruptStructure, "invalid $MFT run range");
        if (offset >= run_start && offset < run_end) {
            const uint64_t within = offset - run_start;
            const size_t take =
                static_cast<size_t>(std::min<uint64_t>(len - done, run_bytes - within));
            const uint64_t physical =
                static_cast<uint64_t>(run.lcn) * boot_.bytes_per_cluster + within;
            auto got = io::read_fully(*dev_, physical, dst + done, take);
            if (!got) return fail(got.error());
            done += *got;
            offset += *got;
            if (done == len) return done;
            if (*got != take)
                return fail(ErrorCode::CorruptStructure, "short read while reading the $MFT");
        }
        run_start = run_end;
    }
    return done;
}

Result<std::optional<NtfsRecord>> NtfsMftReader::load_record(uint64_t record_number) {
    if (record_number >= record_count_) return std::optional<NtfsRecord>{};
    uint64_t offset = 0;
    if (!checked_mul<uint64_t>(record_number, record_size_, offset))
        return std::optional<NtfsRecord>{};

    std::vector<uint8_t> raw(record_size_);
    auto got = read_logical(offset, raw.data(), raw.size());
    if (!got) return fail(got.error());
    if (*got != raw.size())
        return fail(ErrorCode::CorruptStructure, "$MFT record lies outside the runlist");

    auto parsed = parse_mft_record(raw, record_number);
    if (!parsed) return std::optional<NtfsRecord>{};
    if (parsed->kind != NtfsRecordKind::File) return std::optional<NtfsRecord>{};
    return std::optional<NtfsRecord>{std::move(parsed->record)};
}

// ---------------------------------------------------------------------------
// NtfsAllocationMap
// ---------------------------------------------------------------------------

NtfsAllocationMap::NtfsAllocationMap(std::shared_ptr<io::BlockDevice> dev, NtfsBoot boot) noexcept
    : dev_(std::move(dev)), boot_(boot) {}

Result<std::unique_ptr<NtfsAllocationMap>> NtfsAllocationMap::open(
    std::shared_ptr<io::BlockDevice> dev, const NtfsBoot& boot, NtfsMftReader& mft) {
    auto record = mft.load_record(6);
    if (!record) return fail(record.error());
    if (!*record)
        return fail(ErrorCode::CorruptStructure, "the $Bitmap MFT record is missing or corrupt");

    const NtfsAttribute* data = find_attribute(**record, kNtfsAttrData, true);
    if (!data)
        return fail(ErrorCode::CorruptStructure, "$Bitmap has no unnamed $DATA");

    auto map = std::unique_ptr<NtfsAllocationMap>(new NtfsAllocationMap(std::move(dev), boot));
    if (!data->non_resident) {
        map->resident_ = data->resident_data;
        map->bitmap_size_ = map->resident_.size();
        return map;
    }

    if (data->compressed() || data->encrypted())
        return fail(ErrorCode::Unsupported, "$Bitmap is compressed or encrypted");
    if (data->start_vcn != 0)
        return fail(ErrorCode::CorruptStructure, "$Bitmap $DATA does not start at VCN 0");

    auto runs = decode_attribute_runs(boot, *data);
    if (!runs) return fail(runs.error());
    uint64_t expected_vcn = 0;
    for (const DataRun& run : *runs) {
        if (run.vcn != expected_vcn || run.is_sparse())
            return fail(ErrorCode::CorruptStructure, "invalid $Bitmap runlist");
        expected_vcn = run.vcn + run.length_clusters;
    }
    map->runs_ = std::move(*runs);
    map->bitmap_size_ = data->real_size;
    return map;
}

Result<size_t> NtfsAllocationMap::read_bitmap(uint64_t offset, uint8_t* dst, size_t len) const {
    if (offset >= bitmap_size_) return size_t{0};
    size_t done = 0;
    uint64_t run_start = 0;
    for (const DataRun& run : runs_) {
        const uint64_t run_bytes = run.length_clusters * boot_.bytes_per_cluster;
        const uint64_t run_end = run_start + run_bytes;
        if (offset >= run_start && offset < run_end) {
            const uint64_t within = offset - run_start;
            const size_t take =
                static_cast<size_t>(std::min<uint64_t>(len - done, run_bytes - within));
            const uint64_t physical =
                static_cast<uint64_t>(run.lcn) * boot_.bytes_per_cluster + within;
            auto got = io::read_fully(*dev_, physical, dst + done, take);
            if (!got) return fail(got.error());
            done += *got;
            offset += *got;
            if (done == len) return done;
            if (*got != take)
                return fail(ErrorCode::CorruptStructure, "short read while reading $Bitmap");
        }
        run_start = run_end;
    }
    return done;
}

Result<uint8_t> NtfsAllocationMap::bitmap_byte(uint64_t index) const {
    if (index >= bitmap_size_)
        return fail(ErrorCode::CorruptStructure, "cluster lies beyond the $Bitmap");
    if (!resident_.empty()) return resident_[static_cast<size_t>(index)];

    if (index >= window_start_ && index < window_start_ + window_size_)
        return window_[static_cast<size_t>(index - window_start_)];

    const uint64_t start = index & ~(static_cast<uint64_t>(kBitmapWindowBytes) - 1);
    const size_t want =
        static_cast<size_t>(std::min<uint64_t>(kBitmapWindowBytes, bitmap_size_ - start));
    window_.assign(want, 0);
    auto got = read_bitmap(start, window_.data(), want);
    if (!got) {
        window_size_ = 0;
        return fail(got.error());
    }
    if (*got != want) {
        window_size_ = 0;
        return fail(ErrorCode::CorruptStructure, "short read while reading $Bitmap");
    }
    window_start_ = start;
    window_size_ = want;
    return window_[static_cast<size_t>(index - start)];
}

bool NtfsAllocationMap::is_cluster_allocated(uint64_t cluster) const {
    if (cluster >= boot_.total_clusters) return true;
    const uint64_t index = cluster >> 3;
    if (index >= bitmap_size_) return true;
    auto byte = bitmap_byte(index);
    if (!byte) return true;
    return ((*byte >> (cluster & 7)) & 1u) != 0;
}

uint64_t NtfsAllocationMap::cluster_to_byte_offset(uint64_t cluster) const {
    return cluster * boot_.bytes_per_cluster;
}

// ---------------------------------------------------------------------------
// NtfsPathResolver
// ---------------------------------------------------------------------------

Result<NtfsResolvedPath> NtfsPathResolver::resolve(uint64_t record_number) {
    auto cached = cache_.find(record_number);
    if (cached != cache_.end()) {
        lru_.splice(lru_.end(), lru_, cached->second.lru);
        cached->second.lru = std::prev(lru_.end());
        return cached->second.path;
    }

    std::vector<std::string> parts;
    bool uncertain = false;
    uint64_t current = record_number;
    int depth = 0;
    std::unordered_set<uint64_t> visited;

    while (current != 5) {
        ++depth;
        if (depth > 255 || !visited.insert(current).second) {
            uncertain = true;
            break;
        }

        auto loaded = mft_.load_record(current);
        if (!loaded) return fail(loaded.error());
        if (!*loaded) {
            uncertain = true;
            parts.push_back("_MFT" + std::to_string(current));
            break;
        }

        std::vector<NtfsFileName> names;
        for (const auto& attr : (*loaded)->attributes) {
            if (attr.type != kNtfsAttrFileName || attr.non_resident) continue;
            auto name = parse_file_name(attr.resident_data);
            if (name) names.push_back(std::move(*name));
        }
        const NtfsFileName* chosen = best_file_name(names);
        if (!chosen) {
            uncertain = true;
            parts.push_back("_MFT" + std::to_string(current));
            break;
        }
        parts.push_back(sanitize_component(chosen->name));

        const uint64_t parent_index = chosen->parent_record();
        const uint16_t parent_sequence = chosen->parent_sequence();

        auto parent = mft_.load_record(parent_index);
        if (!parent) return fail(parent.error());
        if (!*parent) {
            uncertain = true;
            parts.push_back("__orphans__");
            break;
        }

        const NtfsRecord& parent_record = **parent;
        const bool sequence_ok =
            parent_record.in_use()
                ? parent_record.sequence_number == parent_sequence
                : (parent_record.sequence_number == parent_sequence ||
                   parent_record.sequence_number ==
                       static_cast<uint16_t>(parent_sequence + 1));
        if (!parent_record.is_directory() || !sequence_ok) {
            uncertain = true;
            break;
        }
        current = parent_index;
    }

    NtfsResolvedPath result;
    result.uncertain = uncertain;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!result.path.empty()) result.path.push_back('/');
        result.path += *it;
    }

    if (cache_.size() >= kMaxCacheEntries) {
        const uint64_t evicted = lru_.front();
        lru_.pop_front();
        cache_.erase(evicted);
    }
    lru_.push_back(record_number);
    cache_.emplace(record_number, CacheEntry{result, std::prev(lru_.end())});
    return result;
}

// ---------------------------------------------------------------------------
// NtfsScanner
// ---------------------------------------------------------------------------

NtfsScanner::NtfsScanner(std::shared_ptr<io::BlockDevice> dev, NtfsBoot boot,
                         std::unique_ptr<NtfsMftReader> mft)
    : dev_(std::move(dev)),
      boot_(boot),
      mft_(std::move(mft)),
      geometry_{boot.bytes_per_sector, boot.bytes_per_cluster, boot.total_clusters} {}

Result<std::unique_ptr<NtfsScanner>> NtfsScanner::open(std::shared_ptr<io::BlockDevice> dev) {
    if (!dev) return fail(ErrorCode::InvalidArgument, "null device");
    auto boot = read_ntfs_boot(*dev);
    if (!boot) return fail(boot.error());
    auto mft = NtfsMftReader::open(dev, *boot);
    if (!mft) return fail(mft.error());
    return std::unique_ptr<NtfsScanner>(new NtfsScanner(std::move(dev), *boot, std::move(*mft)));
}

Result<std::optional<RecoveredFile>> NtfsScanner::recover_record(
    const NtfsRecord& record, NtfsPathResolver& resolver, const IAllocationMap* allocation) {
    auto gathered = gather_file_attributes(*dev_, boot_, record, *mft_);
    if (!gathered) return fail(gathered.error());
    if (gathered->data.empty()) return std::optional<RecoveredFile>{};

    const NtfsFileName* chosen = best_file_name(gathered->names);
    RecoveredFile file;
    file.origin = FileOrigin::FilesystemMetadata;

    if (chosen) {
        file.name = sanitize_component(chosen->name);
    } else {
        file.name = "_MFT" + std::to_string(record.record_number);
        file.flags |= file_flags::PathUncertain;
    }

    auto resolved = resolver.resolve(record.record_number);
    if (!resolved) return fail(resolved.error());
    file.path = resolved->path;
    if (resolved->uncertain) file.flags |= file_flags::PathUncertain;
    const std::string unresolved_name = "_MFT" + std::to_string(record.record_number);
    if (!chosen && (file.path == unresolved_name || file.path.empty())) file.path = file.name;

    if (gathered->standard) {
        const NtfsStandardInformation& info = *gathered->standard;
        file.ctime_unix = info.created_unix;
        file.mtime_unix = info.modified_unix;
        file.atime_unix = info.accessed_unix;
    } else if (chosen) {
        file.ctime_unix = chosen->created_unix;
        file.mtime_unix = chosen->modified_unix;
        file.atime_unix = chosen->accessed_unix;
    }

    auto data = assemble_data(*dev_, boot_, gathered->data);
    if (!data) return std::optional<RecoveredFile>{};

    file.size_bytes = data->size;
    file.resident_data = std::move(data->resident);
    file.extents = std::move(data->extents);
    if (data->truncated) file.flags |= file_flags::Truncated;
    file.type_hint = type_hint_for_name(file.name);

    if (data->unsupported) {
        file.confidence = Confidence::Low;
        file.flags |= file_flags::Unsupported;
        file.note = data->reason;
        return std::optional<RecoveredFile>{std::move(file)};
    }

    if (file.resident_data) {
        file.confidence = Confidence::High;
        // A compressed file's content came from clusters on the volume, so reuse still matters
        // even though the file no longer carries extents.
        if (allocation && !data->stored.empty() &&
            extents_reused(data->stored, *allocation, boot_.bytes_per_cluster)) {
            file.confidence = Confidence::Low;
            file.flags |= file_flags::ClustersReallocated;
        }
    } else if (!allocation) {
        file.confidence = Confidence::Medium;
    } else if (extents_reused(file.extents, *allocation, boot_.bytes_per_cluster)) {
        file.confidence = Confidence::Low;
        file.flags |= file_flags::ClustersReallocated;
    } else {
        file.confidence = Confidence::High;
    }

    if (file.confidence == Confidence::High && !file.type_hint.empty() &&
        file.size_bytes >= 16) {
        std::array<uint8_t, 16> head{};
        auto got = read_file(file, 0, head.data(), head.size());
        if (got && *got == head.size() && !magic_matches(file.type_hint, head.data()))
            file.confidence = Confidence::Medium;
    }

    return std::optional<RecoveredFile>{std::move(file)};
}

Result<std::vector<RecoveredFile>> NtfsScanner::scan_deleted(const ScanOptions&, ProgressFn progress) {
    auto allocation = allocation_map();
    const IAllocationMap* map_ptr = nullptr;
    std::unique_ptr<IAllocationMap> map_holder;
    if (allocation) {
        map_holder = std::move(*allocation);
        map_ptr = map_holder.get();
    } else if (allocation.error().code == ErrorCode::IoError) {
        return fail(allocation.error());
    } else {
        log::warn("NTFS $Bitmap unavailable: confidence for non-resident files is Medium");
    }

    std::vector<RecoveredFile> out;
    NtfsPathResolver resolver(*mft_);
    const uint64_t start = 24;
    const uint64_t total = mft_->record_count() > start ? mft_->record_count() - start : 0;
    if (progress && !progress(0, total == 0 ? 1 : total))
        return fail(ErrorCode::Cancelled, "scan cancelled");

    for (uint64_t number = start; number < mft_->record_count(); ++number) {
        auto loaded = mft_->load_record(number);
        if (!loaded) return fail(loaded.error());
        if (*loaded) {
            const NtfsRecord& record = **loaded;
            if (!record.in_use() && !record.is_extension() && !record.is_directory()) {
                auto recovered = recover_record(record, resolver, map_ptr);
                if (!recovered) return fail(recovered.error());
                if (*recovered) out.push_back(std::move(**recovered));
            }
        }
        if (progress && ((number - start) & 0xFF) == 0xFF &&
            !progress(number - start + 1, total == 0 ? 1 : total))
            return fail(ErrorCode::Cancelled, "scan cancelled");
    }

    // A soft delete leaves the original path behind in the recycle bin, so the paths the scan
    // collected are rewritten before they set the order of the report.
    apply_recycle_bin_metadata(out);

    std::sort(out.begin(), out.end(), [](const RecoveredFile& a, const RecoveredFile& b) {
        return a.path < b.path;
    });
    if (progress && !progress(total, total == 0 ? 1 : total))
        return fail(ErrorCode::Cancelled, "scan cancelled");
    return out;
}

Result<std::unique_ptr<IAllocationMap>> NtfsScanner::allocation_map() {
    auto map = NtfsAllocationMap::open(dev_, boot_, *mft_);
    if (!map) return fail(map.error());
    return std::unique_ptr<IAllocationMap>(std::move(*map));
}

Result<size_t> NtfsScanner::read_file(const RecoveredFile& file, uint64_t file_offset,
                                      uint8_t* dst, size_t len) {
    if ((file.flags & file_flags::Unsupported) != 0)
        return fail(ErrorCode::Unsupported,
                    "file content is not available: " + file.note);
    if (file_offset >= file.size_bytes) return size_t{0};
    const uint64_t wanted =
        std::min<uint64_t>(len, file.size_bytes - file_offset);
    if (wanted == 0) return size_t{0};

    if (file.resident_data) {
        const auto& data = *file.resident_data;
        if (file_offset >= data.size()) return size_t{0};
        const uint64_t take =
            std::min<uint64_t>(wanted, static_cast<uint64_t>(data.size()) - file_offset);
        std::memcpy(dst, data.data() + static_cast<size_t>(file_offset),
                    static_cast<size_t>(take));
        return static_cast<size_t>(take);
    }

    uint64_t logical = 0;
    uint64_t done = 0;
    for (const Extent& extent : file.extents) {
        if (done >= wanted) break;
        const uint64_t end = logical + extent.length_bytes;
        if (file_offset >= end) {
            logical = end;
            continue;
        }
        const uint64_t within = file_offset > logical ? file_offset - logical : 0;
        const uint64_t take =
            std::min<uint64_t>(extent.length_bytes - within, wanted - done);
        if (extent.sparse) {
            std::memset(dst + done, 0, static_cast<size_t>(take));
        } else {
            auto got = io::read_fully(*dev_, extent.offset_bytes + within, dst + done,
                                      static_cast<size_t>(take));
            if (!got) return fail(got.error());
            if (*got != take)
                return fail(ErrorCode::CorruptStructure,
                            "short read while recovering " + file.path);
        }
        done += take;
        logical = end;
    }
    return static_cast<size_t>(done);
}

}  // namespace openrecover::fs
