#include "openrecover/io/vhdx_device.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/crc32c.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/io/cached_device.hpp"

namespace openrecover::io {

namespace {

constexpr uint64_t kKiB = 1024;
constexpr uint64_t kMiB = 1024 * 1024;
constexpr uint64_t kFileIdentifierBytes = 64 * kKiB;
constexpr uint64_t kHeader1Offset = 64 * kKiB;
constexpr uint64_t kHeader2Offset = 128 * kKiB;
constexpr uint64_t kHeaderBytes = 4 * kKiB;
constexpr uint64_t kRegionTable1Offset = 192 * kKiB;
constexpr uint64_t kRegionTable2Offset = 256 * kKiB;
constexpr uint64_t kRegionTableBytes = 64 * kKiB;
constexpr uint64_t kRegionTableEntriesAt = 16;
constexpr uint32_t kRegionTableMaxEntries = 2047;
constexpr uint64_t kMetadataHeaderBytes = 32;
constexpr uint64_t kMetadataEntryBytes = 40;
constexpr uint32_t kMetadataMaxEntries = 2047;
constexpr uint64_t kSectorBitmapBytes = kMiB;
// The format caps a virtual disk at 64 TiB.
constexpr uint64_t kMaxVirtualBytes = 64ull << 40;
constexpr uint64_t kMinBlockSize = 1 * kMiB;
constexpr uint64_t kMaxBlockSize = 256 * kMiB;
constexpr uint64_t kMaxChunkRatio = 1ull << 23;
constexpr uint64_t kMaxBatEntries = 1ull << 26;
constexpr uint64_t kContainerCacheBytes = 64ull << 20;

// Header fields, all little-endian.
constexpr size_t kHeaderChecksum = 4;
constexpr size_t kHeaderSequence = 8;
constexpr size_t kHeaderLogGuid = 48;
constexpr size_t kHeaderLogVersion = 64;
constexpr size_t kHeaderVersion = 66;
constexpr size_t kHeaderLogLength = 68;
constexpr size_t kHeaderLogOffset = 72;

constexpr uint32_t kBatNotPresent = 0;
constexpr uint32_t kBatUndefined = 1;
constexpr uint32_t kBatZero = 2;
constexpr uint32_t kBatUnmapped = 3;
constexpr uint32_t kBatFullyPresent = 4;
constexpr uint32_t kBatPartiallyPresent = 5;

using Guid = std::array<uint8_t, 16>;

// Microsoft GUIDs are stored with the first three fields little-endian, the last eight
// bytes verbatim, which is how these literals are written.
constexpr Guid kBatRegionId = {0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42,
                               0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08};
constexpr Guid kMetadataRegionId = {0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B,
                                    0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E};
constexpr Guid kFileParametersId = {0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D,
                                    0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B};
constexpr Guid kVirtualDiskSizeId = {0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48,
                                     0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8};
constexpr Guid kLogicalSectorSizeId = {0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47,
                                       0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F};
constexpr Guid kPhysicalSectorSizeId = {0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44,
                                        0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56};
constexpr Guid kParentLocatorId = {0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45,
                                   0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C};

bool guid_at(ByteView view, size_t off, const Guid& want) {
    if (!view.has(off, want.size())) return false;
    return std::equal(want.begin(), want.end(), view.data() + off);
}

bool guid_is_zero(ByteView view, size_t off) {
    if (!view.has(off, 16)) return false;
    for (size_t i = 0; i < 16; ++i)
        if (view.data()[off + i] != 0) return false;
    return true;
}

// The stored CRC32c covers the whole structure with the checksum field read as zeros.
uint32_t crc32c_skipping(ByteView view, size_t field) {
    static constexpr uint8_t kZeros[4] = {};
    uint32_t state = crc32c_update(0xFFFFFFFFu, view.data(), field);
    state = crc32c_update(state, kZeros, sizeof kZeros);
    state = crc32c_update(state, view.data() + field + 4, view.size() - field - 4);
    return state ^ 0xFFFFFFFFu;
}

bool is_power_of_two(uint64_t value) { return value != 0 && (value & (value - 1)) == 0; }

struct HeaderInfo {
    uint64_t sequence = 0;
    bool log_pending = false;
};

// A header is usable only if its checksum and the fields the reader depends on agree with
// the format; a torn update leaves the other copy to be tried.
bool valid_header(ByteView h, HeaderInfo& out) {
    if (h.size() < kHeaderBytes || !h.equals(0, "head")) return false;
    if (h.u32le(kHeaderChecksum) != crc32c_skipping(h, kHeaderChecksum)) return false;
    if (h.u16le(kHeaderVersion) != 1) return false;
    if (h.u16le(kHeaderLogVersion) != 0) return false;
    out.sequence = h.u64le(kHeaderSequence);
    out.log_pending = !guid_is_zero(h, kHeaderLogGuid) || h.u32le(kHeaderLogLength) != 0 ||
                      h.u64le(kHeaderLogOffset) != 0;
    return true;
}

struct Region {
    bool found = false;
    uint64_t offset = 0;
    uint32_t length = 0;
};

struct Regions {
    Region bat;
    Region metadata;
};

Result<Regions> parse_region_table(ByteView table, uint64_t container_bytes) {
    if (table.size() < kRegionTableBytes || !table.equals(0, "regi"))
        return fail(ErrorCode::CorruptStructure, "VHDX region table signature is missing");
    if (table.u32le(4) != crc32c_skipping(table, 4))
        return fail(ErrorCode::CorruptStructure, "VHDX region table checksum mismatch");

    const uint32_t count = table.u32le(8);
    if (count > kRegionTableMaxEntries)
        return fail(ErrorCode::CorruptStructure, "VHDX region table declares too many entries");
    if (kRegionTableEntriesAt + static_cast<uint64_t>(count) * 32 > table.size())
        return fail(ErrorCode::CorruptStructure, "VHDX region table is truncated");

    Regions regions;
    for (uint32_t i = 0; i < count; ++i) {
        const size_t at = static_cast<size_t>(kRegionTableEntriesAt + static_cast<uint64_t>(i) * 32);
        const uint64_t offset = table.u64le(at + 16);
        const uint32_t length = table.u32le(at + 24);
        const uint32_t required = table.u32le(at + 28);
        if ((required & ~1u) != 0)
            return fail(ErrorCode::CorruptStructure, "VHDX region entry uses reserved flags");

        if ((required & 1u) != 0) {
            if (length == 0 || offset > container_bytes ||
                static_cast<uint64_t>(length) > container_bytes - offset)
                return fail(ErrorCode::CorruptStructure,
                            "VHDX required region extends past the container");
        }

        if (guid_at(table, at, kBatRegionId)) {
            if (regions.bat.found)
                return fail(ErrorCode::CorruptStructure, "VHDX region table names the BAT twice");
            regions.bat = Region{true, offset, length};
        } else if (guid_at(table, at, kMetadataRegionId)) {
            if (regions.metadata.found)
                return fail(ErrorCode::CorruptStructure,
                            "VHDX region table names the metadata region twice");
            regions.metadata = Region{true, offset, length};
        } else if ((required & 1u) != 0) {
            return fail(ErrorCode::Unsupported, "VHDX requires a region this reader does not know");
        }
    }
    if (!regions.bat.found)
        return fail(ErrorCode::CorruptStructure, "VHDX region table has no BAT region");
    if (!regions.metadata.found)
        return fail(ErrorCode::CorruptStructure, "VHDX region table has no metadata region");
    if (regions.bat.length < 8)
        return fail(ErrorCode::CorruptStructure, "VHDX BAT region is empty");
    return regions;
}

struct Metadata {
    uint64_t block_size = 0;
    uint64_t virtual_size = 0;
    uint32_t logical_sector_size = 0;
    uint32_t physical_sector_size = 0;
    bool has_parent = false;
    bool parent_locator = false;
};

Result<Metadata> parse_metadata(ByteView region) {
    if (region.size() < kMetadataHeaderBytes || !region.equals(0, "metadata"))
        return fail(ErrorCode::CorruptStructure, "VHDX metadata table signature is missing");

    const uint32_t count = region.u16le(10);
    if (count > kMetadataMaxEntries)
        return fail(ErrorCode::CorruptStructure, "VHDX metadata table declares too many entries");
    if (kMetadataHeaderBytes + static_cast<uint64_t>(count) * kMetadataEntryBytes > region.size())
        return fail(ErrorCode::CorruptStructure, "VHDX metadata table is truncated");

    Metadata meta;
    bool have_parameters = false, have_size = false, have_logical = false, have_physical = false;
    for (uint32_t i = 0; i < count; ++i) {
        const size_t at = static_cast<size_t>(kMetadataHeaderBytes +
                                              static_cast<uint64_t>(i) * kMetadataEntryBytes);
        const uint32_t offset = region.u32le(at + 16);
        const uint32_t length = region.u32le(at + 20);
        const bool is_virtual = region.u32le(at + 28) != 0;
        const bool is_required = region.u32le(at + 32) != 0;
        if (offset > region.size() || static_cast<uint64_t>(length) > region.size() - offset)
            return fail(ErrorCode::CorruptStructure, "VHDX metadata item extends past its region");
        const ByteView item = region.sub(offset, length);

        const bool known = guid_at(region, at, kFileParametersId) ||
                           guid_at(region, at, kVirtualDiskSizeId) ||
                           guid_at(region, at, kLogicalSectorSizeId) ||
                           guid_at(region, at, kPhysicalSectorSizeId) ||
                           guid_at(region, at, kParentLocatorId);
        if (!known && is_required)
            return fail(ErrorCode::Unsupported,
                        "VHDX requires metadata this reader does not know");
        if (guid_at(region, at, kParentLocatorId)) {
            meta.parent_locator = true;
            continue;
        }
        (void)is_virtual;

        if (guid_at(region, at, kFileParametersId)) {
            if (have_parameters || item.size() < 8)
                return fail(ErrorCode::CorruptStructure, "VHDX file parameters are malformed");
            have_parameters = true;
            meta.block_size = item.u32le(0);
            const uint32_t flags = item.u32le(4);
            if ((flags & ~3u) != 0)
                return fail(ErrorCode::CorruptStructure, "VHDX file parameters use reserved flags");
            meta.has_parent = (flags & 2u) != 0;
        } else if (guid_at(region, at, kVirtualDiskSizeId)) {
            if (have_size || item.size() < 8)
                return fail(ErrorCode::CorruptStructure, "VHDX virtual disk size is malformed");
            have_size = true;
            meta.virtual_size = item.u64le(0);
        } else if (guid_at(region, at, kLogicalSectorSizeId)) {
            if (have_logical || item.size() < 4)
                return fail(ErrorCode::CorruptStructure, "VHDX logical sector size is malformed");
            have_logical = true;
            meta.logical_sector_size = item.u32le(0);
        } else if (guid_at(region, at, kPhysicalSectorSizeId)) {
            if (have_physical || item.size() < 4)
                return fail(ErrorCode::CorruptStructure, "VHDX physical sector size is malformed");
            have_physical = true;
            meta.physical_sector_size = item.u32le(0);
        }
    }

    if (!have_parameters || !have_size || !have_logical || !have_physical)
        return fail(ErrorCode::CorruptStructure, "VHDX metadata is missing a required item");
    if (is_power_of_two(meta.block_size) && (meta.block_size < kMinBlockSize ||
                                             meta.block_size > kMaxBlockSize))
        return fail(ErrorCode::CorruptStructure, "VHDX block size is out of range");
    if (!is_power_of_two(meta.block_size))
        return fail(ErrorCode::CorruptStructure, "VHDX block size is not a power of two");
    if (meta.virtual_size == 0 || meta.virtual_size > kMaxVirtualBytes ||
        meta.virtual_size % 512 != 0)
        return fail(ErrorCode::CorruptStructure, "VHDX virtual disk size is out of range");
    const auto sector_ok = [](uint32_t size) { return size == 512 || size == 4096; };
    if (!sector_ok(meta.logical_sector_size) || !sector_ok(meta.physical_sector_size))
        return fail(ErrorCode::CorruptStructure, "VHDX sector size is not 512 or 4096");
    return meta;
}

struct BatEntry {
    uint32_t state = kBatNotPresent;
    uint64_t file_offset = 0;
};

}  // namespace

// Read-only mapping of a VHDX container onto its virtual disk.
class VhdxDevice final : public BlockDevice {
public:
    static Result<std::unique_ptr<VhdxDevice>> create(std::shared_ptr<BlockDevice> container);

    const DeviceInfo& info() const noexcept override { return info_; }

    Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override {
        if (len == 0 || offset >= info_.size_bytes) return ReadResult{0, false};
        const uint64_t available = info_.size_bytes - offset;
        if (static_cast<uint64_t>(len) > available) len = static_cast<size_t>(available);

        size_t done = 0;
        while (done < len) {
            const uint64_t virtual_offset = offset + done;
            const uint64_t block = virtual_offset / block_size_;
            const uint64_t in_block = virtual_offset - block * block_size_;
            const BatEntry& entry = bat_[static_cast<size_t>(block)];

            if (entry.state == kBatFullyPresent) {
                uint64_t run = block_size_ - in_block;
                if (run > len - done) run = len - done;
                auto copied = copy_payload(entry, in_block, dst + done, static_cast<size_t>(run));
                if (!copied) return fail(copied.error());
                done += static_cast<size_t>(run);
                continue;
            }

            if (entry.state == kBatPartiallyPresent) {
                auto map = bitmap_for(block, entry);
                if (!map) return fail(map.error());
                const uint64_t first_sector = in_block / logical_sector_;
                const uint64_t within_sector = in_block - first_sector * logical_sector_;
                const bool allocated = sector_allocated(**map, first_sector);
                uint64_t run = 0;
                const uint64_t sector_count = block_size_ / logical_sector_;
                while (run < sector_count - first_sector &&
                       sector_allocated(**map, first_sector + run) == allocated)
                    ++run;
                uint64_t take = run * logical_sector_ - within_sector;
                if (take > len - done) take = len - done;
                if (!allocated) {
                    std::memset(dst + done, 0, static_cast<size_t>(take));
                    done += static_cast<size_t>(take);
                    continue;
                }
                auto copied =
                    copy_payload(entry, in_block, dst + done, static_cast<size_t>(take));
                if (!copied) return fail(copied.error());
                done += static_cast<size_t>(take);
                continue;
            }

            // NOT_PRESENT, UNDEFINED and ZERO all read back as zeros.
            uint64_t run = block_size_ - in_block;
            if (run > len - done) run = len - done;
            std::memset(dst + done, 0, static_cast<size_t>(run));
            done += static_cast<size_t>(run);
        }
        return ReadResult{done, false};
    }

    // Payload blocks are not laid out in virtual order, so a container sector number cannot
    // be mapped back to a virtual one. Reporting none is the honest answer.
    std::vector<uint64_t> bad_sectors() const override { return {}; }

private:
    VhdxDevice(std::shared_ptr<BlockDevice> container, DeviceInfo info, uint64_t block_size,
               uint32_t logical_sector_size, uint64_t bitmap_bytes, std::vector<BatEntry> bat)
        : container_(std::move(container)),
          info_(std::move(info)),
          block_size_(block_size),
          logical_sector_(logical_sector_size),
          bitmap_bytes_(bitmap_bytes),
          bat_(std::move(bat)) {}

    Result<ReadResult> copy_payload(const BatEntry& entry, uint64_t in_block, uint8_t* dst,
                                    size_t len) {
        auto got = read_fully(*container_, entry.file_offset + in_block, dst, len);
        if (!got) return fail(got.error());
        // A copy that stopped early leaves the present bytes readable and the missing tail
        // as zeros, the same contract the VHD reader keeps.
        if (*got < len) std::memset(dst + *got, 0, len - *got);
        return ReadResult{len, false};
    }

    using Bitmap = std::shared_ptr<const std::vector<uint8_t>>;

    Result<Bitmap> bitmap_for(uint64_t block, const BatEntry& entry) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (block == cached_block_) return cached_bitmap_;
        auto bitmap = std::make_shared<std::vector<uint8_t>>(static_cast<size_t>(bitmap_bytes_), 0);
        if (entry.file_offset >= kSectorBitmapBytes) {
            const uint64_t at = entry.file_offset - kSectorBitmapBytes;
            auto got = read_fully(*container_, at, bitmap->data(), bitmap->size());
            if (!got) return fail(got.error());
            if (*got < bitmap->size())
                log::warn("VHDX sector bitmap is truncated; the missing sectors read back as zeros");
        } else {
            log::warn("VHDX partly-present block has no room for its sector bitmap; "
                      "its sectors read back as zeros");
        }
        cached_block_ = block;
        cached_bitmap_ = bitmap;
        return bitmap;
    }

    static bool sector_allocated(const std::vector<uint8_t>& bitmap, uint64_t bit) {
        if (bit / 8 >= bitmap.size()) return false;
        return (bitmap[static_cast<size_t>(bit / 8)] & (1u << (bit % 8))) != 0;
    }

    std::shared_ptr<BlockDevice> container_;
    DeviceInfo info_{};
    uint64_t block_size_ = 0;
    uint32_t logical_sector_ = 512;
    uint64_t bitmap_bytes_ = 0;
    std::vector<BatEntry> bat_;

    std::mutex mutex_;
    uint64_t cached_block_ = UINT64_MAX;
    Bitmap cached_bitmap_;
};

Result<std::unique_ptr<VhdxDevice>> VhdxDevice::create(std::shared_ptr<BlockDevice> container) {
    if (!container) return fail(ErrorCode::InvalidArgument, "null VHDX container");
    const uint64_t container_bytes = container->info().size_bytes;
    if (container_bytes < kRegionTable2Offset + kRegionTableBytes)
        return fail(ErrorCode::CorruptStructure, "VHDX is truncated before its region tables");

    std::array<uint8_t, 8> signature{};
    auto sig_got = read_fully(*container, 0, signature.data(), signature.size());
    if (!sig_got) return fail(sig_got.error());
    if (*sig_got != signature.size() || !ByteView(signature).equals(0, "vhdxfile"))
        return fail(ErrorCode::CorruptStructure, "VHDX file identifier is missing");

    std::array<uint8_t, kHeaderBytes> raw{};
    auto load_header = [&](uint64_t at, HeaderInfo& info) -> bool {
        auto got = read_fully(*container, at, raw.data(), raw.size());
        if (!got || *got != raw.size()) return false;
        return valid_header(ByteView(raw), info);
    };
    HeaderInfo first, second;
    const bool first_ok = load_header(kHeader1Offset, first);
    const bool second_ok = load_header(kHeader2Offset, second);
    if (!first_ok && !second_ok)
        return fail(ErrorCode::CorruptStructure, "VHDX headers are both missing or corrupt");
    const bool use_first = second_ok && (!first_ok || second.sequence <= first.sequence);
    const HeaderInfo& chosen = use_first ? second : first;
    if (chosen.log_pending)
        log::warn("VHDX log is not replayed; the disk may lag its last committed write");

    std::array<uint8_t, kRegionTableBytes> table_raw{};
    auto parse_table_at = [&](uint64_t at) -> Result<Regions> {
        auto got = read_fully(*container, at, table_raw.data(), table_raw.size());
        if (!got) return fail(got.error());
        if (*got != table_raw.size())
            return fail(ErrorCode::CorruptStructure, "VHDX region table is truncated");
        return parse_region_table(ByteView(table_raw), container_bytes);
    };
    auto regions = parse_table_at(kRegionTable1Offset);
    if (!regions) {
        auto backup = parse_table_at(kRegionTable2Offset);
        if (!backup) return fail(regions.error());
        regions = backup;
    }

    std::vector<uint8_t> metadata_raw(regions->metadata.length);
    auto meta_got = read_fully(*container, regions->metadata.offset, metadata_raw.data(),
                               metadata_raw.size());
    if (!meta_got) return fail(meta_got.error());
    if (*meta_got != metadata_raw.size())
        return fail(ErrorCode::CorruptStructure, "VHDX metadata region is truncated");
    auto meta = parse_metadata(ByteView(metadata_raw));
    if (!meta) return fail(meta.error());
    if (meta->has_parent || meta->parent_locator)
        return fail(ErrorCode::Unsupported, "differencing VHDX disks are not supported");

    const uint64_t entries = (meta->virtual_size + meta->block_size - 1) / meta->block_size;
    if (entries > kMaxBatEntries)
        return fail(ErrorCode::Unsupported, "VHDX BAT is too large to read");
    const uint64_t bat_bytes = entries * 8;
    if (bat_bytes > regions->bat.length)
        return fail(ErrorCode::CorruptStructure, "VHDX BAT region is smaller than the disk");

    std::vector<uint8_t> bat_raw(static_cast<size_t>(bat_bytes));
    auto bat_got = read_fully(*container, regions->bat.offset, bat_raw.data(), bat_raw.size());
    if (!bat_got) return fail(bat_got.error());
    if (*bat_got != bat_raw.size())
        return fail(ErrorCode::CorruptStructure, "VHDX BAT is truncated");

    const uint64_t chunk_ratio = meta->block_size / meta->logical_sector_size;
    const bool bitmaps_allowed = chunk_ratio <= kMaxChunkRatio;
    uint64_t bitmap_bytes = (chunk_ratio + 7) / 8;
    if (bitmap_bytes > kSectorBitmapBytes) bitmap_bytes = kSectorBitmapBytes;

    ByteView bat_view(bat_raw);
    std::vector<BatEntry> bat(static_cast<size_t>(entries));
    bool warned_truncated = false;
    for (uint64_t i = 0; i < entries; ++i) {
        const uint64_t raw_entry = bat_view.u64le(static_cast<size_t>(i * 8));
        const uint32_t state = static_cast<uint32_t>(raw_entry & 0x7u);
        const uint64_t file_offset_mb = raw_entry >> 20;
        BatEntry entry;
        entry.state = state;
        if (state == kBatFullyPresent || state == kBatPartiallyPresent) {
            if (file_offset_mb == 0)
                return fail(ErrorCode::CorruptStructure,
                            "VHDX present block has no file offset");
            if (state == kBatPartiallyPresent && !bitmaps_allowed)
                return fail(ErrorCode::CorruptStructure,
                            "VHDX block is too large to carry a sector bitmap");
            entry.file_offset = file_offset_mb << 20;
            if (entry.file_offset > container_bytes ||
                meta->block_size > container_bytes - entry.file_offset) {
                if (!warned_truncated) {
                    log::warn("VHDX BAT points past the end of the container; "
                              "truncated blocks read back as zeros");
                    warned_truncated = true;
                }
            }
        } else if (state == kBatUnmapped) {
            return fail(ErrorCode::CorruptStructure,
                        "VHDX block is unmapped and its parent is not readable");
        } else if (state != kBatNotPresent && state != kBatUndefined && state != kBatZero) {
            return fail(ErrorCode::CorruptStructure, "VHDX BAT contains an unknown block state");
        }
        bat[static_cast<size_t>(i)] = entry;
    }

    DeviceInfo info;
    info.container = "vhdx";
    info.description = container->info().description + " (vhdx)";
    info.size_bytes = meta->virtual_size;
    info.logical_sector_size = meta->logical_sector_size;
    info.physical_sector_size = meta->physical_sector_size;
    info.is_image = true;
    info.shared_write_fallback = container->info().shared_write_fallback;
    return std::unique_ptr<VhdxDevice>(new VhdxDevice(
        std::move(container), std::move(info), meta->block_size, meta->logical_sector_size,
        bitmap_bytes, std::move(bat)));
}

Result<std::unique_ptr<BlockDevice>> open_vhdx(std::shared_ptr<BlockDevice> container) {
    if (!container) return fail(ErrorCode::InvalidArgument, "null VHDX container");
    std::shared_ptr<BlockDevice> backing =
        std::make_shared<CachedDevice>(std::move(container), kContainerCacheBytes);
    auto dev = VhdxDevice::create(std::move(backing));
    if (!dev) return fail(dev.error());
    return std::unique_ptr<BlockDevice>(std::move(*dev));
}

}  // namespace openrecover::io
