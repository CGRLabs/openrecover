#include "openrecover/io/vhd_device.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "openrecover/common/bytes.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/io/cached_device.hpp"

namespace openrecover::io {

namespace {

constexpr uint64_t kSectorBytes = 512;
constexpr uint64_t kFooterBytes = 512;
constexpr uint64_t kHeaderBytes = 1024;
constexpr uint32_t kTypeFixed = 2;
constexpr uint32_t kTypeDynamic = 3;
constexpr uint32_t kTypeDifferencing = 4;
constexpr uint32_t kFormatVersion = 0x00010000;
// The format caps a virtual disk at 0xFF000000 sectors (about 2040 GiB).
constexpr uint64_t kMaxVirtualBytes = 0xFF000000ull * kSectorBytes;
constexpr uint64_t kMaxBlockSize = 1ull << 30;
constexpr uint64_t kMaxBatEntries = 1ull << 24;
constexpr uint32_t kUnallocatedEntry = 0xFFFFFFFFu;
constexpr uint64_t kContainerCacheBytes = 64ull << 20;

// Footer fields, all big-endian.
constexpr size_t kFooterVersion = 12;
constexpr size_t kFooterDataOffset = 16;
constexpr size_t kFooterCurrentSize = 48;
constexpr size_t kFooterType = 60;
constexpr size_t kFooterChecksum = 64;

// Dynamic header fields, all big-endian.
constexpr size_t kHeaderTableOffset = 16;
constexpr size_t kHeaderVersion = 24;
constexpr size_t kHeaderMaxEntries = 28;
constexpr size_t kHeaderBlockSize = 32;
constexpr size_t kHeaderChecksum = 36;

uint32_t block_checksum(ByteView data, size_t checksum_offset) {
    uint32_t sum = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i >= checksum_offset && i < checksum_offset + 4) continue;
        sum += data.u8(i);
    }
    return ~sum;
}

struct VhdFooter {
    uint64_t data_offset = 0;
    uint64_t current_size = 0;
    uint32_t type = 0;
};

Result<VhdFooter> parse_footer(ByteView sector) {
    if (sector.size() < kFooterBytes || !sector.equals(0, "conectix"))
        return fail(ErrorCode::CorruptStructure, "VHD footer cookie is missing");
    if (sector.u32be(kFooterVersion) != kFormatVersion)
        return fail(ErrorCode::CorruptStructure, "unsupported VHD format version");
    if (sector.u32be(kFooterChecksum) != block_checksum(sector, kFooterChecksum))
        return fail(ErrorCode::CorruptStructure, "VHD footer checksum mismatch");
    if (sector.failed()) return fail(ErrorCode::CorruptStructure, "truncated VHD footer");

    const uint32_t type = sector.u32be(kFooterType);
    if (type == kTypeDifferencing)
        return fail(ErrorCode::Unsupported, "differencing VHD disks are not supported");
    if (type != kTypeFixed && type != kTypeDynamic)
        return fail(ErrorCode::Unsupported, "unknown VHD disk type");

    VhdFooter footer;
    footer.data_offset = sector.u64be(kFooterDataOffset);
    footer.current_size = sector.u64be(kFooterCurrentSize);
    footer.type = type;
    if (footer.current_size == 0 || footer.current_size > kMaxVirtualBytes)
        return fail(ErrorCode::CorruptStructure, "VHD current size is out of range");
    return footer;
}

bool is_power_of_two(uint64_t value) { return value != 0 && (value & (value - 1)) == 0; }

}  // namespace

// Read-only mapping of a fixed or dynamic VHD container onto its virtual disk.
class VhdDevice final : public BlockDevice {
public:
    static Result<std::unique_ptr<VhdDevice>> create(std::shared_ptr<BlockDevice> container);

    const DeviceInfo& info() const noexcept override { return info_; }

    Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) override {
        if (len == 0 || offset >= info_.size_bytes) return ReadResult{0, false};
        const uint64_t available = info_.size_bytes - offset;
        if (len > available) len = static_cast<size_t>(available);
        if (bat_.empty()) return container_->read(offset, dst, len);
        return read_dynamic(offset, dst, len);
    }

    std::vector<uint64_t> bad_sectors() const override {
        if (!bat_.empty()) return {};
        std::vector<uint64_t> out;
        for (uint64_t sector : container_->bad_sectors()) {
            if (sector * kSectorBytes < info_.size_bytes) out.push_back(sector);
        }
        return out;
    }

private:
    VhdDevice(std::shared_ptr<BlockDevice> container, DeviceInfo info, uint64_t block_size,
              uint64_t bitmap_size, std::vector<uint32_t> bat)
        : container_(std::move(container)),
          info_(std::move(info)),
          block_size_(block_size),
          bitmap_size_(bitmap_size),
          bat_(std::move(bat)) {}

    Result<std::vector<uint8_t>> bitmap_for(uint64_t block) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (block == cached_block_) return cached_bitmap_;
        const uint64_t offset = bat_[static_cast<size_t>(block)];
        std::vector<uint8_t> bitmap(static_cast<size_t>(bitmap_size_), 0);
        auto got = read_fully(*container_, offset, bitmap.data(), bitmap.size());
        if (!got) return fail(got.error());
        if (*got < bitmap.size())
            log::warn("VHD sector bitmap is truncated; the missing sectors read back as zeros");
        cached_block_ = block;
        cached_bitmap_ = bitmap;
        return bitmap;
    }

    static bool sector_allocated(const std::vector<uint8_t>& bitmap, uint64_t bit) {
        if (bit / 8 >= bitmap.size()) return false;
        return (bitmap[static_cast<size_t>(bit / 8)] & (1u << (bit % 8))) != 0;
    }

    Result<ReadResult> read_dynamic(uint64_t offset, uint8_t* dst, size_t len) {
        const uint64_t sectors_per_block = block_size_ / kSectorBytes;
        size_t done = 0;
        while (done < len) {
            const uint64_t virtual_offset = offset + done;
            const uint64_t block = virtual_offset / block_size_;
            const uint64_t in_block = virtual_offset - block * block_size_;
            const uint64_t first_sector = in_block / kSectorBytes;
            const uint64_t within_sector = in_block - first_sector * kSectorBytes;
            const uint32_t entry = bat_[static_cast<size_t>(block)];

            bool allocated = false;
            uint64_t run = 0;
            std::vector<uint8_t> bitmap;
            if (entry == kUnallocatedEntry) {
                run = sectors_per_block - first_sector;
            } else {
                auto map = bitmap_for(block);
                if (!map) return fail(map.error());
                bitmap = std::move(*map);
                allocated = sector_allocated(bitmap, first_sector);
                while (run < sectors_per_block - first_sector &&
                       sector_allocated(bitmap, first_sector + run) == allocated)
                    ++run;
            }

            uint64_t take = run * kSectorBytes - within_sector;
            if (take > len - done) take = len - done;
            if (!allocated) {
                std::memset(dst + done, 0, static_cast<size_t>(take));
                done += static_cast<size_t>(take);
                continue;
            }
            const uint64_t file_offset =
                static_cast<uint64_t>(entry) + bitmap_size_ + first_sector * kSectorBytes +
                within_sector;
            auto got = read_fully(*container_, file_offset, dst + done, static_cast<size_t>(take));
            if (!got) return fail(got.error());
            if (*got < take) {
                // A block truncated by an incomplete copy: the bytes that are present stay
                // readable and the missing tail reads back as zeros.
                std::memset(dst + done + *got, 0, static_cast<size_t>(take - *got));
            }
            done += static_cast<size_t>(take);
        }
        return ReadResult{done, false};
    }

    std::shared_ptr<BlockDevice> container_;
    DeviceInfo info_{};
    uint64_t block_size_ = 0;
    uint64_t bitmap_size_ = 0;
    std::vector<uint32_t> bat_;

    std::mutex mutex_;
    uint64_t cached_block_ = UINT64_MAX;
    std::vector<uint8_t> cached_bitmap_;
};

Result<std::unique_ptr<VhdDevice>> VhdDevice::create(std::shared_ptr<BlockDevice> container) {
    if (!container) return fail(ErrorCode::InvalidArgument, "null VHD container");
    const uint64_t container_bytes = container->info().size_bytes;
    if (container_bytes < kFooterBytes * 2)
        return fail(ErrorCode::Unsupported, "file is too small to be a VHD container");

    // A dynamic VHD stores a copy of the footer at offset 0 plus a primary and a backup
    // copy at the end; a fixed VHD only stores the trailing copy.
    std::array<uint8_t, kFooterBytes> raw{};
    auto load = [&](uint64_t at) -> Result<VhdFooter> {
        auto got = read_fully(*container, at, raw.data(), raw.size());
        if (!got) return fail(got.error());
        if (*got != raw.size())
            return fail(ErrorCode::CorruptStructure, "VHD footer is truncated");
        return parse_footer(ByteView(raw));
    };

    Result<VhdFooter> parsed = load(container_bytes - kFooterBytes);
    if (!parsed && parsed.error().code == ErrorCode::CorruptStructure) {
        auto leading = load(0);
        if (leading) parsed = leading;
    }
    if (!parsed) return fail(parsed.error());
    const VhdFooter footer = *parsed;

    const uint64_t virtual_bytes = align_down(footer.current_size, kSectorBytes);
    if (virtual_bytes == 0)
        return fail(ErrorCode::CorruptStructure, "VHD virtual size is below one sector");

    DeviceInfo info;
    info.container = footer.type == kTypeFixed ? "vhd fixed" : "vhd dynamic";
    info.description = container->info().description + " (" + info.container + ")";
    info.logical_sector_size = static_cast<uint32_t>(kSectorBytes);
    info.physical_sector_size = static_cast<uint32_t>(kSectorBytes);
    info.is_image = true;
    info.shared_write_fallback = container->info().shared_write_fallback;

    if (footer.type == kTypeFixed) {
        const uint64_t readable =
            container_bytes > kFooterBytes
                ? align_down(container_bytes - kFooterBytes, kSectorBytes)
                : 0;
        if (footer.current_size > readable)
            log::warn("fixed VHD footer claims " + std::to_string(footer.current_size) +
                      " bytes but the container holds less; reading " + std::to_string(readable));
        info.size_bytes = std::min(virtual_bytes, readable);
        return std::unique_ptr<VhdDevice>(
            new VhdDevice(std::move(container), std::move(info), 0, 0, {}));
    }

    uint64_t header_offset = footer.data_offset;
    if (header_offset > container_bytes - kFooterBytes ||
        container_bytes - header_offset < kHeaderBytes)
        header_offset = kFooterBytes;

    std::vector<uint8_t> header(kHeaderBytes);
    auto header_got = read_fully(*container, header_offset, header.data(), header.size());
    if (!header_got) return fail(header_got.error());
    if (*header_got != header.size())
        return fail(ErrorCode::CorruptStructure, "VHD dynamic header is truncated");
    ByteView view(header);
    if (!view.equals(0, "cxsparse"))
        return fail(ErrorCode::CorruptStructure, "VHD dynamic header signature is missing");
    if (view.u32be(kHeaderVersion) != kFormatVersion)
        return fail(ErrorCode::CorruptStructure, "unsupported VHD dynamic header version");
    if (view.u32be(kHeaderChecksum) != block_checksum(view, kHeaderChecksum))
        log::warn("VHD dynamic header checksum does not match; reading from the block table");

    const uint64_t bat_offset = view.u64be(kHeaderTableOffset);
    const uint32_t declared_entries = view.u32be(kHeaderMaxEntries);
    const uint64_t block_size = view.u32be(kHeaderBlockSize);
    if (!is_power_of_two(block_size) || block_size < kSectorBytes || block_size > kMaxBlockSize)
        return fail(ErrorCode::CorruptStructure, "VHD block size is invalid");

    const uint64_t entries = (virtual_bytes + block_size - 1) / block_size;
    if (entries > kMaxBatEntries)
        return fail(ErrorCode::Unsupported, "VHD block table is too large to read");
    if (declared_entries != 0 && entries > declared_entries)
        return fail(ErrorCode::CorruptStructure, "VHD block table is smaller than the disk");
    const uint64_t bat_bytes = entries * 4;
    if (bat_offset > container_bytes || container_bytes - bat_offset < bat_bytes)
        return fail(ErrorCode::CorruptStructure, "VHD block table extends past the container");

    const uint64_t sectors_per_block = block_size / kSectorBytes;
    uint64_t bitmap_size = 0;
    if (!align_up((sectors_per_block + 7) / 8, kSectorBytes, bitmap_size))
        return fail(ErrorCode::CorruptStructure, "VHD sector bitmap size overflows");

    std::vector<uint8_t> bat_raw(static_cast<size_t>(bat_bytes));
    auto bat_got = read_fully(*container, bat_offset, bat_raw.data(), bat_raw.size());
    if (!bat_got) return fail(bat_got.error());
    if (*bat_got != bat_raw.size())
        return fail(ErrorCode::CorruptStructure, "VHD block table is truncated");

    ByteView bat_view(bat_raw);
    std::vector<uint32_t> bat(static_cast<size_t>(entries));
    bool warned_truncated = false;
    for (uint64_t i = 0; i < entries; ++i) {
        const uint32_t entry = bat_view.u32be(static_cast<size_t>(i * 4));
        bat[static_cast<size_t>(i)] = entry;
        if (entry == kUnallocatedEntry) continue;
        if (entry > container_bytes || container_bytes - entry < bitmap_size) {
            if (!warned_truncated) {
                log::warn("VHD block table points past the end of the container; "
                          "truncated blocks read back as zeros");
                warned_truncated = true;
            }
        }
    }
    if (bat_view.failed()) return fail(ErrorCode::CorruptStructure, "VHD block table is malformed");

    info.size_bytes = virtual_bytes;
    return std::unique_ptr<VhdDevice>(
        new VhdDevice(std::move(container), std::move(info), block_size, bitmap_size,
                      std::move(bat)));
}

Result<std::unique_ptr<BlockDevice>> open_vhd(std::shared_ptr<BlockDevice> container) {
    if (!container) return fail(ErrorCode::InvalidArgument, "null VHD container");
    // Sector-level translation of a dynamic disk is chatty, so cache container reads.
    std::shared_ptr<BlockDevice> backing =
        std::make_shared<CachedDevice>(std::move(container), kContainerCacheBytes);
    auto dev = VhdDevice::create(std::move(backing));
    if (!dev) return fail(dev.error());
    return std::unique_ptr<BlockDevice>(std::move(*dev));
}

}  // namespace openrecover::io
