#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace openrecover::test {

struct JpegOptions {
    bool jfif = true;
    bool exif_thumbnail = false;
    bool bad_exif = false;
    bool eoi = true;
    bool fill_bytes = false;
    bool rst_markers = false;
    bool entropy = true;
    bool progressive = false;
    bool zero_width = false;
    int sof_count = 1;
};

inline void append_bytes(std::vector<uint8_t>& out, std::initializer_list<uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

inline void append_u16be(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

inline void append_marker(std::vector<uint8_t>& out, uint8_t marker) {
    append_bytes(out, {0xFF, marker});
}

inline void append_segment(std::vector<uint8_t>& out, uint8_t marker,
                           const std::vector<uint8_t>& payload) {
    append_marker(out, marker);
    append_u16be(out, static_cast<uint16_t>(payload.size() + 2));
    out.insert(out.end(), payload.begin(), payload.end());
}

inline std::vector<uint8_t> app0_payload() {
    std::vector<uint8_t> p;
    append_bytes(p, {'J', 'F', 'I', 'F', 0x00});
    append_bytes(p, {0x01, 0x01, 0x00});
    append_u16be(p, 1);
    append_u16be(p, 1);
    append_bytes(p, {0x00, 0x00});
    return p;
}

inline std::vector<uint8_t> dqt_payload() {
    std::vector<uint8_t> p{0x00};
    p.insert(p.end(), 64, 0x01);
    return p;
}

inline std::vector<uint8_t> dht_payload() {
    std::vector<uint8_t> p{0x00};
    for (int i = 0; i < 16; ++i) p.push_back(i == 0 ? 1 : 0);
    p.push_back(0x00);
    return p;
}

inline std::vector<uint8_t> sof_payload(uint16_t width, uint16_t height) {
    std::vector<uint8_t> p;
    append_bytes(p, {0x08});
    append_u16be(p, height);
    append_u16be(p, width);
    append_bytes(p, {0x03});
    for (uint8_t id = 1; id <= 3; ++id)
        append_bytes(p, {id, 0x11, 0x00});
    return p;
}

inline std::vector<uint8_t> sos_payload(uint8_t components, uint8_t ss, uint8_t se) {
    std::vector<uint8_t> p{components};
    for (uint8_t id = 1; id <= components; ++id)
        append_bytes(p, {id, static_cast<uint8_t>(id == 1 ? 0x00 : 0x11)});
    append_bytes(p, {ss, se, 0x00});
    return p;
}

inline std::vector<uint8_t> app1_exif_payload(bool bad_tiff) {
    std::vector<uint8_t> p;
    append_bytes(p, {'E', 'x', 'i', 'f', 0x00, 0x00});
    if (bad_tiff) {
        append_bytes(p, {'X', 'X', '*', 0x00});
    } else {
        append_bytes(p, {'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00});
        // Embedded thumbnail JPEG: the outer validator must include, not parse, it.
        append_bytes(p, {0xFF, 0xD8, 0xFF, 0xD9});
    }
    append_bytes(p, {0x00, 0x00, 0x00, 0x00});
    return p;
}

inline std::vector<uint8_t> make_jpeg(const JpegOptions& options = {}) {
    std::vector<uint8_t> out;
    append_bytes(out, {0xFF, 0xD8});
    if (options.fill_bytes) out.push_back(0xFF);

    if (options.jfif) append_segment(out, 0xE0, app0_payload());
    if (options.exif_thumbnail || options.bad_exif) {
        std::vector<uint8_t> payload = app1_exif_payload(options.bad_exif);
        append_marker(out, 0xE1);
        append_u16be(out, static_cast<uint16_t>(payload.size() + 2));
        out.insert(out.end(), payload.begin(), payload.end());
    }
    append_segment(out, 0xDB, dqt_payload());

    for (int i = 0; i < options.sof_count; ++i) {
        const uint16_t width = options.zero_width ? 0 : 16;
        const uint8_t marker = options.progressive ? 0xC2 : 0xC0;
        std::vector<uint8_t> payload = sof_payload(width, 16);
        append_marker(out, marker);
        append_u16be(out, static_cast<uint16_t>(payload.size() + 2));
        out.insert(out.end(), payload.begin(), payload.end());
    }

    append_segment(out, 0xC4, dht_payload());

    auto append_scan = [&](uint8_t components, uint8_t ss, uint8_t se) {
        std::vector<uint8_t> payload = sos_payload(components, ss, se);
        append_marker(out, 0xDA);
        append_u16be(out, static_cast<uint16_t>(payload.size() + 2));
        out.insert(out.end(), payload.begin(), payload.end());
        if (!options.entropy) return;
        append_bytes(out, {0x12, 0x34, 0x56});
        if (options.rst_markers) append_bytes(out, {0xFF, 0xD0, 0x78, 0xFF, 0x00, 0x9A});
    };

    append_scan(3, 0, 63);
    if (options.progressive) append_scan(1, 1, 63);
    if (options.eoi) append_bytes(out, {0xFF, 0xD9});
    return out;
}

}  // namespace openrecover::test
