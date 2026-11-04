#include "openrecover/carve/signature.hpp"

#include "openrecover/carve/sig_bmp.hpp"
#include "openrecover/carve/sig_cfb.hpp"
#include "openrecover/carve/sig_avi.hpp"
#include "openrecover/carve/sig_mp3.hpp"
#include "openrecover/carve/sig_mp4.hpp"
#include "openrecover/carve/sig_sqlite.hpp"
#include "openrecover/carve/sig_tiff.hpp"
#include "openrecover/carve/sig_generic.hpp"
#include "openrecover/carve/sig_wav.hpp"

#include <nlohmann/json.hpp>

#include <fstream>

#include "openrecover/carve/sig_gif.hpp"
#include "openrecover/carve/sig_jpeg.hpp"
#include "openrecover/carve/sig_pdf.hpp"
#include "openrecover/carve/sig_png.hpp"
#include "openrecover/carve/sig_zip.hpp"

namespace openrecover::carve {

const ISignature* SignatureRegistry::find(std::string_view name) const noexcept {
    for (const ISignature* signature : signatures_) {
        if (signature->name() == name) return signature;
    }
    return nullptr;
}

const SignatureRegistry& SignatureRegistry::builtins() {
    static const SignatureRegistry registry = [] {
        SignatureRegistry result;
        static const JpegSignature jpeg;
        static const PngSignature png;
        static const PdfSignature pdf;
        static const ZipSignature zip;
        static const GifSignature gif;
        static const BmpSignature bmp;
        static const SqliteSignature sqlite;
        static const TiffSignature tiff;
        static const WavSignature wav;
        static const AviSignature avi;
        static const Mp3Signature mp3;
        static const Mp4Signature mp4;
        static const CfbSignature cfb;
        result.add(jpeg);
        result.add(png);
        result.add(pdf);
        result.add(zip);
        result.add(gif);
        result.add(bmp);
        result.add(sqlite);
        result.add(tiff);
        result.add(wav);
        result.add(avi);
        result.add(mp3);
        result.add(mp4);
        result.add(cfb);
        return result;
    }();
    return registry;
}

bool SignatureRegistry::load_from_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    nlohmann::json j;
    try { in >> j; } catch (...) { return false; }
    if (!j.is_array()) return false;
    for (const auto& e : j) {
        if (!e.is_object()) continue;
        if (!e.contains("name") || !e.contains("magic")) continue;
        std::string name = e["name"].get<std::string>();
        std::string hex = e["magic"].get<std::string>();
        std::string ext = e.value("extension", "bin");
        uint64_t maxsz = e.value("max_size", (uint64_t)1024 * 1024);
        std::vector<uint8_t> magic;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            magic.push_back((uint8_t)std::stoi(hex.substr(i, 2), nullptr, 16));
        }
        static std::vector<GenericSignature> owned;
        owned.emplace_back(name, magic, ext, maxsz);
        add(owned.back());
    }
    return true;
}

}  // namespace openrecover::carve