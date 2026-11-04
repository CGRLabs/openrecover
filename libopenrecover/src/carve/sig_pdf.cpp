#include "openrecover/carve/sig_pdf.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "openrecover/carve/bounded_reader.hpp"

namespace openrecover::carve {

namespace {

bool pdf_ws(uint8_t c) {
    return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' ';
}

bool is_delim(uint8_t c) {
    return pdf_ws(c) || c == '/' || c == '[' || c == ']' || c == '<' || c == '>' || c == '(' ||
           c == ')' || c == '%';
}

bool parse_uint_token(std::string_view s, uint64_t& out) {
    if (s.empty()) return false;
    uint64_t value = 0;
    for (char ch : s) {
        if (ch < '0' || ch > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

void skip_ws_sv(std::string_view& s) {
    for (;;) {
        if (!s.empty() && pdf_ws(static_cast<uint8_t>(s.front()))) {
            s.remove_prefix(1);
            continue;
        }
        if (!s.empty() && s.front() == '%') {
            const size_t eol = s.find_first_of("\r\n");
            if (eol == std::string_view::npos) {
                s = {};
            } else {
                s.remove_prefix(eol + 1);
            }
            continue;
        }
        break;
    }
}

bool parse_uint_prefix(std::string_view& s, uint64_t& out) {
    skip_ws_sv(s);
    uint64_t value = 0;
    size_t consumed = 0;
    while (consumed < s.size() && s[consumed] >= '0' && s[consumed] <= '9') {
        const uint64_t digit = static_cast<uint64_t>(s[consumed] - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
        ++consumed;
    }
    if (consumed == 0) return false;
    if (consumed < s.size() && !is_delim(static_cast<uint8_t>(s[consumed]))) return false;
    s.remove_prefix(consumed);
    out = value;
    return true;
}

bool consume_key(std::string_view& s, std::string_view key) {
    for (size_t i = 0; i + key.size() + 1 <= s.size(); ++i) {
        if (s[i] != '/') continue;
        if (s.substr(i + 1, key.size()) != key) continue;
        const size_t after = i + 1 + key.size();
        if (after < s.size() && !is_delim(static_cast<uint8_t>(s[after]))) continue;
        s.remove_prefix(after);
        skip_ws_sv(s);
        return true;
    }
    return false;
}

bool dict_uint(std::string_view dict, std::string_view key, uint64_t& out) {
    std::string_view s = dict;
    if (!consume_key(s, key)) return false;
    return parse_uint_prefix(s, out);
}

bool dict_ref(std::string_view dict, std::string_view key, uint64_t& obj, uint64_t& gen) {
    std::string_view s = dict;
    if (!consume_key(s, key)) return false;
    if (!parse_uint_prefix(s, obj)) return false;
    if (!parse_uint_prefix(s, gen)) return false;
    skip_ws_sv(s);
    if (s.empty() || s.front() != 'R') return false;
    if (s.size() > 1 && !is_delim(static_cast<uint8_t>(s[1]))) return false;
    return true;
}

bool dict_key_present(std::string_view dict, std::string_view key) {
    std::string_view s = dict;
    return consume_key(s, key);
}

bool dict_name(std::string_view dict, std::string_view key, std::string_view name) {
    std::string_view s = dict;
    if (!consume_key(s, key)) return false;
    if (s.empty() || s.front() != '/') return false;
    s.remove_prefix(1);
    if (s.substr(0, name.size()) != name) return false;
    if (s.size() > name.size() && !is_delim(static_cast<uint8_t>(s[name.size()]))) return false;
    return true;
}

bool dict_w(std::string_view dict) {
    std::string_view s = dict;
    if (!consume_key(s, "W")) return false;
    skip_ws_sv(s);
    if (s.empty() || s.front() != '[') return false;
    s.remove_prefix(1);
    uint64_t unused = 0;
    for (int i = 0; i < 3; ++i) {
        if (!parse_uint_prefix(s, unused)) return false;
    }
    return true;
}

struct DictInfo {
    bool has_size = false;
    uint64_t size = 0;
    bool has_root = false;
    uint64_t root_obj = 0;
    uint64_t root_gen = 0;
    bool has_prev = false;
    uint64_t prev = 0;
    bool has_xrefstm = false;
    uint64_t xrefstm = 0;
    bool encrypted = false;
    bool type_xref = false;
    bool w_valid = false;
};

DictInfo parse_dict_info(std::string_view dict) {
    DictInfo info;
    info.has_size = dict_uint(dict, "Size", info.size);
    info.has_root = dict_ref(dict, "Root", info.root_obj, info.root_gen);
    info.has_prev = dict_uint(dict, "Prev", info.prev);
    info.has_xrefstm = dict_uint(dict, "XRefStm", info.xrefstm);
    info.encrypted = dict_key_present(dict, "Encrypt");
    info.type_xref = dict_name(dict, "Type", "XRef");
    info.w_valid = dict_w(dict);
    return info;
}

class PdfCursor {
public:
    PdfCursor(BoundedReader& reader, uint64_t pos, uint64_t end)
        : reader_(reader), pos_(pos), end_(end) {}

    BoundedReader& reader() const noexcept { return reader_; }
    uint64_t pos() const noexcept { return pos_; }
    uint64_t end() const noexcept { return end_; }
    bool eof() const noexcept { return pos_ >= end_; }

    bool peek(uint8_t& c) {
        if (eof()) return false;
        auto value = reader_.u8(pos_);
        if (!value) return false;
        c = *value;
        return true;
    }

    bool take(uint8_t& c) {
        if (!peek(c)) return false;
        ++pos_;
        return true;
    }

    bool skip_ws() {
        while (!eof()) {
            auto c = reader_.u8(pos_);
            if (!c) return false;
            if (pdf_ws(*c)) {
                ++pos_;
                continue;
            }
            if (*c == '%') {
                while (!eof()) {
                    auto b = reader_.u8(pos_++);
                    if (!b) return false;
                    if (*b == '\r' || *b == '\n') break;
                }
                continue;
            }
            break;
        }
        return true;
    }

    bool consume_eol() {
        while (!eof()) {
            auto c = reader_.u8(pos_);
            if (!c) return false;
            if (*c == ' ' || *c == '\t') {
                ++pos_;
                continue;
            }
            if (*c == '\r') {
                ++pos_;
                auto next = reader_.u8(pos_);
                if (next && *next == '\n') ++pos_;
                return true;
            }
            if (*c == '\n') {
                ++pos_;
                return true;
            }
            return false;
        }
        return false;
    }

    bool read_exact(size_t n, std::string& out) {
        if (end_ - pos_ < n) return false;
        auto bytes = reader_.read_vec(pos_, n);
        if (!bytes || bytes->size() != n) return false;
        out.assign(reinterpret_cast<const char*>(bytes->data()), n);
        pos_ += n;
        return true;
    }

    bool advance(uint64_t n) {
        if (end_ - pos_ < n) return false;
        pos_ += n;
        return true;
    }

    bool read_word(std::string& out, size_t max_len = 64) {
        if (!skip_ws()) return false;
        out.clear();
        while (!eof()) {
            auto c = reader_.u8(pos_);
            if (!c) return false;
            if (pdf_ws(*c) || *c == '/' || *c == '<' || *c == '>' || *c == '[' || *c == ']' ||
                *c == '%' || *c == '(' || *c == ')') {
                break;
            }
            if (out.size() >= max_len) return false;
            out.push_back(static_cast<char>(*c));
            ++pos_;
        }
        return !out.empty();
    }

    bool read_uint(uint64_t& out) {
        std::string word;
        if (!read_word(word, 32)) return false;
        return parse_uint_token(word, out);
    }

    bool read_dict(std::string& out, size_t max_len) {
        if (!skip_ws()) return false;
        std::string open;
        if (!read_exact(2, open) || open != "<<") return false;
        out = "<<";
        uint32_t depth = 1;
        while (depth > 0) {
            if (out.size() >= max_len) return false;
            uint8_t c = 0;
            if (!take(c)) return false;
            if (c == '<') {
                uint8_t next = 0;
                if (peek(next) && next == '<') {
                    take(next);
                    out += "<<";
                    ++depth;
                    continue;
                }
            } else if (c == '>') {
                uint8_t next = 0;
                if (peek(next) && next == '>') {
                    take(next);
                    out += ">>";
                    --depth;
                    continue;
                }
            }
            out.push_back(static_cast<char>(c));
        }
        return true;
    }

private:
    BoundedReader& reader_;
    uint64_t pos_;
    uint64_t end_;
};

struct XrefEntry {
    uint64_t offset = 0;
    uint64_t generation = 0;
    uint64_t objnum = 0;
    bool in_use = false;
};

bool parse_digits_field(std::string_view s, uint64_t& out) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return parse_uint_token(s, out);
}

bool parse_xref_entry(std::string_view line, XrefEntry& entry) {
    if (line.size() < 18) return false;
    if (!pdf_ws(static_cast<uint8_t>(line[10])) ||
        !pdf_ws(static_cast<uint8_t>(line[16])))
        return false;
    if (line[17] != 'n' && line[17] != 'f') return false;
    if (!parse_digits_field(line.substr(0, 10), entry.offset)) return false;
    if (!parse_digits_field(line.substr(11, 5), entry.generation)) return false;
    entry.in_use = line[17] == 'n';
    return true;
}

bool read_window(BoundedReader& reader, uint64_t offset, uint64_t length, std::string& out) {
    if (length == 0) {
        out.clear();
        return true;
    }
    auto bytes = reader.read_vec(offset, static_cast<size_t>(length));
    if (!bytes) return false;
    out.assign(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return true;
}

bool object_header_matches(BoundedReader& reader, uint64_t offset, uint64_t objnum,
                           uint64_t generation, uint64_t eof) {
    if (offset >= eof) return false;
    std::string text;
    if (!read_window(reader, offset, std::min<uint64_t>(64, eof - offset), text)) return false;
    std::string_view s(text);
    uint64_t found_obj = 0;
    uint64_t found_gen = 0;
    if (!parse_uint_prefix(s, found_obj)) return false;
    if (!parse_uint_prefix(s, found_gen)) return false;
    skip_ws_sv(s);
    if (s.substr(0, 3) != "obj") return false;
    if (s.size() > 3 && !is_delim(static_cast<uint8_t>(s[3]))) return false;
    return found_obj == objnum && found_gen == generation;
}

bool object_is_catalog(BoundedReader& reader, uint64_t offset, uint64_t eof) {
    if (offset >= eof) return false;
    std::string text;
    if (!read_window(reader, offset, std::min<uint64_t>(8192, eof - offset), text)) return false;
    return dict_name(text, "Type", "Catalog");
}

bool parse_classic_xref(PdfCursor& cursor, uint64_t eof, DictInfo& dict, bool& low,
                        bool& root_verified) {
    std::vector<XrefEntry> entries;
    uint64_t subsections = 0;
    for (;;) {
        std::string word;
        if (!cursor.read_word(word, 32)) return false;
        if (word == "trailer") break;
        if (++subsections > 1024) return false;
        uint64_t first = 0;
        if (!parse_uint_token(word, first)) return false;
        uint64_t count = 0;
        if (!cursor.read_uint(count)) return false;
        if (count > (cursor.end() - cursor.pos()) / 20) return false;
        if (!cursor.consume_eol()) return false;
        for (uint64_t i = 0; i < count; ++i) {
            // Bounded storage keeps hostile subsection counts from exhausting memory.
            if (entries.size() < 4096) {
                std::string line;
                if (!cursor.read_exact(20, line)) return false;
                XrefEntry entry;
                if (!parse_xref_entry(line, entry)) return false;
                entry.objnum = first + i;
                entries.push_back(entry);
            } else if (!cursor.advance(20)) {
                return false;
            }
        }
    }

    std::string trailer;
    if (!cursor.read_dict(trailer, 65536)) return false;
    dict = parse_dict_info(trailer);
    if (!dict.has_size) return false;
    if (!dict.has_root && !dict.has_xrefstm) return false;

    size_t samples = 0;
    size_t matches = 0;
    for (const XrefEntry& entry : entries) {
        if (!entry.in_use) continue;
        if (samples == 16) break;
        ++samples;
        if (object_header_matches(cursor.reader(), entry.offset, entry.objnum, entry.generation,
                                  eof)) {
            ++matches;
        }
    }
    if (samples == 0 || matches == 0) return false;
    if (matches * 10 < samples * 9) low = true;

    if (dict.has_root) {
        for (const XrefEntry& entry : entries) {
            if (!entry.in_use || entry.objnum != dict.root_obj) continue;
            if (entry.generation != dict.root_gen) continue;
            if (object_header_matches(cursor.reader(), entry.offset, entry.objnum, entry.generation,
                                      eof) &&
                object_is_catalog(cursor.reader(), entry.offset, eof)) {
                root_verified = true;
            }
            break;
        }
    }
    return true;
}

bool parse_xref_stream(PdfCursor& cursor, uint64_t eof, DictInfo& dict, bool& root_verified) {
    std::string text;
    const uint64_t dict_start = cursor.pos();
    if (!cursor.read_dict(text, 65536)) return false;
    dict = parse_dict_info(text);
    if (!dict.has_size || !dict.has_root || !dict.type_xref || !dict.w_valid) return false;
    if (!cursor.skip_ws()) return false;
    if (cursor.pos() - dict_start > 1024) return false;
    std::string keyword;
    if (!cursor.read_word(keyword, 16) || keyword != "stream") return false;
    root_verified = false;
    (void)eof;
    return true;
}

struct XrefResult {
    bool low = false;
    bool root_verified = false;
    bool encrypted = false;
    std::vector<uint64_t> chain;
};

bool parse_xref_chain(BoundedReader& reader, uint64_t start, uint64_t eof, XrefResult& result) {
    std::set<uint64_t> visited;
    uint64_t pos = start;
    for (int depth = 0; depth < 64; ++depth) {
        if (pos >= eof || !visited.insert(pos).second) return false;
        PdfCursor cursor(reader, pos, eof);
        std::string word;
        if (!cursor.read_word(word, 32)) return false;

        DictInfo dict;
        bool low = false;
        bool root_verified = false;
        if (word == "xref") {
            if (!parse_classic_xref(cursor, eof, dict, low, root_verified)) return false;
        } else {
            uint64_t objnum = 0;
            uint64_t generation = 0;
            std::string keyword;
            if (!parse_uint_token(word, objnum)) return false;
            if (!cursor.read_uint(generation)) return false;
            if (!cursor.read_word(keyword, 16) || keyword != "obj") return false;
            if (!parse_xref_stream(cursor, eof, dict, root_verified)) return false;
        }

        result.chain.push_back(pos);
        if (low) result.low = true;
        if (depth == 0) result.root_verified = root_verified;
        if (dict.encrypted) result.encrypted = true;
        if (!dict.has_prev) return true;
        if (dict.prev >= eof || dict.prev == pos) return false;
        pos = dict.prev;
    }
    return false;
}

std::vector<uint64_t> find_token(BoundedReader& reader, uint64_t from, uint64_t to,
                                 std::string_view token, size_t max_hits) {
    std::vector<uint64_t> hits;
    if (token.empty() || from >= to || max_hits == 0) return hits;
    constexpr size_t kChunk = 64u << 10;
    std::vector<uint8_t> buffer(kChunk + token.size());
    uint64_t pos = from;
    uint64_t last = UINT64_MAX;
    while (pos < to && hits.size() < max_hits) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(kChunk, to - pos));
        auto got = reader.read_at(pos, buffer.data(), want);
        if (!got || *got == 0) break;
        const size_t n = *got;
        size_t i = 0;
        while (i + token.size() <= n) {
            const auto it = std::search(buffer.begin() + static_cast<std::ptrdiff_t>(i),
                                        buffer.begin() + static_cast<std::ptrdiff_t>(n),
                                        token.begin(), token.end());
            if (it == buffer.begin() + static_cast<std::ptrdiff_t>(n)) break;
            const size_t idx = static_cast<size_t>(it - buffer.begin());
            const uint64_t absolute = pos + idx;
            if (absolute != last) {
                hits.push_back(absolute);
                last = absolute;
                if (hits.size() >= max_hits) break;
            }
            i = idx + 1;
        }
        if (*got < want) break;
        const size_t overlap = token.size() - 1;
        if (n <= overlap) break;
        pos += n - overlap;
    }
    return hits;
}

bool find_last_token(BoundedReader& reader, uint64_t from, uint64_t to, std::string_view token,
                     uint64_t& out) {
    if (token.empty() || from >= to) return false;
    constexpr size_t kChunk = 1u << 20;
    std::vector<uint8_t> buffer(kChunk + token.size());
    uint64_t pos = from;
    bool found = false;
    while (pos < to) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(kChunk, to - pos));
        auto got = reader.read_at(pos, buffer.data(), want);
        if (!got || *got == 0) break;
        const size_t n = *got;
        size_t i = 0;
        while (i + token.size() <= n) {
            const auto it = std::search(buffer.begin() + static_cast<std::ptrdiff_t>(i),
                                        buffer.begin() + static_cast<std::ptrdiff_t>(n),
                                        token.begin(), token.end());
            if (it == buffer.begin() + static_cast<std::ptrdiff_t>(n)) break;
            const size_t idx = static_cast<size_t>(it - buffer.begin());
            out = pos + idx;
            found = true;
            i = idx + 1;
        }
        if (*got < want) break;
        const size_t overlap = token.size() - 1;
        if (n <= overlap) break;
        pos += n - overlap;
    }
    return found;
}

bool parse_startxref(const std::string& window, uint64_t& xref) {
    const size_t at = window.rfind("startxref");
    if (at == std::string::npos) return false;
    if (at > 0 && !is_delim(static_cast<uint8_t>(window[at - 1]))) return false;
    std::string_view s(window.data() + at + 9, window.size() - at - 9);
    skip_ws_sv(s);
    if (!parse_uint_prefix(s, xref)) return false;
    skip_ws_sv(s);
    return s.empty();
}

uint64_t candidate_end(BoundedReader& reader, uint64_t eof, uint64_t limit) {
    uint64_t end = eof + 5;
    if (end >= limit) return end;
    auto c = reader.u8(end);
    if (!c) return end;
    if (*c == '\r') {
        ++end;
        auto next = reader.u8(end);
        if (next && *next == '\n') ++end;
    } else if (*c == '\n') {
        ++end;
    } else if (*c == ' ' || *c == '\t' || *c == 0) {
        ++end;
    }
    return end;
}

bool pdf_version(const std::vector<uint8_t>& header, std::string& subtype) {
    if (header.size() < 8) return false;
    if (std::memcmp(header.data(), "%PDF-", 5) != 0) return false;
    const char a = static_cast<char>(header[5]);
    const char b = static_cast<char>(header[6]);
    const char c = static_cast<char>(header[7]);
    bool ok = false;
    if (a == '1' && b == '.' && c >= '0' && c <= '7') ok = true;
    if (a == '2' && b == '.' && c == '0') ok = true;
    if (!ok) return false;
    subtype = "pdf-";
    subtype.push_back(a);
    subtype.push_back(b);
    subtype.push_back(c);
    return true;
}

void check_linearized_length(BoundedReader& reader, uint64_t limit, uint64_t length,
                             bool& mismatch) {
    mismatch = false;
    if (limit <= 9) return;
    std::string text;
    if (!read_window(reader, 9, std::min<uint64_t>(4096, limit - 9), text)) return;

    // The indicator only counts when it belongs to the first object after the header.
    std::string_view s(text);
    skip_ws_sv(s);
    uint64_t objnum = 0;
    uint64_t generation = 0;
    if (!parse_uint_prefix(s, objnum) || !parse_uint_prefix(s, generation)) return;
    skip_ws_sv(s);
    if (s.substr(0, 3) != "obj") return;
    s.remove_prefix(3);
    if (!s.empty() && !is_delim(static_cast<uint8_t>(s.front()))) return;
    skip_ws_sv(s);
    if (s.substr(0, 2) != "<<") return;
    s = s.substr(0, std::min<size_t>(s.size(), 1024));
    if (s.find("/Linearized") == std::string_view::npos) return;
    uint64_t declared = 0;
    if (!dict_uint(s, "L", declared)) return;
    mismatch = declared != length;
}

}  // namespace

std::span<const std::span<const uint8_t>> PdfSignature::magics() const {
    static const uint8_t m10[] = {'%', 'P', 'D', 'F', '-', '1', '.', '0'};
    static const uint8_t m11[] = {'%', 'P', 'D', 'F', '-', '1', '.', '1'};
    static const uint8_t m12[] = {'%', 'P', 'D', 'F', '-', '1', '.', '2'};
    static const uint8_t m13[] = {'%', 'P', 'D', 'F', '-', '1', '.', '3'};
    static const uint8_t m14[] = {'%', 'P', 'D', 'F', '-', '1', '.', '4'};
    static const uint8_t m15[] = {'%', 'P', 'D', 'F', '-', '1', '.', '5'};
    static const uint8_t m16[] = {'%', 'P', 'D', 'F', '-', '1', '.', '6'};
    static const uint8_t m17[] = {'%', 'P', 'D', 'F', '-', '1', '.', '7'};
    static const uint8_t m20[] = {'%', 'P', 'D', 'F', '-', '2', '.', '0'};
    static const std::span<const uint8_t> list[] = {m10, m11, m12, m13, m14,
                                                    m15, m16, m17, m20};
    return list;
}

ValidationResult PdfSignature::validate(BoundedReader& reader) const {
    const uint64_t limit = reader.limit();
    if (limit < 9) return ValidationResult::invalid();
    auto header = reader.read_vec(0, 8);
    if (!header || header->size() != 8) return ValidationResult::invalid();
    std::string subtype;
    if (!pdf_version(*header, subtype)) return ValidationResult::invalid();
    auto eol = reader.u8(8);
    if (!eol || (*eol != '\r' && *eol != '\n' && *eol != ' '))
        return ValidationResult::invalid();

    std::vector<std::string> notes;

    auto comment_bytes = reader.read_vec(9, 16);
    if (comment_bytes && !comment_bytes->empty() && (*comment_bytes)[0] == '%') {
        size_t high = 0;
        for (size_t i = 1; i < comment_bytes->size(); ++i) {
            if ((*comment_bytes)[i] >= 0x80) ++high;
        }
        if (high >= 4) notes.push_back("binary_comment");
    }

    const std::vector<uint64_t> eofs = find_token(reader, 0, limit, "%%EOF", 4096);

    uint64_t valid_end = 0;
    bool have_valid = false;
    uint64_t last_xref = 0;
    uint64_t last_eof = 0;
    XrefResult latest;
    bool stop = false;

    for (uint64_t eof_pos : eofs) {
        if (stop) break;
        const uint64_t window_start = eof_pos > 1024 ? eof_pos - 1024 : 0;
        std::string window;
        if (!read_window(reader, window_start, eof_pos - window_start, window)) continue;
        uint64_t xref_pos = 0;
        if (!parse_startxref(window, xref_pos)) continue;
        if (xref_pos >= eof_pos) continue;
        // A revision appended after an earlier %%EOF keeps its xref after that
        // EOF. Anything else belongs to a different document carved next door.
        if (have_valid && xref_pos <= last_eof) {
            stop = true;
            break;
        }

        XrefResult result;
        if (!parse_xref_chain(reader, xref_pos, eof_pos, result)) continue;

        if (!have_valid) {
            have_valid = true;
        } else {
            const bool linked = std::find(result.chain.begin(), result.chain.end(), last_xref) !=
                                result.chain.end();
            if (!linked) {
                stop = true;
                break;
            }
        }
        latest = std::move(result);
        last_xref = xref_pos;
        last_eof = eof_pos;
        valid_end = candidate_end(reader, eof_pos, limit);
        if (latest.encrypted) {
            if (std::find(notes.begin(), notes.end(), "encrypted") == notes.end())
                notes.push_back("encrypted");
        }
    }

    if (have_valid) {
        if (valid_end > limit) valid_end = limit;
        bool linearized_mismatch = false;
        check_linearized_length(reader, limit, valid_end, linearized_mismatch);
        if (linearized_mismatch) notes.push_back("linearized_length_mismatch");

        ValidationResult result;
        result.verdict = ValidationResult::Verdict::Valid;
        result.length_bytes = valid_end;
        result.subtype = subtype;
        result.notes = notes;
        if (latest.low) {
            result.confidence = Confidence::Low;
        } else if (linearized_mismatch || !latest.root_verified) {
            result.confidence = Confidence::Medium;
        } else {
            result.confidence = Confidence::High;
        }
        return result;
    }

    if (!eofs.empty()) return ValidationResult::invalid();

    uint64_t last_endobj = 0;
    if (!find_last_token(reader, 9, limit, "endobj", last_endobj))
        return ValidationResult::invalid();
    const std::vector<uint64_t> objects = find_token(reader, 9, last_endobj, "obj", 1);
    if (objects.empty()) return ValidationResult::invalid();
    uint64_t length = last_endobj + 6;
    if (length > limit) length = limit;

    ValidationResult result;
    result.verdict = ValidationResult::Verdict::ValidTruncated;
    result.length_bytes = length;
    result.subtype = subtype;
    result.confidence = Confidence::Low;
    result.notes = notes;
    result.notes.push_back("truncated_no_eof");
    return result;
}

}  // namespace openrecover::carve
