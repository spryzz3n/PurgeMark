#include "pm/canonical_json.hpp"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <utility>
#include <vector>

namespace pm {

namespace {

constexpr std::int64_t kMaxSafeInteger = (std::int64_t{1} << 53) - 1;

// Decodes UTF-8 to UTF-16 code units; nullopt on malformed input
// (overlongs, surrogates, out-of-range code points, truncation).
std::optional<std::u16string> utf8_to_utf16(const std::string& s) {
    std::u16string out;
    for (std::size_t i = 0; i < s.size();) {
        const auto b0 = static_cast<unsigned char>(s[i]);
        std::uint32_t cp = 0;
        std::size_t len = 0;
        if (b0 < 0x80) cp = b0, len = 1;
        else if ((b0 & 0xE0) == 0xC0) cp = b0 & 0x1FU, len = 2;
        else if ((b0 & 0xF0) == 0xE0) cp = b0 & 0x0FU, len = 3;
        else if ((b0 & 0xF8) == 0xF0) cp = b0 & 0x07U, len = 4;
        else return std::nullopt;
        if (i + len > s.size()) return std::nullopt;
        for (std::size_t k = 1; k < len; ++k) {
            const auto b = static_cast<unsigned char>(s[i + k]);
            if ((b & 0xC0) != 0x80) return std::nullopt;
            cp = (cp << 6) | (b & 0x3FU);
        }
        static constexpr std::uint32_t min_for_len[] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp < min_for_len[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return std::nullopt;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
        } else {
            out.push_back(static_cast<char16_t>(cp));
        }
        i += len;
    }
    return out;
}

void write_string(const std::string& s, std::string& out) {
    out.push_back('"');
    for (const char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out.push_back(c);  // everything else, including non-ASCII UTF-8, verbatim
                }
        }
    }
    out.push_back('"');
}

Result<bool> write_value(const nlohmann::json& v, std::string& out) {
    using nlohmann::json;
    switch (v.type()) {
        case json::value_t::null: out += "null"; break;
        case json::value_t::boolean: out += v.get<bool>() ? "true" : "false"; break;
        case json::value_t::number_integer: {
            const auto n = v.get<std::int64_t>();
            if (n > kMaxSafeInteger || n < -kMaxSafeInteger) return Result<bool>::fail("integer outside ±2^53");
            out += std::to_string(n);
            break;
        }
        case json::value_t::number_unsigned: {
            const auto n = v.get<std::uint64_t>();
            if (n > static_cast<std::uint64_t>(kMaxSafeInteger)) return Result<bool>::fail("integer outside ±2^53");
            out += std::to_string(n);
            break;
        }
        case json::value_t::number_float: return Result<bool>::fail("floating-point numbers are not allowed");
        case json::value_t::string: {
            const auto& s = v.get_ref<const std::string&>();
            if (!utf8_to_utf16(s)) return Result<bool>::fail("string is not valid UTF-8");
            write_string(s, out);
            break;
        }
        case json::value_t::array: {
            out.push_back('[');
            bool first = true;
            for (const auto& item : v) {
                if (!first) out.push_back(',');
                first = false;
                if (auto r = write_value(item, out); !r) return r;
            }
            out.push_back(']');
            break;
        }
        case json::value_t::object: {
            std::vector<std::pair<std::u16string, const std::string*>> keys;
            for (auto it = v.begin(); it != v.end(); ++it) {
                auto k16 = utf8_to_utf16(it.key());
                if (!k16) return Result<bool>::fail("object key is not valid UTF-8");
                keys.emplace_back(std::move(*k16), &it.key());
            }
            std::sort(keys.begin(), keys.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
            out.push_back('{');
            bool first = true;
            for (const auto& [k16, key] : keys) {
                if (!first) out.push_back(',');
                first = false;
                write_string(*key, out);
                out.push_back(':');
                if (auto r = write_value(v.at(*key), out); !r) return r;
            }
            out.push_back('}');
            break;
        }
        case json::value_t::binary:
        case json::value_t::discarded: return Result<bool>::fail("unsupported JSON value");
    }
    return Result<bool>::ok(true);
}

}  // namespace

Result<std::string> canonicalize(const nlohmann::json& value) {
    std::string out;
    if (auto r = write_value(value, out); !r) return Result<std::string>::fail(r.error());
    return Result<std::string>::ok(std::move(out));
}

}  // namespace pm
