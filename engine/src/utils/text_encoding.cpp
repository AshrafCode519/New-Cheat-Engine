#include "../../include/utils/text_encoding.hpp"

namespace nce::utils {

namespace {

void push_utf16_unit(std::vector<uint8_t>& out, uint32_t unit) {
    out.push_back(static_cast<uint8_t>(unit & 0xFF));
    out.push_back(static_cast<uint8_t>(unit >> 8));
}

void append_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

} // anonymous namespace

std::optional<std::vector<uint8_t>> utf8_to_utf16le(std::string_view utf8) {
    // Smallest code point each sequence length may encode (anything lower is an overlong form)
    constexpr uint32_t min_code_point[] = {0, 0, 0x80, 0x800, 0x10000};

    std::vector<uint8_t> out;
    out.reserve(utf8.size() * 2);

    size_t i = 0;
    while (i < utf8.size()) {
        const auto lead = static_cast<uint8_t>(utf8[i]);
        uint32_t cp = 0;
        size_t length = 0;

        if (lead < 0x80)                { cp = lead;        length = 1; }
        else if ((lead & 0xE0) == 0xC0) { cp = lead & 0x1F; length = 2; }
        else if ((lead & 0xF0) == 0xE0) { cp = lead & 0x0F; length = 3; }
        else if ((lead & 0xF8) == 0xF0) { cp = lead & 0x07; length = 4; }
        else return std::nullopt;

        if (i + length > utf8.size()) return std::nullopt;
        for (size_t k = 1; k < length; ++k) {
            const auto cont = static_cast<uint8_t>(utf8[i + k]);
            if ((cont & 0xC0) != 0x80) return std::nullopt;
            cp = (cp << 6) | (cont & 0x3F);
        }

        if (cp < min_code_point[length] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return std::nullopt;
        }

        if (cp < 0x10000) {
            push_utf16_unit(out, cp);
        } else {
            cp -= 0x10000;
            push_utf16_unit(out, 0xD800 + (cp >> 10));
            push_utf16_unit(out, 0xDC00 + (cp & 0x3FF));
        }
        i += length;
    }

    return out;
}

std::string utf16le_to_utf8(const uint8_t* data, size_t size) {
    std::string out;
    out.reserve(size);

    size_t i = 0;
    while (i + 1 < size) {
        const uint32_t unit = data[i] | (static_cast<uint32_t>(data[i + 1]) << 8);
        i += 2;

        if (unit >= 0xD800 && unit <= 0xDBFF && i + 1 < size) {
            const uint32_t low = data[i] | (static_cast<uint32_t>(data[i + 1]) << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                append_utf8(out, 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
                i += 2;
                continue;
            }
        }

        append_utf8(out, (unit >= 0xD800 && unit <= 0xDFFF) ? 0xFFFD : unit);
    }

    return out;
}

} // namespace nce::utils
