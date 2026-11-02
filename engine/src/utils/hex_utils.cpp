#include "../../include/utils/hex_utils.hpp"
#include <sstream>
#include <iomanip>
#include <cctype>

namespace nce::utils {

uintptr_t parse_address(const std::string& str) {
    if (str.empty()) return 0;
    try {
        if (str.rfind("0x", 0) == 0 || str.rfind("0X", 0) == 0) {
            return std::stoull(str, nullptr, 16);
        }
        return std::stoull(str, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

std::string format_address(uintptr_t address) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setw(sizeof(uintptr_t) * 2) << std::setfill('0') << address;
    return ss.str();
}

std::string format_hex_dump(uintptr_t base_address, const uint8_t* data, size_t size) {
    std::ostringstream ss;
    constexpr size_t bytes_per_line = 16;

    for (size_t i = 0; i < size; i += bytes_per_line) {
        ss << format_address(base_address + i) << ": ";
        
        // Hex bytes
        for (size_t j = 0; j < bytes_per_line; ++j) {
            if (i + j < size) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i + j]) << " ";
            } else {
                ss << "   ";
            }
            if (j == 7) ss << " ";
        }

        ss << " |";
        // ASCII representation
        for (size_t j = 0; j < bytes_per_line; ++j) {
            if (i + j < size) {
                uint8_t c = data[i + j];
                ss << (std::isprint(c) ? static_cast<char>(c) : '.');
            } else {
                ss << " ";
            }
        }
        ss << "|\n";
    }

    return ss.str();
}

std::optional<scanner::AOBPattern> parse_aob_pattern(const std::string& pattern_str) {
    std::istringstream stream(pattern_str);
    std::string token;
    scanner::AOBPattern pattern;

    while (stream >> token) {
        if (token == "?" || token == "??") {
            pattern.bytes.push_back(0);
            pattern.mask.push_back(false);
        } else {
            try {
                auto byte = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
                pattern.bytes.push_back(byte);
                pattern.mask.push_back(true);
            } catch (...) {
                return std::nullopt;
            }
        }
    }

    if (pattern.bytes.empty()) {
        return std::nullopt;
    }

    return pattern;
}

} // namespace nce::utils

