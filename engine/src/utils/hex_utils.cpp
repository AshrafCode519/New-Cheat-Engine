#include "../../include/utils/hex_utils.hpp"
#include <sstream>
#include <iomanip>
#include <cctype>
#include <charconv>
#include <system_error>
#include <cmath>

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

std::string trim_cr(std::string line) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

std::optional<scanner::DataType> parse_data_type(const std::string& type_str) {
    using scanner::DataType;
    if (type_str == "i8") return DataType::Int8;
    if (type_str == "i16") return DataType::Int16;
    if (type_str == "i32" || type_str == "int") return DataType::Int32;
    if (type_str == "i64") return DataType::Int64;
    if (type_str == "u8") return DataType::UInt8;
    if (type_str == "u16") return DataType::UInt16;
    if (type_str == "u32") return DataType::UInt32;
    if (type_str == "u64") return DataType::UInt64;
    if (type_str == "f32" || type_str == "float") return DataType::Float;
    if (type_str == "f64" || type_str == "double") return DataType::Double;
    if (type_str == "str" || type_str == "string") return DataType::String;
    if (type_str == "wstr" || type_str == "utf16") return DataType::String16;
    if (type_str == "aob") return DataType::AOB;
    return std::nullopt;
}

std::string format_data_type(scanner::DataType type) {
    using scanner::DataType;
    switch (type) {
        case DataType::Int8:     return "i8";
        case DataType::Int16:    return "i16";
        case DataType::Int32:    return "i32";
        case DataType::Int64:    return "i64";
        case DataType::UInt8:    return "u8";
        case DataType::UInt16:   return "u16";
        case DataType::UInt32:   return "u32";
        case DataType::UInt64:   return "u64";
        case DataType::Float:    return "f32";
        case DataType::Double:   return "f64";
        case DataType::String:   return "str";
        case DataType::String16: return "wstr";
        case DataType::AOB:      return "aob";
    }
    return "?";
}

std::optional<scanner::ScanValue> parse_scan_value(scanner::DataType type, const std::string& value_str) {
    std::optional<scanner::ScanValue> result;
    if (value_str.empty()) return result;

    scanner::dispatch_numeric(type, [&]<typename T>() {
        const char* first = value_str.data();
        const char* last = first + value_str.size();
        T value{};
        auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec == std::errc() && ptr == last) {
            scanner::ScanValue sv;
            sv.type = type;
            sv.value = value;
            result = sv;
        }
    });

    return result;
}

std::optional<std::pair<double, double>> float_match_range(const std::string& value_str, scanner::FloatMatchMode mode) {
    if (mode == scanner::FloatMatchMode::Exact || value_str.empty()) return std::nullopt;
    if (value_str.find_first_not_of("+-0123456789.") != std::string::npos) return std::nullopt; // e-notation, inf, nan

    const char* first = value_str.data();
    const char* last = first + value_str.size();
    double value = 0.0;
    auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc() || ptr != last) return std::nullopt;

    const size_t dot = value_str.find('.');
    const int decimals = (dot == std::string::npos) ? 0 : static_cast<int>(value_str.size() - dot - 1);
    const double unit = std::pow(10.0, -decimals);
    const bool negative = (value_str[0] == '-');

    if (mode == scanner::FloatMatchMode::Rounded) {
        return std::make_pair(value - unit / 2, std::nextafter(value + unit / 2, value)); // [v - u/2, v + u/2)
    }
    if (!negative) {
        return std::make_pair(value, std::nextafter(value + unit, value));                // [v, v + u)
    }
    return std::make_pair(std::nextafter(value - unit, value), value);                    // (v - u, v]
}

} // namespace nce::utils

