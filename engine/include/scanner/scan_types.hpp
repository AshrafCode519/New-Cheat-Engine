#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <variant>
#include <cmath>
#include <sstream>
#include <iomanip>
#include "../utils/text_encoding.hpp"

namespace nce::scanner {

enum class DataType {
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    String,   // UTF-8 / ASCII bytes, stored as std::string
    String16, // UTF-16LE bytes (wide strings), stored as std::vector<uint8_t>
    AOB
};

// How an exact float/double value typed by the user is matched (Cheat Engine style).
// Rounded: "25.5" matches anything that rounds to 25.5 at one decimal; Truncated: anything that
// truncates to it; Exact: within a fixed epsilon.
enum class FloatMatchMode {
    Rounded,
    Truncated,
    Exact
};

enum class ScanCondition {
    ExactValue,
    GreaterThan,
    LessThan,
    Between,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy,
    DecreasedBy
};

struct ScanValue {
    DataType type{DataType::Int32};
    std::variant<
        int8_t, int16_t, int32_t, int64_t,
        uint8_t, uint16_t, uint32_t, uint64_t,
        float, double,
        std::string,
        std::vector<uint8_t>
    > value{static_cast<int32_t>(0)};

    template <typename T>
    [[nodiscard]] static ScanValue of(DataType type, T v) {
        ScanValue sv;
        sv.type = type;
        sv.value = std::move(v);
        return sv;
    }

    [[nodiscard]] size_t size() const noexcept {
        switch (type) {
            case DataType::Int8:   case DataType::UInt8:  return 1;
            case DataType::Int16:  case DataType::UInt16: return 2;
            case DataType::Int32:  case DataType::UInt32: return 4;
            case DataType::Int64:  case DataType::UInt64: return 8;
            case DataType::Float:                         return sizeof(float);
            case DataType::Double:                        return sizeof(double);
            case DataType::String:                        return std::get<std::string>(value).size();
            case DataType::String16:
            case DataType::AOB:                           return std::get<std::vector<uint8_t>>(value).size();
        }
        return 4;
    }

    [[nodiscard]] std::string to_string() const {
        std::ostringstream ss;
        switch (type) {
            case DataType::Int8:   ss << static_cast<int>(std::get<int8_t>(value)); break;
            case DataType::Int16:  ss << std::get<int16_t>(value); break;
            case DataType::Int32:  ss << std::get<int32_t>(value); break;
            case DataType::Int64:  ss << std::get<int64_t>(value); break;
            case DataType::UInt8:  ss << static_cast<unsigned int>(std::get<uint8_t>(value)); break;
            case DataType::UInt16: ss << std::get<uint16_t>(value); break;
            case DataType::UInt32: ss << std::get<uint32_t>(value); break;
            case DataType::UInt64: ss << std::get<uint64_t>(value); break;
            case DataType::Float:  ss << std::get<float>(value); break;
            case DataType::Double: ss << std::get<double>(value); break;
            case DataType::String: ss << "\"" << std::get<std::string>(value) << "\""; break;
            case DataType::String16: {
                const auto& bytes = std::get<std::vector<uint8_t>>(value);
                ss << "\"" << utils::utf16le_to_utf8(bytes.data(), bytes.size()) << "\"";
                break;
            }
            case DataType::AOB: {
                const auto& bytes = std::get<std::vector<uint8_t>>(value);
                for (size_t i = 0; i < bytes.size(); ++i) {
                    if (i > 0) ss << " ";
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
                }
                break;
            }
        }
        return ss.str();
    }
};

struct AOBPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask; // true: must match, false: wildcard '?'
};

inline size_t get_data_type_size(DataType type) noexcept {
    switch (type) {
        case DataType::Int8:   case DataType::UInt8:  return 1;
        case DataType::Int16:  case DataType::UInt16: return 2;
        case DataType::Int32:  case DataType::UInt32: return 4;
        case DataType::Int64:  case DataType::UInt64: return 8;
        case DataType::Float:                         return sizeof(float);
        case DataType::Double:                        return sizeof(double);
        default: return 1;
    }
}

// Calls f.template operator()<T>() with the C++ type of a numeric DataType.
// Returns false (without calling f) for String and AOB.
template <typename F>
bool dispatch_numeric(DataType type, F&& f) {
    switch (type) {
        case DataType::Int8:   f.template operator()<int8_t>();   return true;
        case DataType::Int16:  f.template operator()<int16_t>();  return true;
        case DataType::Int32:  f.template operator()<int32_t>();  return true;
        case DataType::Int64:  f.template operator()<int64_t>();  return true;
        case DataType::UInt8:  f.template operator()<uint8_t>();  return true;
        case DataType::UInt16: f.template operator()<uint16_t>(); return true;
        case DataType::UInt32: f.template operator()<uint32_t>(); return true;
        case DataType::UInt64: f.template operator()<uint64_t>(); return true;
        case DataType::Float:  f.template operator()<float>();    return true;
        case DataType::Double: f.template operator()<double>();   return true;
        default: return false;
    }
}

} // namespace nce::scanner

