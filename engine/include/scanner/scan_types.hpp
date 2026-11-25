#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <variant>
#include <cmath>
#include <cstring>
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
    AOB,
    // Big-Endian types for Console Emulators (Dolphin, RPCS3, CEMU, etc.)
    Int16BE,
    Int32BE,
    Int64BE,
    UInt16BE,
    UInt32BE,
    UInt64BE,
    FloatBE,
    DoubleBE
};

// Endianness byte-swapping helper routines
inline uint16_t swap_bytes(uint16_t v) noexcept {
#if defined(_MSC_VER)
    return _byteswap_ushort(v);
#else
    return __builtin_bswap16(v);
#endif
}

inline uint32_t swap_bytes(uint32_t v) noexcept {
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}

inline uint64_t swap_bytes(uint64_t v) noexcept {
#if defined(_MSC_VER)
    return _byteswap_uint64(v);
#else
    return __builtin_bswap64(v);
#endif
}

inline int16_t swap_bytes(int16_t v) noexcept {
    return static_cast<int16_t>(swap_bytes(static_cast<uint16_t>(v)));
}

inline int32_t swap_bytes(int32_t v) noexcept {
    return static_cast<int32_t>(swap_bytes(static_cast<uint32_t>(v)));
}

inline int64_t swap_bytes(int64_t v) noexcept {
    return static_cast<int64_t>(swap_bytes(static_cast<uint64_t>(v)));
}

inline float swap_bytes(float v) noexcept {
    uint32_t u = 0;
    std::memcpy(&u, &v, sizeof(float));
    u = swap_bytes(u);
    float out = 0.0f;
    std::memcpy(&out, &u, sizeof(float));
    return out;
}

inline double swap_bytes(double v) noexcept {
    uint64_t u = 0;
    std::memcpy(&u, &v, sizeof(double));
    u = swap_bytes(u);
    double out = 0.0;
    std::memcpy(&out, &u, sizeof(double));
    return out;
}

inline uint8_t swap_bytes(uint8_t v) noexcept { return v; }
inline int8_t swap_bytes(int8_t v) noexcept { return v; }

inline bool is_big_endian(DataType type) noexcept {
    switch (type) {
        case DataType::Int16BE:
        case DataType::Int32BE:
        case DataType::Int64BE:
        case DataType::UInt16BE:
        case DataType::UInt32BE:
        case DataType::UInt64BE:
        case DataType::FloatBE:
        case DataType::DoubleBE:
            return true;
        default:
            return false;
    }
}

inline DataType to_native_endian(DataType type) noexcept {
    switch (type) {
        case DataType::Int16BE: return DataType::Int16;
        case DataType::Int32BE: return DataType::Int32;
        case DataType::Int64BE: return DataType::Int64;
        case DataType::UInt16BE: return DataType::UInt16;
        case DataType::UInt32BE: return DataType::UInt32;
        case DataType::UInt64BE: return DataType::UInt64;
        case DataType::FloatBE: return DataType::Float;
        case DataType::DoubleBE: return DataType::Double;
        default: return type;
    }
}

inline DataType to_big_endian(DataType type) noexcept {
    switch (type) {
        case DataType::Int16: return DataType::Int16BE;
        case DataType::Int32: return DataType::Int32BE;
        case DataType::Int64: return DataType::Int64BE;
        case DataType::UInt16: return DataType::UInt16BE;
        case DataType::UInt32: return DataType::UInt32BE;
        case DataType::UInt64: return DataType::UInt64BE;
        case DataType::Float: return DataType::FloatBE;
        case DataType::Double: return DataType::DoubleBE;
        default: return type;
    }
}

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
            case DataType::Int16:  case DataType::UInt16:
            case DataType::Int16BE: case DataType::UInt16BE: return 2;
            case DataType::Int32:  case DataType::UInt32:
            case DataType::Int32BE: case DataType::UInt32BE: return 4;
            case DataType::Int64:  case DataType::UInt64:
            case DataType::Int64BE: case DataType::UInt64BE: return 8;
            case DataType::Float:  case DataType::FloatBE:   return sizeof(float);
            case DataType::Double: case DataType::DoubleBE:  return sizeof(double);
            case DataType::String:                        return std::get<std::string>(value).size();
            case DataType::String16:
            case DataType::AOB:                           return std::get<std::vector<uint8_t>>(value).size();
        }
        return 4;
    }

    [[nodiscard]] std::string to_string() const {
        std::ostringstream ss;
        switch (type) {
            case DataType::Int8:     ss << static_cast<int>(std::get<int8_t>(value)); break;
            case DataType::Int16:
            case DataType::Int16BE:  ss << std::get<int16_t>(value); break;
            case DataType::Int32:
            case DataType::Int32BE:  ss << std::get<int32_t>(value); break;
            case DataType::Int64:
            case DataType::Int64BE:  ss << std::get<int64_t>(value); break;
            case DataType::UInt8:    ss << static_cast<unsigned int>(std::get<uint8_t>(value)); break;
            case DataType::UInt16:
            case DataType::UInt16BE: ss << std::get<uint16_t>(value); break;
            case DataType::UInt32:
            case DataType::UInt32BE: ss << std::get<uint32_t>(value); break;
            case DataType::UInt64:
            case DataType::UInt64BE: ss << std::get<uint64_t>(value); break;
            case DataType::Float:
            case DataType::FloatBE:  ss << std::get<float>(value); break;
            case DataType::Double:
            case DataType::DoubleBE: ss << std::get<double>(value); break;
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
        case DataType::Int16:  case DataType::UInt16:
        case DataType::Int16BE: case DataType::UInt16BE: return 2;
        case DataType::Int32:  case DataType::UInt32:
        case DataType::Int32BE: case DataType::UInt32BE: return 4;
        case DataType::Int64:  case DataType::UInt64:
        case DataType::Int64BE: case DataType::UInt64BE: return 8;
        case DataType::Float:  case DataType::FloatBE:   return sizeof(float);
        case DataType::Double: case DataType::DoubleBE:  return sizeof(double);
        default: return 1;
    }
}

// Calls f.template operator()<T>() with the C++ type of a numeric DataType.
// Returns false (without calling f) for String and AOB.
template <typename F>
bool dispatch_numeric(DataType type, F&& f) {
    switch (type) {
        case DataType::Int8:     f.template operator()<int8_t>();   return true;
        case DataType::Int16:
        case DataType::Int16BE:  f.template operator()<int16_t>();  return true;
        case DataType::Int32:
        case DataType::Int32BE:  f.template operator()<int32_t>();  return true;
        case DataType::Int64:
        case DataType::Int64BE:  f.template operator()<int64_t>();  return true;
        case DataType::UInt8:    f.template operator()<uint8_t>();  return true;
        case DataType::UInt16:
        case DataType::UInt16BE: f.template operator()<uint16_t>(); return true;
        case DataType::UInt32:
        case DataType::UInt32BE: f.template operator()<uint32_t>(); return true;
        case DataType::UInt64:
        case DataType::UInt64BE: f.template operator()<uint64_t>(); return true;
        case DataType::Float:
        case DataType::FloatBE:  f.template operator()<float>();    return true;
        case DataType::Double:
        case DataType::DoubleBE: f.template operator()<double>();   return true;
        default: return false;
    }
}

} // namespace nce::scanner

