#pragma once

#include "../scanner/scan_types.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <utility>

namespace nce::utils {

uintptr_t parse_address(const std::string& str);
std::string format_address(uintptr_t address);
std::string format_hex_dump(uintptr_t base_address, const uint8_t* data, size_t size);

std::optional<scanner::AOBPattern> parse_aob_pattern(const std::string& pattern_str);

// "i8".."i64", "u8".."u64", "f32"/"float", "f64"/"double", "str", "wstr", "aob"; nullopt for anything else
std::optional<scanner::DataType> parse_data_type(const std::string& type_str);

// Inverse of parse_data_type: Int32 -> "i32", String16 -> "wstr", ...
std::string format_data_type(scanner::DataType type);

// Numeric types only. Fails on empty input, trailing characters or values out of the type's range.
std::optional<scanner::ScanValue> parse_scan_value(scanner::DataType type, const std::string& value_str);

// [low, high] range of values that a typed float stands for under `mode`, using the number of
// decimals typed: Rounded "25.5" -> [25.45, 25.55), Truncated "25.5" -> [25.5, 25.6).
// The open edge is returned already stepped inward with nextafter, so the range can be used inclusively.
// nullopt for FloatMatchMode::Exact, exponent notation, inf/nan, or text that is not a number.
std::optional<std::pair<double, double>> float_match_range(const std::string& value_str, scanner::FloatMatchMode mode);

} // namespace nce::utils

