#pragma once

#include "../scanner/scan_types.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace nce::utils {

uintptr_t parse_address(const std::string& str);
std::string format_address(uintptr_t address);
std::string format_hex_dump(uintptr_t base_address, const uint8_t* data, size_t size);

std::optional<scanner::AOBPattern> parse_aob_pattern(const std::string& pattern_str);

// "i8".."i64", "u8".."u64", "f32"/"float", "f64"/"double", "aob"; nullopt for anything else
std::optional<scanner::DataType> parse_data_type(const std::string& type_str);

// Numeric types only. Fails on empty input, trailing characters or values out of the type's range.
std::optional<scanner::ScanValue> parse_scan_value(scanner::DataType type, const std::string& value_str);

} // namespace nce::utils

