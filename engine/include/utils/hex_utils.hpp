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

} // namespace nce::utils

