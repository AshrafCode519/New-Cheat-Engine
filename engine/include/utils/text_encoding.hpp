#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nce::utils {

// UTF-8 text -> UTF-16LE bytes (the layout of Windows wide strings).
// nullopt if the input is not valid UTF-8 (bad sequences, overlongs, surrogates, > U+10FFFF).
std::optional<std::vector<uint8_t>> utf8_to_utf16le(std::string_view utf8);

// UTF-16LE bytes -> UTF-8 text. Unpaired surrogates become U+FFFD; a trailing odd byte is ignored.
std::string utf16le_to_utf8(const uint8_t* data, size_t size);

} // namespace nce::utils
