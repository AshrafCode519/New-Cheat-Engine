#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace nce::scanner {

enum class StringEncoding {
    ASCII,
    UTF16
};

struct ExtractedString {
    uintptr_t address{0};
    std::string text;
    StringEncoding encoding{StringEncoding::ASCII};
    size_t byte_length{0};
};

class StringsScanner {
public:
    explicit StringsScanner(std::shared_ptr<hal::IProcess> process);

    // Scans memory regions for printable strings.
    // min_length: minimum character count (default 4).
    // filter: optional case-insensitive substring filter.
    // max_results: limit returned results (default 1000).
    // only_modules: if true, scans only executable/data modules; if false, scans all committed readable memory.
    [[nodiscard]] std::vector<ExtractedString> scan(size_t min_length = 4,
                                                   const std::string& filter = "",
                                                   size_t max_results = 1000,
                                                   bool only_modules = false) const;

private:
    std::shared_ptr<hal::IProcess> m_process;
};

} // namespace nce::scanner
