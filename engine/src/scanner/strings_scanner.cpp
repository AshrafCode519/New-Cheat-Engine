#include "scanner/strings_scanner.hpp"
#include <algorithm>
#include <cctype>

namespace nce::scanner {

namespace {

bool case_insensitive_contains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2) { return std::tolower(static_cast<unsigned char>(ch1)) == std::tolower(static_cast<unsigned char>(ch2)); }
    );
    return it != haystack.end();
}

inline bool is_printable_ascii(uint8_t c) {
    return (c >= 32 && c <= 126) || c == '\t' || c == '\r' || c == '\n';
}

} // anonymous namespace

StringsScanner::StringsScanner(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process)) {}

std::vector<ExtractedString> StringsScanner::scan(size_t min_length,
                                                const std::string& filter,
                                                size_t max_results,
                                                bool only_modules) const {
    std::vector<ExtractedString> results;
    if (!m_process || !m_process->is_attached()) return results;

    auto regions = m_process->query_regions();
    auto modules = m_process->get_modules();

    // Chunk size 64KB for streaming reads
    constexpr size_t kChunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(kChunkSize);

    for (const auto& reg : regions) {
        if (!reg.is_readable) continue;
        if (reg.size == 0) continue;

        if (only_modules) {
            bool in_module = false;
            for (const auto& mod : modules) {
                if (reg.base_address >= mod.base_address && reg.base_address < mod.base_address + mod.size) {
                    in_module = true;
                    break;
                }
            }
            if (!in_module) continue;
        }

        uintptr_t cur_addr = reg.base_address;
        size_t remaining = reg.size;

        while (remaining > 0 && results.size() < max_results) {
            size_t to_read = std::min(remaining, kChunkSize);
            if (!m_process->read_raw(cur_addr, buffer.data(), to_read)) {
                break;
            }

            // 1. Scan for ASCII strings in buffer
            size_t seq_start = 0;
            size_t seq_len = 0;

            for (size_t i = 0; i < to_read; ++i) {
                uint8_t b = buffer[i];
                if (is_printable_ascii(b)) {
                    if (seq_len == 0) seq_start = i;
                    seq_len++;
                } else {
                    if (seq_len >= min_length) {
                        std::string text(reinterpret_cast<const char*>(&buffer[seq_start]), seq_len);
                        if (case_insensitive_contains(text, filter)) {
                            results.push_back({
                                cur_addr + seq_start,
                                std::move(text),
                                StringEncoding::ASCII,
                                seq_len
                            });
                            if (results.size() >= max_results) break;
                        }
                    }
                    seq_len = 0;
                }
            }
            if (seq_len >= min_length && results.size() < max_results) {
                std::string text(reinterpret_cast<const char*>(&buffer[seq_start]), seq_len);
                if (case_insensitive_contains(text, filter)) {
                    results.push_back({
                        cur_addr + seq_start,
                        std::move(text),
                        StringEncoding::ASCII,
                        seq_len
                    });
                }
            }

            // 2. Scan for UTF-16LE strings (common in Windows & games)
            if (results.size() < max_results && to_read >= 2) {
                size_t w_seq_start = 0;
                size_t w_seq_len = 0;

                for (size_t i = 0; i + 1 < to_read; i += 2) {
                    uint8_t low = buffer[i];
                    uint8_t high = buffer[i + 1];

                    if (high == 0 && is_printable_ascii(low)) {
                        if (w_seq_len == 0) w_seq_start = i;
                        w_seq_len++;
                    } else {
                        if (w_seq_len >= min_length) {
                            std::string utf8_text;
                            utf8_text.reserve(w_seq_len);
                            for (size_t k = 0; k < w_seq_len; ++k) {
                                utf8_text += static_cast<char>(buffer[w_seq_start + k * 2]);
                            }
                            if (case_insensitive_contains(utf8_text, filter)) {
                                results.push_back({
                                    cur_addr + w_seq_start,
                                    std::move(utf8_text),
                                    StringEncoding::UTF16,
                                    w_seq_len * 2
                                });
                                if (results.size() >= max_results) break;
                            }
                        }
                        w_seq_len = 0;
                    }
                }
            }

            cur_addr += to_read;
            remaining -= to_read;
        }

        if (results.size() >= max_results) break;
    }

    return results;
}

} // namespace nce::scanner
