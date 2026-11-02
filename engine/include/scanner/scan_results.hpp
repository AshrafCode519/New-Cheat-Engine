#pragma once

#include "scan_types.hpp"
#include <vector>
#include <cstdint>
#include <algorithm>
#include <optional>
#include <string>

namespace nce::scanner {

struct ScanMatch {
    uintptr_t address{0};
    ScanValue current_value;
    ScanValue previous_value;
};

class ScanResults {
public:
    ScanResults() = default;

    void add_match(uintptr_t address, const ScanValue& current_val, const ScanValue& prev_val = {}) {
        m_matches.push_back({address, current_val, prev_val});
    }

    void reserve(size_t capacity) {
        m_matches.reserve(capacity);
    }

    void clear() {
        m_matches.clear();
    }

    [[nodiscard]] size_t count() const noexcept {
        return m_matches.size();
    }

    [[nodiscard]] bool empty() const noexcept {
        return m_matches.empty();
    }

    [[nodiscard]] const std::vector<ScanMatch>& get_matches() const noexcept {
        return m_matches;
    }

    [[nodiscard]] std::vector<ScanMatch>& get_matches() noexcept {
        return m_matches;
    }

    [[nodiscard]] const ScanMatch& operator[](size_t index) const {
        return m_matches[index];
    }

private:
    std::vector<ScanMatch> m_matches;
};

// Raw copy of the scanned memory taken by an "unknown initial value" first scan.
// The next scan compares live memory against it and turns it into regular ScanResults.
struct MemorySnapshot {
    struct Block {
        uintptr_t base_address{0};
        std::vector<uint8_t> bytes;
    };

    DataType type{DataType::Int32};
    size_t alignment{4};
    std::vector<Block> blocks;

    [[nodiscard]] size_t total_bytes() const noexcept {
        size_t total = 0;
        for (const auto& b : blocks) total += b.bytes.size();
        return total;
    }
};

struct SavedResults {
    uint32_t pid{0};
    DataType type{DataType::Int32};
    ScanResults results;
};

// Plain-text results file: a small header, then one "<address> <value bytes>" line per match (both hex).
bool save_results(const std::string& path, uint32_t pid, DataType type, const ScanResults& results);
std::optional<SavedResults> load_results(const std::string& path);

} // namespace nce::scanner

