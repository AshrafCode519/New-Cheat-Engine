#pragma once

#include "scan_types.hpp"
#include <vector>
#include <cstdint>
#include <algorithm>

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

} // namespace nce::scanner

