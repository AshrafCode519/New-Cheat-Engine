#pragma once

#include "scan_types.hpp"
#include <vector>
#include <cstdint>
#include <algorithm>
#include <optional>
#include <string>

namespace nce::scanner {

// One decoded result. ScanResults stores matches compactly and builds these on demand.
struct ScanMatch {
    uintptr_t address{0};
    ScanValue current_value;
    ScanValue previous_value;
};

// Raw bytes of a value: the in-memory representation of a number, or the matched String/String16/AOB bytes
std::vector<uint8_t> value_to_bytes(const ScanValue& value);

// Inverse of value_to_bytes; nullopt if `size` does not fit the type (e.g. 2 bytes for an i32)
std::optional<ScanValue> value_from_bytes(DataType type, const uint8_t* data, size_t size);

// Scan results stored column-wise: per match only the address and the raw current/previous bytes
// (16 bytes for an i32 result). Every match in one set has the same type and value size.
class ScanResults {
public:
    ScanResults() = default;
    ScanResults(DataType type, size_t value_size) : m_type(type), m_value_size(value_size) {}

    // current/previous point at value_size() bytes each
    void add(uintptr_t address, const void* current, const void* previous) {
        const auto* c = static_cast<const uint8_t*>(current);
        const auto* p = static_cast<const uint8_t*>(previous);
        m_addresses.push_back(address);
        m_current.insert(m_current.end(), c, c + m_value_size);
        m_previous.insert(m_previous.end(), p, p + m_value_size);
    }

    // Decoded-value variant of add(); on an empty set the first match fixes the type and value size.
    // Throws std::invalid_argument if the value does not fit the set.
    void add_match(uintptr_t address, const ScanValue& current_val, const ScanValue& prev_val = {});

    // Appends a set of the same type (used to merge per-thread results in address order)
    void append(const ScanResults& other);

    void reserve(size_t capacity) {
        m_addresses.reserve(capacity);
        m_current.reserve(capacity * m_value_size);
        m_previous.reserve(capacity * m_value_size);
    }

    void clear() {
        m_addresses.clear();
        m_current.clear();
        m_previous.clear();
    }

    [[nodiscard]] size_t count() const noexcept { return m_addresses.size(); }
    [[nodiscard]] bool empty() const noexcept { return m_addresses.empty(); }
    [[nodiscard]] DataType type() const noexcept { return m_type; }
    [[nodiscard]] size_t value_size() const noexcept { return m_value_size; }

    [[nodiscard]] uintptr_t address(size_t index) const { return m_addresses[index]; }
    [[nodiscard]] const uint8_t* current_bytes(size_t index) const { return m_current.data() + index * m_value_size; }
    [[nodiscard]] const uint8_t* previous_bytes(size_t index) const { return m_previous.data() + index * m_value_size; }

    // Decoded copy of one match
    [[nodiscard]] ScanMatch operator[](size_t index) const;

    // Heap bytes held by the result set
    [[nodiscard]] size_t memory_bytes() const noexcept {
        return m_addresses.capacity() * sizeof(uintptr_t) + m_current.capacity() + m_previous.capacity();
    }

private:
    DataType m_type{DataType::Int32};
    size_t m_value_size{0};
    std::vector<uintptr_t> m_addresses;
    std::vector<uint8_t> m_current;
    std::vector<uint8_t> m_previous;
};

// Raw copy of the scanned memory taken by an "unknown initial value" first scan. Every aligned slot
// starts as a candidate; MemoryScanner::filter_snapshot clears the slots that fail a condition and
// drops blocks with no candidates left, so the snapshot shrinks as the search narrows.
struct MemorySnapshot {
    struct Block {
        uintptr_t base_address{0};
        std::vector<uint8_t> bytes;
        std::vector<uint64_t> alive; // one bit per slot (offset = slot * alignment); set = still a candidate
    };

    DataType type{DataType::Int32};
    size_t alignment{4};
    std::vector<Block> blocks;

    [[nodiscard]] size_t total_bytes() const noexcept {
        size_t total = 0;
        for (const auto& b : blocks) total += b.bytes.size();
        return total;
    }

    [[nodiscard]] size_t memory_bytes() const noexcept {
        size_t total = 0;
        for (const auto& b : blocks) total += b.bytes.size() + b.alive.size() * sizeof(uint64_t);
        return total;
    }

    [[nodiscard]] size_t candidate_count() const noexcept;
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
