#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <vector>
#include <memory>
#include <optional>

namespace nce::view {

struct DiffByte {
    uintptr_t address{0};
    uint8_t   old_val{0};
    uint8_t   new_val{0};
};

struct DiffSummary {
    uintptr_t address{0};
    size_t total_bytes{0};
    size_t changed_bytes{0};
    double changed_percentage{0.0};
    std::vector<DiffByte> diffs;
};

class MemoryDiff {
public:
    MemoryDiff() = default;

    // Capture initial baseline snapshot (Snapshot A)
    bool take_snapshot_a(hal::IProcess& proc, uintptr_t address, size_t size);

    // Capture second snapshot (Snapshot B) of the same region
    bool take_snapshot_b(hal::IProcess& proc);

    // Compute differences between Snapshot A and Snapshot B
    [[nodiscard]] DiffSummary compare() const;

    // Static helper to compare any two buffers
    static DiffSummary compare_buffers(uintptr_t base_addr,
                                       const uint8_t* buf_a,
                                       const uint8_t* buf_b,
                                       size_t size);

    [[nodiscard]] bool has_snapshot_a() const noexcept { return !m_snapshot_a.empty(); }
    [[nodiscard]] bool has_snapshot_b() const noexcept { return !m_snapshot_b.empty(); }
    [[nodiscard]] uintptr_t address() const noexcept { return m_address; }
    [[nodiscard]] size_t size() const noexcept { return m_size; }

    [[nodiscard]] const std::vector<uint8_t>& snapshot_a() const noexcept { return m_snapshot_a; }
    [[nodiscard]] const std::vector<uint8_t>& snapshot_b() const noexcept { return m_snapshot_b; }

    void clear() {
        m_snapshot_a.clear();
        m_snapshot_b.clear();
        m_address = 0;
        m_size = 0;
    }

private:
    uintptr_t m_address{0};
    size_t m_size{0};
    std::vector<uint8_t> m_snapshot_a;
    std::vector<uint8_t> m_snapshot_b;
};

} // namespace nce::view
