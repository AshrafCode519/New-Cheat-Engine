#include "../../include/view/memory_diff.hpp"
#include <algorithm>

namespace nce::view {

bool MemoryDiff::take_snapshot_a(hal::IProcess& proc, uintptr_t address, size_t size) {
    if (!proc.is_attached() || address == 0 || size == 0) {
        return false;
    }

    m_snapshot_a.resize(size);
    if (!proc.read_raw(address, m_snapshot_a.data(), size)) {
        m_snapshot_a.clear();
        return false;
    }

    m_address = address;
    m_size = size;
    m_snapshot_b.clear();
    return true;
}

bool MemoryDiff::take_snapshot_b(hal::IProcess& proc) {
    if (!proc.is_attached() || m_address == 0 || m_size == 0 || m_snapshot_a.empty()) {
        return false;
    }

    m_snapshot_b.resize(m_size);
    if (!proc.read_raw(m_address, m_snapshot_b.data(), m_size)) {
        m_snapshot_b.clear();
        return false;
    }

    return true;
}

DiffSummary MemoryDiff::compare() const {
    if (m_snapshot_a.empty() || m_snapshot_b.empty()) {
        return {};
    }

    const size_t cmp_len = std::min(m_snapshot_a.size(), m_snapshot_b.size());
    return compare_buffers(m_address, m_snapshot_a.data(), m_snapshot_b.data(), cmp_len);
}

DiffSummary MemoryDiff::compare_buffers(uintptr_t base_addr,
                                       const uint8_t* buf_a,
                                       const uint8_t* buf_b,
                                       size_t size) {
    DiffSummary summary;
    summary.address = base_addr;
    summary.total_bytes = size;

    if (!buf_a || !buf_b || size == 0) {
        return summary;
    }

    for (size_t i = 0; i < size; ++i) {
        if (buf_a[i] != buf_b[i]) {
            summary.diffs.push_back(DiffByte{
                base_addr + i,
                buf_a[i],
                buf_b[i]
            });
        }
    }

    summary.changed_bytes = summary.diffs.size();
    if (size > 0) {
        summary.changed_percentage = (static_cast<double>(summary.changed_bytes) / static_cast<double>(size)) * 100.0;
    }

    return summary;
}

} // namespace nce::view
