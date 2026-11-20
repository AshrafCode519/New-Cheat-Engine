#pragma once

#include "../hal/process.hpp"
#include "scan_types.hpp"
#include "scan_results.hpp"
#include "noise_map.hpp"
#include <memory>
#include <functional>

namespace nce::scanner {

using ScanProgressCallback = std::function<void(size_t scanned_bytes, size_t total_bytes, size_t matches_count)>;

class MemoryScanner {
public:
    explicit MemoryScanner(std::shared_ptr<hal::IProcess> process);

    [[nodiscard]] ScanResults first_scan(
        DataType type,
        ScanCondition condition,
        const ScanValue& val1,
        const ScanValue& val2 = {},
        size_t alignment = 4,
        uint32_t region_filter = hal::FilterFlags::DefaultScanFilter,
        ScanProgressCallback progress = nullptr
    );

    [[nodiscard]] ScanResults first_scan_aob(
        const std::string& aob_pattern,
        size_t alignment = 1,
        uint32_t region_filter = hal::FilterFlags::DefaultScanFilter,
        ScanProgressCallback progress = nullptr
    );

    // Case-sensitive text search. utf16 = true looks for UTF-16LE (wide) strings, otherwise for the UTF-8 bytes.
    [[nodiscard]] ScanResults first_scan_string(
        const std::string& utf8_text,
        bool utf16,
        size_t alignment = 1,
        uint32_t region_filter = hal::FilterFlags::DefaultScanFilter,
        ScanProgressCallback progress = nullptr
    );

    // "Unknown initial value": copies the scanned memory so the next scan can compare against it.
    // Numeric types only; the snapshot is as large as the scanned memory.
    [[nodiscard]] MemorySnapshot first_scan_unknown(
        DataType type,
        size_t alignment = 4,
        uint32_t region_filter = hal::FilterFlags::DefaultScanFilter,
        ScanProgressCallback progress = nullptr
    );

    [[nodiscard]] ScanResults next_scan(
        const ScanResults& previous_results,
        ScanCondition condition,
        const ScanValue& val1 = {},
        const ScanValue& val2 = {},
        ScanProgressCallback progress = nullptr
    );

    // Next scan after first_scan_unknown: compares live memory with the snapshot's candidates and
    // returns the matches as results (previous value = the snapshot's value)
    [[nodiscard]] ScanResults next_scan(
        const MemorySnapshot& snapshot,
        ScanCondition condition,
        const ScanValue& val1 = {},
        const ScanValue& val2 = {},
        ScanProgressCallback progress = nullptr
    );

    // Same comparison, but keeps the snapshot form: the result holds live bytes, only the candidates
    // that matched stay set, and blocks with no candidates left are dropped. Cheaper than results
    // while millions of candidates remain (1 bit per slot instead of a full result entry).
    [[nodiscard]] MemorySnapshot filter_snapshot(
        const MemorySnapshot& snapshot,
        ScanCondition condition,
        const ScanValue& val1 = {},
        const ScanValue& val2 = {},
        ScanProgressCallback progress = nullptr
    );

    // The snapshot's remaining candidates as results (current and previous = the snapshot's value)
    [[nodiscard]] static ScanResults snapshot_to_results(const MemorySnapshot& snapshot);

    void set_thread_count(size_t threads) { m_thread_count = threads; }
    [[nodiscard]] size_t get_thread_count() const noexcept { return m_thread_count; }

    // Addresses that change on their own: first scans skip them, next scans drop them (nullptr = none)
    void set_noise_map(std::shared_ptr<const NoiseMap> noise) { m_noise = std::move(noise); }

private:
    std::shared_ptr<hal::IProcess> m_process;
    std::shared_ptr<const NoiseMap> m_noise;
    size_t m_thread_count;
};

} // namespace nce::scanner

