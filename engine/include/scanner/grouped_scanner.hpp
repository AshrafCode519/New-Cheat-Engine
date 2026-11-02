#pragma once

#include "../hal/process.hpp"
#include "scan_types.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace nce::scanner {

struct GroupedEntry {
    DataType type{DataType::Int32};
    ScanValue value;
    size_t expected_offset{0}; // 0 = any offset within window, or exact offset if specified
    bool exact_offset{false};
};

struct GroupedMatch {
    uintptr_t base_address{0};
    std::vector<uintptr_t> member_addresses;
};

class GroupedScanner {
public:
    explicit GroupedScanner(std::shared_ptr<hal::IProcess> process);

    std::vector<GroupedMatch> scan(
        const std::vector<GroupedEntry>& entries,
        size_t window_size = 0x100, // Search within 256 bytes
        uint32_t region_filter = hal::FilterFlags::DefaultScanFilter
    );

private:
    std::shared_ptr<hal::IProcess> m_process;
};

} // namespace nce::scanner

