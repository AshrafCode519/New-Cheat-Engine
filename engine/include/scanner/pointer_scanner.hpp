#pragma once

#include "../hal/process.hpp"
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <cstdint>

namespace nce::scanner {

struct PointerPath {
    std::string module_name;
    uintptr_t base_offset{0};
    std::vector<int64_t> offsets; // Offsets from base to target

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] uintptr_t resolve(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules) const;
};

struct PointerNode {
    uintptr_t to_address{0};
    uintptr_t from_address{0};

    bool operator<(const PointerNode& other) const noexcept {
        return to_address < other.to_address;
    }
};

class PointerMap {
public:
    PointerMap() = default;

    void build(
        const hal::IProcess& process,
        const std::vector<hal::MemoryRegion>& regions,
        std::function<void(size_t scanned_regions, size_t total_regions)> progress = nullptr
    );

    [[nodiscard]] size_t size() const noexcept { return m_pointers.size(); }
    [[nodiscard]] bool empty() const noexcept { return m_pointers.empty(); }

    [[nodiscard]] const std::vector<PointerNode>& get_pointers() const noexcept { return m_pointers; }

    // Find all pointers whose to_address is within [target_address - max_offset, target_address]
    std::vector<std::pair<uintptr_t, int64_t>> find_predecessors(uintptr_t target_address, size_t max_offset) const;

private:
    std::vector<PointerNode> m_pointers;
};

class PointerScanner {
public:
    explicit PointerScanner(std::shared_ptr<hal::IProcess> process);

    // Scan backwards from target address to find static pointer chains
    std::vector<PointerPath> scan(
        uintptr_t target_address,
        size_t max_depth = 5,
        size_t max_offset = 0x800,
        size_t max_results = 500,
        std::function<void(size_t current_depth, size_t paths_found)> progress = nullptr
    );

    // Filter paths against current memory to remove unstable / broken paths
    static std::vector<PointerPath> verify_paths(
        const hal::IProcess& process,
        const std::vector<PointerPath>& paths,
        uintptr_t expected_target
    );

private:
    std::shared_ptr<hal::IProcess> m_process;
    PointerMap m_pointer_map;
    bool m_map_built{false};
};

} // namespace nce::scanner

