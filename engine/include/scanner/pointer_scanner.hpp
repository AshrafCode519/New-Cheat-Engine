#pragma once

#include "../hal/process.hpp"
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <optional>
#include <cstdint>

namespace nce::scanner {

struct PointerPath {
    std::string module_name;
    uintptr_t base_offset{0};
    std::vector<int64_t> offsets; // Applied in order: read [module + base_offset], add offsets[0], read, ...

    [[nodiscard]] std::string to_string() const;

    // Address the path points to right now, or 0 if the module is not loaded or a link can't be read.
    // A path with no offsets is a static address: module base + base_offset.
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

    // Collects every aligned value in `regions` that points into one of `regions`.
    // pointer_size is the target's (4 for 32-bit processes).
    void build(
        const hal::IProcess& process,
        const std::vector<hal::MemoryRegion>& regions,
        size_t pointer_size = sizeof(uintptr_t),
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

struct PointerScanOptions {
    size_t max_depth{4};
    size_t max_offset{0x800};
    size_t max_results{100000};
    std::string base_module; // only accept static bases in this module (case-insensitive); empty = any module
};

struct PointerScanResult {
    // Best first: bases in the main module, then the smallest total offset, then fewer levels
    std::vector<PointerPath> paths;
    size_t pointer_map_size{0};
    size_t nodes_explored{0};
    bool truncated{false}; // the search hit max_results or its node budget before exploring everything
};

class PointerScanner {
public:
    explicit PointerScanner(std::shared_ptr<hal::IProcess> process);

    // Scans backwards from target address to find static pointer chains (builds a fresh pointer map)
    PointerScanResult scan(
        uintptr_t target_address,
        const PointerScanOptions& options = {},
        std::function<void(size_t current_depth, size_t paths_found)> progress = nullptr
    );

    // Keeps the paths that resolve to expected_target in the current process. Run it after the target
    // restarts (or moves the value) to drop paths that only worked by coincidence.
    static std::vector<PointerPath> verify_paths(
        const hal::IProcess& process,
        const std::vector<PointerPath>& paths,
        uintptr_t expected_target
    );

private:
    std::shared_ptr<hal::IProcess> m_process;
};

// Plain-text pointer path files: "<module>\t<base offset>\t<offset,offset,...>" per line (hex)
bool save_pointer_paths(const std::string& path, const std::vector<PointerPath>& paths);
std::optional<std::vector<PointerPath>> load_pointer_paths(const std::string& path);

} // namespace nce::scanner
