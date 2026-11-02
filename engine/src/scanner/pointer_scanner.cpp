#include "../../include/scanner/pointer_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <queue>
#include <sstream>
#include <unordered_set>
#include <iostream>

namespace nce::scanner {

std::string PointerPath::to_string() const {
    std::ostringstream ss;
    ss << "[" << module_name << " + 0x" << std::hex << std::uppercase << base_offset << "]";
    for (const auto& off : offsets) {
        ss << " -> [0x" << std::hex << std::uppercase << off << "]";
    }
    return ss.str();
}

uintptr_t PointerPath::resolve(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules) const {
    uintptr_t base_module_addr = 0;
    for (const auto& mod : modules) {
        if (mod.name == module_name) {
            base_module_addr = mod.base_address;
            break;
        }
    }

    if (base_module_addr == 0) return 0;

    uintptr_t current = 0;
    if (!process.read(base_module_addr + base_offset, current)) {
        return 0;
    }

    for (size_t i = 0; i < offsets.size(); ++i) {
        current += offsets[i];
        if (i + 1 < offsets.size()) {
            if (!process.read(current, current)) {
                return 0;
            }
        }
    }

    return current;
}

void PointerMap::build(
    const hal::IProcess& process,
    const std::vector<hal::MemoryRegion>& regions,
    std::function<void(size_t scanned_regions, size_t total_regions)> progress
) {
    m_pointers.clear();
    if (regions.empty()) return;

    // Find min and max address bounds of committed memory
    uintptr_t min_addr = UINTPTR_MAX;
    uintptr_t max_addr = 0;
    for (const auto& r : regions) {
        min_addr = std::min(min_addr, r.base_address);
        max_addr = std::max(max_addr, r.end_address());
    }

    constexpr size_t CHUNK_SIZE = 512 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    constexpr size_t PTR_SIZE = sizeof(uintptr_t);
    constexpr size_t ALIGNMENT = PTR_SIZE;

    for (size_t r_idx = 0; r_idx < regions.size(); ++r_idx) {
        const auto& reg = regions[r_idx];
        uintptr_t current_addr = reg.base_address;
        size_t remaining = reg.size;

        while (remaining >= PTR_SIZE) {
            size_t to_read = std::min(remaining, CHUNK_SIZE);
            if (process.read_raw(current_addr, buffer.data(), to_read)) {
                size_t limit = to_read - PTR_SIZE;
                for (size_t off = 0; off <= limit; off += ALIGNMENT) {
                    uintptr_t candidate = 0;
                    std::memcpy(&candidate, buffer.data() + off, PTR_SIZE);

                    // Quick bounds check
                    if (candidate >= min_addr && candidate < max_addr) {
                        m_pointers.push_back({candidate, current_addr + off});
                    }
                }
            }

            current_addr += to_read;
            remaining -= to_read;
        }

        if (progress) {
            progress(r_idx + 1, regions.size());
        }
    }

    // Sort pointers by to_address for binary search
    std::sort(m_pointers.begin(), m_pointers.end());
}

std::vector<std::pair<uintptr_t, int64_t>> PointerMap::find_predecessors(uintptr_t target_address, size_t max_offset) const {
    std::vector<std::pair<uintptr_t, int64_t>> predecessors;
    if (m_pointers.empty()) return predecessors;

    uintptr_t min_target = (target_address >= max_offset) ? (target_address - max_offset) : 0;

    PointerNode dummy_min{min_target, 0};
    auto it = std::lower_bound(m_pointers.begin(), m_pointers.end(), dummy_min);

    while (it != m_pointers.end() && it->to_address <= target_address) {
        int64_t offset = static_cast<int64_t>(target_address - it->to_address);
        predecessors.emplace_back(it->from_address, offset);
        ++it;
    }

    return predecessors;
}

PointerScanner::PointerScanner(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
{}

std::vector<PointerPath> PointerScanner::scan(
    uintptr_t target_address,
    size_t max_depth,
    size_t max_offset,
    size_t max_results,
    std::function<void(size_t current_depth, size_t paths_found)> progress
) {
    std::vector<PointerPath> results;
    if (!m_process || !m_process->is_attached()) return results;

    auto modules = m_process->get_modules();
    if (modules.empty()) return results;

    if (!m_map_built) {
        auto regions = m_process->query_regions();
        m_pointer_map.build(*m_process, regions);
        m_map_built = true;
    }

    struct BFSNode {
        uintptr_t address{0};
        std::vector<int64_t> offsets; // Offsets accumulated from target backwards
    };

    std::queue<BFSNode> queue;
    queue.push({target_address, {}});

    std::unordered_set<uintptr_t> visited_modules;

    size_t current_depth = 0;

    while (!queue.empty() && results.size() < max_results) {
        size_t level_size = queue.size();
        if (current_depth > max_depth) break;

        for (size_t i = 0; i < level_size && results.size() < max_results; ++i) {
            BFSNode current = queue.front();
            queue.pop();

            // Check if current.address resides inside any module
            for (const auto& mod : modules) {
                if (current.address >= mod.base_address && current.address < (mod.base_address + mod.size)) {
                    // Valid Static Base Found!
                    PointerPath path;
                    path.module_name = mod.name;
                    path.base_offset = current.address - mod.base_address;

                    // Invert backwards offsets to target direction
                    path.offsets = current.offsets;
                    std::reverse(path.offsets.begin(), path.offsets.end());

                    results.push_back(path);
                    break;
                }
            }

            // Expand next depth if allowed
            if (current.offsets.size() < max_depth) {
                auto preds = m_pointer_map.find_predecessors(current.address, max_offset);
                for (const auto& [from_addr, offset] : preds) {
                    BFSNode next_node;
                    next_node.address = from_addr;
                    next_node.offsets = current.offsets;
                    next_node.offsets.push_back(offset);
                    queue.push(next_node);

                    if (queue.size() > 50000) break; // Limit search space explosion
                }
            }
        }

        current_depth++;
        if (progress) {
            progress(current_depth, results.size());
        }
    }

    return results;
}

std::vector<PointerPath> PointerScanner::verify_paths(
    const hal::IProcess& process,
    const std::vector<PointerPath>& paths,
    uintptr_t expected_target
) {
    std::vector<PointerPath> valid_paths;
    auto modules = process.get_modules();

    for (const auto& path : paths) {
        if (path.resolve(process, modules) == expected_target) {
            valid_paths.push_back(path);
        }
    }

    return valid_paths;
}

} // namespace nce::scanner

