#include "../../include/scanner/pointer_scanner.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "parallel.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

namespace nce::scanner {

namespace {

constexpr size_t MAP_CHUNK_SIZE = 512 * 1024;
constexpr size_t MAX_SEARCH_NODES = 5'000'000; // ~120 MB of search state
constexpr uint32_t NO_PARENT = UINT32_MAX;

bool equals_ignore_case(const std::string& a, const std::string& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
    });
}

// Reads a pointer of the target's size, zero-extended
bool read_pointer(const hal::IProcess& process, uintptr_t address, size_t pointer_size, uintptr_t& out) {
    if (pointer_size == 4) {
        uint32_t value = 0;
        if (!process.read(address, value)) return false;
        out = value;
        return true;
    }
    return process.read(address, out);
}

// `modules` sorted by base address
const hal::ModuleInfo* module_containing(const std::vector<hal::ModuleInfo>& modules, uintptr_t address) {
    auto it = std::upper_bound(modules.begin(), modules.end(), address,
        [](uintptr_t a, const hal::ModuleInfo& m) { return a < m.base_address; });
    if (it == modules.begin()) return nullptr;
    --it;
    return address < it->base_address + it->size ? &*it : nullptr;
}

} // anonymous namespace

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
        if (equals_ignore_case(mod.name, module_name)) {
            base_module_addr = mod.base_address;
            break;
        }
    }

    if (base_module_addr == 0) return 0;

    // Each offset is applied to the pointer read at the current address
    uintptr_t current = base_module_addr + base_offset;
    for (const auto offset : offsets) {
        uintptr_t value = 0;
        if (!read_pointer(process, current, process.pointer_size(), value)) {
            return 0;
        }
        current = value + static_cast<uintptr_t>(offset);
    }

    return current;
}

void PointerMap::build(
    const hal::IProcess& process,
    const std::vector<hal::MemoryRegion>& regions,
    size_t pointer_size,
    std::function<void(size_t scanned_regions, size_t total_regions)> progress
) {
    m_pointers.clear();
    if (regions.empty()) return;

    const size_t ptr_size = (pointer_size == 4) ? 4 : sizeof(uintptr_t);

    // Sorted, merged [begin, end) ranges: a value only counts as a pointer if it points into one of them
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
    ranges.reserve(regions.size());
    for (const auto& r : regions) ranges.emplace_back(r.base_address, r.end_address());
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<uintptr_t, uintptr_t>> merged;
    for (const auto& r : ranges) {
        if (!merged.empty() && r.first <= merged.back().second) {
            merged.back().second = std::max(merged.back().second, r.second);
        } else {
            merged.push_back(r);
        }
    }
    const uintptr_t lowest = merged.front().first;
    const uintptr_t highest = merged.back().second;

    auto points_into_memory = [&](uintptr_t value) {
        if (value < lowest || value >= highest) return false;
        auto it = std::upper_bound(merged.begin(), merged.end(), value,
            [](uintptr_t v, const std::pair<uintptr_t, uintptr_t>& r) { return v < r.first; });
        return it != merged.begin() && value < std::prev(it)->second;
    };

    std::vector<std::vector<PointerNode>> parts(regions.size());
    std::atomic<size_t> finished{0};

    detail::parallel_for(regions.size(), detail::default_thread_count(),
        [] { return std::vector<uint8_t>(MAP_CHUNK_SIZE); },
        [&](std::vector<uint8_t>& buffer, size_t idx) {
            const auto& reg = regions[idx];
            for (size_t offset = 0; offset < reg.size; offset += MAP_CHUNK_SIZE) {
                const size_t to_read = std::min(MAP_CHUNK_SIZE, reg.size - offset);
                if (!process.read_raw(reg.base_address + offset, buffer.data(), to_read)) continue;

                for (size_t off = 0; off + ptr_size <= to_read; off += ptr_size) {
                    uintptr_t candidate = 0;
                    std::memcpy(&candidate, buffer.data() + off, ptr_size); // little-endian: 4 bytes zero-extend
                    if (points_into_memory(candidate)) {
                        parts[idx].push_back({candidate, reg.base_address + offset + off});
                    }
                }
            }

            const size_t done = finished.fetch_add(1) + 1;
            if (progress) {
                progress(done, regions.size());
            }
        });

    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    m_pointers.reserve(total);
    for (auto& p : parts) {
        m_pointers.insert(m_pointers.end(), p.begin(), p.end());
        p = {};
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

PointerScanResult PointerScanner::scan(
    uintptr_t target_address,
    const PointerScanOptions& options,
    std::function<void(size_t current_depth, size_t paths_found)> progress
) {
    PointerScanResult result;
    if (!m_process || !m_process->is_attached()) return result;

    auto modules = m_process->get_modules();
    if (modules.empty()) return result;
    const std::string main_module = modules.front().name; // the executable is listed first
    std::sort(modules.begin(), modules.end(),
        [](const hal::ModuleInfo& a, const hal::ModuleInfo& b) { return a.base_address < b.base_address; });

    PointerMap map;
    map.build(*m_process, m_process->query_regions(), m_process->pointer_size());
    result.pointer_map_size = map.size();

    // Breadth-first search backwards from the target. Each node is a pointer slot; it keeps its parent
    // (the node it points near) and the offset to add, so paths are rebuilt only for static bases.
    struct Node {
        uintptr_t address{0};
        uint32_t parent{NO_PARENT};
        int64_t offset{0};
    };
    std::vector<Node> nodes;
    nodes.push_back({target_address, NO_PARENT, 0});

    auto record_path = [&](uint32_t index, const hal::ModuleInfo& mod) {
        PointerPath path;
        path.module_name = mod.name;
        path.base_offset = nodes[index].address - mod.base_address;
        for (uint32_t i = index; nodes[i].parent != NO_PARENT; i = nodes[i].parent) {
            path.offsets.push_back(nodes[i].offset);
        }
        result.paths.push_back(std::move(path));
    };

    size_t level_begin = 0;
    bool results_full = false;
    for (size_t depth = 0; depth <= options.max_depth && level_begin < nodes.size() && !results_full; ++depth) {
        const size_t level_end = nodes.size();

        for (size_t i = level_begin; i < level_end; ++i) {
            const uintptr_t address = nodes[i].address;

            if (const auto* mod = module_containing(modules, address)) {
                if (options.base_module.empty() || equals_ignore_case(mod->name, options.base_module)) {
                    record_path(static_cast<uint32_t>(i), *mod);
                    if (result.paths.size() >= options.max_results) {
                        results_full = true;
                        result.truncated = true;
                        break;
                    }
                }
            }

            if (depth == options.max_depth) continue;
            for (const auto& [from_addr, offset] : map.find_predecessors(address, options.max_offset)) {
                if (nodes.size() >= MAX_SEARCH_NODES) {
                    result.truncated = true;
                    break;
                }
                nodes.push_back({from_addr, static_cast<uint32_t>(i), offset});
            }
        }

        level_begin = level_end;
        if (progress) {
            progress(depth, result.paths.size());
        }
    }
    result.nodes_explored = nodes.size();

    // Best first: the executable's own statics, then the smallest total offset (real struct chains use
    // small field offsets; chains that hop through allocator structures need large ones), then fewer levels
    auto offset_sum = [](const PointerPath& p) {
        int64_t sum = 0;
        for (const auto o : p.offsets) sum += o;
        return sum;
    };
    std::stable_sort(result.paths.begin(), result.paths.end(), [&](const PointerPath& a, const PointerPath& b) {
        const bool a_main = equals_ignore_case(a.module_name, main_module);
        const bool b_main = equals_ignore_case(b.module_name, main_module);
        if (a_main != b_main) return a_main;
        const int64_t a_sum = offset_sum(a);
        const int64_t b_sum = offset_sum(b);
        if (a_sum != b_sum) return a_sum < b_sum;
        return a.offsets.size() < b.offsets.size();
    });

    return result;
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

bool save_pointer_paths(const std::string& path, const std::vector<PointerPath>& paths) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;

    out << "NCE-POINTERS 1\ncount " << paths.size() << "\n";
    for (const auto& p : paths) {
        out << p.module_name << "\t" << std::hex << std::uppercase << p.base_offset << "\t";
        if (p.offsets.empty()) out << "-";
        for (size_t i = 0; i < p.offsets.size(); ++i) {
            out << (i > 0 ? "," : "") << p.offsets[i];
        }
        out << std::dec << "\n";
    }
    return static_cast<bool>(out);
}

std::optional<std::vector<PointerPath>> load_pointer_paths(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::nullopt;

    std::string line;
    if (!std::getline(in, line) || utils::trim_cr(line) != "NCE-POINTERS 1") return std::nullopt;
    if (!std::getline(in, line)) return std::nullopt;
    size_t count = 0;
    {
        std::istringstream header(line);
        std::string key;
        if (!(header >> key >> count) || key != "count") return std::nullopt;
    }

    auto parse_hex = [](const std::string& text, auto& value) {
        auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
        return ec == std::errc() && ptr == text.data() + text.size() && !text.empty();
    };

    std::vector<PointerPath> paths;
    paths.reserve(count);
    while (std::getline(in, line)) {
        line = utils::trim_cr(line);
        if (line.empty()) continue;

        const size_t tab1 = line.find('\t');
        const size_t tab2 = (tab1 == std::string::npos) ? std::string::npos : line.find('\t', tab1 + 1);
        if (tab2 == std::string::npos) return std::nullopt;

        PointerPath p;
        p.module_name = line.substr(0, tab1);
        if (p.module_name.empty() || !parse_hex(line.substr(tab1 + 1, tab2 - tab1 - 1), p.base_offset)) return std::nullopt;

        const std::string offsets = line.substr(tab2 + 1);
        if (offsets != "-") {
            std::istringstream list(offsets);
            std::string item;
            while (std::getline(list, item, ',')) {
                int64_t offset = 0;
                if (!parse_hex(item, offset)) return std::nullopt;
                p.offsets.push_back(offset);
            }
        }
        paths.push_back(std::move(p));
    }

    if (paths.size() != count) return std::nullopt;
    return paths;
}

} // namespace nce::scanner
