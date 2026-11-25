#include "debugger/ultimap.hpp"
#include "debugger/debug_coordinator.hpp"
#include "debugger/elf_analyzer.hpp"
#include "debugger/pe_analyzer.hpp"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <unordered_set>

namespace nce::debugger {

namespace {

bool icontains(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(
        hay.begin(), hay.end(), needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != hay.end();
}

std::string hex_addr(uintptr_t a) {
    std::ostringstream ss;
    ss << "sub_" << std::hex << std::uppercase << a;
    return ss.str();
}

} // namespace

size_t UltimapProfiler::discover_functions(
    hal::IProcess& proc,
    const std::string& module_filter,
    size_t max_functions)
{
    if (!proc.is_attached() || max_functions == 0) return 0;

    std::unordered_set<uintptr_t> seen;
    for (const auto& f : m_functions) seen.insert(f.address);

    size_t added = 0;
    const auto mods = proc.get_modules();
    for (const auto& mod : mods) {
        if (added >= max_functions) break;
        if (!icontains(mod.name, module_filter)) continue;

        if (ELFAnalyzer::is_elf_magic(proc, mod.base_address)) {
            if (auto elf = ELFAnalyzer::analyze(proc, mod.base_address)) {
                for (const auto& sym : elf->symbols) {
                    if (added >= max_functions) break;
                    if (sym.va == 0 || (sym.type != 2 && !sym.is_exported)) continue;
                    if (seen.insert(sym.va).second) {
                        m_functions.push_back({sym.va, sym.name, mod.name});
                        ++added;
                    }
                }
            }
        } else if (auto pe = PEAnalyzer::analyze(proc, mod.base_address)) {
            for (const auto& exp : pe->exports) {
                if (added >= max_functions) break;
                if (exp.va == 0 || exp.is_forwarded) continue;
                if (seen.insert(exp.va).second) {
                    std::string fn = exp.name.empty() ? ("#" + std::to_string(exp.ordinal)) : exp.name;
                    m_functions.push_back({exp.va, std::move(fn), mod.name});
                    ++added;
                }
            }
            // Also scan .text for x64 function prologues (`push rbp; mov rbp, rsp` / `sub rsp, imm8` after `0xCC`/`0xC3`)
            for (const auto& sec : pe->sections) {
                if (added >= max_functions) break;
                if (!sec.is_executable || sec.virtual_size == 0) continue;
                const size_t scan_sz = std::min<size_t>(sec.virtual_size, 512 * 1024);
                std::vector<uint8_t> buf(scan_sz);
                if (!proc.read_raw(mod.base_address + sec.virtual_address, buf.data(), buf.size())) continue;
                for (size_t i = 1; i + 5 <= buf.size() && added < max_functions; ++i) {
                    const uint8_t prev = buf[i - 1];
                    if (prev != 0xCC && prev != 0xC3 && prev != 0x90) continue;
                    const bool is_frame_prolog = (buf[i] == 0x55 && buf[i + 1] == 0x48 && buf[i + 2] == 0x89 && buf[i + 3] == 0xE5);
                    const bool is_sub_rsp      = (buf[i] == 0x48 && buf[i + 1] == 0x83 && buf[i + 2] == 0xEC);
                    const bool is_shadow_save  = (buf[i] == 0x48 && buf[i + 1] == 0x89 && buf[i + 2] == 0x5C && buf[i + 3] == 0x24);
                    if (is_frame_prolog || is_sub_rsp || is_shadow_save) {
                        const uintptr_t va = mod.base_address + sec.virtual_address + i;
                        if (seen.insert(va).second) {
                            m_functions.push_back({va, hex_addr(va), mod.name});
                            ++added;
                        }
                    }
                }
            }
        }
    }
    return added;
}

void UltimapProfiler::add_function(uintptr_t address, const std::string& name, const std::string& module_name) {
    if (address == 0) return;
    for (const auto& f : m_functions) {
        if (f.address == address) return;
    }
    m_functions.push_back({address, name.empty() ? hex_addr(address) : name, module_name});
}

void UltimapProfiler::reset() {
    for (auto& f : m_functions) {
        f.baseline_hits = 0;
        f.window_hits = 0;
        f.excluded = false;
    }
}

void UltimapProfiler::clear() {
    m_functions.clear();
}

size_t UltimapProfiler::arm_tracepoints(DebugCoordinator& dbg) {
    size_t count = 0;
    for (auto& f : m_functions) {
        if (f.excluded || f.trace_armed) continue;
        if (dbg.set_breakpoint(f.address, "ultimap:" + f.name, false, "", true)) {
            f.trace_armed = true;
            ++count;
        }
    }
    return count;
}

void UltimapProfiler::disarm_tracepoints(DebugCoordinator& dbg) {
    for (auto& f : m_functions) {
        if (f.trace_armed) {
            dbg.remove_breakpoint(f.address);
            f.trace_armed = false;
        }
    }
}

void UltimapProfiler::sync_from_debugger(const DebugCoordinator& dbg) {
    const auto bps = dbg.get_breakpoints();
    for (auto& f : m_functions) {
        if (f.excluded) continue;
        for (const auto& bp : bps) {
            if (bp.address == f.address) {
                f.window_hits = bp.hit_count;
                break;
            }
        }
    }
}

void UltimapProfiler::record_hit(uintptr_t address, size_t count) {
    for (auto& f : m_functions) {
        if (f.address == address && !f.excluded) {
            f.window_hits += count;
            return;
        }
    }
}

void UltimapProfiler::begin_action_window() {
    for (auto& f : m_functions) {
        f.baseline_hits = f.window_hits;
    }
}

size_t UltimapProfiler::mark_idle_noisy() {
    size_t eliminated = 0;
    for (auto& f : m_functions) {
        if (!f.excluded && f.window_hits > f.baseline_hits) {
            f.excluded = true;
            ++eliminated;
        }
        f.baseline_hits = f.window_hits;
    }
    return eliminated;
}

size_t UltimapProfiler::keep_only_executed() {
    size_t kept = 0;
    for (auto& f : m_functions) {
        if (f.excluded) continue;
        if (f.window_hits <= f.baseline_hits) {
            f.excluded = true;
        } else {
            f.baseline_hits = f.window_hits;
            ++kept;
        }
    }
    return kept;
}

void UltimapProfiler::reset_window_delta() {
    for (auto& f : m_functions) {
        f.baseline_hits = f.window_hits;
    }
}

std::vector<UltimapFunction> UltimapProfiler::ranked_candidates(bool include_excluded) const {
    std::vector<UltimapFunction> out;
    for (const auto& f : m_functions) {
        if (include_excluded || !f.excluded) {
            out.push_back(f);
        }
    }
    std::sort(out.begin(), out.end(), [](const UltimapFunction& a, const UltimapFunction& b) {
        if (a.excluded != b.excluded) return !a.excluded;
        const size_t da = (a.window_hits >= a.baseline_hits) ? (a.window_hits - a.baseline_hits) : 0;
        const size_t db = (b.window_hits >= b.baseline_hits) ? (b.window_hits - b.baseline_hits) : 0;
        if (da != db) return da > db;
        return a.window_hits > b.window_hits;
    });
    return out;
}

size_t UltimapProfiler::active_count() const {
    return static_cast<size_t>(std::count_if(
        m_functions.begin(), m_functions.end(), [](const UltimapFunction& f) { return !f.excluded; }));
}

} // namespace nce::debugger
