#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace nce::debugger {

class DebugCoordinator;

struct UltimapFunction {
    uintptr_t address{0};
    std::string name;
    std::string module_name;
    size_t baseline_hits{0};
    size_t window_hits{0};
    bool excluded{false};
    bool trace_armed{false};
};

/// Cheat Engine Ultimap-style execution profiler: discovers function entry points across
/// modules, filters out noisy/idle background functions, and ranks code triggered during
/// specific in-game actions.
class UltimapProfiler {
public:
    /// Discovers candidate function entry points via PE/ELF symbols and x64 prologue heuristics.
    size_t discover_functions(
        hal::IProcess& proc,
        const std::string& module_filter = "",
        size_t max_functions = 256);

    /// Adds a specific function address manually.
    void add_function(uintptr_t address, const std::string& name = "", const std::string& module_name = "");

    /// Resets all hit counters and un-excludes all discovered functions.
    void reset();
    void clear();

    /// Arms non-blocking tracepoints on active (non-excluded) functions via DebugCoordinator.
    size_t arm_tracepoints(DebugCoordinator& dbg);
    void disarm_tracepoints(DebugCoordinator& dbg);

    /// Pulls live tracepoint hit counts from DebugCoordinator into window_hits.
    void sync_from_debugger(const DebugCoordinator& dbg);

    /// Manually records hits (useful for scripted trace analysis and unit tests).
    void record_hit(uintptr_t address, size_t count = 1);

    /// Marks the start of a new capture window (stores current hits as baseline).
    void begin_action_window();

    /// Excludes any function that fired during idle monitoring (window_hits > baseline_hits).
    size_t mark_idle_noisy();

    /// Keeps ONLY functions that fired since the window started, excluding untouched functions.
    size_t keep_only_executed();

    /// Resets epoch hit delta cleanly without removing remaining candidates.
    void reset_window_delta();

    [[nodiscard]] std::vector<UltimapFunction> ranked_candidates(bool include_excluded = false) const;
    [[nodiscard]] size_t active_count() const;
    [[nodiscard]] size_t total_count() const { return m_functions.size(); }

private:
    std::vector<UltimapFunction> m_functions;
};

} // namespace nce::debugger
