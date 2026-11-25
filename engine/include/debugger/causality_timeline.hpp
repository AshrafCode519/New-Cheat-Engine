#pragma once

#include "access_watcher.hpp"
#include "debug_coordinator.hpp"
#include "../hal/process.hpp"
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace nce::debugger {

struct RegisterDelta {
    std::string name;
    uint64_t before{0};
    uint64_t after{0};
};

struct MemoryDeltaByte {
    uintptr_t address{0};
    uint8_t before{0};
    uint8_t after{0};
};

struct CausalityEvent {
    size_t sequence{0};
    uint64_t timestamp_us{0};
    uint32_t thread_id{0};
    uintptr_t instruction_address{0};
    std::string symbol;
    std::string disassembly;
    Registers registers;
    std::vector<RegisterDelta> reg_deltas;
    uintptr_t watched_address{0};
    std::vector<uint8_t> watched_bytes;
    std::vector<MemoryDeltaByte> memory_deltas;
    std::string summary;
};

struct TimelineDiff {
    std::vector<RegisterDelta> reg_deltas;
    std::vector<MemoryDeltaByte> memory_deltas;
};

// Execution Causality / Time-Travel Timeline: records ordered instruction hits & optional memory
// windows so users can scrub forward/backward through state mutations and inspect exact causality.
class CausalityTimeline {
public:
    explicit CausalityTimeline(size_t max_events = 4096) : m_max_events(max_events) {}

    void clear();
    void set_max_events(size_t cap);

    void push_event(
        uintptr_t instruction_address,
        std::string symbol,
        std::string disassembly,
        const Registers& regs,
        uint32_t thread_id = 0,
        uintptr_t watch_address = 0,
        std::vector<uint8_t> watch_bytes = {}
    );

    void record_trace(
        const std::vector<TraceEntry>& trace_entries,
        const hal::IProcess* process = nullptr,
        uintptr_t watch_address = 0,
        size_t watch_bytes_len = 64
    );

    void record_hits(
        const std::vector<AccessHit>& hits,
        const hal::IProcess* process = nullptr,
        uintptr_t watch_address = 0,
        size_t watch_bytes_len = 64
    );

    [[nodiscard]] size_t count() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] size_t cursor() const noexcept;

    bool seek(size_t index);
    bool step_backward();
    bool step_forward();

    [[nodiscard]] std::optional<CausalityEvent> current() const;
    [[nodiscard]] std::optional<CausalityEvent> at(size_t index) const;
    [[nodiscard]] std::vector<CausalityEvent> events() const;
    [[nodiscard]] TimelineDiff diff_between(size_t from_idx, size_t to_idx) const;
    [[nodiscard]] std::vector<size_t> find_memory_mutations() const;
    [[nodiscard]] std::string format_report(size_t from_idx = 0, size_t max_count = 64) const;

private:
    static std::vector<RegisterDelta> compute_reg_deltas(const Registers& a, const Registers& b);
    static std::vector<MemoryDeltaByte> compute_mem_deltas(
        uintptr_t addr_a, const std::vector<uint8_t>& mem_a,
        uintptr_t addr_b, const std::vector<uint8_t>& mem_b);

    mutable std::mutex m_mutex;
    size_t m_max_events{4096};
    uint64_t m_next_seq{1};
    size_t m_cursor{0};
    std::vector<CausalityEvent> m_events;
};

} // namespace nce::debugger
