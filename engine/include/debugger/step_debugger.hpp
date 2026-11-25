#pragma once

#include "../hal/process.hpp"
#include "access_watcher.hpp"
#include "debug_coordinator.hpp"
#include "disassembler.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace nce::debugger {

// High-level interactive debugger facade backed by a shared DebugCoordinator (supports Win32 Debug API
// and in-process VEH modes, conditional INT 3 breakpoints, tracepoints, single-step, and StackWalk64).
class StepDebugger {
public:
    explicit StepDebugger(std::shared_ptr<hal::IProcess> process,
                          std::shared_ptr<DebugCoordinator> coordinator = nullptr);
    ~StepDebugger();

    StepDebugger(const StepDebugger&) = delete;
    StepDebugger& operator=(const StepDebugger&) = delete;

    void set_coordinator(std::shared_ptr<DebugCoordinator> coordinator);
    [[nodiscard]] DebugCoordinator* coordinator() const noexcept { return m_coord.get(); }

    // Attach/detach debugging engine
    bool attach(DebugBackend backend = DebugBackend::Win32DebugAPI);
    void detach();
    void set_preferred_backend(DebugBackend backend) { m_preferred_backend = backend; }
    [[nodiscard]] DebugBackend backend() const noexcept;

    // Breakpoint management (INT 3 / 0xCC) with optional condition and non-blocking tracepoint mode
    bool set_breakpoint(uintptr_t address, const std::string& note = "", bool temporary = false,
                        const std::string& condition = "", bool is_tracepoint = false);
    bool remove_breakpoint(uintptr_t address);
    bool enable_breakpoint(uintptr_t address, bool enable);
    [[nodiscard]] bool has_breakpoint(uintptr_t address) const;
    [[nodiscard]] std::vector<Breakpoint> get_breakpoints() const;

    // Execution control
    bool resume();
    bool pause();
    bool step_into();
    bool step_over();
    bool step_out();

    // Current state & inspection
    [[nodiscard]] DebuggerState state() const noexcept;
    [[nodiscard]] bool is_attached() const noexcept;
    [[nodiscard]] bool is_paused() const noexcept;
    [[nodiscard]] uintptr_t current_rip() const noexcept;
    [[nodiscard]] const Registers& registers() const noexcept;
    [[nodiscard]] uint32_t active_thread_id() const noexcept;
    [[nodiscard]] const std::string& last_error() const noexcept;

    // Call stack unwinding (StackWalk64 + PDB symbols on live Win32 processes, fallback to walk_stack)
    [[nodiscard]] std::vector<StackFrame> get_call_stack(size_t max_frames = 16) const;
    [[nodiscard]] std::vector<DecodedInstruction> get_disassembly_around_rip(size_t count = 15) const;

    // Trace log access
    [[nodiscard]] std::vector<TraceEntry> get_trace_log() const;
    void clear_trace_log();

    void set_breakpoint_callback(DebugCoordinator::BreakpointCallback cb);

    // Helper static methods for unit testing stack walk and call detection
    static bool is_call_instruction(const DecodedInstruction& insn);
    static std::vector<StackFrame> walk_stack(const hal::IProcess& proc,
                                              uintptr_t rbp,
                                              uintptr_t rsp,
                                              const std::vector<hal::ModuleInfo>& modules,
                                              size_t max_frames = 16);

private:
    std::shared_ptr<hal::IProcess> m_process;
    std::shared_ptr<DebugCoordinator> m_coord;
    bool m_owns_coord{false};
    DebugBackend m_preferred_backend{DebugBackend::Win32DebugAPI};
};

} // namespace nce::debugger
