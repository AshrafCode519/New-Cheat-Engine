#pragma once

#include "../hal/process.hpp"
#include "access_watcher.hpp"
#include "disassembler.hpp"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace nce::debugger {

namespace veh { struct VehSharedState; }

enum class DebuggerState {
    Detached,
    Running,
    PausedAtBreakpoint,
    PausedAtStep,
    Terminated
};

enum class DebugBackend {
    Win32DebugAPI,
    VEH
};

struct StackFrame {
    uintptr_t rbp{0};
    uintptr_t return_address{0};
    std::string module_name;
    uintptr_t module_offset{0};
    std::string symbol_name; // e.g. "game.exe+0x1234" or resolved PDB symbol
};

struct Breakpoint {
    uintptr_t address{0};
    uint8_t original_byte{0};
    bool is_enabled{false};
    bool is_temporary{false};  // step-over / step-out
    bool is_tracepoint{false}; // log registers & execution without pausing target
    size_t hit_count{0};
    std::string condition;     // e.g. "rax == 0x10 && dword[rcx+0x8] > 0"
    std::string note;
};

struct TraceEntry {
    size_t sequence{0};
    uint32_t thread_id{0};
    uintptr_t address{0};
    std::string symbol;
    std::string disassembly;
    Registers registers;
};

struct HardwareWatchSlot {
    using HitCallback = std::function<void(uint32_t thread_id, uintptr_t rip, const Registers& regs)>;
    bool active{false};
    uintptr_t address{0};
    size_t size{4};
    WatchKind kind{WatchKind::Write};
    HitCallback on_hit;
};

// Unified debugging backend coordinator: runs ONE debug loop per attached process (either Win32
// DebugActiveProcess OR in-process VEH shared-memory agent) and multiplexes both hardware watches
// (DR0-DR3) and software INT 3 breakpoints (with condition evaluation & tracepoints).
class DebugCoordinator {
public:
    explicit DebugCoordinator(std::shared_ptr<hal::IProcess> process);
    ~DebugCoordinator();

    DebugCoordinator(const DebugCoordinator&) = delete;
    DebugCoordinator& operator=(const DebugCoordinator&) = delete;

    // Lifecycle & Backend
    bool attach(DebugBackend backend = DebugBackend::Win32DebugAPI);
    void detach();
    [[nodiscard]] bool is_attached() const noexcept { return m_is_attached; }
    [[nodiscard]] DebugBackend backend() const noexcept { return m_backend; }
    [[nodiscard]] DebuggerState state() const noexcept { return m_state; }
    [[nodiscard]] bool is_paused() const noexcept {
        return m_state == DebuggerState::PausedAtBreakpoint || m_state == DebuggerState::PausedAtStep;
    }

    // Software breakpoints (INT 3) with optional condition and non-pausing tracepoint mode
    bool set_breakpoint(uintptr_t address, const std::string& note = "", bool temporary = false,
                        const std::string& condition = "", bool is_tracepoint = false);
    bool remove_breakpoint(uintptr_t address);
    bool enable_breakpoint(uintptr_t address, bool enable);
    [[nodiscard]] bool has_breakpoint(uintptr_t address) const;
    [[nodiscard]] std::vector<Breakpoint> get_breakpoints() const;

    // Hardware watches (DR0-DR3: up to 4 concurrent watches)
    int add_hw_watch(uintptr_t address, size_t size, WatchKind kind, HardwareWatchSlot::HitCallback cb);
    bool remove_hw_watch(uintptr_t address);
    void remove_all_hw_watches();
    [[nodiscard]] std::vector<uintptr_t> active_hw_watch_addresses() const;

    // Execution control
    bool resume();
    bool pause();
    bool step_into();
    bool step_over();
    bool step_out();

    // Inspection
    [[nodiscard]] uintptr_t current_rip() const noexcept { return m_registers.rip; }
    [[nodiscard]] const Registers& registers() const noexcept { return m_registers; }
    [[nodiscard]] uint32_t active_thread_id() const noexcept { return m_active_thread_id; }
    [[nodiscard]] const std::string& last_error() const noexcept { return m_last_error; }

    [[nodiscard]] std::vector<StackFrame> get_call_stack(size_t max_frames = 16) const;
    [[nodiscard]] std::vector<DecodedInstruction> get_disassembly_around_rip(size_t count = 15) const;
    [[nodiscard]] std::string resolve_symbol(uintptr_t address) const;

    // Execution Trace Log
    [[nodiscard]] std::vector<TraceEntry> get_trace_log() const;
    void clear_trace_log();

    // Optional breakpoint interception callback (e.g. Lua debugger_onBreakpoint).
    // Returning true continues silently (auto single-step & re-arm INT 3); false pauses normally.
    using BreakpointCallback = std::function<bool(uint32_t thread_id, uintptr_t address, Registers& regs)>;
    void set_breakpoint_callback(BreakpointCallback cb);

private:
    bool apply_breakpoint(Breakpoint& bp);
    bool restore_breakpoint_byte(Breakpoint& bp);
    void sync_hw_registers_all_threads();

    // Unified event handlers called by Win32, VEH, and Linux ptrace loops.
    // Returns true if execution should pause waiting for user, false to continue immediately.
    bool process_sw_breakpoint(uint32_t thread_id, uintptr_t bp_addr, Registers& regs, bool& request_tf);
    bool process_single_step(uint32_t thread_id, uintptr_t rip, uint64_t dr6, Registers& regs, bool& request_tf, bool& request_rf);
    void wait_while_paused(bool& out_step, uintptr_t& out_new_rip);
    void append_trace(uint32_t thread_id, uintptr_t addr, const Registers& regs);
    void sync_veh_breakpoints();

#ifdef _WIN32
    void win32_debug_loop(std::promise<bool> start_promise);
    bool veh_attach_impl();
    void veh_debug_loop();
    void veh_cleanup();
    void arm_thread_hw(void* thread_handle) const;
#else
    struct PendingByteWrite { uintptr_t address; uint8_t value; };
    std::vector<PendingByteWrite> m_pending_linux_writes;
    std::atomic<bool> m_linux_sync_hw{false};
    std::atomic<uint64_t> m_linux_hw_gen{0};
    void linux_ptrace_loop(std::promise<bool> start_promise);
#endif

    std::shared_ptr<hal::IProcess> m_process;
    std::atomic<DebuggerState> m_state{DebuggerState::Detached};
    std::atomic<bool> m_is_attached{false};
    std::atomic<bool> m_stop_requested{false};
    DebugBackend m_backend{DebugBackend::Win32DebugAPI};

    uint32_t m_pid{0};
    uint32_t m_active_thread_id{0};
    Registers m_registers{};
    std::string m_last_error;

    mutable std::mutex m_mutex;
    std::condition_variable m_pause_cv;
    bool m_resume_pending{false};
    bool m_step_pending{false};
    bool m_user_step_requested{false};
    bool m_silent_step{false};
    bool m_initial_bp_seen{false};
    uintptr_t m_rearm_bp_addr{0};
    BreakpointCallback m_bp_callback;

    std::map<uintptr_t, Breakpoint> m_breakpoints;
    HardwareWatchSlot m_hw_slots[4]{};
    std::vector<hal::ModuleInfo> m_modules;

    std::vector<TraceEntry> m_trace_log;
    size_t m_trace_seq{0};
    static constexpr size_t kMaxTraceEntries = 2000;

    std::thread m_debug_thread;

#ifdef _WIN32
    void* m_veh_map{nullptr};
    void* m_veh_evt_hit{nullptr};
    void* m_veh_evt_cont{nullptr};
    veh::VehSharedState* m_veh_state{nullptr};
    bool m_sym_initialized{false};
    void* m_sym_proc{nullptr};
#endif
};

} // namespace nce::debugger
