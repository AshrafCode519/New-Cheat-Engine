#include "../../include/debugger/debug_coordinator.hpp"
#include "../../include/debugger/condition_eval.hpp"
#include "../../include/debugger/step_debugger.hpp"
#include "../../include/debugger/veh_protocol.hpp"
#include "../../include/hal/injector.hpp"
#include "../../include/utils/hex_utils.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <unordered_map>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dbghelp.h>
#else
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>
#endif

namespace nce::debugger {

namespace {

std::string format_symbol(uintptr_t addr, const std::vector<hal::ModuleInfo>& modules) {
    for (const auto& mod : modules) {
        if (addr >= mod.base_address && addr < mod.base_address + mod.size) {
            std::ostringstream ss;
            ss << mod.name << "+0x" << std::hex << std::uppercase << (addr - mod.base_address);
            return ss.str();
        }
    }
    return utils::format_address(addr);
}

#ifdef _WIN32
void regs_from_win32_ctx(const CONTEXT& ctx, Registers& r) {
    r.rax = ctx.Rax; r.rbx = ctx.Rbx; r.rcx = ctx.Rcx; r.rdx = ctx.Rdx;
    r.rsi = ctx.Rsi; r.rdi = ctx.Rdi; r.rbp = ctx.Rbp; r.rsp = ctx.Rsp;
    r.rip = ctx.Rip;
    r.r8  = ctx.R8;  r.r9  = ctx.R9;  r.r10 = ctx.R10; r.r11 = ctx.R11;
    r.r12 = ctx.R12; r.r13 = ctx.R13; r.r14 = ctx.R14; r.r15 = ctx.R15;
    r.eflags = ctx.EFlags;
}

void win32_ctx_from_regs(const Registers& r, CONTEXT& ctx) {
    ctx.Rax = r.rax; ctx.Rbx = r.rbx; ctx.Rcx = r.rcx; ctx.Rdx = r.rdx;
    ctx.Rsi = r.rsi; ctx.Rdi = r.rdi; ctx.Rbp = r.rbp; ctx.Rsp = r.rsp;
    ctx.Rip = r.rip;
    ctx.R8  = r.r8;  ctx.R9  = r.r9;  ctx.R10 = r.r10; ctx.R11 = r.r11;
    ctx.R12 = r.r12; ctx.R13 = r.r13; ctx.R14 = r.r14; ctx.R15 = r.r15;
    ctx.EFlags = static_cast<DWORD>(r.eflags);
}

void regs_from_wow64_ctx(const WOW64_CONTEXT& wc, Registers& r) {
    r.rax = wc.Eax; r.rbx = wc.Ebx; r.rcx = wc.Ecx; r.rdx = wc.Edx;
    r.rsi = wc.Esi; r.rdi = wc.Edi; r.rbp = wc.Ebp; r.rsp = wc.Esp;
    r.rip = wc.Eip;
    r.r8 = r.r9 = r.r10 = r.r11 = r.r12 = r.r13 = r.r14 = r.r15 = 0;
    r.eflags = wc.EFlags;
}

void wow64_ctx_from_regs(const Registers& r, WOW64_CONTEXT& wc) {
    wc.Eax = static_cast<DWORD>(r.rax); wc.Ebx = static_cast<DWORD>(r.rbx);
    wc.Ecx = static_cast<DWORD>(r.rcx); wc.Edx = static_cast<DWORD>(r.rdx);
    wc.Esi = static_cast<DWORD>(r.rsi); wc.Edi = static_cast<DWORD>(r.rdi);
    wc.Ebp = static_cast<DWORD>(r.rbp); wc.Esp = static_cast<DWORD>(r.rsp);
    wc.Eip = static_cast<DWORD>(r.rip);
    wc.EFlags = static_cast<DWORD>(r.eflags);
}

#ifndef STATUS_WX86_BREAKPOINT
constexpr DWORD kStatusWx86Breakpoint = 0x4000001FUL;
#else
constexpr DWORD kStatusWx86Breakpoint = STATUS_WX86_BREAKPOINT;
#endif
#ifndef STATUS_WX86_SINGLE_STEP
constexpr DWORD kStatusWx86SingleStep = 0x4000001EUL;
#else
constexpr DWORD kStatusWx86SingleStep = STATUS_WX86_SINGLE_STEP;
#endif

void regs_from_veh(const veh::VehRegisters& vr, Registers& r) {
    r.rax = vr.rax; r.rbx = vr.rbx; r.rcx = vr.rcx; r.rdx = vr.rdx;
    r.rsi = vr.rsi; r.rdi = vr.rdi; r.rbp = vr.rbp; r.rsp = vr.rsp;
    r.rip = vr.rip;
    r.r8  = vr.r8;  r.r9  = vr.r9;  r.r10 = vr.r10; r.r11 = vr.r11;
    r.r12 = vr.r12; r.r13 = vr.r13; r.r14 = vr.r14; r.r15 = vr.r15;
    r.eflags = vr.eflags;
}

void regs_to_veh(const Registers& r, veh::VehRegisters& vr) {
    vr.rax = r.rax; vr.rbx = r.rbx; vr.rcx = r.rcx; vr.rdx = r.rdx;
    vr.rsi = r.rsi; vr.rdi = r.rdi; vr.rbp = r.rbp; vr.rsp = r.rsp;
    vr.rip = r.rip;
    vr.r8  = r.r8;  vr.r9  = r.r9;  vr.r10 = r.r10; vr.r11 = r.r11;
    vr.r12 = r.r12; vr.r13 = r.r13; vr.r14 = r.r14; vr.r15 = r.r15;
    vr.eflags = r.eflags;
}

std::wstring format_pid_str(const wchar_t* prefix, uint32_t pid) {
    return std::wstring(prefix) + std::to_wstring(pid);
}
#endif

void apply_hw_slots_to_dr(const HardwareWatchSlot slots[4], uint64_t& dr0, uint64_t& dr1, uint64_t& dr2, uint64_t& dr3, uint64_t& dr7) {
    uint64_t* drs[4] = {&dr0, &dr1, &dr2, &dr3};
    dr7 &= ~0xFFFF00FFULL; // preserve reserved bits, clear L0-L3, G0-G3, RW0-RW3, LEN0-LEN3
    for (int s = 0; s < 4; ++s) {
        if (!slots[s].active) {
            *drs[s] = 0;
            continue;
        }
        *drs[s] = slots[s].address;
        dr7 |= (1ULL << (s * 2)); // L_s local enable

        uint64_t rw = 1; // 01 = Write
        if (slots[s].kind == WatchKind::Access) rw = 3; // 11 = Read/Write
        else if (slots[s].kind == WatchKind::Execute) rw = 0; // 00 = Execute

        uint64_t len = 3; // 4 bytes default
        if (slots[s].kind == WatchKind::Execute || slots[s].size == 1) len = 0;
        else if (slots[s].size == 2) len = 1;
        else if (slots[s].size == 8) len = 2;

        dr7 |= (rw << (16 + s * 4)) | (len << (18 + s * 4));
    }
}

} // anonymous namespace

DebugCoordinator::DebugCoordinator(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
{}

DebugCoordinator::~DebugCoordinator() {
    detach();
}

bool DebugCoordinator::is_target_64bit() const noexcept {
    if (m_is_wow64) return false;
    return !m_process || m_process->pointer_size() != 4;
}

bool DebugCoordinator::set_breakpoint(uintptr_t address, const std::string& note, bool temporary,
                                      const std::string& condition, bool is_tracepoint) {
    if (address == 0) return false;
    if (!condition.empty()) {
        if (auto err = ConditionEvaluator::validate(condition)) {
            m_last_error = "Invalid breakpoint condition: " + *err;
            return false;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_breakpoints.find(address);
    if (it != m_breakpoints.end()) {
        it->second.note = note;
        it->second.is_temporary = temporary;
        it->second.condition = condition;
        it->second.is_tracepoint = is_tracepoint;
        it->second.is_enabled = true;
        if (m_is_attached) {
            apply_breakpoint(it->second);
            sync_veh_breakpoints();
        }
        return true;
    }

    uint8_t orig = 0;
    if (m_process && m_process->is_attached()) {
        if (!m_process->read_raw(address, &orig, 1)) return false;
    }

    Breakpoint bp;
    bp.address = address;
    bp.original_byte = orig;
    bp.is_enabled = true;
    bp.is_temporary = temporary;
    bp.is_tracepoint = is_tracepoint;
    bp.condition = condition;
    bp.note = note;

    if (m_is_attached) {
        apply_breakpoint(bp);
    }

    m_breakpoints[address] = std::move(bp);
    if (m_is_attached) sync_veh_breakpoints();
    return true;
}

bool DebugCoordinator::remove_breakpoint(uintptr_t address) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_breakpoints.find(address);
    if (it == m_breakpoints.end()) return false;

    if (m_is_attached && it->second.is_enabled) {
        restore_breakpoint_byte(it->second);
    }

    m_breakpoints.erase(it);
    if (m_is_attached) sync_veh_breakpoints();
    return true;
}

bool DebugCoordinator::enable_breakpoint(uintptr_t address, bool enable) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_breakpoints.find(address);
    if (it == m_breakpoints.end()) return false;
    if (it->second.is_enabled == enable) return true;
    it->second.is_enabled = enable;

    if (m_is_attached) {
        if (enable) apply_breakpoint(it->second);
        else restore_breakpoint_byte(it->second);
        sync_veh_breakpoints();
    }
    return true;
}

bool DebugCoordinator::has_breakpoint(uintptr_t address) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_breakpoints.find(address) != m_breakpoints.end();
}

std::vector<Breakpoint> DebugCoordinator::get_breakpoints() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<Breakpoint> list;
    list.reserve(m_breakpoints.size());
    for (const auto& [addr, bp] : m_breakpoints) {
        list.push_back(bp);
    }
    return list;
}

int DebugCoordinator::add_hw_watch(uintptr_t address, size_t size, WatchKind kind, HardwareWatchSlot::HitCallback cb) {
    if (address == 0) return -1;
    if (size != 1 && size != 2 && size != 4 && size != 8) size = 4;

    int assigned_slot = -1;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (int s = 0; s < 4; ++s) {
            if (m_hw_slots[s].active && m_hw_slots[s].address == address) {
                m_hw_slots[s].size = size;
                m_hw_slots[s].kind = kind;
                m_hw_slots[s].on_hit = std::move(cb);
                assigned_slot = s;
                break;
            }
        }
        if (assigned_slot == -1) {
            for (int s = 0; s < 4; ++s) {
                if (!m_hw_slots[s].active) {
                    m_hw_slots[s].active = true;
                    m_hw_slots[s].address = address;
                    m_hw_slots[s].size = size;
                    m_hw_slots[s].kind = kind;
                    m_hw_slots[s].on_hit = std::move(cb);
                    assigned_slot = s;
                    break;
                }
            }
        }
    }

    if (assigned_slot != -1 && m_is_attached) {
        sync_hw_registers_all_threads();
    }
    return assigned_slot;
}

bool DebugCoordinator::remove_hw_watch(uintptr_t address) {
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (int s = 0; s < 4; ++s) {
            if (m_hw_slots[s].active && m_hw_slots[s].address == address) {
                m_hw_slots[s] = {};
                removed = true;
            }
        }
    }
    if (removed && m_is_attached) {
        sync_hw_registers_all_threads();
    }
    return removed;
}

void DebugCoordinator::remove_all_hw_watches() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (int s = 0; s < 4; ++s) {
            m_hw_slots[s] = {};
        }
    }
    if (m_is_attached) {
        sync_hw_registers_all_threads();
    }
}

std::vector<uintptr_t> DebugCoordinator::active_hw_watch_addresses() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<uintptr_t> out;
    for (int s = 0; s < 4; ++s) {
        if (m_hw_slots[s].active) out.push_back(m_hw_slots[s].address);
    }
    return out;
}

bool DebugCoordinator::apply_guard_page(uintptr_t page_base, uint32_t& out_orig_prot) {
#ifdef _WIN32
    if (m_pid == 0 || page_base == 0) return false;
    HANDLE hp = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, m_pid);
    if (!hp) return false;
    DWORD prot = static_cast<DWORD>(out_orig_prot);
    if (prot == 0) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hp, reinterpret_cast<LPCVOID>(page_base), &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT) {
            CloseHandle(hp);
            return false;
        }
        prot = mbi.Protect & ~static_cast<DWORD>(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
        if (prot == 0 || prot == PAGE_NOACCESS) {
            CloseHandle(hp);
            return false;
        }
        out_orig_prot = static_cast<uint32_t>(prot);
    }
    DWORD dummy = 0;
    const BOOL ok = VirtualProtectEx(hp, reinterpret_cast<LPVOID>(page_base), 4096, prot | PAGE_GUARD, &dummy);
    CloseHandle(hp);
    return ok == TRUE;
#else
    (void)page_base;
    (void)out_orig_prot;
    return false;
#endif
}

void DebugCoordinator::restore_guard_page(uintptr_t page_base, uint32_t orig_prot) {
#ifdef _WIN32
    if (m_pid == 0 || page_base == 0 || orig_prot == 0) return;
    HANDLE hp = OpenProcess(PROCESS_VM_OPERATION, FALSE, m_pid);
    if (!hp) return;
    DWORD dummy = 0;
    VirtualProtectEx(hp, reinterpret_cast<LPVOID>(page_base), 4096, static_cast<DWORD>(orig_prot), &dummy);
    CloseHandle(hp);
#else
    (void)page_base;
    (void)orig_prot;
#endif
}

bool DebugCoordinator::add_guard_watch(uintptr_t address, size_t size, HardwareWatchSlot::HitCallback cb) {
#ifdef _WIN32
    if (address == 0) return false;
    if (size == 0) size = 4;
    const uintptr_t page_base = address & ~uintptr_t{0xFFF};

    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& g : m_guard_watches) {
        if (g.address == address) {
            g.size = size;
            g.on_hit = std::move(cb);
            if (m_is_attached && !g.armed) {
                uint32_t prot = g.orig_prot;
                if (!apply_guard_page(page_base, prot)) return false;
                g.orig_prot = prot;
                g.armed = true;
            }
            return true;
        }
    }

    uint32_t shared_prot = 0;
    bool already_armed = false;
    for (const auto& g : m_guard_watches) {
        if (g.page_base == page_base && g.armed) {
            shared_prot = g.orig_prot;
            already_armed = true;
            break;
        }
    }

    GuardWatchSlot slot;
    slot.address = address;
    slot.size = size;
    slot.page_base = page_base;
    slot.orig_prot = shared_prot;
    slot.armed = already_armed;
    slot.on_hit = std::move(cb);

    if (m_is_attached && !slot.armed) {
        if (!apply_guard_page(page_base, slot.orig_prot)) return false;
        slot.armed = true;
    }
    m_guard_watches.push_back(std::move(slot));
    return true;
#else
    (void)address;
    (void)size;
    (void)cb;
    return false;
#endif
}

bool DebugCoordinator::remove_guard_watch(uintptr_t address) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = std::find_if(m_guard_watches.begin(), m_guard_watches.end(),
                           [address](const GuardWatchSlot& g) { return g.address == address; });
    if (it == m_guard_watches.end()) return false;
    const uintptr_t page_base = it->page_base;
    const uint32_t orig_prot = it->orig_prot;
    const bool was_armed = it->armed;
    m_guard_watches.erase(it);

    const bool still_used = std::any_of(m_guard_watches.begin(), m_guard_watches.end(),
                                        [page_base](const GuardWatchSlot& g) { return g.page_base == page_base; });
    if (!still_used) {
        if (m_rearm_guard_page == page_base) m_rearm_guard_page = 0;
        if (was_armed) restore_guard_page(page_base, orig_prot);
    }
    return true;
}

void DebugCoordinator::remove_all_guard_watches() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::pair<uintptr_t, uint32_t>> pages;
    for (const auto& g : m_guard_watches) {
        if (g.armed && std::none_of(pages.begin(), pages.end(),
                                    [&](const auto& p) { return p.first == g.page_base; })) {
            pages.emplace_back(g.page_base, g.orig_prot);
        }
    }
    m_guard_watches.clear();
    m_rearm_guard_page = 0;
    for (const auto& [pg, prot] : pages) {
        restore_guard_page(pg, prot);
    }
}

std::vector<uintptr_t> DebugCoordinator::active_guard_watch_addresses() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<uintptr_t> out;
    out.reserve(m_guard_watches.size());
    for (const auto& g : m_guard_watches) out.push_back(g.address);
    return out;
}

bool DebugCoordinator::attach(DebugBackend backend) {
    if (m_is_attached) {
        if (m_backend == backend) return true;
        detach();
    }
    if (!m_process || !m_process->is_attached()) {
        m_last_error = "Target process is not attached.";
        return false;
    }

    m_backend = backend;
    m_pid = m_process->get_pid();
    m_modules = m_process->get_modules();
    m_stop_requested = false;
    m_initial_bp_seen = false;
    m_wow64_initial_bp_seen = false;
    m_is_wow64 = (m_process->pointer_size() == 4);
    m_rearm_bp_addr = 0;
    m_rearm_guard_page = 0;
    m_silent_step = false;
    m_resume_pending = false;
    m_step_pending = false;
    m_user_step_requested = false;

#ifdef _WIN32
    m_sym_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_pid);
    if (m_sym_proc) {
        BOOL w64 = FALSE;
        if (IsWow64Process(static_cast<HANDLE>(m_sym_proc), &w64) && w64) {
            m_is_wow64 = true;
        }
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        m_sym_initialized = (SymInitialize(static_cast<HANDLE>(m_sym_proc), nullptr, TRUE) == TRUE);
    }

    if (backend == DebugBackend::VEH) {
        if (!veh_attach_impl()) {
            if (m_sym_initialized && m_sym_proc) { SymCleanup(static_cast<HANDLE>(m_sym_proc)); m_sym_initialized = false; }
            if (m_sym_proc) { CloseHandle(static_cast<HANDLE>(m_sym_proc)); m_sym_proc = nullptr; }
            return false;
        }
        m_is_attached = true;
        m_state = DebuggerState::Running;
        // Apply any queued SW breakpoints & HW watches
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& [addr, bp] : m_breakpoints) {
                if (bp.is_enabled) apply_breakpoint(bp);
            }
            sync_veh_breakpoints();
        }
        sync_hw_registers_all_threads();
        m_debug_thread = std::thread([this]() { veh_debug_loop(); });
        return true;
    }

    std::promise<bool> start_promise;
    auto future = start_promise.get_future();
    m_debug_thread = std::thread([this, p = std::move(start_promise)]() mutable {
        win32_debug_loop(std::move(p));
    });

    const bool ok = future.get();
    if (!ok) {
        if (m_debug_thread.joinable()) m_debug_thread.join();
        if (m_sym_initialized && m_sym_proc) { SymCleanup(static_cast<HANDLE>(m_sym_proc)); m_sym_initialized = false; }
        if (m_sym_proc) { CloseHandle(static_cast<HANDLE>(m_sym_proc)); m_sym_proc = nullptr; }
        m_is_attached = false;
        m_state = DebuggerState::Detached;
        return false;
    }

    m_is_attached = true;
    m_state = DebuggerState::Running;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [addr, bp] : m_breakpoints) {
            if (bp.is_enabled) apply_breakpoint(bp);
        }
        for (auto& g : m_guard_watches) {
            if (!g.armed && apply_guard_page(g.page_base, g.orig_prot)) {
                g.armed = true;
            }
        }
    }
    sync_hw_registers_all_threads();
    return true;
#else
    std::promise<bool> start_promise;
    auto future = start_promise.get_future();
    m_debug_thread = std::thread([this, p = std::move(start_promise)]() mutable {
        linux_ptrace_loop(std::move(p));
    });

    const bool ok = future.get();
    if (!ok) {
        if (m_debug_thread.joinable()) m_debug_thread.join();
        m_is_attached = false;
        m_state = DebuggerState::Detached;
        return false;
    }

    m_is_attached = true;
    m_state = DebuggerState::Running;
    return true;
#endif
}

void DebugCoordinator::detach() {
    if (!m_is_attached && !m_debug_thread.joinable()) return;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stop_requested = true;
        m_resume_pending = true;
        if (m_process && m_process->is_attached()) {
            for (auto& [addr, bp] : m_breakpoints) {
                if (bp.is_enabled) restore_breakpoint_byte(bp);
            }
            for (auto& g : m_guard_watches) {
                if (g.armed) {
                    restore_guard_page(g.page_base, g.orig_prot);
                    g.armed = false;
                }
            }
            m_rearm_guard_page = 0;
        }
#ifdef _WIN32
        if (m_veh_state) {
            m_veh_state->detach_requested = 1;
            m_veh_state->command = static_cast<uint32_t>(veh::VehCommand::Detach);
            if (m_veh_evt_cont) SetEvent(static_cast<HANDLE>(m_veh_evt_cont));
        }
#endif
    }
    m_pause_cv.notify_all();
#ifndef _WIN32
    if (m_pid != 0) {
        kill(static_cast<pid_t>(m_pid), SIGCONT);
    }
#endif

    if (m_debug_thread.joinable()) {
        m_debug_thread.join();
    }

#ifdef _WIN32
    // Disarm DR0-DR3 on target threads without destroying caller watch configurations if switching backends
    if (m_pid != 0) {
        auto threads = hal::ProcessInjector::list_threads(m_pid);
        for (const auto& t : threads) {
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, t.tid);
            if (!th) continue;
            if (SuspendThread(th) != static_cast<DWORD>(-1)) {
                if (m_is_wow64) {
                    WOW64_CONTEXT wctx{};
                    wctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
                    if (Wow64GetThreadContext(th, &wctx)) {
                        wctx.Dr0 = wctx.Dr1 = wctx.Dr2 = wctx.Dr3 = 0;
                        wctx.Dr7 &= ~0xFFFF00FFUL;
                        Wow64SetThreadContext(th, &wctx);
                    }
                } else {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(th, &ctx)) {
                        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
                        ctx.Dr7 &= ~0xFFFF00FFULL;
                        SetThreadContext(th, &ctx);
                    }
                }
                ResumeThread(th);
            }
            CloseHandle(th);
        }
    }
    veh_cleanup();
    if (m_sym_initialized && m_sym_proc) {
        SymCleanup(static_cast<HANDLE>(m_sym_proc));
        m_sym_initialized = false;
    }
    if (m_sym_proc) {
        CloseHandle(static_cast<HANDLE>(m_sym_proc));
        m_sym_proc = nullptr;
    }
#endif

    m_is_attached = false;
    m_state = DebuggerState::Detached;
    m_is_wow64 = false;
    m_pid = 0;
}

bool DebugCoordinator::resume() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!is_paused()) return false;
    m_state = DebuggerState::Running;
    m_resume_pending = true;
    m_user_step_requested = false;
    m_pause_cv.notify_all();
    return true;
}

bool DebugCoordinator::pause() {
    if (!m_is_attached || m_state != DebuggerState::Running) return false;
#ifdef _WIN32
    auto threads = hal::ProcessInjector::list_threads(m_pid);
    if (threads.empty()) return false;

    const uint32_t target_tid = (m_active_thread_id != 0) ? m_active_thread_id : threads[0].tid;
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, target_tid);
    if (!th) return false;

    if (SuspendThread(th) != static_cast<DWORD>(-1)) {
        if (m_is_wow64) {
            WOW64_CONTEXT wctx{};
            wctx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER;
            if (Wow64GetThreadContext(th, &wctx)) {
                wctx.EFlags |= 0x100UL;
                Wow64SetThreadContext(th, &wctx);
                std::lock_guard<std::mutex> lock(m_mutex);
                m_user_step_requested = true;
                regs_from_wow64_ctx(wctx, m_registers);
                m_active_thread_id = target_tid;
            }
        } else {
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (GetThreadContext(th, &ctx)) {
                if (m_backend == DebugBackend::Win32DebugAPI || m_backend == DebugBackend::VEH) {
                    ctx.EFlags |= 0x100UL; // Arm Trap Flag so thread cleanly hits debug loop on next instruction
                    SetThreadContext(th, &ctx);
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_user_step_requested = true;
                        regs_from_win32_ctx(ctx, m_registers);
                        m_active_thread_id = target_tid;
                    }
                }
            }
        }
        ResumeThread(th);
        CloseHandle(th);
        return true;
    }
    CloseHandle(th);
#else
    const uint32_t target_tid = (m_active_thread_id != 0) ? m_active_thread_id : m_pid;
    if (target_tid != 0) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_user_step_requested = true;
        }
#ifdef SYS_tkill
        if (syscall(SYS_tkill, static_cast<pid_t>(target_tid), SIGSTOP) == 0) {
            return true;
        }
#endif
        if (kill(static_cast<pid_t>(m_pid), SIGSTOP) == 0) {
            return true;
        }
    }
#endif
    return false;
}

bool DebugCoordinator::step_into() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!is_paused()) return false;
    m_state = DebuggerState::Running;
    m_step_pending = true;
    m_user_step_requested = true;
    m_pause_cv.notify_all();
    return true;
}

bool DebugCoordinator::step_over() {
    uintptr_t rip = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!is_paused() || !m_process || m_registers.rip == 0) return false;
        rip = m_registers.rip;
    }

    uint8_t code_buf[16]{};
    if (m_process->read_raw(rip, code_buf, sizeof(code_buf))) {
        auto insn = Disassembler::decode(code_buf, sizeof(code_buf), rip, is_target_64bit());
        if (StepDebugger::is_call_instruction(insn)) {
            uintptr_t ret_addr = rip + insn.length;
            set_breakpoint(ret_addr, "step-over-temp", true);
            return resume();
        }
    }
    return step_into();
}

bool DebugCoordinator::step_out() {
    uintptr_t rsp = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!is_paused() || !m_process || m_registers.rsp == 0) return false;
        rsp = m_registers.rsp;
    }

    uintptr_t ret_addr = 0;
    bool read_ok = false;
    if (!is_target_64bit()) {
        uint32_t ret32 = 0;
        read_ok = m_process->read_raw(rsp, &ret32, sizeof(ret32));
        ret_addr = ret32;
    } else {
        read_ok = m_process->read_raw(rsp, &ret_addr, sizeof(ret_addr));
    }
    if (read_ok && ret_addr > 0x1000) {
        set_breakpoint(ret_addr, "step-out-temp", true);
        return resume();
    }
    return false;
}

std::vector<StackFrame> DebugCoordinator::get_call_stack(size_t max_frames) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_process || !m_process->is_attached()) return {};

#ifdef _WIN32
    if (m_sym_proc && m_active_thread_id != 0 && is_paused()) {
        HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, m_active_thread_id);
        if (th) {
            CONTEXT ctx64{};
            WOW64_CONTEXT ctx32{};
            STACKFRAME64 sf{};
            void* ctx_ptr = nullptr;
            DWORD machine = IMAGE_FILE_MACHINE_AMD64;
            bool ctx_ok = false;

            if (m_is_wow64) {
                machine = IMAGE_FILE_MACHINE_I386;
                ctx32.ContextFlags = WOW64_CONTEXT_FULL;
                ctx_ok = (Wow64GetThreadContext(th, &ctx32) == TRUE);
                if (ctx_ok) {
                    sf.AddrPC.Offset = ctx32.Eip;
                    sf.AddrFrame.Offset = ctx32.Ebp;
                    sf.AddrStack.Offset = ctx32.Esp;
                    ctx_ptr = &ctx32;
                }
            } else {
                ctx64.ContextFlags = CONTEXT_FULL;
                ctx_ok = (GetThreadContext(th, &ctx64) == TRUE);
                if (ctx_ok) {
                    sf.AddrPC.Offset = ctx64.Rip;
                    sf.AddrFrame.Offset = ctx64.Rbp;
                    sf.AddrStack.Offset = ctx64.Rsp;
                    ctx_ptr = &ctx64;
                }
            }

            if (ctx_ok) {
                sf.AddrPC.Mode = AddrModeFlat;
                sf.AddrFrame.Mode = AddrModeFlat;
                sf.AddrStack.Mode = AddrModeFlat;

                std::vector<StackFrame> frames;
                for (size_t i = 0; i < max_frames; ++i) {
                    if (!StackWalk64(machine,
                                     static_cast<HANDLE>(m_sym_proc),
                                     th,
                                     &sf,
                                     ctx_ptr,
                                     nullptr,
                                     SymFunctionTableAccess64,
                                     SymGetModuleBase64,
                                     nullptr)) {
                        break;
                    }
                    if (sf.AddrPC.Offset == 0) break;

                    StackFrame out_f;
                    out_f.rbp = static_cast<uintptr_t>(sf.AddrFrame.Offset);
                    out_f.return_address = static_cast<uintptr_t>(sf.AddrReturn.Offset != 0 ? sf.AddrReturn.Offset : sf.AddrPC.Offset);

                    const uintptr_t sym_addr = static_cast<uintptr_t>(sf.AddrPC.Offset);
                    for (const auto& mod : m_modules) {
                        if (sym_addr >= mod.base_address && sym_addr < mod.base_address + mod.size) {
                            out_f.module_name = mod.name;
                            out_f.module_offset = sym_addr - mod.base_address;
                            break;
                        }
                    }

                    bool resolved_pdb = false;
                    if (m_sym_initialized) {
                        alignas(SYMBOL_INFO) uint8_t sym_buf[sizeof(SYMBOL_INFO) + 256]{};
                        auto* sym = reinterpret_cast<SYMBOL_INFO*>(sym_buf);
                        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
                        sym->MaxNameLen = 255;
                        DWORD64 disp = 0;
                        if (SymFromAddr(static_cast<HANDLE>(m_sym_proc), sym_addr, &disp, sym)) {
                            std::ostringstream ss;
                            if (!out_f.module_name.empty()) ss << out_f.module_name << "!";
                            ss << sym->Name << "+0x" << std::hex << std::uppercase << disp;
                            out_f.symbol_name = ss.str();
                            resolved_pdb = true;
                        }
                    }
                    if (!resolved_pdb) {
                        out_f.symbol_name = format_symbol(sym_addr, m_modules);
                    }
                    frames.push_back(std::move(out_f));
                    if (sf.AddrReturn.Offset == 0) break;
                }
                CloseHandle(th);
                if (!frames.empty()) return frames;
            } else {
                CloseHandle(th);
            }
        }
    }
#endif

    return StepDebugger::walk_stack(*m_process, m_registers.rbp, m_registers.rsp, m_modules, max_frames);
}

std::vector<DecodedInstruction> DebugCoordinator::get_disassembly_around_rip(size_t count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_process || !m_process->is_attached() || m_registers.rip == 0) return {};

    const size_t bytes_to_read = count * 15;
    std::vector<uint8_t> code(bytes_to_read, 0);
    if (!m_process->read_raw(m_registers.rip, code.data(), bytes_to_read)) return {};
    auto insns = Disassembler::disassemble_range(code.data(), bytes_to_read, m_registers.rip, count, is_target_64bit());
    return insns;
}

std::string DebugCoordinator::resolve_symbol(uintptr_t address) const {
    if (address == 0) return {};
    std::lock_guard<std::mutex> lock(m_mutex);
#ifdef _WIN32
    if (m_sym_initialized && m_sym_proc) {
        alignas(SYMBOL_INFO) uint8_t sym_buf[sizeof(SYMBOL_INFO) + 256]{};
        auto* sym = reinterpret_cast<SYMBOL_INFO*>(sym_buf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = 255;
        DWORD64 disp = 0;
        if (SymFromAddr(static_cast<HANDLE>(m_sym_proc), address, &disp, sym)) {
            std::string mod_prefix;
            for (const auto& mod : m_modules) {
                if (address >= mod.base_address && address < mod.base_address + mod.size) {
                    mod_prefix = mod.name + "!";
                    break;
                }
            }
            if (disp == 0) return mod_prefix + sym->Name;
            std::ostringstream ss;
            ss << mod_prefix << sym->Name << "+0x" << std::hex << std::uppercase << disp;
            return ss.str();
        }
    }
#endif
    for (const auto& mod : m_modules) {
        if (address >= mod.base_address && address < mod.base_address + mod.size) {
            return format_symbol(address, m_modules);
        }
    }
    return {};
}

std::vector<TraceEntry> DebugCoordinator::get_trace_log() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_trace_log;
}

void DebugCoordinator::clear_trace_log() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_trace_log.clear();
    m_trace_seq = 0;
}

bool DebugCoordinator::apply_breakpoint(Breakpoint& bp) {
    if (!m_process || bp.address == 0) return false;
#ifdef _WIN32
    uint8_t int3 = 0xCC;
    return m_process->write_raw(bp.address, &int3, 1, true);
#else
    if (m_is_attached && std::this_thread::get_id() != m_debug_thread.get_id()) {
        m_pending_linux_writes.push_back({bp.address, 0xCC});
        if (m_pid != 0) kill(static_cast<pid_t>(m_pid), SIGSTOP);
        return true;
    }
    if (m_is_attached && m_pid != 0) {
        // Already inside ptrace tracer loop: poke directly bypassing RX protection
        const size_t wsz = sizeof(long);
        const uintptr_t aligned = bp.address & ~(wsz - 1);
        const size_t off = bp.address - aligned;
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, static_cast<pid_t>(m_pid), reinterpret_cast<void*>(aligned), nullptr);
        if (errno == 0) {
            uint8_t bytes[sizeof(long)];
            std::memcpy(bytes, &word, wsz);
            bytes[off] = 0xCC;
            std::memcpy(&word, bytes, wsz);
            if (ptrace(PTRACE_POKETEXT, static_cast<pid_t>(m_pid), reinterpret_cast<void*>(aligned), reinterpret_cast<void*>(word)) == 0) {
                return true;
            }
        }
    }
    uint8_t int3 = 0xCC;
    return m_process->write_raw(bp.address, &int3, 1, true);
#endif
}

bool DebugCoordinator::restore_breakpoint_byte(Breakpoint& bp) {
    if (!m_process || bp.address == 0) return false;
#ifdef _WIN32
    return m_process->write_raw(bp.address, &bp.original_byte, 1, true);
#else
    if (m_is_attached && std::this_thread::get_id() != m_debug_thread.get_id()) {
        m_pending_linux_writes.push_back({bp.address, bp.original_byte});
        if (m_pid != 0) kill(static_cast<pid_t>(m_pid), SIGSTOP);
        return true;
    }
    if (m_is_attached && m_pid != 0) {
        const size_t wsz = sizeof(long);
        const uintptr_t aligned = bp.address & ~(wsz - 1);
        const size_t off = bp.address - aligned;
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, static_cast<pid_t>(m_pid), reinterpret_cast<void*>(aligned), nullptr);
        if (errno == 0) {
            uint8_t bytes[sizeof(long)];
            std::memcpy(bytes, &word, wsz);
            bytes[off] = bp.original_byte;
            std::memcpy(&word, bytes, wsz);
            if (ptrace(PTRACE_POKETEXT, static_cast<pid_t>(m_pid), reinterpret_cast<void*>(aligned), reinterpret_cast<void*>(word)) == 0) {
                return true;
            }
        }
    }
    return m_process->write_raw(bp.address, &bp.original_byte, 1, true);
#endif
}

void DebugCoordinator::sync_veh_breakpoints() {
#ifdef _WIN32
    if (!m_veh_state) return;
    uint32_t count = 0;
    for (const auto& [addr, bp] : m_breakpoints) {
        if (bp.is_enabled && count < veh::kMaxSwBreakpoints) {
            m_veh_state->sw_bps[count++] = addr;
        }
    }
    m_veh_state->sw_bp_count = count;
#endif
}

#ifdef _WIN32
void DebugCoordinator::arm_thread_hw(void* thread_handle) const {
    HANDLE th = static_cast<HANDLE>(thread_handle);
    if (m_is_wow64) {
        WOW64_CONTEXT wctx{};
        wctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
        if (!Wow64GetThreadContext(th, &wctx)) return;

        uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr7 = wctx.Dr7;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            apply_hw_slots_to_dr(m_hw_slots, dr0, dr1, dr2, dr3, dr7);
        }
        wctx.Dr0 = static_cast<DWORD>(dr0);
        wctx.Dr1 = static_cast<DWORD>(dr1);
        wctx.Dr2 = static_cast<DWORD>(dr2);
        wctx.Dr3 = static_cast<DWORD>(dr3);
        wctx.Dr7 = static_cast<DWORD>(dr7);
        Wow64SetThreadContext(th, &wctx);
        return;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(th, &ctx)) return;

    uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr7 = ctx.Dr7;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        apply_hw_slots_to_dr(m_hw_slots, dr0, dr1, dr2, dr3, dr7);
    }
    ctx.Dr0 = dr0; ctx.Dr1 = dr1; ctx.Dr2 = dr2; ctx.Dr3 = dr3;
    ctx.Dr7 = dr7;
    SetThreadContext(th, &ctx);
}

void DebugCoordinator::sync_hw_registers_all_threads() {
    if (!m_is_attached || m_pid == 0) return;

    uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr7 = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        apply_hw_slots_to_dr(m_hw_slots, dr0, dr1, dr2, dr3, dr7);
        if (m_veh_state) {
            m_veh_state->regs.dr0 = dr0;
            m_veh_state->regs.dr1 = dr1;
            m_veh_state->regs.dr2 = dr2;
            m_veh_state->regs.dr3 = dr3;
            m_veh_state->regs.dr7 = dr7;
        }
    }

    auto threads = hal::ProcessInjector::list_threads(m_pid);
    for (const auto& t : threads) {
        HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, t.tid);
        if (!th) continue;
        if (SuspendThread(th) != static_cast<DWORD>(-1)) {
            arm_thread_hw(th);
            ResumeThread(th);
        }
        CloseHandle(th);
    }
}
#endif

void DebugCoordinator::append_trace(uint32_t thread_id, uintptr_t addr, const Registers& regs) {
    TraceEntry entry;
    entry.sequence = ++m_trace_seq;
    entry.thread_id = thread_id;
    entry.address = addr;
    entry.symbol = format_symbol(addr, m_modules);
    entry.registers = regs;

    if (m_process && m_process->is_attached()) {
        uint8_t code[16]{};
        if (m_process->read_raw(addr, code, sizeof(code))) {
            auto d = Disassembler::decode(code, sizeof(code), addr, is_target_64bit());
            entry.disassembly = d.mnemonic + (d.operands.empty() ? "" : " " + d.operands);
        }
    }

    if (m_trace_log.size() >= kMaxTraceEntries) {
        m_trace_log.erase(m_trace_log.begin());
    }
    m_trace_log.push_back(std::move(entry));
}

void DebugCoordinator::set_breakpoint_callback(BreakpointCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_bp_callback = std::move(cb);
}

bool DebugCoordinator::process_sw_breakpoint(uint32_t thread_id, uintptr_t bp_addr, Registers& regs, bool& request_tf) {
    request_tf = false;
    std::unique_lock<std::mutex> lock(m_mutex);

    auto it = m_breakpoints.find(bp_addr);
    if (it == m_breakpoints.end()) {
        return false; // Not our breakpoint
    }

    Breakpoint& bp = it->second;
    ++bp.hit_count;
    restore_breakpoint_byte(bp);

    bool cond_matched = true;
    if (!bp.condition.empty()) {
        auto eval = ConditionEvaluator::evaluate(bp.condition, regs, m_process.get(), bp.hit_count);
        cond_matched = eval.ok && eval.matched;
    }

    if (!cond_matched) {
        // Condition false: silently execute 1 original instruction, then re-arm 0xCC
        m_rearm_bp_addr = bp_addr;
        m_silent_step = true;
        request_tf = true;
        return false;
    }

    if (bp.is_tracepoint) {
        append_trace(thread_id, bp_addr, regs);
        m_rearm_bp_addr = bp_addr;
        m_silent_step = true;
        request_tf = true;
        return false;
    }

    const bool was_temp = bp.is_temporary;
    if (was_temp) {
        m_breakpoints.erase(it);
        sync_veh_breakpoints();
    }

    BreakpointCallback cb = m_bp_callback;
    if (cb) {
        m_active_thread_id = thread_id;
        m_registers = regs;
        lock.unlock();
        const bool auto_continue = cb(thread_id, bp_addr, regs);
        lock.lock();
        if (auto_continue) {
            if (!was_temp && m_breakpoints.find(bp_addr) != m_breakpoints.end()) {
                m_rearm_bp_addr = bp_addr;
                m_silent_step = true;
                request_tf = true;
            }
            return false;
        }
    }

    // Real hit!
    if (!was_temp && m_breakpoints.find(bp_addr) != m_breakpoints.end()) {
        m_rearm_bp_addr = bp_addr;
    }

    m_active_thread_id = thread_id;
    m_registers = regs;
    m_state = DebuggerState::PausedAtBreakpoint;
    return true;
}

bool DebugCoordinator::process_single_step(uint32_t thread_id, uintptr_t rip, uint64_t dr6,
                                           Registers& regs, bool& request_tf, bool& request_rf) {
    request_tf = false;
    request_rf = false;

    std::vector<HardwareWatchSlot::HitCallback> hw_callbacks;
    bool handled_rearm = false;
    bool pause_for_user = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // 1. Dispatch any triggered hardware watch slots (DR0-DR3)
        for (int s = 0; s < 4; ++s) {
            if ((dr6 & (1ULL << s)) && m_hw_slots[s].active) {
                if (m_hw_slots[s].kind == WatchKind::Execute) {
                    request_rf = true; // EFLAGS.RF avoids re-trapping on same Execute BP
                }
                if (m_hw_slots[s].on_hit) {
                    hw_callbacks.push_back(m_hw_slots[s].on_hit);
                }
            }
        }

        // 2. Re-arm software INT 3 if we stepped past a restored breakpoint
        if (m_rearm_bp_addr != 0) {
            auto it = m_breakpoints.find(m_rearm_bp_addr);
            if (it != m_breakpoints.end() && it->second.is_enabled) {
                apply_breakpoint(it->second);
            }
            m_rearm_bp_addr = 0;
            handled_rearm = true;
        }

        // 2b. Re-arm stealth PAGE_GUARD after the faulting instruction completed
        if (m_rearm_guard_page != 0) {
            for (const auto& g : m_guard_watches) {
                if (g.page_base == m_rearm_guard_page && g.armed) {
                    uint32_t prot = g.orig_prot;
                    apply_guard_page(m_rearm_guard_page, prot);
                    break;
                }
            }
            m_rearm_guard_page = 0;
            handled_rearm = true;
        }

        // 3. Determine whether this single-step should pause for the user
        if (m_silent_step) {
            m_silent_step = false;
            pause_for_user = false;
        } else if (m_user_step_requested || (handled_rearm && hw_callbacks.empty())) {
            m_user_step_requested = false;
            m_active_thread_id = thread_id;
            m_registers = regs;
            m_state = DebuggerState::PausedAtStep;
            pause_for_user = true;
        }
    }

    // Invoke HW watch callbacks outside m_mutex
    for (const auto& cb : hw_callbacks) {
        cb(thread_id, rip, regs);
    }

    return pause_for_user;
}

void DebugCoordinator::wait_while_paused(bool& out_step, uintptr_t& out_new_rip) {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_resume_pending = false;
    m_step_pending = false;
    m_pause_cv.wait(lock, [&] {
        return m_resume_pending || m_step_pending || m_stop_requested;
    });
    out_step = m_step_pending;
    out_new_rip = m_registers.rip;
    m_resume_pending = false;
    m_step_pending = false;
}

#ifdef _WIN32
void DebugCoordinator::win32_debug_loop(std::promise<bool> start_promise) {
    if (!DebugActiveProcess(m_pid)) {
        m_last_error = "DebugActiveProcess failed (error " + std::to_string(GetLastError()) + ").";
        start_promise.set_value(false);
        return;
    }
    DebugSetProcessKillOnExit(FALSE);
    start_promise.set_value(true);

    DEBUG_EVENT ev{};
    while (!m_stop_requested) {
        if (!WaitForDebugEvent(&ev, 50)) continue;

        DWORD continue_status = DBG_CONTINUE;
        bool should_pause = false;
        uintptr_t pause_rip = 0;

        if (ev.dwProcessId == m_pid) {
            switch (ev.dwDebugEventCode) {
                case CREATE_PROCESS_DEBUG_EVENT:
                    arm_thread_hw(ev.u.CreateProcessInfo.hThread);
                    if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                    break;

                case CREATE_THREAD_DEBUG_EVENT:
                    arm_thread_hw(ev.u.CreateThread.hThread);
                    break;

                case EXCEPTION_DEBUG_EVENT: {
                    const auto& ex = ev.u.Exception.ExceptionRecord;
                    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, ev.dwThreadId);
                    if (!th) {
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        break;
                    }

                    CONTEXT ctx{};
                    WOW64_CONTEXT wctx{};
                    bool ctx_ok = false;
                    uint64_t dr6_val = 0;
                    Registers regs{};

                    if (m_is_wow64) {
                        wctx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_DEBUG_REGISTERS;
                        ctx_ok = (Wow64GetThreadContext(th, &wctx) == TRUE);
                        if (ctx_ok) {
                            regs_from_wow64_ctx(wctx, regs);
                            dr6_val = wctx.Dr6;
                        }
                    } else {
                        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
                        ctx_ok = (GetThreadContext(th, &ctx) == TRUE);
                        if (ctx_ok) {
                            regs_from_win32_ctx(ctx, regs);
                            dr6_val = ctx.Dr6;
                        }
                    }

                    if (!ctx_ok) {
                        CloseHandle(th);
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        break;
                    }

                    const bool is_sw_bp_code = (ex.ExceptionCode == EXCEPTION_BREAKPOINT ||
                                                ex.ExceptionCode == kStatusWx86Breakpoint);
                    const bool is_step_code = (ex.ExceptionCode == EXCEPTION_SINGLE_STEP ||
                                               ex.ExceptionCode == kStatusWx86SingleStep);

                    if (is_sw_bp_code) {
                        const uintptr_t ex_addr = reinterpret_cast<uintptr_t>(ex.ExceptionAddress);
                        bool is_user_bp = false;
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            is_user_bp = (m_breakpoints.find(ex_addr) != m_breakpoints.end());
                        }

                        if (!is_user_bp && ex.ExceptionCode == EXCEPTION_BREAKPOINT && !m_initial_bp_seen) {
                            m_initial_bp_seen = true; // Ignore 64-bit loader initial attach INT 3
                            continue_status = DBG_CONTINUE;
                        } else if (!is_user_bp && ex.ExceptionCode == kStatusWx86Breakpoint && !m_wow64_initial_bp_seen) {
                            m_wow64_initial_bp_seen = true; // Ignore WOW64 32-bit loader initial INT 3
                            continue_status = DBG_CONTINUE;
                        } else if (is_user_bp) {
                            regs.rip = ex_addr;
                            bool req_tf = false;
                            should_pause = process_sw_breakpoint(ev.dwThreadId, ex_addr, regs, req_tf);
                            pause_rip = regs.rip;
                            if (m_is_wow64) {
                                wow64_ctx_from_regs(regs, wctx);
                                if (req_tf) wctx.EFlags |= 0x100UL;
                                Wow64SetThreadContext(th, &wctx);
                            } else {
                                win32_ctx_from_regs(regs, ctx);
                                if (req_tf) ctx.EFlags |= 0x100UL;
                                SetThreadContext(th, &ctx);
                            }
                            continue_status = DBG_CONTINUE;
                        } else {
                            continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    } else if (is_step_code) {
                        bool req_tf = false, req_rf = false;
                        should_pause = process_single_step(ev.dwThreadId, static_cast<uintptr_t>(regs.rip), dr6_val, regs, req_tf, req_rf);
                        pause_rip = static_cast<uintptr_t>(regs.rip);
                        if (m_is_wow64) {
                            wctx.Dr6 = 0;
                            if (req_tf) wctx.EFlags |= 0x100UL;
                            if (req_rf) wctx.EFlags |= 0x10000UL;
                            Wow64SetThreadContext(th, &wctx);
                        } else {
                            ctx.Dr6 = 0;
                            if (req_tf) ctx.EFlags |= 0x100UL;
                            if (req_rf) ctx.EFlags |= 0x10000UL;
                            SetThreadContext(th, &ctx);
                        }
                        continue_status = DBG_CONTINUE;
                    } else if (ex.ExceptionCode == EXCEPTION_GUARD_PAGE) {
                        const uintptr_t fault_addr = (ex.NumberParameters >= 2)
                            ? static_cast<uintptr_t>(ex.ExceptionInformation[1])
                            : 0;
                        const uintptr_t fault_page = fault_addr & ~uintptr_t{0xFFF};
                        std::vector<HardwareWatchSlot::HitCallback> guard_cbs;
                        bool ours = false;
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            for (const auto& g : m_guard_watches) {
                                if (!g.armed) continue;
                                if (fault_addr == 0 || g.page_base == fault_page) {
                                    ours = true;
                                    const uintptr_t lo = g.address;
                                    const uintptr_t hi = g.address + g.size;
                                    if (fault_addr == 0 || (fault_addr + 8 > lo && fault_addr < hi)) {
                                        if (g.on_hit) guard_cbs.push_back(g.on_hit);
                                    }
                                }
                            }
                            if (ours) {
                                m_rearm_guard_page = (fault_page != 0) ? fault_page : m_guard_watches.front().page_base;
                                m_silent_step = true;
                            }
                        }
                        if (ours) {
                            for (const auto& cb : guard_cbs) {
                                cb(ev.dwThreadId, static_cast<uintptr_t>(regs.rip), regs);
                            }
                            if (m_is_wow64) {
                                wctx.EFlags |= 0x100UL;
                                Wow64SetThreadContext(th, &wctx);
                            } else {
                                ctx.EFlags |= 0x100UL;
                                SetThreadContext(th, &ctx);
                            }
                            continue_status = DBG_CONTINUE;
                        } else {
                            continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    } else {
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    }

                    CloseHandle(th);
                    break;
                }

                case EXIT_PROCESS_DEBUG_EVENT:
                    m_state = DebuggerState::Terminated;
                    m_stop_requested = true;
                    break;

                default:
                    break;
            }
        }

        if (should_pause && !m_stop_requested) {
            bool do_step = false;
            uintptr_t new_rip = pause_rip;
            wait_while_paused(do_step, new_rip);

            if (!m_stop_requested) {
                bool need_tf = do_step;
                Registers updated_regs{};
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    updated_regs = m_registers;
                    if (m_rearm_bp_addr != 0) {
                        // Must step 1 instruction with TF=1 so handle_single_step re-inserts 0xCC
                        need_tf = true;
                        if (!do_step) m_silent_step = true;
                    }
                }
                HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, ev.dwThreadId);
                if (th) {
                    if (m_is_wow64) {
                        WOW64_CONTEXT wctx{};
                        wctx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER;
                        if (Wow64GetThreadContext(th, &wctx)) {
                            wow64_ctx_from_regs(updated_regs, wctx);
                            wctx.Eip = static_cast<DWORD>(new_rip);
                            if (need_tf) wctx.EFlags |= 0x100UL;
                            Wow64SetThreadContext(th, &wctx);
                        }
                    } else {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                        if (GetThreadContext(th, &ctx)) {
                            win32_ctx_from_regs(updated_regs, ctx);
                            ctx.Rip = new_rip;
                            if (need_tf) ctx.EFlags |= 0x100UL; // Trap Flag TF = 1
                            SetThreadContext(th, &ctx);
                        }
                    }
                    CloseHandle(th);
                }
            }
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continue_status);
    }

    DebugActiveProcessStop(m_pid);
}

bool DebugCoordinator::veh_attach_impl() {
    if (m_is_wow64) {
        m_last_error = "In-process 64-bit VEH is not supported on 32-bit WOW64 targets; use Win32 DebugAPI.";
        return false;
    }
    const std::wstring map_name  = format_pid_str(L"Local\\NCE_VEH_MEM_", m_pid);
    const std::wstring hit_name  = format_pid_str(L"Local\\NCE_VEH_HIT_", m_pid);
    const std::wstring cont_name = format_pid_str(L"Local\\NCE_VEH_CONT_", m_pid);

    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(veh::VehSharedState), map_name.c_str());
    if (!hMap) {
        m_last_error = "VEH CreateFileMappingW failed.";
        return false;
    }

    auto* state = static_cast<veh::VehSharedState*>(MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(veh::VehSharedState)));
    if (!state) {
        CloseHandle(hMap);
        m_last_error = "VEH MapViewOfFile failed.";
        return false;
    }

    std::memset(state, 0, sizeof(veh::VehSharedState));
    state->magic = veh::kVehMagic;
    state->version = veh::kVehVersion;

    HANDLE hHit  = CreateEventW(nullptr, FALSE, FALSE, hit_name.c_str());
    HANDLE hCont = CreateEventW(nullptr, FALSE, FALSE, cont_name.c_str());
    if (!hHit || !hCont) {
        if (hHit) CloseHandle(hHit);
        if (hCont) CloseHandle(hCont);
        UnmapViewOfFile(state);
        CloseHandle(hMap);
        m_last_error = "VEH CreateEventW failed.";
        return false;
    }

    m_veh_map = hMap;
    m_veh_evt_hit = hHit;
    m_veh_evt_cont = hCont;
    m_veh_state = state;

    // Locate nce_veh.dll next to executable
    std::filesystem::path dll_path = std::filesystem::path(hal::ProcessInjector::executable_directory()) / "nce_veh.dll";
    if (!std::filesystem::exists(dll_path)) {
        dll_path = "nce_veh.dll";
    }

    std::string inj_err;
    if (!hal::ProcessInjector::inject_dll(m_pid, dll_path.string(), inj_err)) {
        m_last_error = "VEH DLL injection failed: " + inj_err;
        veh_cleanup();
        return false;
    }

    // Confirm handler ready
    for (int i = 0; i < 100 && !m_veh_state->agent_ready; ++i) {
        Sleep(10);
    }
    if (!m_veh_state->agent_ready) {
        m_last_error = "VEH agent did not become ready in time.";
        veh_cleanup();
        return false;
    }
    return true;
}

void DebugCoordinator::veh_debug_loop() {
    while (!m_stop_requested && m_veh_state && m_veh_evt_hit && m_veh_evt_cont) {
        DWORD w = WaitForSingleObject(static_cast<HANDLE>(m_veh_evt_hit), 50);
        if (w != WAIT_OBJECT_0) continue;
        if (m_stop_requested) break;

        const auto kind = static_cast<veh::VehEventKind>(m_veh_state->event_kind);
        const uint32_t tid = m_veh_state->hit_thread_id;
        const uintptr_t hit_addr = static_cast<uintptr_t>(m_veh_state->hit_address);
        const uint64_t dr6 = m_veh_state->regs.dr6;

        Registers regs;
        regs_from_veh(m_veh_state->regs, regs);

        bool should_pause = false;
        bool req_tf = false;
        bool req_rf = false;

        if (kind == veh::VehEventKind::SoftwareBreakpoint) {
            should_pause = process_sw_breakpoint(tid, hit_addr, regs, req_tf);
        } else if (kind == veh::VehEventKind::SingleStep || kind == veh::VehEventKind::HardwareBreakpoint) {
            should_pause = process_single_step(tid, hit_addr, dr6, regs, req_tf, req_rf);
        }

        if (should_pause && !m_stop_requested) {
            bool do_step = false;
            uintptr_t new_rip = regs.rip;
            wait_while_paused(do_step, new_rip);
            regs.rip = new_rip;
            if (do_step) req_tf = true;
            else {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_rearm_bp_addr != 0) {
                    req_tf = true;
                    m_silent_step = true;
                }
            }
        }

        if (m_stop_requested) {
            m_veh_state->command = static_cast<uint32_t>(veh::VehCommand::Detach);
        } else {
            regs_to_veh(regs, m_veh_state->regs);
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                uint64_t dr7 = m_veh_state->regs.dr7;
                apply_hw_slots_to_dr(m_hw_slots,
                                     m_veh_state->regs.dr0, m_veh_state->regs.dr1,
                                     m_veh_state->regs.dr2, m_veh_state->regs.dr3, dr7);
                m_veh_state->regs.dr7 = dr7;
            }
            if (req_rf) m_veh_state->regs.eflags |= 0x10000ULL;
            m_veh_state->command = static_cast<uint32_t>(req_tf ? veh::VehCommand::SingleStep : veh::VehCommand::Continue);
        }

        SetEvent(static_cast<HANDLE>(m_veh_evt_cont));
    }
}

void DebugCoordinator::veh_cleanup() {
    if (m_veh_state) {
        UnmapViewOfFile(m_veh_state);
        m_veh_state = nullptr;
    }
    if (m_veh_evt_cont) { CloseHandle(static_cast<HANDLE>(m_veh_evt_cont)); m_veh_evt_cont = nullptr; }
    if (m_veh_evt_hit)  { CloseHandle(static_cast<HANDLE>(m_veh_evt_hit));  m_veh_evt_hit = nullptr; }
    if (m_veh_map)      { CloseHandle(static_cast<HANDLE>(m_veh_map));      m_veh_map = nullptr; }
}

#else // !_WIN32 (Linux ptrace debug backend)

namespace {
#if defined(__x86_64__)
void regs_from_linux_user(const struct user_regs_struct& ur, Registers& r) {
    r.rax = ur.rax; r.rbx = ur.rbx; r.rcx = ur.rcx; r.rdx = ur.rdx;
    r.rsi = ur.rsi; r.rdi = ur.rdi; r.rbp = ur.rbp; r.rsp = ur.rsp;
    r.rip = ur.rip;
    r.r8  = ur.r8;  r.r9  = ur.r9;  r.r10 = ur.r10; r.r11 = ur.r11;
    r.r12 = ur.r12; r.r13 = ur.r13; r.r14 = ur.r14; r.r15 = ur.r15;
    r.eflags = ur.eflags;
}

void linux_user_from_regs(const Registers& r, struct user_regs_struct& ur) {
    ur.rax = r.rax; ur.rbx = r.rbx; ur.rcx = r.rcx; ur.rdx = r.rdx;
    ur.rsi = r.rsi; ur.rdi = r.rdi; ur.rbp = r.rbp; ur.rsp = r.rsp;
    ur.rip = r.rip;
    ur.r8  = r.r8;  ur.r9  = r.r9;  ur.r10 = r.r10; ur.r11 = r.r11;
    ur.r12 = r.r12; ur.r13 = r.r13; ur.r14 = r.r14; ur.r15 = r.r15;
    ur.eflags = r.eflags;
}

void apply_dr_to_linux_tid(pid_t tid, const HardwareWatchSlot slots[4]) {
    uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr7 = 0;
    apply_hw_slots_to_dr(slots, dr0, dr1, dr2, dr3, dr7);
    ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[0])), reinterpret_cast<void*>(dr0));
    ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[1])), reinterpret_cast<void*>(dr1));
    ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[2])), reinterpret_cast<void*>(dr2));
    ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[3])), reinterpret_cast<void*>(dr3));
    ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[7])), reinterpret_cast<void*>(dr7));
}
#endif
} // namespace

void DebugCoordinator::sync_hw_registers_all_threads() {
#if defined(__x86_64__)
    if (!m_is_attached || m_pid == 0) return;
    m_linux_hw_gen.fetch_add(1);
    if (std::this_thread::get_id() == m_debug_thread.get_id()) {
        HardwareWatchSlot snapshot[4];
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (int i = 0; i < 4; ++i) snapshot[i] = m_hw_slots[i];
        }
        for (const auto& t : hal::ProcessInjector::list_threads(m_pid)) {
            apply_dr_to_linux_tid(static_cast<pid_t>(t.tid), snapshot);
        }
        return;
    }
    m_linux_sync_hw.store(true);
    for (const auto& t : hal::ProcessInjector::list_threads(m_pid)) {
#ifdef SYS_tgkill
        syscall(SYS_tgkill, static_cast<pid_t>(m_pid), static_cast<pid_t>(t.tid), SIGSTOP);
#else
        kill(static_cast<pid_t>(t.tid), SIGSTOP);
#endif
    }
#endif
}

void DebugCoordinator::linux_ptrace_loop(std::promise<bool> start_promise) {
#if defined(__x86_64__)
    std::unordered_map<uint32_t, uint64_t> tid_hw_gen;
    const uint64_t init_hw_gen = m_linux_hw_gen.load();
    auto threads = hal::ProcessInjector::list_threads(m_pid);
    std::vector<pid_t> attached_tids;
    for (const auto& t : threads) {
        pid_t tid = static_cast<pid_t>(t.tid);
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            int st = 0;
            waitpid(tid, &st, __WALL);
            if (tid == static_cast<pid_t>(m_pid)) {
                ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                       reinterpret_cast<void*>(static_cast<uintptr_t>(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT)));
            }
            attached_tids.push_back(tid);
        }
    }

    if (attached_tids.empty()) {
        m_last_error = "ptrace(PTRACE_ATTACH) failed for target process (errno " + std::to_string(errno) + ").";
        start_promise.set_value(false);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [addr, bp] : m_breakpoints) {
            if (bp.is_enabled) apply_breakpoint(bp);
        }
        for (auto& g : m_guard_watches) {
            if (!g.armed && apply_guard_page(g.page_base, g.orig_prot)) {
                g.armed = true;
            }
        }
        for (pid_t tid : attached_tids) {
            apply_dr_to_linux_tid(tid, m_hw_slots);
            tid_hw_gen[static_cast<uint32_t>(tid)] = init_hw_gen;
        }
    }

    for (pid_t tid : attached_tids) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }
    start_promise.set_value(true);

    while (!m_stop_requested) {
        int status = 0;
        pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
        if (tid <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (tid == static_cast<pid_t>(m_pid)) {
                m_state = DebuggerState::Terminated;
                m_stop_requested = true;
                break;
            }
            continue;
        }

        if (!WIFSTOPPED(status)) continue;

        const int sig = WSTOPSIG(status);
        const int evt = (status >> 16) & 0xFFFF;
        bool should_pause = false;
        bool req_tf = false;
        bool req_rf = false;
        int forward_sig = 0;

        if (sig == SIGTRAP && evt == PTRACE_EVENT_CLONE) {
            unsigned long new_tid = 0;
            ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &new_tid);
            if (new_tid > 0) {
                std::lock_guard<std::mutex> lock(m_mutex);
                apply_dr_to_linux_tid(static_cast<pid_t>(new_tid), m_hw_slots);
            }
        } else if (sig == SIGTRAP) {
            struct user_regs_struct ur{};
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &ur) == 0) {
                Registers regs{};
                regs_from_linux_user(ur, regs);

                const uintptr_t bp_candidate = regs.rip > 0 ? (regs.rip - 1) : 0;
                bool is_sw_bp = false;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    is_sw_bp = (m_breakpoints.find(bp_candidate) != m_breakpoints.end());
                }

                if (is_sw_bp) {
                    regs.rip = bp_candidate;
                    should_pause = process_sw_breakpoint(static_cast<uint32_t>(tid), bp_candidate, regs, req_tf);
                } else {
                    errno = 0;
                    long dr6_val = ptrace(PTRACE_PEEKUSER, tid,
                                          reinterpret_cast<void*>(offsetof(struct user, u_debugreg[6])), nullptr);
                    uint64_t dr6 = (errno == 0) ? static_cast<uint64_t>(dr6_val) : 0ULL;
                    ptrace(PTRACE_POKEUSER, tid,
                           reinterpret_cast<void*>(offsetof(struct user, u_debugreg[6])), nullptr);
                    should_pause = process_single_step(
                        static_cast<uint32_t>(tid), regs.rip, dr6, regs, req_tf, req_rf);
                }

                if (should_pause && !m_stop_requested) {
                    bool do_step = false;
                    uintptr_t new_rip = regs.rip;
                    wait_while_paused(do_step, new_rip);
                    regs.rip = new_rip;
                    if (do_step) req_tf = true;
                    else {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        if (m_rearm_bp_addr != 0) {
                            req_tf = true;
                            m_silent_step = true;
                        }
                    }
                }

                if (req_rf) regs.eflags |= 0x10000ULL;
                linux_user_from_regs(regs, ur);
                ptrace(PTRACE_SETREGS, tid, nullptr, &ur);

                std::lock_guard<std::mutex> lock(m_mutex);
                apply_dr_to_linux_tid(tid, m_hw_slots);
            }
        } else if (sig == SIGSTOP) {
            // Apply queued breakpoint pokes/restores directly while stopped inside tracer thread
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                for (const auto& pw : m_pending_linux_writes) {
                    const size_t wsz = sizeof(long);
                    const uintptr_t aligned = pw.address & ~(wsz - 1);
                    const size_t off = pw.address - aligned;
                    errno = 0;
                    long word = ptrace(PTRACE_PEEKTEXT, tid, reinterpret_cast<void*>(aligned), nullptr);
                    if (errno == 0) {
                        uint8_t bytes[sizeof(long)];
                        std::memcpy(bytes, &word, wsz);
                        bytes[off] = pw.value;
                        std::memcpy(&word, bytes, wsz);
                        ptrace(PTRACE_POKETEXT, tid, reinterpret_cast<void*>(aligned), reinterpret_cast<void*>(word));
                    }
                }
                m_pending_linux_writes.clear();
                if (m_linux_sync_hw.exchange(false)) {
                    apply_dr_to_linux_tid(tid, m_hw_slots);
                }
            }
            struct user_regs_struct ur{};
            if (m_user_step_requested && ptrace(PTRACE_GETREGS, tid, nullptr, &ur) == 0) {
                Registers regs{};
                regs_from_linux_user(ur, regs);
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_user_step_requested = false;
                    m_active_thread_id = static_cast<uint32_t>(tid);
                    m_registers = regs;
                    m_state = DebuggerState::PausedAtStep;
                }
                bool do_step = false;
                uintptr_t new_rip = regs.rip;
                wait_while_paused(do_step, new_rip);
                regs.rip = new_rip;
                req_tf = do_step;
                linux_user_from_regs(regs, ur);
                ptrace(PTRACE_SETREGS, tid, nullptr, &ur);
            }
        } else {
            forward_sig = sig;
        }

        if (!m_stop_requested) {
            const uint64_t want_gen = m_linux_hw_gen.load();
            const uint32_t utid = static_cast<uint32_t>(tid);
            if (tid_hw_gen[utid] != want_gen) {
                std::lock_guard<std::mutex> lock(m_mutex);
                apply_dr_to_linux_tid(tid, m_hw_slots);
                tid_hw_gen[utid] = want_gen;
            }
            ptrace(req_tf ? PTRACE_SINGLESTEP : PTRACE_CONT,
                   tid, nullptr, reinterpret_cast<void*>(static_cast<intptr_t>(forward_sig)));
        }
    }

    for (const auto& t : hal::ProcessInjector::list_threads(m_pid)) {
        pid_t tid = static_cast<pid_t>(t.tid);
        HardwareWatchSlot cleared[4]{};
        apply_dr_to_linux_tid(tid, cleared);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
#else
    m_last_error = "Linux ptrace debug loop requires x86_64 host.";
    start_promise.set_value(false);
#endif
}

#endif // _WIN32

} // namespace nce::debugger
