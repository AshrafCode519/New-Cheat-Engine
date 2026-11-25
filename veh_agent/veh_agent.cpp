#include "../engine/include/debugger/veh_protocol.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdio>

using namespace nce::debugger::veh;

namespace {

HANDLE g_map = nullptr;
HANDLE g_evt_hit = nullptr;
HANDLE g_evt_cont = nullptr;
VehSharedState* g_state = nullptr;
PVOID g_veh_handle = nullptr;
CRITICAL_SECTION g_cs;
bool g_cs_init = false;

void format_pid_name(wchar_t* out, size_t cap, const wchar_t* prefix, DWORD pid) {
    _snwprintf(out, cap, L"%s%lu", prefix, static_cast<unsigned long>(pid));
}

bool is_our_sw_bp(uint64_t addr) {
    if (!g_state) return false;
    uint32_t count = g_state->sw_bp_count;
    if (count > kMaxSwBreakpoints) count = static_cast<uint32_t>(kMaxSwBreakpoints);
    for (uint32_t i = 0; i < count; ++i) {
        if (g_state->sw_bps[i] == addr) return true;
    }
    return false;
}

void copy_context_to_state(const CONTEXT* ctx, uint64_t override_rip) {
    VehRegisters& r = g_state->regs;
    r.rax = ctx->Rax; r.rbx = ctx->Rbx; r.rcx = ctx->Rcx; r.rdx = ctx->Rdx;
    r.rsi = ctx->Rsi; r.rdi = ctx->Rdi; r.rbp = ctx->Rbp; r.rsp = ctx->Rsp;
    r.rip = override_rip ? override_rip : ctx->Rip;
    r.r8  = ctx->R8;  r.r9  = ctx->R9;  r.r10 = ctx->R10; r.r11 = ctx->R11;
    r.r12 = ctx->R12; r.r13 = ctx->R13; r.r14 = ctx->R14; r.r15 = ctx->R15;
    r.eflags = ctx->EFlags;
    r.dr0 = ctx->Dr0; r.dr1 = ctx->Dr1; r.dr2 = ctx->Dr2; r.dr3 = ctx->Dr3;
    r.dr6 = ctx->Dr6; r.dr7 = ctx->Dr7;
}

void copy_state_to_context(CONTEXT* ctx) {
    const VehRegisters& r = g_state->regs;
    ctx->Rax = r.rax; ctx->Rbx = r.rbx; ctx->Rcx = r.rcx; ctx->Rdx = r.rdx;
    ctx->Rsi = r.rsi; ctx->Rdi = r.rdi; ctx->Rbp = r.rbp; ctx->Rsp = r.rsp;
    ctx->Rip = r.rip;
    ctx->R8  = r.r8;  ctx->R9  = r.r9;  ctx->R10 = r.r10; ctx->R11 = r.r11;
    ctx->R12 = r.r12; ctx->R13 = r.r13; ctx->R14 = r.r14; ctx->R15 = r.r15;
    ctx->EFlags = static_cast<DWORD>(r.eflags);
    ctx->Dr0 = r.dr0; ctx->Dr1 = r.dr1; ctx->Dr2 = r.dr2; ctx->Dr3 = r.dr3;
    ctx->Dr6 = 0; // acknowledge hardware breakpoint / single-step status
    ctx->Dr7 = r.dr7;
}

LONG CALLBACK veh_handler(PEXCEPTION_POINTERS info) {
    if (!g_state || g_state->magic != kVehMagic || g_state->detach_requested) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD code = info->ExceptionRecord->ExceptionCode;
    PCONTEXT ctx = info->ContextRecord;
    const uint64_t ex_addr = reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress);

    if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXCEPTION_BREAKPOINT && !is_our_sw_bp(ex_addr)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXCEPTION_SINGLE_STEP) {
        const bool is_hw = (ctx->Dr6 & 0x0FULL) != 0;
        const bool is_step = (g_state->single_step_active != 0);
        if (!is_hw && !is_step) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    EnterCriticalSection(&g_cs);

    if (g_state->detach_requested) {
        LeaveCriticalSection(&g_cs);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    VehEventKind kind = VehEventKind::None;
    uint64_t report_rip = ctx->Rip;

    if (code == EXCEPTION_BREAKPOINT) {
        kind = VehEventKind::SoftwareBreakpoint;
        report_rip = ex_addr; // exact address of 0xCC instruction
    } else {
        if ((ctx->Dr6 & 0x0FULL) != 0) {
            kind = VehEventKind::HardwareBreakpoint;
        } else {
            kind = VehEventKind::SingleStep;
            g_state->single_step_active = 0;
        }
    }

    copy_context_to_state(ctx, report_rip);
    g_state->hit_thread_id = GetCurrentThreadId();
    g_state->hit_address = report_rip;
    g_state->command = static_cast<uint32_t>(VehCommand::None);
    MemoryBarrier();
    g_state->event_kind = static_cast<uint32_t>(kind);

    SetEvent(g_evt_hit);

    // Wait for NCE host to process event (evaluate condition / pause UI / step)
    while (!g_state->detach_requested) {
        DWORD w = WaitForSingleObject(g_evt_cont, 100);
        if (w == WAIT_OBJECT_0 || g_state->command != static_cast<uint32_t>(VehCommand::None)) {
            break;
        }
    }

    const uint32_t cmd = g_state->command;
    g_state->event_kind = static_cast<uint32_t>(VehEventKind::None);
    g_state->command = static_cast<uint32_t>(VehCommand::None);

    if (cmd == static_cast<uint32_t>(VehCommand::Detach) || g_state->detach_requested) {
        ctx->Dr6 = 0;
        LeaveCriticalSection(&g_cs);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    copy_state_to_context(ctx);
    if (cmd == static_cast<uint32_t>(VehCommand::SingleStep)) {
        ctx->EFlags |= 0x100UL; // Set Trap Flag (TF)
        g_state->single_step_active = 1;
    } else {
        ctx->EFlags &= ~0x100UL;
    }

    LeaveCriticalSection(&g_cs);
    return EXCEPTION_CONTINUE_EXECUTION;
}

void cleanup() {
    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = nullptr;
    }
    if (g_state) {
        g_state->agent_ready = 0;
        UnmapViewOfFile(g_state);
        g_state = nullptr;
    }
    if (g_evt_cont) { CloseHandle(g_evt_cont); g_evt_cont = nullptr; }
    if (g_evt_hit)  { CloseHandle(g_evt_hit);  g_evt_hit = nullptr; }
    if (g_map)      { CloseHandle(g_map);      g_map = nullptr; }
    if (g_cs_init) {
        DeleteCriticalSection(&g_cs);
        g_cs_init = false;
    }
}

} // anonymous namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        g_cs_init = true;

        const DWORD pid = GetCurrentProcessId();
        wchar_t map_name[128]{}, hit_name[128]{}, cont_name[128]{};
        format_pid_name(map_name, 128, L"Local\\NCE_VEH_MEM_", pid);
        format_pid_name(hit_name, 128, L"Local\\NCE_VEH_HIT_", pid);
        format_pid_name(cont_name, 128, L"Local\\NCE_VEH_CONT_", pid);

        g_map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, map_name);
        if (!g_map) { cleanup(); return FALSE; }

        g_state = static_cast<VehSharedState*>(MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(VehSharedState)));
        if (!g_state || g_state->magic != kVehMagic) { cleanup(); return FALSE; }

        g_evt_hit = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, hit_name);
        g_evt_cont = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, cont_name);
        if (!g_evt_hit || !g_evt_cont) { cleanup(); return FALSE; }

        g_veh_handle = AddVectoredExceptionHandler(1, veh_handler);
        if (!g_veh_handle) { cleanup(); return FALSE; }

        g_state->agent_ready = 1;
        MemoryBarrier();
    } else if (reason == DLL_PROCESS_DETACH) {
        cleanup();
    }
    return TRUE;
}
