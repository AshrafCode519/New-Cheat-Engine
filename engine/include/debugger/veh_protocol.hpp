#pragma once

#include <cstdint>

namespace nce::debugger::veh {

constexpr uint32_t kVehMagic = 0x4E434556; // 'NCEV'
constexpr uint32_t kVehVersion = 1;
constexpr size_t kMaxSwBreakpoints = 128;

enum class VehEventKind : uint32_t {
    None = 0,
    SoftwareBreakpoint = 1,
    SingleStep = 2,
    HardwareBreakpoint = 3
};

enum class VehCommand : uint32_t {
    None = 0,
    Continue = 1,
    SingleStep = 2,
    Detach = 3
};

#pragma pack(push, 8)
struct VehRegisters {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, eflags;
    uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
};

struct VehSharedState {
    uint32_t magic;
    uint32_t version;
    volatile uint32_t agent_ready;
    volatile uint32_t detach_requested;
    volatile uint32_t single_step_active;

    volatile uint32_t event_kind;      // VehEventKind
    volatile uint32_t command;         // VehCommand
    volatile uint32_t hit_thread_id;
    uint64_t hit_address;

    VehRegisters regs;

    // Host populates active SW BP addresses so the in-process VEH handler ignores unrelated exceptions
    volatile uint32_t sw_bp_count;
    uint64_t sw_bps[kMaxSwBreakpoints];
};
#pragma pack(pop)

} // namespace nce::debugger::veh
