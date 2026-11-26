#pragma once

#include "access_watcher.hpp"
#include "disassembler.hpp"
#include "../hal/process.hpp"
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace nce::debugger {

struct MemWritePatch {
    uintptr_t address{0};
    std::vector<uint8_t> bytes;
};

struct EmuMemoryAccess {
    uintptr_t address{0};
    size_t size{0};
    uint64_t value{0};
    uint64_t previous{0};
    bool is_write{false};
};

struct EmuStepLog {
    uintptr_t address{0};
    std::string disassembly;
    uint64_t rax_after{0};
    uint64_t rsp_after{0};
};

struct EmulationResult {
    bool completed{false};
    bool returned_cleanly{false};
    size_t steps_executed{0};
    Registers final_regs{};
    std::array<double, 8> xmm_f64{};
    std::vector<EmuMemoryAccess> accesses;
    std::vector<EmuStepLog> trace;
    std::string fault_reason;
};

struct TaintStep {
    uintptr_t address{0};
    std::string instruction;
    std::vector<std::string> tainted_regs;
    std::string origin_note;
};

// Safe Copy-On-Write x86/x64 Micro-Emulator + Backward Taint Slicer:
// Executes code in an isolated memory overlay without touching the target process, enabling
// dry-run testing of Auto-Assembler hooks/caves and backward data-flow slicing ("where did this register come from?").
class MicroEmulator {
public:
    [[nodiscard]] static EmulationResult emulate(
        const hal::IProcess* process,
        uintptr_t entry_rip,
        const Registers& initial_regs,
        size_t max_steps = 64,
        bool is_64bit = true,
        const std::vector<MemWritePatch>& overlay_patches = {}
    );

    [[nodiscard]] static EmulationResult dry_run_hook(
        const hal::IProcess& process,
        uintptr_t target_address,
        const std::vector<uint8_t>& cave_code,
        uintptr_t cave_address,
        const Registers& initial_regs,
        size_t max_steps = 64
    );

    [[nodiscard]] static std::vector<TaintStep> backward_taint(
        const ControlFlowGraph& cfg,
        uintptr_t sink_address,
        const std::string& target_reg
    );
};

} // namespace nce::debugger
