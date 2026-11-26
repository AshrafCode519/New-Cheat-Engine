#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "assembler/auto_assembler.hpp"
#include "debugger/condition_eval.hpp"
#include "debugger/debug_coordinator.hpp"
#include "debugger/disassembler.hpp"
#include "debugger/hook_engine.hpp"
#include "debugger/step_debugger.hpp"
#include "session/session.hpp"
#include "utils/sig_generator.hpp"

#include <cstring>
#include <memory>
#include <vector>

using namespace nce;
using test::FakeProcess;

TEST_CASE("WOW64 / 32-bit target: stack walking, x86 CFG disassembly, signature gen, and hooks") {
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->set_name("game32.exe");
    proc->set_pointer_size(4);
    proc->add_module("game32.exe", 0x0000, 0x4000);
    proc->add_module("engine32.dll", 0x4000, 0x4000);

    // 1. DebugCoordinator recognizes 32-bit target mode and guards incompatible 64-bit VEH agent
    debugger::DebugCoordinator coord(proc);
    CHECK(coord.is_target_64bit() == false);
#ifdef _WIN32
    // On WOW64 targets, 64-bit VEH DLL cannot inject cleanly and reports explicit error
    // (Win32 DebugAPI uses WOW64_CONTEXT + STATUS_WX86_*)
    CHECK(coord.is_wow64() == false); // becomes true on attach()
#endif

    // 2. StepDebugger::walk_stack reads 4-byte EBP/return frames on 32-bit targets
    // Layout: ESP = kBase + 0x9000 -> [ESP] = ret0 (game32+0x120)
    // EBP0 = kBase + 0x9020 -> [EBP0]=EBP1 (0x9040), [EBP0+4]=ret1 (engine32+0x500)
    // EBP1 = kBase + 0x9040 -> [EBP1]=0,             [EBP1+4]=ret2 (game32+0x80)
    const uintptr_t esp32 = FakeProcess::kBase + 0x9000;
    const uintptr_t ebp0  = FakeProcess::kBase + 0x9020;
    const uintptr_t ebp1  = FakeProcess::kBase + 0x9040;
    proc->put<uint32_t>(0x9000, static_cast<uint32_t>(FakeProcess::kBase + 0x0120));
    proc->put<uint32_t>(0x9020, static_cast<uint32_t>(ebp1));
    proc->put<uint32_t>(0x9024, static_cast<uint32_t>(FakeProcess::kBase + 0x4500));
    proc->put<uint32_t>(0x9040, 0);
    proc->put<uint32_t>(0x9044, static_cast<uint32_t>(FakeProcess::kBase + 0x0080));

    const auto frames = debugger::StepDebugger::walk_stack(*proc, ebp0, esp32, proc->get_modules(), 10);
    REQUIRE(frames.size() == 3);
    CHECK(frames[0].return_address == FakeProcess::kBase + 0x0120);
    CHECK(frames[0].module_name == "game32.exe");
    CHECK(frames[1].return_address == FakeProcess::kBase + 0x4500);
    CHECK(frames[1].module_name == "engine32.dll");
    CHECK(frames[2].return_address == FakeProcess::kBase + 0x0080);

    // 3. Disassembler::build_cfg & PseudoCDecompiler respect 32-bit pointer_size (inc eax 0x40, dec ecx 0x49, push ebp 0x55)
    // Function at kBase + 0x200:
    // 55            push ebp
    // 89 E5         mov ebp, esp
    // 40            inc eax      (must NOT be parsed as 64-bit REX!)
    // 49            dec ecx
    // 8B 45 08      mov eax, dword ptr [ebp+0x8]
    // 5D            pop ebp
    // C3            ret
    const std::vector<uint8_t> fn32 = {
        0x55, 0x89, 0xE5, 0x40, 0x49, 0x8B, 0x45, 0x08, 0x5D, 0xC3
    };
    const uintptr_t fn32_addr = FakeProcess::kBase + 0x200;
    REQUIRE(proc->write_raw(fn32_addr, fn32.data(), fn32.size()));

    const auto cfg = debugger::Disassembler::build_cfg(*proc, fn32_addr, 32, 8);
    REQUIRE(cfg.blocks.size() == 1);
    REQUIRE(cfg.blocks[0].instructions.size() == 7);
    CHECK(cfg.blocks[0].instructions[0].mnemonic == "push");
    CHECK(cfg.blocks[0].instructions[0].operands == "ebp");
    CHECK(cfg.blocks[0].instructions[2].mnemonic == "inc");
    CHECK(cfg.blocks[0].instructions[2].operands == "eax");
    CHECK(cfg.blocks[0].instructions[3].mnemonic == "dec");
    CHECK(cfg.blocks[0].instructions[3].operands == "ecx");

    // SignatureGenerator & AutoAssembler AOB script also decode in 32-bit mode cleanly
    const auto sig32 = utils::SignatureGenerator::generate(*proc, fn32_addr, 10);
    REQUIRE(sig32.has_value());
    CHECK(sig32->is_unique);
    const std::string aob_script = assembler::AutoAssembler::generate_aob_hook_script(*proc, fn32_addr, "HOOK32", 5);
    CHECK(aob_script.find("HOOK32:") != std::string::npos);

    // 4. HookEngine supports 32-bit 5-byte E9 rel32 detours & payload hooks (never 14-byte x64 FF 25!)
    debugger::HookEngine hooks(proc);
    const uintptr_t cave_dest = proc->allocate_memory(64, 0x40);
    // Notice FakeProcess caves are at 0x40000000 while kBase is 0x10000 -> diff fits rel32!
    uintptr_t tramp = 0;
    REQUIRE(hooks.install_detour(fn32_addr, cave_dest, &tramp));
    CHECK(tramp != 0);
    uint8_t hooked_first = 0;
    REQUIRE(proc->read_raw(fn32_addr, &hooked_first, 1));
    CHECK(hooked_first == 0xE9);
    CHECK(hooks.get_active_hooks()[0].stolen_bytes_count == 5); // 55(1) + 89 E5(2) + 40(1) + 49(1) = 5 bytes cleanly!
    hooks.remove_all_hooks();

    // Payload hook on 32-bit target only needs >= 5 stolen bytes cleanly
    const auto pinfo = hooks.install_payload_hook(fn32_addr, {0x90, 0x90});
    REQUIRE(pinfo.has_value());
    CHECK(pinfo->stolen_bytes_count == 5);
    hooks.remove_all_hooks();

    // 5. ConditionEvaluator evaluates 32-bit registers (eax, ecx, ebp, eip) + dword[ebp+0x8]
    proc->put<int32_t>(0x9028, 1337); // [ebp0 + 8] = kBase + 0x9028
    debugger::Registers regs32{};
    regs32.rax = 0x100000005ULL; // upper bits ignored when checking `eax`
    regs32.rbp = ebp0;
    regs32.rip = fn32_addr;
    const auto ev = debugger::ConditionEvaluator::evaluate(
        "eax == 5 && dword[ebp+0x8] == 1337 && eip == 0x10200", regs32, proc.get(), 1);
    CHECK(ev.ok);
    CHECK(ev.matched);
}
