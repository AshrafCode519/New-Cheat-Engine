#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "debugger/step_debugger.hpp"
#include "session/session.hpp"

using namespace nce;
using test::FakeProcess;

TEST_CASE("StepDebugger manages breakpoints correctly") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    uintptr_t code_addr = FakeProcess::kBase + 0x100;
    process->put<uint8_t>(0x100, 0x90); // NOP

    debugger::StepDebugger dbg(process);
    CHECK_FALSE(dbg.has_breakpoint(code_addr));
    CHECK(dbg.get_breakpoints().empty());

    // Set breakpoint
    REQUIRE(dbg.set_breakpoint(code_addr, "test-bp"));
    CHECK(dbg.has_breakpoint(code_addr));
    auto bps = dbg.get_breakpoints();
    REQUIRE(bps.size() == 1);
    CHECK(bps[0].address == code_addr);
    CHECK(bps[0].note == "test-bp");
    CHECK(bps[0].is_enabled);
    CHECK(bps[0].original_byte == 0x90);

    // Disable breakpoint
    CHECK(dbg.enable_breakpoint(code_addr, false));
    bps = dbg.get_breakpoints();
    REQUIRE(bps.size() == 1);
    CHECK_FALSE(bps[0].is_enabled);

    // Re-enable breakpoint
    CHECK(dbg.enable_breakpoint(code_addr, true));
    bps = dbg.get_breakpoints();
    REQUIRE(bps.size() == 1);
    CHECK(bps[0].is_enabled);

    // Remove breakpoint
    CHECK(dbg.remove_breakpoint(code_addr));
    CHECK_FALSE(dbg.has_breakpoint(code_addr));
    CHECK(dbg.get_breakpoints().empty());
}

TEST_CASE("StepDebugger identifies CALL instructions correctly") {
    // 1. Direct relative call: E8 10 00 00 00
    debugger::DecodedInstruction call_rel;
    call_rel.mnemonic = "call";
    call_rel.bytes = { 0xE8, 0x10, 0x00, 0x00, 0x00 };
    CHECK(debugger::StepDebugger::is_call_instruction(call_rel));

    // 2. Indirect call: FF 15 00 00 00 00 (CALL QWORD PTR [rip+...])
    debugger::DecodedInstruction call_ind;
    call_ind.mnemonic = "call";
    call_ind.bytes = { 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00 };
    CHECK(debugger::StepDebugger::is_call_instruction(call_ind));

    // 3. Regular non-call instructions
    debugger::DecodedInstruction mov_insn;
    mov_insn.mnemonic = "mov";
    mov_insn.bytes = { 0x89, 0xC0 };
    CHECK_FALSE(debugger::StepDebugger::is_call_instruction(mov_insn));

    debugger::DecodedInstruction jmp_insn;
    jmp_insn.mnemonic = "jmp";
    jmp_insn.bytes = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    CHECK_FALSE(debugger::StepDebugger::is_call_instruction(jmp_insn));

    debugger::DecodedInstruction nop_insn;
    nop_insn.mnemonic = "nop";
    nop_insn.bytes = { 0x90 };
    CHECK_FALSE(debugger::StepDebugger::is_call_instruction(nop_insn));
}

TEST_CASE("StepDebugger unwinds simulated call stack frames") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    const uintptr_t base = FakeProcess::kBase;

    // Simulate standard stack layout in FakeProcess:
    // Frame 0: RBP = base + 0x2000
    // [base + 0x2000] = base + 0x2100 (saved RBP1)
    // [base + 0x2008] = 0x140001234 (return address 0)
    process->put<uintptr_t>(0x2000, base + 0x2100);
    process->put<uintptr_t>(0x2008, 0x140001234ULL);

    // Frame 1: RBP = base + 0x2100
    // [base + 0x2100] = base + 0x2200 (saved RBP2)
    // [base + 0x2108] = 0x140005678 (return address 1)
    process->put<uintptr_t>(0x2100, base + 0x2200);
    process->put<uintptr_t>(0x2108, 0x140005678ULL);

    // Frame 2: RBP = base + 0x2200
    // [base + 0x2200] = 0 (top of call stack)
    // [base + 0x2208] = 0x140009999 (return address 2)
    process->put<uintptr_t>(0x2200, 0);
    process->put<uintptr_t>(0x2208, 0x140009999ULL);

    std::vector<hal::ModuleInfo> modules = {
        { "game.exe", "C:\\game.exe", 0x140000000ULL, 0x50000 }
    };

    auto frames = debugger::StepDebugger::walk_stack(*process, base + 0x2000, 0, modules, 8);
    REQUIRE(frames.size() == 3);

    CHECK(frames[0].rbp == base + 0x2000);
    CHECK(frames[0].return_address == 0x140001234ULL);
    CHECK(frames[0].module_name == "game.exe");
    CHECK(frames[0].module_offset == 0x1234);
    CHECK(frames[0].symbol_name == "game.exe+0x1234");

    CHECK(frames[1].rbp == base + 0x2100);
    CHECK(frames[1].return_address == 0x140005678ULL);
    CHECK(frames[1].symbol_name == "game.exe+0x5678");

    CHECK(frames[2].rbp == base + 0x2200);
    CHECK(frames[2].return_address == 0x140009999ULL);
    CHECK(frames[2].symbol_name == "game.exe+0x9999");
}

TEST_CASE("Session step debugger forwarding methods work safely") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    session::Session s(process);

    // Detached state
    CHECK(s.step_debugger() == nullptr);
    CHECK_FALSE(s.dbg_attach());
    CHECK_FALSE(s.dbg_set_bp(0x1234));
    CHECK_FALSE(s.dbg_remove_bp(0x1234));
    CHECK_FALSE(s.dbg_resume());
    CHECK_FALSE(s.dbg_pause());
    CHECK_FALSE(s.dbg_step_into());
    CHECK_FALSE(s.dbg_step_over());
    CHECK_FALSE(s.dbg_step_out());

    // Attached state
    REQUIRE(s.attach(1).ok);
    REQUIRE(s.step_debugger() != nullptr);

    CHECK_FALSE(s.step_debugger()->is_paused());
    CHECK(s.dbg_set_bp(FakeProcess::kBase + 0x100, "hp-bp"));
    CHECK(s.step_debugger()->has_breakpoint(FakeProcess::kBase + 0x100));

    CHECK(s.dbg_remove_bp(FakeProcess::kBase + 0x100));
    CHECK_FALSE(s.step_debugger()->has_breakpoint(FakeProcess::kBase + 0x100));

    s.detach();
    CHECK(s.step_debugger() == nullptr);
}
