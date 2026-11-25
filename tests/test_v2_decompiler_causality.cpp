#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "debugger/causality_timeline.hpp"
#include "debugger/decompiler.hpp"
#include "debugger/disassembler.hpp"
#include "session/session.hpp"

#include <cstring>
#include <memory>
#include <vector>

using namespace nce;
using test::FakeProcess;

TEST_CASE("PseudoCDecompiler lifts CFG with struct fields, branches, xor-zeroing, and symbols") {
    auto proc = std::make_shared<FakeProcess>(0x4000);
    proc->set_name("game.exe");
    proc->add_module("game.exe", 0, 0x2000);

    // Function at kBase + 0x100:
    // +0x00: 48 83 EC 28        sub rsp, 0x28
    // +0x04: 8B 41 10           mov eax, dword ptr [rcx+0x10]
    // +0x07: 83 F8 00           cmp eax, 0
    // +0x0A: 7E 09              jle +9 (-> +0x15)
    // +0x0C: 33 C0              xor eax, eax
    // +0x0E: E8 1D 00 00 00     call +0x1D (-> kBase + 0x130)
    // +0x13: EB 03              jmp +3 (-> +0x18)
    // +0x15: 89 41 10           mov dword ptr [rcx+0x10], eax
    // +0x18: 48 83 C4 28        add rsp, 0x28
    // +0x1C: C3                 ret
    const std::vector<uint8_t> code = {
        0x48, 0x83, 0xEC, 0x28,
        0x8B, 0x41, 0x10,
        0x83, 0xF8, 0x00,
        0x7E, 0x09,
        0x33, 0xC0,
        0xE8, 0x1D, 0x00, 0x00, 0x00,
        0xEB, 0x03,
        0x89, 0x41, 0x10,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    const uintptr_t entry = FakeProcess::kBase + 0x100;
    REQUIRE(proc->write_raw(entry, code.data(), code.size()));
    const uint8_t target_ret = 0xC3;
    REQUIRE(proc->write_raw(FakeProcess::kBase + 0x130, &target_ret, 1));

    // Populate a realistic player struct at kBase + 0x800 so StructureDissector recognizes fields
    const uintptr_t struct_addr = FakeProcess::kBase + 0x800;
    proc->put<int32_t>(0x810, 100);
    proc->put<float>(0x814, 50.0f);

    const auto cfg = debugger::Disassembler::build_cfg(*proc, entry, 64, 16);
    CHECK(cfg.blocks.size() >= 3);

    debugger::DecompileOptions opts;
    opts.struct_base_reg = "rcx";
    opts.struct_fields[0x10] = {"int32_t", "health"};
    opts.symbol_resolver = [entry](uintptr_t addr) -> std::string {
        if (addr == entry + 0x30) return "apply_damage";
        return "";
    };

    const auto decomp = debugger::PseudoCDecompiler::decompile(cfg, opts);
    CHECK(decomp.entry_address == entry);
    CHECK(!decomp.code.empty());
    CHECK(decomp.code.find("rcx->health") != std::string::npos);
    CHECK(decomp.code.find("apply_damage") != std::string::npos);
    CHECK(decomp.code.find("if (") != std::string::npos);
    CHECK(decomp.code.find("= 0") != std::string::npos);
    CHECK(decomp.code.find("return") != std::string::npos);

    // Also test Session::decompile_function integration with StructureDissector
    session::Session ses(proc, hal::IHotkeys::create());
    const auto ses_decomp = ses.decompile_function(entry, struct_addr, 64);
    CHECK(ses_decomp.entry_address == entry);
    CHECK(ses_decomp.code.find("if (") != std::string::npos);
    CHECK(ses_decomp.code.find("rcx->") != std::string::npos);
}

TEST_CASE("PseudoCDecompiler detects loop back-edges in CFG") {
    auto make_insn = [](uintptr_t addr, std::vector<uint8_t> bytes, std::string mnem, std::string ops, uintptr_t target = 0) {
        debugger::DecodedInstruction d;
        d.address = addr;
        d.length = bytes.size();
        d.mnemonic = std::move(mnem);
        d.operands = std::move(ops);
        d.bytes = std::move(bytes);
        d.branch_target = target;
        return d;
    };

    debugger::ControlFlowGraph cfg;
    cfg.entry_address = 0x401000;

    debugger::BasicBlock b0;
    b0.id = 0;
    b0.start_address = 0x401000;
    b0.end_address = 0x401002;
    b0.instructions.push_back(make_insn(0x401000, {0x31, 0xC9}, "xor", "ecx, ecx"));

    debugger::BasicBlock b1;
    b1.id = 1;
    b1.start_address = 0x401002;
    b1.end_address = 0x401009;
    b1.instructions.push_back(make_insn(0x401002, {0xFF, 0xC1}, "inc", "ecx"));
    b1.instructions.push_back(make_insn(0x401004, {0x83, 0xF9, 0x0A}, "cmp", "ecx, 0xa"));
    b1.instructions.push_back(make_insn(0x401007, {0x7C, 0xF9}, "jl", "0x401002", 0x401002));

    debugger::BasicBlock b2;
    b2.id = 2;
    b2.start_address = 0x401009;
    b2.end_address = 0x40100A;
    b2.instructions.push_back(make_insn(0x401009, {0xC3}, "ret", ""));

    cfg.blocks = {b0, b1, b2};
    cfg.edges = {
        {0, 1, debugger::CFGEdge::Kind::Unconditional},
        {1, 1, debugger::CFGEdge::Kind::TrueBranch},
        {1, 2, debugger::CFGEdge::Kind::FalseBranch},
    };

    const auto fn = debugger::PseudoCDecompiler::decompile(cfg);
    CHECK((fn.code.find("while") != std::string::npos || fn.code.find("do") != std::string::npos || fn.code.find("goto") != std::string::npos));
    CHECK(fn.code.find("return") != std::string::npos);
}

TEST_CASE("CausalityTimeline records register & memory deltas, seeks, diffs, and respects cap") {
    debugger::CausalityTimeline tl(8);
    CHECK(tl.empty());
    CHECK(tl.count() == 0);
    CHECK(!tl.current().has_value());

    debugger::Registers r0{};
    r0.rip = 0x1000;
    r0.rax = 100;
    r0.rcx = 0x2000;
    tl.push_event(0x1000, "tick+0x0", "mov eax, 100", r0, 7, 0x2000, {100, 0, 0, 0});

    debugger::Registers r1 = r0;
    r1.rip = 0x1005;
    r1.rax = 75;
    tl.push_event(0x1005, "tick+0x5", "sub eax, 25", r1, 7, 0x2000, {75, 0, 0, 0});

    debugger::Registers r2 = r1;
    r2.rip = 0x1008;
    r2.rdx = 42;
    tl.push_event(0x1008, "tick+0x8", "mov edx, 42", r2, 7, 0x2000, {75, 0, 0, 0});

    REQUIRE(tl.count() == 3);
    CHECK(tl.cursor() == 2);

    const auto ev1 = tl.at(1);
    REQUIRE(ev1.has_value());
    CHECK(ev1->symbol == "tick+0x5");
    CHECK(!ev1->reg_deltas.empty());
    CHECK(ev1->memory_deltas.size() == 1);
    CHECK(ev1->memory_deltas[0].address == 0x2000);
    CHECK(ev1->memory_deltas[0].before == 100);
    CHECK(ev1->memory_deltas[0].after == 75);

    const auto mutations = tl.find_memory_mutations();
    REQUIRE(mutations.size() == 1);
    CHECK(mutations[0] == 1);

    CHECK(tl.step_backward());
    CHECK(tl.cursor() == 1);
    CHECK(tl.current()->instruction_address == 0x1005);

    CHECK(tl.seek(0));
    CHECK(tl.cursor() == 0);
    CHECK(!tl.step_backward());

    CHECK(tl.step_forward());
    CHECK(tl.cursor() == 1);

    const auto diff = tl.diff_between(0, 2);
    CHECK(!diff.reg_deltas.empty());
    CHECK(diff.memory_deltas.size() == 1);

    const auto report = tl.format_report(0, 10);
    CHECK(report.find("tick+0x5") != std::string::npos);

    // Record from TraceEntry + live FakeProcess watch memory
    auto proc = std::make_shared<FakeProcess>(0x1000);
    proc->put<uint32_t>(0x100, 0xAABBCCDDu);
    std::vector<debugger::TraceEntry> traces(2);
    traces[0].sequence = 10;
    traces[0].thread_id = 9;
    traces[0].address = 0x4000;
    traces[0].symbol = "fn_a";
    traces[0].disassembly = "nop";
    traces[0].registers = r0;
    traces[1] = traces[0];
    traces[1].sequence = 11;
    traces[1].address = 0x4001;
    traces[1].registers = r1;

    tl.clear();
    tl.record_trace(traces, proc.get(), FakeProcess::kBase + 0x100, 4);
    CHECK(tl.count() == 2);
    CHECK(tl.at(0)->watched_bytes.size() == 4);

    // Capacity bound check
    tl.set_max_events(2);
    tl.push_event(0x5000, "fn_c", "ret", r2, 9);
    CHECK(tl.count() == 2);
}
