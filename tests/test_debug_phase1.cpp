#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "debugger/condition_eval.hpp"
#include "debugger/debug_coordinator.hpp"
#include "debugger/step_debugger.hpp"
#include "hal/injector.hpp"
#include "session/session.hpp"
#include "table/standalone_generator.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace nce;
using test::FakeProcess;

TEST_CASE("ConditionEvaluator: registers, arithmetic, bitwise, and 32-bit sign handling") {
    debugger::Registers regs{};
    regs.rax = 0x100;
    regs.rbx = 0xFFFFFFFFULL; // -1 in 32-bit EAX/EBX
    regs.rcx = 0x2000;
    regs.rdx = 25;
    regs.r8  = 0x123456ABULL;

    CHECK(debugger::ConditionEvaluator::evaluate("rax == 0x100", regs).matched);
    CHECK_FALSE(debugger::ConditionEvaluator::evaluate("rax == 0x200", regs).matched);
    CHECK(debugger::ConditionEvaluator::evaluate("ebx == -1", regs).matched);
    CHECK(debugger::ConditionEvaluator::evaluate("rdx > 10 && rcx != 0", regs).matched);
    CHECK(debugger::ConditionEvaluator::evaluate("(r8 & 0xFF) == 0xAB", regs).matched);
    CHECK(debugger::ConditionEvaluator::evaluate("hit >= 5", regs, nullptr, 5).matched);
    CHECK_FALSE(debugger::ConditionEvaluator::evaluate("hit >= 5", regs, nullptr, 4).matched);
}

TEST_CASE("ConditionEvaluator: live memory dereference and syntax validation") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    const uintptr_t obj = FakeProcess::kBase + 0x400;
    process->put<int32_t>(0x400 + 0x10, 1337);
    process->put<uint64_t>(0x400 + 0x18, 0x140001000ULL);
    process->put<uint8_t>(0x400 + 0x20, 0xCC);
    process->put<uint16_t>(0x400 + 0x22, 0x1234);

    debugger::Registers regs{};
    regs.rcx = obj;

    CHECK(debugger::ConditionEvaluator::evaluate("dword[rcx + 0x10] == 1337", regs, process.get()).matched);
    CHECK(debugger::ConditionEvaluator::evaluate("[rcx + 0x18] == 0x140001000", regs, process.get()).matched);
    CHECK(debugger::ConditionEvaluator::evaluate("byte[rcx + 0x20] == 0xCC", regs, process.get()).matched);
    CHECK(debugger::ConditionEvaluator::evaluate("word[rcx + 0x22] == 0x1234", regs, process.get()).matched);
    CHECK_FALSE(debugger::ConditionEvaluator::evaluate("dword[rcx + 0x10] < 1000", regs, process.get()).matched);

    // Syntax validation checks
    CHECK_FALSE(debugger::ConditionEvaluator::validate("rax == 10 && dword[rcx+0x8] > 0").has_value());
    CHECK(debugger::ConditionEvaluator::validate("rax == ").has_value());
    CHECK(debugger::ConditionEvaluator::validate("bogus_reg == 1").has_value());
    CHECK(debugger::ConditionEvaluator::validate("[rcx + 4").has_value());
}

TEST_CASE("DebugCoordinator: unified HW watch slots DR0-DR3 and conditional/trace breakpoints") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<uint8_t>(0x100, 0x90);
    process->put<uint8_t>(0x110, 0xC3);

    session::Session s(process);
    REQUIRE(s.attach(1).ok);
    REQUIRE(s.debug_coordinator() != nullptr);
    REQUIRE(s.step_debugger() != nullptr);
    CHECK(s.step_debugger()->coordinator() == s.debug_coordinator());

    // Allocate 4 concurrent HW watch slots
    auto* coord = s.debug_coordinator();
    CHECK(coord->add_hw_watch(FakeProcess::kBase + 0x200, 4, debugger::WatchKind::Write, nullptr) == 0);
    CHECK(coord->add_hw_watch(FakeProcess::kBase + 0x204, 4, debugger::WatchKind::Access, nullptr) == 1);
    CHECK(coord->add_hw_watch(FakeProcess::kBase + 0x208, 1, debugger::WatchKind::Execute, nullptr) == 2);
    CHECK(coord->add_hw_watch(FakeProcess::kBase + 0x20C, 8, debugger::WatchKind::Write, nullptr) == 3);
    CHECK(coord->add_hw_watch(FakeProcess::kBase + 0x210, 4, debugger::WatchKind::Write, nullptr) == -1); // 4 slots full
    CHECK(coord->active_hw_watch_addresses().size() == 4);

    // Remove one and reuse slot
    CHECK(coord->remove_hw_watch(FakeProcess::kBase + 0x204));
    CHECK(coord->active_hw_watch_addresses().size() == 3);
    CHECK(coord->add_hw_watch(FakeProcess::kBase + 0x210, 4, debugger::WatchKind::Write, nullptr) == 1);

    // Conditional & Trace breakpoints
    CHECK_FALSE(s.dbg_set_bp(FakeProcess::kBase + 0x100, "bad", "rax === 1"));
    CHECK(s.dbg_set_bp(FakeProcess::kBase + 0x100, "cond-bp", "rax == 100", false));
    CHECK(s.dbg_set_bp(FakeProcess::kBase + 0x110, "trace", "rcx != 0", true));

    auto bps = s.step_debugger()->get_breakpoints();
    REQUIRE(bps.size() == 2);
    CHECK(bps[0].condition == "rax == 100");
    CHECK_FALSE(bps[0].is_tracepoint);
    CHECK(bps[1].condition == "rcx != 0");
    CHECK(bps[1].is_tracepoint);

    coord->remove_all_hw_watches();
    CHECK(coord->active_hw_watch_addresses().empty());
}

TEST_CASE("StandaloneGenerator: emits all 6 numeric types and preserves frozen values") {
    table::CheatTable tbl;
    tbl.process_name = "rpg.exe";

    auto add_typed = [&](const std::string& desc, uintptr_t off, scanner::DataType dt, const std::string& val) {
        table::TableEntry e;
        e.description = desc;
        e.type = dt;
        e.location.module_name = "rpg.exe";
        e.location.base_offset = off;
        e.frozen_value = val;
        tbl.entries.push_back(std::move(e));
    };

    add_typed("HP", 0x100, scanner::DataType::Int32, "777");
    add_typed("XP", 0x108, scanner::DataType::Int64, "9876543210");
    add_typed("Mana", 0x110, scanner::DataType::Float, "123.5");
    add_typed("Speed", 0x118, scanner::DataType::Double, "4.25");
    add_typed("Arrows", 0x120, scanner::DataType::Int16, "250");
    add_typed("Lives", 0x122, scanner::DataType::Int8, "99");

    std::string cpp = table::generate_standalone_trainer_cpp(tbl, "rpg.exe", table::TrainerKind::Console);
    CHECK(cpp.find("777") != std::string::npos);
    CHECK(cpp.find("9876543210") != std::string::npos);
    CHECK(cpp.find("123.5") != std::string::npos);
    CHECK(cpp.find("4.25") != std::string::npos);
    CHECK(cpp.find("it.typeId == 1") != std::string::npos);
    CHECK(cpp.find("it.typeId == 3") != std::string::npos);
    CHECK(cpp.find("it.typeId == 4") != std::string::npos);
    CHECK(cpp.find("it.typeId == 5") != std::string::npos);
}

TEST_CASE("ProcessInjector: enumerates current process threads and executable directory") {
    CHECK_FALSE(hal::ProcessInjector::executable_directory().empty());
#ifdef _WIN32
    auto threads = hal::ProcessInjector::list_threads(GetCurrentProcessId());
    CHECK(threads.size() >= 1);
#endif
}
