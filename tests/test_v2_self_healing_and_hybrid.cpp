#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "debugger/pe_analyzer.hpp"
#include "session/session.hpp"
#include "table/cheat_table.hpp"

#include <cstring>
#include <memory>
#include <vector>

using namespace nce;
using test::FakeProcess;

namespace {

void write_minimal_pe64(FakeProcess& proc, size_t base_offset) {
    // DOS header: "MZ" + e_lfanew = 0x80
    proc.put<uint16_t>(base_offset + 0x00, 0x5A4D);
    proc.put<uint32_t>(base_offset + 0x3C, 0x80);
    // NT headers: "PE\0\0" + IMAGE_FILE_HEADER (20B) + IMAGE_OPTIONAL_HEADER64 (0xF0)
    const size_t nt = base_offset + 0x80;
    proc.put<uint32_t>(nt + 0x00, 0x00004550u);
    proc.put<uint16_t>(nt + 0x04, 0x8664); // AMD64
    proc.put<uint16_t>(nt + 0x06, 1);      // NumberOfSections
    proc.put<uint16_t>(nt + 0x14, 0x00F0); // SizeOfOptionalHeader
    proc.put<uint16_t>(nt + 0x16, 0x0022); // Executable image
    proc.put<uint16_t>(nt + 0x18, 0x020B); // PE32+ Magic
    proc.put<uint32_t>(nt + 0x50, 0x2000); // SizeOfImage
    // Section ".text"
    const size_t sec = nt + 0x18 + 0x00F0;
    const char name[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};
    proc.write_raw(FakeProcess::kBase + sec, name, 8);
    proc.put<uint32_t>(sec + 0x08, 0x1000); // VirtualSize
    proc.put<uint32_t>(sec + 0x0C, 0x1000); // VirtualAddress
    proc.put<uint32_t>(sec + 0x24, 0x60000020u);
}

void write_minimal_elf64(FakeProcess& proc, size_t base_offset) {
    const uint8_t elf_hdr[64] = {
        0x7F, 'E', 'L', 'F',
        2, // ELFCLASS64
        1, // ELFDATA2LSB
        1, // EV_CURRENT
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        3, 0, // ET_DYN
        0x3E, 0, // EM_X86_64
        1, 0, 0, 0 // e_version
    };
    proc.write_raw(FakeProcess::kBase + base_offset, elf_hdr, sizeof(elf_hdr));
}

} // namespace

TEST_CASE("Self-healing CheatTable SignatureAnchor & migrate_table_by_signatures across updates") {
    // Build v1 binary image with unique instruction sequence: mov eax, dword ptr [rip + disp32]
    FakeProcess v1(0x10000);
    v1.set_name("hero.exe");
    v1.add_module("hero.exe", 0, 0x8000);

    // Unique function prologue + RIP-relative load:
    // 0x0FF6: 48 89 5C 24 08 57 48 83 EC 20  (10 bytes unique prologue)
    // 0x1000: 8B 05 FA 1F 00 00              (mov eax, [rip + 0x1FFA] -> 0x1006 + 0x1FFA = 0x3000 -> kBase+0x3000)
    // 0x1006: 48 83 C4 20 5F C3              (6 bytes unique epilogue)
    const std::vector<uint8_t> fn_v1 = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20,
        0x8B, 0x05, 0xFA, 0x1F, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3
    };
    REQUIRE(v1.write_raw(FakeProcess::kBase + 0x0FF6, fn_v1.data(), fn_v1.size()));
    v1.put<int32_t>(0x3000, 777);

    table::CheatTable tbl;
    tbl.process_name = "hero.exe";
    auto entry = table::make_entry(FakeProcess::kBase + 0x3000, scanner::DataType::Int32, v1.get_modules(), "PlayerGold");
    const auto anchor = table::create_signature_anchor(v1, v1.get_modules(), FakeProcess::kBase + 0x1000, 0);
    REQUIRE(anchor.has_value());
    CHECK(anchor->module_name == "hero.exe");
    CHECK(anchor->is_rip_relative);
    CHECK(!anchor->aob_pattern.empty());
    entry.signature_anchor = anchor;
    tbl.entries.push_back(entry);

    // JSON round-trip preserves SignatureAnchor
    const std::string json_text = table::to_json(tbl);
    auto restored = table::from_json(json_text);
    REQUIRE(restored.has_value());
    REQUIRE(restored->entries.size() == 1);
    REQUIRE(restored->entries[0].signature_anchor.has_value());
    CHECK(restored->entries[0].signature_anchor->aob_pattern == anchor->aob_pattern);

    // Simulate updated v2 binary where both the code AND static data moved:
    // Prologue starts at 0x2200 -> RIP insn at 0x220A, target at 0x5500 -> disp32 = 0x5500 - 0x2210 = 0x32F0
    FakeProcess v2(0x10000);
    v2.set_name("hero.exe");
    v2.add_module("hero.exe", 0, 0x8000);
    const std::vector<uint8_t> fn_v2 = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20,
        0x8B, 0x05, 0xF0, 0x32, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3
    };
    REQUIRE(v2.write_raw(FakeProcess::kBase + 0x2200, fn_v2.data(), fn_v2.size()));
    v2.put<int32_t>(0x5500, 9999);

    const auto report = table::migrate_table_by_signatures(*restored, v2, v2.get_modules());
    CHECK(report.total_anchored == 1);
    CHECK(report.updated == 1);
    CHECK(report.failed == 0);
    CHECK(restored->entries[0].address(v2, v2.get_modules()) == FakeProcess::kBase + 0x5500);

    const auto val = table::read_entry(restored->entries[0], v2, v2.get_modules());
    REQUIRE(val.has_value());
    CHECK(std::get<int32_t>(val->value) == 9999);
}

TEST_CASE("Hybrid PE + ELF analyzer identifies Wine/Proton mapped PE modules alongside ELF") {
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->set_name("wine64-preloader");
    proc->add_module("game.exe", 0x0000, 0x3000);
    proc->add_module("winevulkan.so", 0x4000, 0x3000);

    write_minimal_pe64(*proc, 0x0000);
    write_minimal_elf64(*proc, 0x4000);

    CHECK(debugger::PEAnalyzer::is_pe_magic(*proc, FakeProcess::kBase));
    CHECK(!debugger::PEAnalyzer::is_pe_magic(*proc, FakeProcess::kBase + 0x4000));

    session::Session ses(proc, hal::IHotkeys::create());
    const auto mods = ses.inspect_hybrid_modules();
    REQUIRE(mods.size() == 2);
    CHECK(mods[0].name == "game.exe");
    CHECK(mods[0].format == "PE");
    CHECK(mods[0].is_64bit);
    CHECK(mods[1].name == "winevulkan.so");
    CHECK(mods[1].format == "ELF");
    CHECK(mods[1].is_64bit);
    CHECK(ses.is_proton_or_wine());
}

TEST_CASE("Lua 5.4 eval_expression REPL, v2 globals, and CheatTable <LuaScript>") {
    auto proc = std::make_shared<FakeProcess>(0x4000);
    proc->set_name("script_test.exe");
    proc->add_module("script_test.exe", 0, 0x2000);
    proc->put<int32_t>(0x100, 42);

    session::Session ses(proc, hal::IHotkeys::create());

    // Expression returning value
    for (int i = 0; i < 15; ++i) {
        const auto r = ses.eval_lua_expression("2 + 40");
        CHECK(r.success);
        CHECK(r.output.find("42") != std::string::npos);
    }

    // Statement fallback + readback
    const auto st = ses.eval_lua_expression("repl_counter = 6 * 7");
    CHECK(st.success);
    const auto rd = ses.eval_lua_expression("repl_counter");
    CHECK(rd.success);
    CHECK(rd.output.find("42") != std::string::npos);

    // Check v2 global functions exist in Lua environment
    const auto fn_check = ses.eval_lua_expression(
        "type(decompile) .. ',' .. type(anchorEntry) .. ',' .. type(migrateTable) .. ',' .. type(timelineReport) .. ',' .. type(connectRemote)");
    CHECK(fn_check.success);
    CHECK(fn_check.output == "function,function,function,function,function");

    // Table <LuaScript> execution
    ses.table().with([](table::CheatTable& t, const std::vector<hal::ModuleInfo>&) {
        t.lua_script = "ct_boot_flag = 'nce_v2_ready'";
    });
    const auto ct_res = ses.run_table_lua_script();
    CHECK(ct_res.ok);
    const auto ct_check = ses.eval_lua_expression("ct_boot_flag");
    CHECK(ct_check.success);
    CHECK(ct_check.output == "nce_v2_ready");
}
