#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "assembler/auto_assembler.hpp"
#include "assembler/x86_assembler.hpp"
#include "debugger/debug_coordinator.hpp"
#include "debugger/hook_engine.hpp"
#include "script/lua_engine.hpp"
#include "session/session.hpp"
#include "table/ce_table_format.hpp"
#include "table/cheat_table.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

using namespace nce;
using test::FakeProcess;

TEST_CASE("AutoAssembler Phase 2: define, globalalloc, assert, readmem, fullaccess, data & numbers") {
    auto process = std::make_shared<FakeProcess>(0x20000);
    // Target bytes at kBase + 0x1000
    const uint8_t target_bytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08};
    REQUIRE(process->write_raw(FakeProcess::kBase + 0x1000, target_bytes, sizeof(target_bytes)));

    assembler::AutoAssembler aa(process);

    SUBCASE("define, #decimal, $hex, globalalloc, readmem, fullaccess, dw/dd/dq/float/double") {
        const std::string script =
            "[ENABLE]\n"
            "define(MAGIC_NUM, #1234)\n"
            "define(PATCH_ADDR, $11000)\n"
            "globalalloc(g_shared_cave, $40)\n"
            "fullaccess(PATCH_ADDR, 8)\n"
            "PATCH_ADDR:\n"
            "  readmem($11000, 4)\n"
            "alloc(data_block, #64)\n"
            "registersymbol(data_block)\n"
            "data_block:\n"
            "  dw #515\n"
            "  dd MAGIC_NUM\n"
            "  dq $123456789ABCDEF0\n"
            "  float 3.5\n"
            "  double 12.25\n"
            "[DISABLE]\n"
            "dealloc(data_block)\n"
            "dealloc(g_shared_cave)\n"
            "unregistersymbol(data_block)\n";

        auto res = aa.enable(script);
        INFO(res.message);
        REQUIRE(res.ok);

        auto data_sym = aa.symbol("data_block");
        REQUIRE(data_sym.has_value());
        CHECK(aa.symbol("g_shared_cave").has_value());

        uint16_t u16 = 0;
        uint32_t u32 = 0;
        uint64_t u64 = 0;
        float f32 = 0.0f;
        double f64 = 0.0;
        REQUIRE(process->read_raw(*data_sym, &u16, sizeof(u16)));
        REQUIRE(process->read_raw(*data_sym + 2, &u32, sizeof(u32)));
        REQUIRE(process->read_raw(*data_sym + 6, &u64, sizeof(u64)));
        REQUIRE(process->read_raw(*data_sym + 14, &f32, sizeof(f32)));
        REQUIRE(process->read_raw(*data_sym + 18, &f64, sizeof(f64)));
        CHECK(u16 == 515);
        CHECK(u32 == 1234);
        CHECK(u64 == 0x123456789ABCDEF0ULL);
        CHECK(f32 == doctest::Approx(3.5f));
        CHECK(f64 == doctest::Approx(12.25));

        auto dis = aa.disable(script, res.effect);
        CHECK(dis.ok);
    }

    SUBCASE("assert validates bytes and rolls back on mismatch") {
        const std::string bad_script =
            "[ENABLE]\n"
            "0x11000:\n"
            "  db 90\n"
            "assert(0x11001, AA BB CC)\n";

        auto fail_res = aa.enable(bad_script);
        CHECK_FALSE(fail_res.ok);
        uint8_t first_byte = 0;
        REQUIRE(process->read_raw(FakeProcess::kBase + 0x1000, &first_byte, 1));
        CHECK(first_byte == 0x48); // Rolled back!

        const std::string good_script =
            "[ENABLE]\n"
            "assert(0x11000, 48 89 ? 24 08)\n"
            "0x11000:\n"
            "  db 90 90\n"
            "[DISABLE]\n"
            "0x11000:\n"
            "  db 48 89\n";
        auto ok_res = aa.enable(good_script);
        INFO(ok_res.message);
        REQUIRE(ok_res.ok);
        uint8_t patched[2]{};
        REQUIRE(process->read_raw(FakeProcess::kBase + 0x1000, patched, 2));
        CHECK(patched[0] == 0x90);
        CHECK(patched[1] == 0x90);
        CHECK(aa.disable(good_script, ok_res.effect).ok);
    }
}

TEST_CASE("AutoAssembler Phase 2: aobscan, aobscanregion & hybrid {$lua} block") {
    auto process = std::make_shared<FakeProcess>(0x20000);
    const uint8_t sig[] = {0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00};
    REQUIRE(process->write_raw(FakeProcess::kBase + 0x2500, sig, sizeof(sig)));
    REQUIRE(process->write_raw(FakeProcess::kBase + 0x9500, sig, sizeof(sig)));

    session::Session session(process);
    REQUIRE(session.attach(1).ok);

    SUBCASE("aobscan and aobscanregion through TableKeeper with {$lua} block") {
        const std::string script =
            "[ENABLE]\n"
            "{$lua}\n"
            "print('LUA_BLOCK_RAN')\n"
            "{$asm}\n"
            "aobscan(HIT_ANY, 55 48 89 E5 B8 ? 00 00 00)\n"
            "aobscanregion(HIT_HIGH, 0x18000, 0x20000, 55 48 89 E5 B8 ? 00 00 00)\n"
            "HIT_HIGH:\n"
            "  nop\n"
            "[DISABLE]\n"
            "HIT_HIGH:\n"
            "  db 55\n";

        REQUIRE(session.table().add_script("LuaHybridTest", script).ok);
        auto on = session.table().set_script_enabled(0, true);
        INFO(on.message);
        REQUIRE(on.ok);

        uint8_t b_low = 0, b_high = 0;
        REQUIRE(process->read_raw(FakeProcess::kBase + 0x2500, &b_low, 1));
        REQUIRE(process->read_raw(FakeProcess::kBase + 0x9500, &b_high, 1));
        CHECK(b_low == 0x55);
        CHECK(b_high == 0x90);

        CHECK(session.table().set_script_enabled(0, false).ok);
        REQUIRE(process->read_raw(FakeProcess::kBase + 0x9500, &b_high, 1));
        CHECK(b_high == 0x55);
    }

    SUBCASE("X86Assembler supports $hex and #decimal immediates") {
        assembler::X86Assembler enc;
        std::string err;
        auto enc_dec = enc.encode("mov eax, #1000", 0x10000, err);
        INFO(err);
        REQUIRE(enc_dec.has_value());
        REQUIRE(enc_dec->bytes.size() == 5);
        CHECK(enc_dec->bytes[0] == 0xB8);
        int32_t imm = 0;
        std::memcpy(&imm, &enc_dec->bytes[1], 4);
        CHECK(imm == 1000);

        auto enc_hex = enc.encode("add eax, $20", 0x10000, err);
        INFO(err);
        REQUIRE(enc_hex.has_value());
        CHECK(!enc_hex->bytes.empty());
    }
}

TEST_CASE("LuaEngine Phase 2: AOBScan, HookEngine, Scanner automation, Hotkeys, Timers & Breakpoint callback") {
    auto process = std::make_shared<FakeProcess>(0x30000);
    process->add_module("game.exe", 0x1000, 0x4000);
    process->add_module("helper.dll", 0x6000, 0x4000);

    const uint8_t pat_game[] = {0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44};
    const uint8_t pat_dll[]  = {0x48, 0x8B, 0x05, 0x99, 0x22, 0x33, 0x44};
    REQUIRE(process->write_raw(FakeProcess::kBase + 0x1800, pat_game, sizeof(pat_game)));
    REQUIRE(process->write_raw(FakeProcess::kBase + 0x6800, pat_dll, sizeof(pat_dll)));

    // 5-byte valid instruction for HookEngine cave test: mov [rsp+8], rbx (48 89 5C 24 08)
    const uint8_t hook_target_code[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x90, 0x90};
    const uintptr_t hook_addr = FakeProcess::kBase + 0x2000;
    REQUIRE(process->write_raw(hook_addr, hook_target_code, sizeof(hook_target_code)));

    // Known integer value for firstScan / nextScan automation
    const uintptr_t val_addr = FakeProcess::kBase + 0x12000;
    process->put<int32_t>(0x12000, 555111);

    session::Session session(process);
    REQUIRE(session.attach(1).ok);
    auto* lua = session.lua_engine();
    REQUIRE(lua != nullptr);

    SUBCASE("AOBScan, AOBScanFirst and AOBScanModule") {
        auto res = lua->execute_string(
            "local all = AOBScan('48 8B 05 ? 22 33 44')\n"
            "assert(#all == 2, 'expected 2 matches, got ' .. #all)\n"
            "local first = AOBScanFirst('48 8B 05 ? 22 33 44')\n"
            "assert(first == all[1])\n"
            "local dllHit, dllAll = AOBScanModule('helper.dll', '48 8B 05 ? 22 33 44')\n"
            "assert(dllHit ~= nil and #dllAll == 1)\n"
            "print(toHex(dllHit))\n");
        INFO(res.error);
        REQUIRE(res.success);
        CHECK(res.output.find("16800") != std::string::npos);
    }

    SUBCASE("Scanner automation firstScan / nextScan / getScanResults") {
        auto r1 = lua->execute_string(
            "local ok, cnt = firstScan('int32', 555111)\n"
            "assert(ok and cnt >= 1, 'firstScan failed')\n");
        INFO(r1.error);
        REQUIRE(r1.success);

        process->put<int32_t>(0x12000, 555222);

        auto r2 = lua->execute_string(
            "local ok, cnt = nextScan('increased')\n"
            "assert(ok and cnt == getScanCount())\n"
            "local hits = getScanResults(10)\n"
            "assert(#hits >= 1)\n"
            "local found = false\n"
            "for _, h in ipairs(hits) do\n"
            "  if h.address == " + std::to_string(val_addr) + " and h.value == '555222' then found = true end\n"
            "end\n"
            "assert(found, 'missing updated address in getScanResults')\n");
        INFO(r2.error);
        REQUIRE(r2.success);
    }

    SUBCASE("HookEngine Lua bindings installHook / getHooks / removeHook") {
        std::string code =
            "local info, err = installHook(" + std::to_string(hook_addr) + ", '90 90 90')\n"
            "assert(info ~= nil, tostring(err))\n"
            "assert(info.cave ~= 0 and info.stolen >= 5)\n"
            "local list = getHooks()\n"
            "assert(#list == 1 and list[1].active)\n";
        auto res = lua->execute_string(code);
        INFO(res.error);
        REQUIRE(res.success);

        uint8_t patched_opcode = 0;
        REQUIRE(process->read_raw(hook_addr, &patched_opcode, 1));
        CHECK(patched_opcode == 0xE9);

        auto unhook_res = lua->execute_string(
            "assert(removeHook(" + std::to_string(hook_addr) + "))\n"
            "assert(#getHooks() == 0)\n");
        INFO(unhook_res.error);
        REQUIRE(unhook_res.success);

        uint8_t restored[5]{};
        REQUIRE(process->read_raw(hook_addr, restored, sizeof(restored)));
        CHECK(std::memcmp(restored, hook_target_code, 5) == 0);
    }

    SUBCASE("Lua hotkeys and timers") {
        auto hk = lua->execute_string(
            "hk_count = 0\n"
            "local id = createHotkey('ctrl+f7', function(k) hk_count = hk_count + 1; hk_key = k end)\n"
            "assert(id == 'Ctrl+F7')\n"
            "assert(triggerHotkey('Ctrl+F7'))\n"
            "assert(hk_count == 1 and hk_key == 'Ctrl+F7')\n"
            "assert(destroyHotkey('ctrl+f7'))\n"
            "assert(not triggerHotkey('Ctrl+F7'))\n");
        INFO(hk.error);
        REQUIRE(hk.success);
        CHECK(lua->active_hotkey_count() == 0);

        auto tmr = lua->execute_string(
            "tick_count = 0\n"
            "tmr_id = createTimer(10, function(id)\n"
            "  tick_count = tick_count + 1\n"
            "  if tick_count >= 3 then destroyTimer(id) end\n"
            "end)\n");
        INFO(tmr.error);
        REQUIRE(tmr.success);

        for (int i = 0; i < 40; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            auto chk = lua->execute_string("return tick_count >= 3");
            if (chk.success && lua->active_timer_count() == 0) break;
        }
        lua->clear_timers();
        auto verify_ticks = lua->execute_string("assert(tick_count >= 3, 'timer did not fire enough')");
        INFO(verify_ticks.error);
        CHECK(verify_ticks.success);
    }

    SUBCASE("debugger_onBreakpoint callback reads & writes registers") {
        auto setup = lua->execute_string(
            "function debugger_onBreakpoint()\n"
            "  last_tid = THREADID\n"
            "  RAX = RAX + 50\n"
            "  RIP = RIP + 1\n"
            "  return 1\n"
            "end\n");
        INFO(setup.error);
        REQUIRE(setup.success);

        debugger::Registers regs{};
        regs.rax = 100;
        regs.rip = 0x140001000ULL;
        const bool cont = lua->on_breakpoint_hit(42, regs.rip, regs);
        CHECK(cont);
        CHECK(regs.rax == 150);
        CHECK(regs.rip == 0x140001001ULL);

        auto pause_setup = lua->execute_string(
            "function debugger_onBreakpoint()\n"
            "  RBX = 777\n"
            "  return 0\n"
            "end\n");
        REQUIRE(pause_setup.success);
        const bool cont2 = lua->on_breakpoint_hit(42, regs.rip, regs);
        CHECK_FALSE(cont2);
        CHECK(regs.rbx == 777);
    }
}

TEST_CASE("CheatTable Phase 2: <LuaScript> persistence in JSON and .CT XML") {
    table::CheatTable tbl;
    tbl.process_name = "rpg_game.exe";
    tbl.lua_script = "function onOpen()\n  if readInteger(0x10) < 100 then print('Low HP & Alert!') end\nend\n";

    const std::string json_str = table::to_json(tbl);
    auto parsed_json = table::from_json(json_str);
    REQUIRE(parsed_json.has_value());
    CHECK(parsed_json->lua_script == tbl.lua_script);

    const std::string xml_str = table::serialize_ce_table(tbl);
    CHECK(xml_str.find("<LuaScript>") != std::string::npos);

    table::CheatTable parsed_xml;
    std::string err;
    REQUIRE(table::parse_ce_table(xml_str, parsed_xml, err));
    CHECK(parsed_xml.lua_script == tbl.lua_script);
}
