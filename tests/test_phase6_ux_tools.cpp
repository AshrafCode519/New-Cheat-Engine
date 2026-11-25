#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "assembler/auto_assembler.hpp"
#include "session/session.hpp"
#include "view/engine_inspector.hpp"

#include <array>
#include <cstring>
#include <sstream>
#include <vector>

using namespace nce;
using test::FakeProcess;

namespace {

template <typename T>
void wr_v(std::vector<uint8_t>& buf, size_t off, T val) {
    if (off + sizeof(T) > buf.size()) buf.resize(off + sizeof(T), 0);
    std::memcpy(buf.data() + off, &val, sizeof(T));
}

void setup_fname_entry(std::vector<uint8_t>& blk, uint32_t& cur, const std::string& text, uint32_t& out_idx) {
    out_idx = cur / 2;
    const uint16_t hdr = static_cast<uint16_t>((text.size() << 6));
    wr_v<uint16_t>(blk, cur, hdr);
    std::memcpy(blk.data() + cur + 2, text.data(), text.size());
    cur += static_cast<uint32_t>(((2 + text.size() + 1) / 2) * 2);
}

} // namespace

TEST_CASE("Phase 6 AutoAssembler::generate_aob_hook_script: creates live enable/disable cave script") {
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->attach(1);
    proc->add_module("game.exe", 0, 0x10000);

    const uintptr_t hook_addr = FakeProcess::kBase + 0x1000;
    // Unique x64 instructions:
    // sub [rcx+0x10], eax (3B) + mov eax, [rcx+0x10] (3B) + add rsp, 0x28 (4B) + mov rax, rbx (3B) + ret (1B)
    const std::array<uint8_t, 14> orig_bytes = {
        0x29, 0x41, 0x10,
        0x8B, 0x41, 0x10,
        0x48, 0x83, 0xC4, 0x28,
        0x48, 0x89, 0xD8,
        0xC3
    };
    REQUIRE(proc->write_raw(hook_addr, orig_bytes.data(), orig_bytes.size()));

    session::Session ses(proc);
    REQUIRE(ses.attach(1).ok);

    const std::string script = ses.generate_aob_hook_script(hook_addr, "GODHOOK", 5);
    INFO("Generated script:\n" << script);
    REQUIRE(!script.empty());
    CHECK(script.find("[ENABLE]") != std::string::npos);
    CHECK(script.find("[DISABLE]") != std::string::npos);
    CHECK(script.find("aobscanmodule(GODHOOK, game.exe,") != std::string::npos);
    CHECK(script.find("alloc(newmem,") != std::string::npos);
    CHECK(script.find("jmp newmem") != std::string::npos);
    CHECK(script.find("registersymbol(GODHOOK)") != std::string::npos);
    CHECK(script.find("unregistersymbol(GODHOOK)") != std::string::npos);
    CHECK(script.find("dealloc(newmem)") != std::string::npos);

    assembler::AutoAssembler aa(proc);
    const auto en = aa.enable(script);
    INFO("Enable msg: " << en.message);
    REQUIRE(en.ok);

    std::array<uint8_t, 14> patched{};
    REQUIRE(proc->read_raw(hook_addr, patched.data(), patched.size()));
    CHECK(patched[0] == 0xE9);
    CHECK(patched[5] == 0x90);
    CHECK(patched != orig_bytes);

    const auto dis = aa.disable(script, en.effect);
    INFO("Disable msg: " << dis.message);
    REQUIRE(dis.ok);

    std::array<uint8_t, 14> restored{};
    REQUIRE(proc->read_raw(hook_addr, restored.data(), restored.size()));
    CHECK(restored == orig_bytes);

    // Lua generateAOBScript integration
    std::ostringstream lua;
    lua << "local s = generateAOBScript(" << hook_addr << ", 'LUAHOOK', 5)\n"
        << "assert(s and s:find('%[ENABLE%]') and s:find('aobscanmodule%(LUAHOOK'))\n"
        << "print('LUA_AOB_SCRIPT_OK')\n";
    const auto lres = ses.run_lua(lua.str());
    INFO("Lua err: " << lres.error);
    CHECK(lres.success);
    CHECK(lres.output.find("LUA_AOB_SCRIPT_OK") != std::string::npos);
}

TEST_CASE("Phase 6 EngineInspector::find_unreal_globals: auto-discovers GWorld alongside GNames and GUObjectArray") {
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->attach(1);

    const uintptr_t gnames_va  = FakeProcess::kBase + 0x2000;
    const uintptr_t block0_va  = FakeProcess::kBase + 0x3000;
    const uintptr_t gobj_va    = FakeProcess::kBase + 0x4000;
    const uintptr_t chunks_va  = FakeProcess::kBase + 0x4200;
    const uintptr_t chunk0_va  = FakeProcess::kBase + 0x4400;
    const uintptr_t ucls_va    = FakeProcess::kBase + 0x5000;
    const uintptr_t actor_va   = FakeProcess::kBase + 0x6000;
    const uintptr_t world_va   = FakeProcess::kBase + 0x7000;
    const uintptr_t level_va   = FakeProcess::kBase + 0x7200;
    const uintptr_t act_arr    = FakeProcess::kBase + 0x7400;
    const uintptr_t root_va    = FakeProcess::kBase + 0x7600;
    const uintptr_t gworld_ptr = FakeProcess::kBase + 0x7800;

    std::vector<uint8_t> blk(0x200, 0);
    uint32_t cur = 0, i_none = 0, i_cls = 0, i_hero = 0;
    setup_fname_entry(blk, cur, "None", i_none);
    setup_fname_entry(blk, cur, "AMyHero", i_cls);
    setup_fname_entry(blk, cur, "HeroPawn_0", i_hero);
    proc->write_raw(block0_va, blk.data(), blk.size());

    proc->put<uint32_t>(0x2008, 0);
    proc->put<uint32_t>(0x200C, cur);
    proc->put_pointer(0x2010, block0_va);

    proc->put_pointer(0x4010, chunks_va);
    proc->put<uint32_t>(0x4024, 1);
    proc->put<uint32_t>(0x402C, 1);
    proc->put_pointer(0x4200, chunk0_va);
    proc->put_pointer(0x4400, actor_va);

    proc->put<uint32_t>(0x5018, i_cls);
    proc->put_pointer(0x6010, ucls_va);
    proc->put<uint32_t>(0x6018, i_hero);
    proc->put_pointer(0x6130, root_va);

    proc->put<float>(0x771C, 12.5f);
    proc->put<float>(0x7720, -3.0f);
    proc->put<float>(0x7724, 40.0f);

    proc->put_pointer(0x7030, level_va);
    proc->put_pointer(0x7298, act_arr);
    proc->put<int32_t>(0x72A0, 1);
    proc->put_pointer(0x7400, actor_va);
    proc->put_pointer(0x7800, world_va); // GWorld** global pointing to UWorld*

    // Inject 3 RIP-relative x64 references:
    // +0x00: 48 8D 05 disp32 (GNames)
    // +0x07: 48 8D 0D disp32 (GUObjectArray)
    // +0x0E: 48 8B 05 disp32 (GWorld**)
    const int32_t disp_gn = static_cast<int32_t>(static_cast<int64_t>(gnames_va)  - static_cast<int64_t>(FakeProcess::kBase + 7));
    const int32_t disp_go = static_cast<int32_t>(static_cast<int64_t>(gobj_va)    - static_cast<int64_t>(FakeProcess::kBase + 14));
    const int32_t disp_gw = static_cast<int32_t>(static_cast<int64_t>(gworld_ptr) - static_cast<int64_t>(FakeProcess::kBase + 21));
    uint8_t rip_code[21] = {
        0x48, 0x8D, 0x05, 0,0,0,0,
        0x48, 0x8D, 0x0D, 0,0,0,0,
        0x48, 0x8B, 0x05, 0,0,0,0
    };
    std::memcpy(rip_code + 3,  &disp_gn, 4);
    std::memcpy(rip_code + 10, &disp_go, 4);
    std::memcpy(rip_code + 17, &disp_gw, 4);
    proc->write_raw(FakeProcess::kBase, rip_code, sizeof(rip_code));

    session::Session ses(proc);
    REQUIRE(ses.attach(1).ok);

    auto globals = ses.find_unreal_globals();
    CHECK(globals.found_names);
    CHECK(globals.found_objects);
    CHECK(globals.found_world);
    CHECK(globals.fname_pool_va == gnames_va);
    CHECK(globals.guobject_array_va == gobj_va);
    CHECK(globals.gworld_va == world_va);

    auto actors = ses.dump_unreal_actors(globals.gworld_va, globals.fname_pool_va);
    REQUIRE(actors.size() == 1);
    CHECK(actors[0].name == "HeroPawn_0");
    CHECK(actors[0].has_location);
    CHECK(actors[0].x == doctest::Approx(12.5));
    CHECK(actors[0].y == doctest::Approx(-3.0));
    CHECK(actors[0].z == doctest::Approx(40.0));

    std::ostringstream script;
    script << "local g = findUnrealGlobals()\n"
           << "assert(g.found_world and g.gworld == " << world_va << ")\n"
           << "print('LUA_GWORLD_OK')\n";
    auto lres = ses.run_lua(script.str());
    INFO("Lua err: " << lres.error);
    CHECK(lres.success);
    CHECK(lres.output.find("LUA_GWORLD_OK") != std::string::npos);
}
