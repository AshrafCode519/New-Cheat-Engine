#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "debugger/disassembler.hpp"
#include "scanner/pointer_scanner.hpp"
#include "session/session.hpp"
#include "view/engine_inspector.hpp"

#include <array>
#include <cstring>
#include <filesystem>
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

void write_ffield(
    FakeProcess& proc, size_t off, uintptr_t next_ptr, uintptr_t fcls_ptr,
    uint32_t name_idx, int32_t elem_sz, int32_t prop_off)
{
    view::UnrealOffsets uo;
    proc.put_pointer(off + uo.ffield_class_offset, fcls_ptr);
    proc.put_pointer(off + uo.ffield_next_offset, next_ptr);
    proc.put<uint32_t>(off + uo.ffield_name_offset, name_idx);
    proc.put<int32_t>(off + uo.ffield_elem_size_offset, elem_sz);
    proc.put<int32_t>(off + uo.ffield_offset_internal, prop_off);
}

} // namespace

TEST_CASE("Phase 7 Disassembler: 32-bit mode, x87 FPU, VEX AVX, and X-Refs") {
    // 1. 32-bit x86 instructions (0x40..0x4F = inc/dec, 0x55 = push ebp, [disp32] abs memory)
    {
        const uint8_t x86_inc = 0x40; // inc eax in 32-bit mode (REX in 64-bit)
        auto d = debugger::Disassembler::decode(&x86_inc, 1, 0x00401000, false);
        CHECK(d.mnemonic == "inc");
        CHECK(d.operands == "eax");
        CHECK(d.length == 1);

        const uint8_t x86_dec = 0x49; // dec ecx
        auto d2 = debugger::Disassembler::decode(&x86_dec, 1, 0x00401001, false);
        CHECK(d2.mnemonic == "dec");
        CHECK(d2.operands == "ecx");

        const uint8_t x86_push = 0x55; // push ebp
        auto d3 = debugger::Disassembler::decode(&x86_push, 1, 0x00401002, false);
        CHECK(d3.mnemonic == "push");
        CHECK(d3.operands == "ebp");

        const uint8_t x86_mov_abs[6] = {0x8B, 0x05, 0x78, 0x56, 0x34, 0x00}; // mov eax, [0x00345678]
        auto d4 = debugger::Disassembler::decode(x86_mov_abs, sizeof(x86_mov_abs), 0x00401003, false);
        CHECK(d4.mnemonic == "mov");
        CHECK(d4.length == 6);
        CHECK(d4.branch_target == 0x00345678ULL);
    }

    // 2. x87 FPU instructions (fld dword ptr [rcx], fstp qword ptr [rcx], fnstsw ax)
    {
        const uint8_t fld_rcx[2] = {0xD9, 0x01};
        auto f1 = debugger::Disassembler::decode(fld_rcx, 2, 0x10000);
        CHECK(f1.mnemonic == "fld");
        CHECK(f1.length == 2);

        const uint8_t fstp_rcx[2] = {0xDD, 0x19};
        auto f2 = debugger::Disassembler::decode(fstp_rcx, 2, 0x10002);
        CHECK(f2.mnemonic == "fstp");
        CHECK(f2.length == 2);

        const uint8_t fnstsw[2] = {0xDF, 0xE0};
        auto f3 = debugger::Disassembler::decode(fnstsw, 2, 0x10004);
        CHECK(f3.mnemonic == "fnstsw");
        CHECK(f3.operands == "ax");
    }

    // 3. VEX / AVX instructions (vzeroupper, vaddps ymm0, ymm0, ymm1)
    {
        const uint8_t vzeroupper[3] = {0xC5, 0xF8, 0x77};
        auto v1 = debugger::Disassembler::decode(vzeroupper, 3, 0x20000);
        CHECK(v1.mnemonic == "vzeroupper");
        CHECK(v1.length == 3);

        const uint8_t vaddps_ymm[4] = {0xC5, 0xFC, 0x58, 0xC1};
        auto v2 = debugger::Disassembler::decode(vaddps_ymm, 4, 0x20003);
        CHECK(v2.mnemonic == "vaddps");
        CHECK(v2.operands == "ymm0, ymm0, ymm1");
        CHECK(v2.length == 4);
    }

    // 4. Cross-References (find_references) + Lua findXRefs
    auto proc = std::make_shared<FakeProcess>(0x4000);
    proc->attach(1);
    proc->add_module("app.exe", 0, 0x4000);

    const uintptr_t target_fn = FakeProcess::kBase + 0x1200;
    const uintptr_t c0 = FakeProcess::kBase + 0x100; // call target_fn (5B)
    const uintptr_t c1 = FakeProcess::kBase + 0x105; // lea rdx, [rip+disp32] -> target_fn (7B)
    const uintptr_t c2 = FakeProcess::kBase + 0x10C; // je target_fn (6B)

    const int32_t rel_call = static_cast<int32_t>(static_cast<int64_t>(target_fn) - static_cast<int64_t>(c0 + 5));
    const int32_t rel_lea  = static_cast<int32_t>(static_cast<int64_t>(target_fn) - static_cast<int64_t>(c1 + 7));
    const int32_t rel_je   = static_cast<int32_t>(static_cast<int64_t>(target_fn) - static_cast<int64_t>(c2 + 6));

    std::vector<uint8_t> code(18, 0x90);
    code[0] = 0xE8; std::memcpy(code.data() + 1, &rel_call, 4);
    code[5] = 0x48; code[6] = 0x8D; code[7] = 0x15; std::memcpy(code.data() + 8, &rel_lea, 4);
    code[12] = 0x0F; code[13] = 0x84; std::memcpy(code.data() + 14, &rel_je, 4);
    REQUIRE(proc->write_raw(c0, code.data(), code.size()));

    session::Session ses(proc);
    REQUIRE(ses.attach(1).ok);

    auto refs = ses.find_references(target_fn);
    REQUIRE(refs.size() == 3);
    CHECK(refs[0].from_address == c0);
    CHECK(refs[0].kind == "call");
    CHECK(refs[1].from_address == c1);
    CHECK(refs[1].kind == "rip-mem");
    CHECK(refs[2].from_address == c2);
    CHECK(refs[2].kind == "jcc");

    std::ostringstream lua;
    lua << "local x = findXRefs(" << target_fn << ")\n"
        << "assert(#x == 3 and x[1].kind == 'call' and x[2].kind == 'rip-mem')\n"
        << "print('LUA_XREF_OK')\n";
    auto lres = ses.run_lua(lua.str());
    INFO("Lua err: " << lres.error);
    CHECK(lres.success);
    CHECK(lres.output.find("LUA_XREF_OK") != std::string::npos);
}

TEST_CASE("Phase 7 PointerMap binary persistence, scan_with_map, and cross-run comparison") {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const std::string map1_path = (tmp_dir / "nce_test_run1.ncem").string();
    const std::string map2_path = (tmp_dir / "nce_test_run2.ncem").string();
    std::filesystem::remove(map1_path);
    std::filesystem::remove(map2_path);

    // Run 1: two static slots point near target1 (+0x18), one real and one decoy
    auto proc1 = std::make_shared<FakeProcess>(0x10000);
    proc1->attach(1);
    proc1->add_module("game.exe", 0, 0x1000);
    const uintptr_t t1 = FakeProcess::kBase + 0x2018;
    proc1->put_pointer(0x100, FakeProcess::kBase + 0x2000); // real chain: [game.exe+0x100] -> +0x18
    proc1->put_pointer(0x200, FakeProcess::kBase + 0x2000); // decoy chain: [game.exe+0x200] -> +0x18

    session::Session s1(proc1);
    REQUIRE(s1.attach(1).ok);
    REQUIRE(s1.build_and_save_pointer_map(map1_path));
    auto res1 = s1.scan_saved_pointer_map(map1_path, t1);
    CHECK(res1.paths.size() == 2);

    // Run 2: decoy now points elsewhere while [game.exe+0x100] points to relocated heap object +0x18
    auto proc2 = std::make_shared<FakeProcess>(0x10000);
    proc2->attach(1);
    proc2->add_module("game.exe", 0, 0x1000);
    const uintptr_t t2 = FakeProcess::kBase + 0x6018;
    proc2->put_pointer(0x100, FakeProcess::kBase + 0x6000); // valid across restart!
    proc2->put_pointer(0x200, FakeProcess::kBase + 0x8000); // moved elsewhere

    session::Session s2(proc2);
    REQUIRE(s2.attach(1).ok);
    REQUIRE(s2.build_and_save_pointer_map(map2_path));
    auto res2 = s2.scan_saved_pointer_map(map2_path, t2);
    REQUIRE(res2.paths.size() == 1);

    auto common = scanner::PointerScanner::intersect_paths(res1.paths, res2.paths);
    REQUIRE(common.size() == 1);
    CHECK(common[0].module_name == "game.exe");
    CHECK(common[0].base_offset == 0x100);
    REQUIRE(common[0].offsets.size() == 1);
    CHECK(common[0].offsets[0] == 0x18);

    std::filesystem::remove(map1_path);
    std::filesystem::remove(map2_path);
}

TEST_CASE("Phase 7 EngineInspector::calibrate_unreal_offsets: auto-detects shifted UE5 LWC offsets") {
    auto proc = std::make_shared<FakeProcess>(0x12000);
    proc->attach(1);

    const uintptr_t gnames_va  = FakeProcess::kBase + 0x1000;
    const uintptr_t block0_va  = FakeProcess::kBase + 0x1800;
    const uintptr_t world_va   = FakeProcess::kBase + 0x2000;
    const uintptr_t level_va   = FakeProcess::kBase + 0x2800;
    const uintptr_t act_arr_va = FakeProcess::kBase + 0x3000;
    const uintptr_t actor_va   = FakeProcess::kBase + 0x4000;
    const uintptr_t root_va    = FakeProcess::kBase + 0x5000;

    // Classes & FField metadata blocks
    const uintptr_t cls_world  = FakeProcess::kBase + 0x6000;
    const uintptr_t cls_actor  = FakeProcess::kBase + 0x6400;
    const uintptr_t cls_scene  = FakeProcess::kBase + 0x6800;
    const uintptr_t fcls_obj   = FakeProcess::kBase + 0x7000;
    const uintptr_t fcls_dbl   = FakeProcess::kBase + 0x7100;
    const uintptr_t ff_world   = FakeProcess::kBase + 0x7400;
    const uintptr_t ff_actor   = FakeProcess::kBase + 0x7500;
    const uintptr_t ff_scene   = FakeProcess::kBase + 0x7600;

    std::vector<uint8_t> blk(0x300, 0);
    uint32_t cur = 0;
    uint32_t i_none=0, i_uw=0, i_pl=0, i_act_cls=0, i_scn_cls=0, i_rc=0, i_rl=0, i_fobj=0, i_fdbl=0, i_hero=0;
    setup_fname_entry(blk, cur, "None", i_none);
    setup_fname_entry(blk, cur, "UWorld", i_uw);
    setup_fname_entry(blk, cur, "PersistentLevel", i_pl);
    setup_fname_entry(blk, cur, "AActor", i_act_cls);
    setup_fname_entry(blk, cur, "USceneComponent", i_scn_cls);
    setup_fname_entry(blk, cur, "RootComponent", i_rc);
    setup_fname_entry(blk, cur, "RelativeLocation", i_rl);
    setup_fname_entry(blk, cur, "ObjectProperty", i_fobj);
    setup_fname_entry(blk, cur, "DoubleProperty", i_fdbl);
    setup_fname_entry(blk, cur, "HeroPawn_LWC", i_hero);
    proc->write_raw(block0_va, blk.data(), blk.size());

    proc->put<uint32_t>(0x1008, 0);
    proc->put<uint32_t>(0x100C, cur);
    proc->put_pointer(0x1010, block0_va);

    proc->put<uint32_t>(0x7000, i_fobj);
    proc->put<uint32_t>(0x7100, i_fdbl);

    // Non-default offsets:
    // UWorld::PersistentLevel @ +0x48 (default 0x30)
    // ULevel::Actors @ +0xA0 (default 0x98)
    // AActor::RootComponent @ +0x198 (default 0x130)
    // USceneComponent::RelativeLocation @ +0x140 as UE5 Double3 (default 0x11C Float3)
    proc->put<uint32_t>(0x6018, i_uw);
    proc->put_pointer(0x6050, ff_world);
    write_ffield(*proc, 0x7400, 0, fcls_obj, i_pl, 8, 0x48);

    proc->put<uint32_t>(0x6418, i_act_cls);
    proc->put_pointer(0x6450, ff_actor);
    write_ffield(*proc, 0x7500, 0, fcls_obj, i_rc, 8, 0x198);

    proc->put<uint32_t>(0x6818, i_scn_cls);
    proc->put_pointer(0x6850, ff_scene);
    write_ffield(*proc, 0x7600, 0, fcls_dbl, i_rl, 24, 0x140);

    proc->put_pointer(0x2010, cls_world);
    proc->put_pointer(0x2048, level_va);
    proc->put_pointer(0x28A0, act_arr_va);
    proc->put<int32_t>(0x28A8, 1);
    proc->put_pointer(0x3000, actor_va);

    proc->put_pointer(0x4010, cls_actor);
    proc->put<uint32_t>(0x4018, i_hero);
    proc->put_pointer(0x4198, root_va);

    proc->put_pointer(0x5010, cls_scene);
    proc->put<double>(0x5140, 101.5);
    proc->put<double>(0x5148, -22.25);
    proc->put<double>(0x5150, 88.0);

    session::Session ses(proc);
    REQUIRE(ses.attach(1).ok);

    auto cal = ses.calibrate_unreal_offsets(world_va, gnames_va);
    REQUIRE(cal.ok);
    CHECK(cal.offsets.uworld_level_offset == 0x48);
    CHECK(cal.offsets.ulevel_actors_offset == 0xA0);
    CHECK(cal.offsets.actor_root_comp_offset == 0x198);
    CHECK(cal.offsets.scene_comp_location_offset == 0x140);
    CHECK(cal.offsets.lwc_double_coords == true);

    auto actors = ses.dump_unreal_actors(world_va, gnames_va, cal.offsets);
    REQUIRE(actors.size() == 1);
    CHECK(actors[0].name == "HeroPawn_LWC");
    CHECK(actors[0].has_location);
    CHECK(actors[0].x == doctest::Approx(101.5));
    CHECK(actors[0].y == doctest::Approx(-22.25));
    CHECK(actors[0].z == doctest::Approx(88.0));

    std::ostringstream lua;
    lua << "local c = calibrateUnrealOffsets(" << world_va << ", " << gnames_va << ")\n"
        << "assert(c.ok and c.uworld_level == 0x48 and c.ulevel_actors == 0xA0 and c.root_comp == 0x198 and c.rel_location == 0x140 and c.lwc_double)\n"
        << "print('LUA_UE_CAL_OK')\n";
    auto lres = ses.run_lua(lua.str());
    INFO("Lua err: " << lres.error);
    CHECK(lres.success);
    CHECK(lres.output.find("LUA_UE_CAL_OK") != std::string::npos);
}
