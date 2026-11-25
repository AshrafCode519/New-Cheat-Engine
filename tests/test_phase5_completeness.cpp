#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "assembler/x86_assembler.hpp"
#include "debugger/disassembler.hpp"
#include "debugger/hook_engine.hpp"
#include "debugger/pe_analyzer.hpp"
#include "debugger/ultimap.hpp"
#include "session/session.hpp"
#include "table/standalone_generator.hpp"
#include "view/engine_inspector.hpp"

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

void wr_s(std::vector<uint8_t>& buf, size_t off, const std::string& s) {
    if (off + s.size() + 1 > buf.size()) buf.resize(off + s.size() + 1, 0);
    std::memcpy(buf.data() + off, s.data(), s.size());
    buf[off + s.size()] = 0;
}

void setup_fname_entry(std::vector<uint8_t>& blk, uint32_t& cur, const std::string& text, uint32_t& out_idx) {
    out_idx = cur / 2;
    const uint16_t hdr = static_cast<uint16_t>((text.size() << 6));
    wr_v<uint16_t>(blk, cur, hdr);
    std::memcpy(blk.data() + cur + 2, text.data(), text.size());
    cur += static_cast<uint32_t>(((2 + text.size() + 1) / 2) * 2);
}

} // namespace

TEST_CASE("Phase 5 X86Assembler: SSE2 packed ops, conversions, bit tests, and bswap") {
    assembler::X86Assembler enc(true);
    std::string err;

    struct Case { const char* line; const char* mnem; };
    const Case cases[] = {
        {"movups xmm0, xmm1", "movups"},
        {"movaps xmm2, xmm3", "movaps"},
        {"movdqu xmm0, xmmword ptr [rcx]", "movdqu"},
        {"addps xmm0, xmm1", "addps"},
        {"subpd xmm2, xmm3", "subpd"},
        {"comiss xmm0, xmm1", "comiss"},
        {"sqrtss xmm0, xmm1", "sqrtss"},
        {"cvtsi2ss xmm0, eax", "cvtsi2ss"},
        {"cvtsi2sd xmm1, rcx", "cvtsi2sd"},
        {"cvttss2si eax, xmm0", "cvttss2si"},
        {"cvttsd2si rax, xmm1", "cvttsd2si"},
        {"bt rax, 3", "bt"},
        {"bts qword ptr [rcx], 5", "bts"},
        {"bsf eax, ecx", "bsf"},
        {"bsr r8, r9", "bsr"},
        {"bswap eax", "bswap"},
        {"bswap r12", "bswap"},
    };

    for (const auto& c : cases) {
        auto out = enc.encode(c.line, 0x140001000ULL, err);
        INFO("Instruction: " << std::string(c.line) << " err=" << err);
        REQUIRE(out.has_value());
        REQUIRE(!out->bytes.empty());

        auto dec = debugger::Disassembler::decode(out->bytes.data(), out->bytes.size(), 0x140001000ULL);
        CHECK(dec.mnemonic == c.mnem);
        CHECK(dec.length == out->bytes.size());
    }
}

TEST_CASE("Phase 5 Disassembler CFG: splits basic blocks and classifies branch edges") {
    // Function layout at 0x10000:
    // +0x00: 85 C0       test eax, eax
    // +0x02: 74 08       jz +8 (target = +0x0C)
    // +0x04: B8 01000000 mov eax, 1
    // +0x09: EB 05       jmp +5 (target = +0x10)
    // +0x0B: 90          nop (padding)
    // +0x0C: 31 C0       xor eax, eax
    // +0x0E: EB 00       jmp +0 (+0x10)
    // +0x10: C3          ret
    const uint8_t code[] = {
        0x85, 0xC0,
        0x74, 0x08,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xEB, 0x05,
        0x90,
        0x31, 0xC0,
        0xEB, 0x00,
        0xC3
    };

    auto proc = std::make_shared<FakeProcess>(0x4000);
    proc->write_raw(FakeProcess::kBase, code, sizeof(code));
    proc->attach(1);

    session::Session ses(proc);
    CHECK(ses.attach(1).ok);

    auto cfg = ses.build_cfg(FakeProcess::kBase, 64, 16);
    CHECK(cfg.entry_address == FakeProcess::kBase);
    REQUIRE(cfg.blocks.size() == 4);
    CHECK(cfg.blocks[0].level == 0);
    CHECK(cfg.blocks[1].start_address == FakeProcess::kBase + 0x04);
    CHECK(cfg.blocks[2].start_address == FakeProcess::kBase + 0x0C);
    CHECK(cfg.blocks[3].start_address == FakeProcess::kBase + 0x10);

    bool has_true = false, has_false = false, has_uncond = false;
    for (const auto& e : cfg.edges) {
        if (e.kind == debugger::CFGEdge::Kind::TrueBranch) has_true = true;
        if (e.kind == debugger::CFGEdge::Kind::FalseBranch) has_false = true;
        if (e.kind == debugger::CFGEdge::Kind::Unconditional) has_uncond = true;
    }
    CHECK(has_true);
    CHECK(has_false);
    CHECK(has_uncond);
}

TEST_CASE("Phase 5 UltimapProfiler: eliminates idle noise and isolates action-triggered functions") {
    debugger::UltimapProfiler um;
    um.add_function(0x140001000, "IdleRenderTick", "game.exe");
    um.add_function(0x140002000, "AudioMixerPump", "game.exe");
    um.add_function(0x140003000, "PlayerJump", "game.exe");
    um.add_function(0x140004000, "UnusedMenu", "game.exe");

    CHECK(um.active_count() == 4);

    // 1. Idle window: render & audio run continuously
    um.begin_action_window();
    um.record_hit(0x140001000, 120);
    um.record_hit(0x140002000, 30);
    CHECK(um.mark_idle_noisy() == 2);
    CHECK(um.active_count() == 2);

    // 2. Action window: player presses Jump
    um.begin_action_window();
    um.record_hit(0x140003000, 2);
    CHECK(um.keep_only_executed() == 1);

    auto ranked = um.ranked_candidates();
    REQUIRE(ranked.size() == 1);
    CHECK(ranked[0].name == "PlayerJump");
    CHECK(ranked[0].window_hits == 2);
}

TEST_CASE("Phase 5 Unity Inspector: RAM global-metadata scan + live Il2CppClass object reflection") {
    auto proc = std::make_shared<FakeProcess>(0x10000);

    // 1. Place IL2CPP global-metadata header & string/field/type tables in process RAM at +0x5000
    std::vector<uint8_t> meta(0x500, 0);
    constexpr uint32_t kStrOff = 0x120, kFldOff = 0x200, kTypOff = 0x260;
    wr_s(meta, kStrOff + 1, "HeroNS");
    wr_s(meta, kStrOff + 10, "PlayerStats");
    wr_s(meta, kStrOff + 25, "hp");
    wr_v<uint32_t>(meta, kFldOff + 0, 25);
    wr_v<uint32_t>(meta, kTypOff + 0x00, 10); // name
    wr_v<uint32_t>(meta, kTypOff + 0x04, 1);  // ns
    wr_v<int32_t>(meta,  kTypOff + 0x24, 0);  // fieldStart
    wr_v<uint16_t>(meta, kTypOff + 0x44, 1);  // field_count
    wr_v<uint32_t>(meta, 0x00, 0xFAB11BAF);
    wr_v<int32_t>(meta,  0x04, 29);
    wr_v<uint32_t>(meta, 0x18, kStrOff);
    wr_v<uint32_t>(meta, 0x1C, 64);
    wr_v<uint32_t>(meta, 0x60, kFldOff);
    wr_v<uint32_t>(meta, 0x64, 12);
    wr_v<uint32_t>(meta, 0xA0, kTypOff);
    wr_v<uint32_t>(meta, 0xA4, 88);
    proc->write_raw(FakeProcess::kBase + 0x5000, meta.data(), meta.size());

    // 2. Construct live Il2CppObject -> Il2CppClass -> FieldInfo[2] in RAM
    const uintptr_t obj_va     = FakeProcess::kBase + 0x7000;
    const uintptr_t klass_va   = FakeProcess::kBase + 0x7200;
    const uintptr_t fields_va  = FakeProcess::kBase + 0x7500;
    const uintptr_t cname_va   = FakeProcess::kBase + 0x7700;
    const uintptr_t cns_va     = FakeProcess::kBase + 0x7720;
    const uintptr_t fname0_va  = FakeProcess::kBase + 0x7740;
    const uintptr_t fname1_va  = FakeProcess::kBase + 0x7760;

    proc->write_raw(cname_va, "PlayerController", 17);
    proc->write_raw(cns_va, "Game", 5);
    proc->write_raw(fname0_va, "health", 7);
    proc->write_raw(fname1_va, "moveSpeed", 10);

    // Object: +0x00 klass*, +0x24 health(100), +0x28 moveSpeed(5.5f)
    proc->put_pointer(0x7000, klass_va);
    proc->put<int32_t>(0x7024, 100);
    proc->put<float>(0x7028, 5.5f);

    // Il2CppClass defaults: name @ +0x10, ns @ +0x18, fields @ +0x80, field_count @ +0x114
    proc->put_pointer(0x7210, cname_va);
    proc->put_pointer(0x7218, cns_va);
    proc->put_pointer(0x7280, fields_va);
    proc->put<uint16_t>(0x7314, 2);

    // FieldInfo[0] & FieldInfo[1] (stride 32: name_ptr @ +0, offset @ +0x18, token @ +0x1C)
    proc->put_pointer(0x7500 + 0x00, fname0_va);
    proc->put<int32_t>(0x7500 + 0x18, 0x24);
    proc->put<uint32_t>(0x7500 + 0x1C, 0x04000001);
    proc->put_pointer(0x7520 + 0x00, fname1_va);
    proc->put<int32_t>(0x7520 + 0x18, 0x28);
    proc->put<uint32_t>(0x7520 + 0x1C, 0x04000002);

    proc->attach(1);
    session::Session ses(proc);
    CHECK(ses.attach(1).ok);

    // Auto-scan RAM without giving address!
    auto mem_rep = ses.inspect_unity_metadata_memory(0, "PlayerStats");
    REQUIRE(mem_rep.valid);
    REQUIRE(mem_rep.types.size() == 1);
    CHECK(mem_rep.types[0].namespaze == "HeroNS");

    auto obj_layout = ses.dissect_unity_object(obj_va);
    CHECK(obj_layout.class_name == "Game.PlayerController");
    REQUIRE(obj_layout.fields.size() == 2);
    CHECK(obj_layout.fields[0].name == "health");
    CHECK(obj_layout.fields[0].offset == 0x24);
    CHECK(obj_layout.fields[1].name == "moveSpeed");
    CHECK(obj_layout.fields[1].offset == 0x28);
}

TEST_CASE("Phase 5 Unreal Inspector: Auto-Finder, FField class dissection, and GWorld Actors") {
    class ExecFakeProcess final : public FakeProcess {
    public:
        using FakeProcess::FakeProcess;
        [[nodiscard]] std::vector<hal::MemoryRegion> query_regions(
            uint32_t filter_flags = hal::FilterFlags::DefaultScanFilter) const override
        {
            auto regs = FakeProcess::query_regions(hal::FilterFlags::DefaultScanFilter);
            for (auto& r : regs) r.is_executable = true;
            if (filter_flags & hal::FilterFlags::ExecutableOnly) return regs;
            return FakeProcess::query_regions(filter_flags);
        }
    };

    auto proc = std::make_shared<ExecFakeProcess>(0x10000);

    // Build FNamePool @ +0x2000, Block0 @ +0x3000
    const uintptr_t gnames_va = FakeProcess::kBase + 0x2000;
    const uintptr_t block0_va = FakeProcess::kBase + 0x3000;
    const uintptr_t gobj_va   = FakeProcess::kBase + 0x4000;
    const uintptr_t chunks_va = FakeProcess::kBase + 0x4200;
    const uintptr_t chunk0_va = FakeProcess::kBase + 0x4400;
    const uintptr_t ucls_va   = FakeProcess::kBase + 0x5000;
    const uintptr_t ffield_va = FakeProcess::kBase + 0x5200;
    const uintptr_t fcls_va   = FakeProcess::kBase + 0x5300;
    const uintptr_t actor_va  = FakeProcess::kBase + 0x6000;
    const uintptr_t world_va  = FakeProcess::kBase + 0x7000;
    const uintptr_t level_va  = FakeProcess::kBase + 0x7200;
    const uintptr_t act_arr   = FakeProcess::kBase + 0x7400;
    const uintptr_t root_va   = FakeProcess::kBase + 0x7600;

    std::vector<uint8_t> blk(0x200, 0);
    uint32_t cur = 0, i_none = 0, i_cls = 0, i_hero = 0, i_hp = 0, i_flt = 0;
    setup_fname_entry(blk, cur, "None", i_none);
    setup_fname_entry(blk, cur, "AMyHero", i_cls);
    setup_fname_entry(blk, cur, "HeroPawn_0", i_hero);
    setup_fname_entry(blk, cur, "Health", i_hp);
    setup_fname_entry(blk, cur, "FloatProperty", i_flt);
    proc->write_raw(block0_va, blk.data(), blk.size());

    proc->put<uint32_t>(0x2008, 0);
    proc->put<uint32_t>(0x200C, cur);
    proc->put_pointer(0x2010, block0_va);

    // FUObjectArray pointing to HeroPawn_0
    proc->put_pointer(0x4010, chunks_va);
    proc->put<uint32_t>(0x4024, 1);
    proc->put<uint32_t>(0x402C, 1);
    proc->put_pointer(0x4200, chunk0_va);
    proc->put_pointer(0x4400, actor_va);

    // UStruct (ucls_va) + FField (ffield_va -> FloatProperty "Health" @ +0x40)
    proc->put<uint32_t>(0x5018, i_cls);
    proc->put_pointer(0x5050, ffield_va); // ChildProperties
    proc->put_pointer(0x5208, fcls_va);   // FField::ClassPrivate
    proc->put<uint32_t>(0x5228, i_hp);    // FField::NamePrivate
    proc->put<int32_t>(0x523C, 4);        // FProperty::ElementSize
    proc->put<int32_t>(0x5244, 0x40);     // FProperty::Offset_Internal
    proc->put<uint32_t>(0x5300, i_flt);   // FFieldClass::Name

    // Actor instance: Class=ucls_va, Name="HeroPawn_0", Health(+0x40)=95.5f, RootComponent @ +0x130
    proc->put_pointer(0x6010, ucls_va);
    proc->put<uint32_t>(0x6018, i_hero);
    proc->put<float>(0x6040, 95.5f);
    proc->put_pointer(0x6130, root_va);

    // RootComponent location (x=12.5, y=-3.0, z=40.0) at +0x11C
    proc->put<float>(0x771C, 12.5f);
    proc->put<float>(0x7720, -3.0f);
    proc->put<float>(0x7724, 40.0f);

    // UWorld -> PersistentLevel (+0x30) -> Actors TArray (+0x98, count @ +0xA0)
    proc->put_pointer(0x7030, level_va);
    proc->put_pointer(0x7298, act_arr);
    proc->put<int32_t>(0x72A0, 1);
    proc->put_pointer(0x7400, actor_va);

    // Inject two x64 RIP-relative instructions at offset 0x00 (`48 8D 05 disp32` -> gnames_va, `48 8D 0D disp32` -> gobj_va)
    const int32_t disp_gn = static_cast<int32_t>(static_cast<int64_t>(gnames_va) - static_cast<int64_t>(FakeProcess::kBase + 7));
    const int32_t disp_go = static_cast<int32_t>(static_cast<int64_t>(gobj_va) - static_cast<int64_t>(FakeProcess::kBase + 14));
    uint8_t rip_code[14] = {0x48, 0x8D, 0x05, 0,0,0,0, 0x48, 0x8D, 0x0D, 0,0,0,0};
    std::memcpy(rip_code + 3, &disp_gn, 4);
    std::memcpy(rip_code + 10, &disp_go, 4);
    proc->write_raw(FakeProcess::kBase, rip_code, sizeof(rip_code));

    session::Session ses(proc);
    CHECK(ses.attach(1).ok);

    // 1. Auto-Finder discovers GNames & GUObjectArray from RIP-relative instructions
    auto globals = ses.find_unreal_globals();
    CHECK(globals.found_names);
    CHECK(globals.found_objects);
    CHECK(globals.fname_pool_va == gnames_va);
    CHECK(globals.guobject_array_va == gobj_va);

    // 2. FField reflection dissects Actor health property
    auto dis = ses.dissect_unreal_object(actor_va, gnames_va);
    CHECK(dis.class_name == "AMyHero");
    REQUIRE(dis.fields.size() == 1);
    CHECK(dis.fields[0].name == "Health");
    CHECK(dis.fields[0].type == "float");
    CHECK(dis.fields[0].offset == 0x40);
    CHECK(std::stof(dis.fields[0].value) == doctest::Approx(95.5f));

    // 3. UWorld Actors dump recovers 3D position
    auto actors = ses.dump_unreal_actors(world_va, gnames_va);
    REQUIRE(actors.size() == 1);
    CHECK(actors[0].name == "HeroPawn_0");
    CHECK(actors[0].class_name == "AMyHero");
    CHECK(actors[0].has_location);
    CHECK(actors[0].x == doctest::Approx(12.5));
    CHECK(actors[0].y == doctest::Approx(-3.0));
    CHECK(actors[0].z == doctest::Approx(40.0));

    // 4. Lua Phase 4/5 integration check
    std::ostringstream script;
    script << "local g = findUnrealGlobals()\n"
           << "assert(g.found_names and g.gnames == " << gnames_va << ")\n"
           << "local n = readUnrealName(" << gnames_va << ", " << i_hero << ")\n"
           << "assert(n == 'HeroPawn_0')\n"
           << "local act = dumpUnrealActors(" << world_va << ", " << gnames_va << ")\n"
           << "assert(#act == 1 and act[1].has_location and act[1].x > 12.0)\n"
           << "print('LUA_UE_OK')\n";
    auto lres = ses.run_lua(script.str());
    INFO("Lua err: " << lres.error);
    CHECK(lres.success);
    CHECK(lres.output.find("LUA_UE_OK") != std::string::npos);

    // 5. Linux standalone trainer source generation
    table::CheatTable tbl;
    tbl.process_name = "spacegame";
    table::TableEntry entry;
    entry.description = "Health";
    entry.type = scanner::DataType::Int32;
    entry.frozen_value = "999";
    tbl.entries.push_back(entry);
    std::string linux_cpp = table::generate_standalone_trainer_cpp(tbl, "spacegame", table::TrainerKind::LinuxConsole);
    CHECK(linux_cpp.find("process_vm_writev") != std::string::npos);
    CHECK(linux_cpp.find("GetLinuxModuleBase") != std::string::npos);
    CHECK(linux_cpp.find("Health") != std::string::npos);
}

TEST_CASE("Phase 5 Bugfix Regressions: HookEngine RIP relocation and PEAnalyzer ASLR base") {
    // 1. HookEngine relocates stolen RIP-relative load + E9 jmp when detouring into cave/trampoline
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->attach(1);

    const uintptr_t fn_addr      = FakeProcess::kBase + 0x1000;
    const uintptr_t data_target  = FakeProcess::kBase + 0x2000;
    const uintptr_t jmp_target   = FakeProcess::kBase + 0x1500;
    // Target bytes:
    // +0x00: 48 8B 05 <disp32>  (mov rax, [rip + disp32] -> data_target)  [7 bytes]
    // +0x07: E9 <rel32>         (jmp jmp_target)                            [5 bytes]
    // +0x0C: 90 90 90           (nop; nop; nop -> >= 14 bytes total stolen)
    std::vector<uint8_t> code(15, 0x90);
    code[0] = 0x48; code[1] = 0x8B; code[2] = 0x05;
    const int32_t d_rip = static_cast<int32_t>(static_cast<int64_t>(data_target) - static_cast<int64_t>(fn_addr + 7));
    std::memcpy(&code[3], &d_rip, 4);
    code[7] = 0xE9;
    const int32_t d_jmp = static_cast<int32_t>(static_cast<int64_t>(jmp_target) - static_cast<int64_t>(fn_addr + 12));
    std::memcpy(&code[8], &d_jmp, 4);
    proc->write_raw(fn_addr, code.data(), code.size());

    debugger::HookEngine hooks(proc);
    uintptr_t tramp_addr = 0;
    REQUIRE(hooks.install_detour(fn_addr, FakeProcess::kBase + 0x3000, &tramp_addr));
    REQUIRE(tramp_addr != 0);

    uint8_t tramp_buf[16]{};
    REQUIRE(proc->read_raw(tramp_addr, tramp_buf, sizeof(tramp_buf)));
    auto reloc_mov = debugger::Disassembler::decode(tramp_buf, sizeof(tramp_buf), tramp_addr);
    CHECK(reloc_mov.length == 7);
    CHECK(reloc_mov.branch_target == data_target);
    CHECK(hooks.remove_hook(fn_addr));

    // Also test install_payload_hook relocating both MOV [rip+disp] and JMP rel32 inside cave
    const std::vector<uint8_t> payload = {0x90, 0x90};
    auto hinfo = hooks.install_payload_hook(fn_addr, payload);
    REQUIRE(hinfo.has_value());
    const uintptr_t cave_stolen_addr = hinfo->cave_address + payload.size();
    uint8_t cave_buf[32]{};
    REQUIRE(proc->read_raw(cave_stolen_addr, cave_buf, sizeof(cave_buf)));
    auto c_mov = debugger::Disassembler::decode(cave_buf, sizeof(cave_buf), cave_stolen_addr);
    CHECK(c_mov.length == 7);
    CHECK(c_mov.branch_target == data_target);
    auto c_jmp = debugger::Disassembler::decode(cave_buf + 7, sizeof(cave_buf) - 7, cave_stolen_addr + 7);
    CHECK(c_jmp.mnemonic == "jmp");
    CHECK(c_jmp.branch_target == jmp_target);

    // 2. PEAnalyzer uses live relocated module_base (ASLR) instead of stale OptionalHeader.ImageBase
    std::vector<uint8_t> pe_buf(0x2000, 0);
    wr_v<uint16_t>(pe_buf, 0x00, 0x5A4D);
    wr_v<uint32_t>(pe_buf, 0x3C, 0x80);
    wr_v<uint32_t>(pe_buf, 0x80, 0x00004550);
    wr_v<uint16_t>(pe_buf, 0x84, 0x8664);
    wr_v<uint16_t>(pe_buf, 0x86, 1);
    wr_v<uint16_t>(pe_buf, 0x94, 0xF0);
    wr_v<uint16_t>(pe_buf, 0x98, 0x020B);
    wr_v<uint64_t>(pe_buf, 0xB0, 0x140000000ULL); // Stale un-relocated header ImageBase!
    wr_v<uint32_t>(pe_buf, 0xC8, 0x2000);
    wr_s(pe_buf, 0x188, ".text");
    wr_v<uint32_t>(pe_buf, 0x190, 0x1000);
    wr_v<uint32_t>(pe_buf, 0x194, 0x1000);
    wr_v<uint32_t>(pe_buf, 0x198, 0x1000);
    wr_v<uint32_t>(pe_buf, 0x19C, 0x1000);
    wr_v<uint32_t>(pe_buf, 0x1AC, 0x60000020);

    const uintptr_t aslr_base = FakeProcess::kBase + 0x4000;
    proc->write_raw(aslr_base, pe_buf.data(), pe_buf.size());
    auto pe = debugger::PEAnalyzer::analyze(*proc, aslr_base);
    REQUIRE(pe.has_value());
    CHECK(pe->image_base == aslr_base);
    const auto* sec = debugger::PEAnalyzer::find_section(*pe, aslr_base + 0x1050);
    REQUIRE(sec != nullptr);
    CHECK(sec->name == ".text");
}
