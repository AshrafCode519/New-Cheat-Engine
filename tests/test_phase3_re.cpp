#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "assembler/x86_assembler.hpp"
#include "debugger/disassembler.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "session/session.hpp"
#include "table/ce_table_format.hpp"
#include "table/cheat_table.hpp"
#include "view/structure_dissector.hpp"

#include <cstring>
#include <filesystem>
#include <memory>
#include <vector>

using namespace nce;
using test::FakeProcess;

TEST_CASE("Phase 3 Disassembler & X86Assembler: round-trip extended x86-64/SSE instructions") {
    assembler::X86Assembler enc;
    std::string err;

    struct Case { const char* asm_line; const char* expected_mnem; };
    const Case cases[] = {
        {"movzx eax, byte ptr [rcx]", "movzx"},
        {"movzx r8d, word ptr [rbx+4]", "movzx"},
        {"movsx rax, byte ptr [rdx]", "movsx"},
        {"movsxd rax, ecx", "movsxd"},
        {"imul eax, ecx", "imul"},
        {"imul rax, rdx, 12", "imul"},
        {"shl rax, 3", "shl"},
        {"shr ecx, cl", "shr"},
        {"sar edx, 1", "sar"},
        {"xchg rax, rcx", "xchg"},
        {"cmovne rax, rbx", "cmovne"},
        {"sete al", "sete"},
        {"movss xmm0, dword ptr [rax]", "movss"},
        {"addss xmm1, xmm2", "addss"},
        {"mulsd xmm3, xmm4", "mulsd"},
        {"leave", "leave"},
        {"cqo", "cqo"},
        {"ret 8", "ret"},
    };

    for (const auto& c : cases) {
        auto encoded = enc.encode(c.asm_line, 0x140001000ULL, err);
        INFO(c.asm_line << " -> " << err);
        REQUIRE(encoded.has_value());
        auto dec = debugger::Disassembler::decode(encoded->bytes.data(), encoded->bytes.size(), 0x140001000ULL);
        CHECK(dec.length == encoded->bytes.size());
        CHECK(dec.mnemonic == c.expected_mnem);
    }

    SUBCASE("Near conditional jump 0F 84 resolves branch_target") {
        // je +0x100 from 0x1000 (len=6 -> target=0x1106)
        const uint8_t jcc[] = {0x0F, 0x84, 0x00, 0x01, 0x00, 0x00};
        auto dec = debugger::Disassembler::decode(jcc, sizeof(jcc), 0x1000);
        CHECK(dec.length == 6);
        CHECK(dec.mnemonic == "je");
        CHECK(dec.branch_target == 0x1106);
    }
}

TEST_CASE("Phase 3 Session: PE Export symbol resolution and annotate_disassembly") {
    auto proc = std::make_shared<FakeProcess>(0x10000);
    const uintptr_t mod_base = FakeProcess::kBase + 0x2000;
    proc->add_module("mock.dll", 0x2000, 0x4000);

    // Construct minimal valid PE32+ headers + 1 export entry inside mock.dll
    // e_lfanew = 0x80
    proc->put<uint16_t>(0x2000 + 0x00, 0x5A4D); // MZ
    proc->put<int32_t>(0x2000 + 0x3C, 0x80);
    proc->put<uint32_t>(0x2000 + 0x80, 0x00004550); // PE\0\0
    proc->put<uint16_t>(0x2000 + 0x84 + 2, 0);      // NumberOfSections = 0
    proc->put<uint16_t>(0x2000 + 0x84 + 16, 240);   // SizeOfOptionalHeader
    const size_t opt = 0x2000 + 0x84 + 20;
    proc->put<uint16_t>(opt + 0, 0x020B);           // PE32+ magic
    proc->put<uint32_t>(opt + 56, 0x4000);          // SizeOfImage
    // DataDirectory[0] Export at opt + 112: RVA=0x1000, Size=0x100
    proc->put<uint32_t>(opt + 112, 0x1000);
    proc->put<uint32_t>(opt + 116, 0x100);

    // IMAGE_EXPORT_DIRECTORY at mod_base + 0x1000
    const size_t exp_off = 0x2000 + 0x1000;
    proc->put<uint32_t>(exp_off + 16, 1);           // Base = 1
    proc->put<uint32_t>(exp_off + 20, 1);           // NumberOfFunctions
    proc->put<uint32_t>(exp_off + 24, 1);           // NumberOfNames
    proc->put<uint32_t>(exp_off + 28, 0x1040);      // AddressOfFunctions RVA
    proc->put<uint32_t>(exp_off + 32, 0x1048);      // AddressOfNames RVA
    proc->put<uint32_t>(exp_off + 36, 0x1050);      // AddressOfNameOrdinals RVA

    proc->put<uint32_t>(0x2000 + 0x1040, 0x2200);   // Export func RVA = 0x2200 -> VA = mod_base + 0x2200
    proc->put<uint32_t>(0x2000 + 0x1048, 0x1060);   // Export name RVA = 0x1060
    proc->put<uint16_t>(0x2000 + 0x1050, 0);        // Ordinal index 0
    const char exp_name[] = "TestExportFunc";
    proc->write_raw(mod_base + 0x1060, exp_name, sizeof(exp_name));

    // Write `call (mod_base + 0x2200)` at mod_base + 0x500
    assembler::X86Assembler enc;
    std::string err;
    auto call_enc = enc.encode("call " + std::to_string(mod_base + 0x2200), mod_base + 0x500, err);
    REQUIRE(call_enc.has_value());
    proc->write_raw(mod_base + 0x500, call_enc->bytes.data(), call_enc->bytes.size());

    session::Session session(proc);
    REQUIRE(session.attach(1).ok);

    CHECK(session.resolve_symbol(mod_base + 0x2200) == "mock.dll!TestExportFunc");
    auto insns = debugger::Disassembler::disassemble_range(call_enc->bytes.data(), call_enc->bytes.size(), mod_base + 0x500, 1);
    REQUIRE(insns.size() == 1);
    session.annotate_disassembly(insns);
    CHECK(insns[0].resolved_symbol == "mock.dll!TestExportFunc");
}

TEST_CASE("Phase 3 StructureDissector: Multi-Struct side-by-side comparison") {
    auto proc = std::make_shared<FakeProcess>(0x10000);
    const size_t p_off = 0x1000;
    const size_t e_off = 0x1200;

    // Player: health=100, armor=50.5f, team=1
    proc->put<int32_t>(p_off + 0, 100);
    proc->put<float>(p_off + 4, 50.5f);
    proc->put<int32_t>(p_off + 8, 1);

    // Enemy: health=80, armor=50.5f, team=2
    proc->put<int32_t>(e_off + 0, 80);
    proc->put<float>(e_off + 4, 50.5f);
    proc->put<int32_t>(e_off + 8, 2);

    view::StructureDissector d(proc);
    auto cmp_all = d.compare({FakeProcess::kBase + p_off, FakeProcess::kBase + e_off}, 12);
    REQUIRE(cmp_all.rows.size() == 3);
    CHECK(cmp_all.rows[0].differs);    // 100 vs 80
    CHECK(cmp_all.rows[1].all_equal);  // 50.5 vs 50.5
    CHECK(cmp_all.rows[2].differs);    // 1 vs 2

    auto cmp_diff = d.compare({FakeProcess::kBase + p_off, FakeProcess::kBase + e_off}, 12, {}, true);
    REQUIRE(cmp_diff.rows.size() == 2);
    CHECK(cmp_diff.to_report(true).find("DIFF") != std::string::npos);
    CHECK(cmp_diff.to_report(true).find("SAME") == std::string::npos);
}

TEST_CASE("Phase 3 Scanner: AVX2 SIMD range conditions and XOR obfuscated scanning") {
    auto proc = std::make_shared<FakeProcess>(0x10000);

    // Populate > 12 aligned u32 values (spans multiple 256-bit AVX2 lanes + tail), including > INT32_MAX!
    for (size_t i = 0; i < 12; ++i) {
        proc->put<uint32_t>(0x100 + i * 4, static_cast<uint32_t>(0x7FFFFFFA + i));
        proc->put<int32_t>(0x200 + i * 4, static_cast<int32_t>(i * 10 - 30));
        proc->put<float>(0x300 + i * 4, static_cast<float>(i) * 1.5f);
        proc->put<double>(0x400 + i * 8, static_cast<double>(i) * 2.5);
    }

    scanner::MemoryScanner ms(proc);

    SUBCASE("Unsigned u32 GreaterThan / Between above 0x80000000 boundary") {
        auto gt = ms.first_scan(
            scanner::DataType::UInt32, scanner::ScanCondition::GreaterThan,
            scanner::ScanValue::of(scanner::DataType::UInt32, uint32_t{0x80000000U}), {}, 4);
        CHECK(test::contains_address(gt, FakeProcess::kBase + 0x100 + 7 * 4)); // 0x80000001
        CHECK_FALSE(test::contains_address(gt, FakeProcess::kBase + 0x100 + 5 * 4)); // 0x7FFFFFFF
    }

    SUBCASE("Signed i32, float, and double Between / LessThan") {
        auto btw_i32 = ms.first_scan(
            scanner::DataType::Int32, scanner::ScanCondition::Between,
            scanner::ScanValue::of(scanner::DataType::Int32, int32_t{-10}),
            scanner::ScanValue::of(scanner::DataType::Int32, int32_t{20}), 4);
        CHECK(test::contains_address(btw_i32, FakeProcess::kBase + 0x200 + 2 * 4)); // -10
        CHECK(test::contains_address(btw_i32, FakeProcess::kBase + 0x200 + 5 * 4)); // 20
        CHECK_FALSE(test::contains_address(btw_i32, FakeProcess::kBase + 0x200 + 6 * 4)); // 30

        auto btw_f32 = ms.first_scan(
            scanner::DataType::Float, scanner::ScanCondition::Between,
            scanner::ScanValue::of(scanner::DataType::Float, 3.0f),
            scanner::ScanValue::of(scanner::DataType::Float, 6.0f), 4);
        CHECK(test::contains_address(btw_f32, FakeProcess::kBase + 0x300 + 2 * 4)); // 3.0
        CHECK_FALSE(test::contains_address(btw_f32, FakeProcess::kBase + 0x300 + 5 * 4)); // 7.5

        auto gt_f64 = ms.first_scan(
            scanner::DataType::Double, scanner::ScanCondition::GreaterThan,
            scanner::ScanValue::of(scanner::DataType::Double, 20.0), {}, 8);
        CHECK(test::contains_address(gt_f64, FakeProcess::kBase + 0x400 + 9 * 8)); // 22.5
        CHECK_FALSE(test::contains_address(gt_f64, FakeProcess::kBase + 0x400 + 8 * 8)); // 20.0
    }

    SUBCASE("XOR explicit key & paired auto-discovery + ScanSession next_scan") {
        const uint32_t key = 0xA5A5A5A5U;
        proc->put<uint32_t>(0x1000, key);
        proc->put<uint32_t>(0x1004, uint32_t{777} ^ key);

        auto explicit_hits = ms.first_scan_xor(
            scanner::DataType::UInt32, key, scanner::ScanValue::of(scanner::DataType::UInt32, uint32_t{777}), 4);
        CHECK(test::contains_address(explicit_hits, FakeProcess::kBase + 0x1004));

        auto auto_hits = ms.first_scan_xor_auto(
            scanner::DataType::UInt32, scanner::ScanValue::of(scanner::DataType::UInt32, uint32_t{777}), -4, 4);
        CHECK(test::contains_address(auto_hits, FakeProcess::kBase + 0x1004));

        session::Session s(proc);
        REQUIRE(s.attach(1).ok);
        REQUIRE(s.scans().first_scan_xor("u32", "777", "0xA5A5A5A5").ok);
        CHECK(s.scans().state().results.count() >= 1);

        proc->put<uint32_t>(0x1004, uint32_t{888} ^ key);
        REQUIRE(s.scans().next_scan("exact", "888", "", scanner::FloatMatchMode::Rounded).ok);
        CHECK(test::contains_address(s.scans().state().results, FakeProcess::kBase + 0x1004));
    }
}

TEST_CASE("Phase 3 PointerScanner negative offsets & CheatTable groups/dropdown") {
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->add_module("game.exe", 0x0, 0x1000);
    const uintptr_t obj_target = FakeProcess::kBase + 0x4000;
    const uintptr_t ptr_dest = obj_target + 0x20; // pointer points PAST target (+0x20), requiring offset -0x20
    proc->put_pointer(0x200, ptr_dest);

    scanner::PointerScanner ps(proc);
    scanner::PointerScanOptions opts;
    opts.max_depth = 2;
    opts.max_offset = 0x100;
    opts.max_negative_offset = 0x40;
    auto res = ps.scan(obj_target, opts);
    REQUIRE(res.paths.size() == 1);
    CHECK(res.paths[0].offsets == std::vector<int64_t>{-0x20});
    CHECK(res.paths[0].to_string() == "[game.exe + 0x200] -> [-0x20]");
    CHECK(res.paths[0].resolve(*proc, proc->get_modules()) == obj_target);

    const auto tmp = std::filesystem::temp_directory_path() / "nce_neg_ptr_test.ptr";
    REQUIRE(scanner::save_pointer_paths(tmp.string(), res.paths));
    auto loaded = scanner::load_pointer_paths(tmp.string());
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    REQUIRE(loaded.has_value());
    REQUIRE(loaded->size() == 1);
    CHECK((*loaded)[0].offsets == std::vector<int64_t>{-0x20});

    SUBCASE("CheatTable group & dropdown JSON and .CT XML roundtrip") {
        table::CheatTable tbl;
        tbl.process_name = "game.exe";
        table::TableEntry e;
        e.description = "WeaponID";
        e.group = "Inventory";
        e.type = scanner::DataType::Int32;
        e.location = res.paths[0];
        e.dropdown["1"] = "Pistol";
        e.dropdown["2"] = "Rifle";
        tbl.entries.push_back(e);

        auto parsed_json = table::from_json(table::to_json(tbl));
        REQUIRE(parsed_json.has_value());
        REQUIRE(parsed_json->entries.size() == 1);
        CHECK(parsed_json->entries[0].group == "Inventory");
        CHECK(parsed_json->entries[0].dropdown["1"] == "Pistol");
        CHECK(parsed_json->entries[0].dropdown["2"] == "Rifle");

        const std::string xml = table::serialize_ce_table(tbl);
        table::CheatTable parsed_xml;
        std::string perr;
        REQUIRE(table::parse_ce_table(xml, parsed_xml, perr));
        REQUIRE(parsed_xml.entries.size() == 1);
        CHECK(parsed_xml.entries[0].group == "Inventory");
        CHECK(parsed_xml.entries[0].dropdown["1"] == "Pistol");
        CHECK(parsed_xml.entries[0].dropdown["2"] == "Rifle");
        CHECK(parsed_xml.entries[0].location.offsets == std::vector<int64_t>{-0x20});
    }
}
