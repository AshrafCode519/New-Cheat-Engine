#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "debugger/elf_analyzer.hpp"
#include "debugger/disassembler.hpp"
#include "session/session.hpp"
#include "view/engine_inspector.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

using namespace nce;
using test::FakeProcess;

namespace {

template <typename T>
void wr_le(std::vector<uint8_t>& buf, size_t off, T val) {
    if (off + sizeof(T) > buf.size()) buf.resize(off + sizeof(T), 0);
    std::memcpy(buf.data() + off, &val, sizeof(T));
}

void wr_str(std::vector<uint8_t>& buf, size_t off, const std::string& s) {
    if (off + s.size() + 1 > buf.size()) buf.resize(off + s.size() + 1, 0);
    std::memcpy(buf.data() + off, s.data(), s.size());
    buf[off + s.size()] = 0;
}

// Builds a synthetic ELF64 ET_DYN shared object with PT_LOAD, PT_DYNAMIC,
// DT_NEEDED ("libc.so.6"), DT_HASH, .dynsym, .dynstr, and section headers.
std::vector<uint8_t> build_synthetic_elf64() {
    std::vector<uint8_t> img(0x2000, 0);

    // Offsets inside the ELF64 buffer
    constexpr uint64_t kPhOff     = 0x0040;
    constexpr uint64_t kDynStrOff = 0x0200;
    constexpr uint64_t kDynSymOff = 0x0300;
    constexpr uint64_t kHashOff   = 0x0380;
    constexpr uint64_t kTextOff   = 0x0400;
    constexpr uint64_t kDynOff    = 0x0800;
    constexpr uint64_t kShStrOff  = 0x0A00;
    constexpr uint64_t kShOff     = 0x1000;

    // 1. Elf64_Ehdr
    img[0] = 0x7F; img[1] = 'E'; img[2] = 'L'; img[3] = 'F';
    img[4] = 2; // ELFCLASS64
    img[5] = 1; // ELFDATA2LSB
    img[6] = 1; // EV_CURRENT
    wr_le<uint16_t>(img, 16, 3);       // ET_DYN
    wr_le<uint16_t>(img, 18, 62);      // EM_X86_64
    wr_le<uint32_t>(img, 20, 1);       // EV_CURRENT
    wr_le<uint64_t>(img, 24, kTextOff);// e_entry
    wr_le<uint64_t>(img, 32, kPhOff);  // e_phoff
    wr_le<uint64_t>(img, 40, kShOff);  // e_shoff
    wr_le<uint16_t>(img, 52, 64);      // e_ehsize
    wr_le<uint16_t>(img, 54, 56);      // e_phentsize
    wr_le<uint16_t>(img, 56, 2);       // e_phnum
    wr_le<uint16_t>(img, 58, 64);      // e_shentsize
    wr_le<uint16_t>(img, 60, 5);       // e_shnum
    wr_le<uint16_t>(img, 62, 4);       // e_shstrndx

    // 2. Program Headers: PT_LOAD + PT_DYNAMIC
    // PT_LOAD covering [0..0x2000)
    wr_le<uint32_t>(img, kPhOff + 0, 1);      // PT_LOAD
    wr_le<uint32_t>(img, kPhOff + 4, 7);      // PF_R|PF_W|PF_X
    wr_le<uint64_t>(img, kPhOff + 8, 0);      // p_offset
    wr_le<uint64_t>(img, kPhOff + 16, 0);     // p_vaddr
    wr_le<uint64_t>(img, kPhOff + 24, 0);     // p_paddr
    wr_le<uint64_t>(img, kPhOff + 32, 0x2000);// p_filesz
    wr_le<uint64_t>(img, kPhOff + 40, 0x2000);// p_memsz
    wr_le<uint64_t>(img, kPhOff + 48, 0x1000);// p_align

    // PT_DYNAMIC
    wr_le<uint32_t>(img, kPhOff + 56 + 0, 2);       // PT_DYNAMIC
    wr_le<uint32_t>(img, kPhOff + 56 + 4, 6);       // PF_R|PF_W
    wr_le<uint64_t>(img, kPhOff + 56 + 8, kDynOff);
    wr_le<uint64_t>(img, kPhOff + 56 + 16, kDynOff);
    wr_le<uint64_t>(img, kPhOff + 56 + 24, kDynOff);
    wr_le<uint64_t>(img, kPhOff + 56 + 32, 0x80);
    wr_le<uint64_t>(img, kPhOff + 56 + 40, 0x80);
    wr_le<uint64_t>(img, kPhOff + 56 + 48, 8);

    // 3. .dynstr: "\0GameUpdate\0GetHealth\0libc.so.6\0"
    img[kDynStrOff] = 0;
    const uint32_t off_game_update = 1;
    wr_str(img, kDynStrOff + off_game_update, "GameUpdate");
    const uint32_t off_get_health = off_game_update + 11;
    wr_str(img, kDynStrOff + off_get_health, "GetHealth");
    const uint32_t off_libc = off_get_health + 10;
    wr_str(img, kDynStrOff + off_libc, "libc.so.6");
    constexpr uint64_t kDynStrSize = 64;

    // 4. .dynsym (3 x 24 bytes: UND, GameUpdate, GetHealth)
    // Sym 1: GameUpdate @ 0x400 size 0x40, STB_GLOBAL(1)<<4 | STT_FUNC(2) = 0x12
    wr_le<uint32_t>(img, kDynSymOff + 24 + 0, off_game_update);
    img[kDynSymOff + 24 + 4] = 0x12;
    wr_le<uint16_t>(img, kDynSymOff + 24 + 6, 1);
    wr_le<uint64_t>(img, kDynSymOff + 24 + 8, kTextOff);
    wr_le<uint64_t>(img, kDynSymOff + 24 + 16, 0x40);

    // Sym 2: GetHealth @ 0x440 size 0x20
    wr_le<uint32_t>(img, kDynSymOff + 48 + 0, off_get_health);
    img[kDynSymOff + 48 + 4] = 0x12;
    wr_le<uint16_t>(img, kDynSymOff + 48 + 6, 1);
    wr_le<uint64_t>(img, kDynSymOff + 48 + 8, kTextOff + 0x40);
    wr_le<uint64_t>(img, kDynSymOff + 48 + 16, 0x20);

    // 5. DT_HASH: nbucket=1, nchain=3
    wr_le<uint32_t>(img, kHashOff + 0, 1);
    wr_le<uint32_t>(img, kHashOff + 4, 3);

    // 6. .dynamic entries (16 bytes each)
    auto put_dyn = [&](size_t idx, int64_t tag, uint64_t val) {
        wr_le<int64_t>(img, kDynOff + idx * 16, tag);
        wr_le<uint64_t>(img, kDynOff + idx * 16 + 8, val);
    };
    put_dyn(0, 1, off_libc);      // DT_NEEDED
    put_dyn(1, 5, kDynStrOff);    // DT_STRTAB
    put_dyn(2, 6, kDynSymOff);    // DT_SYMTAB
    put_dyn(3, 10, kDynStrSize);  // DT_STRSZ
    put_dyn(4, 11, 24);           // DT_SYMENT
    put_dyn(5, 4, kHashOff);      // DT_HASH
    put_dyn(6, 0, 0);             // DT_NULL

    // 7. .text stub instructions (ret = 0xC3)
    img[kTextOff] = 0x90;
    img[kTextOff + 1] = 0xC3;

    // 8. .shstrtab
    img[kShStrOff] = 0;
    wr_str(img, kShStrOff + 1, ".text");       // 1
    wr_str(img, kShStrOff + 7, ".dynsym");     // 7
    wr_str(img, kShStrOff + 15, ".dynstr");    // 15
    wr_str(img, kShStrOff + 23, ".shstrtab");  // 23

    // 9. Section Headers (5 x 64 bytes): NULL, .text, .dynsym, .dynstr, .shstrtab
    auto put_sh = [&](size_t idx, uint32_t name_off, uint32_t type, uint64_t flags,
                      uint64_t addr, uint64_t off, uint64_t sz, uint32_t link, uint64_t entsz) {
        size_t base = kShOff + idx * 64;
        wr_le<uint32_t>(img, base + 0, name_off);
        wr_le<uint32_t>(img, base + 4, type);
        wr_le<uint64_t>(img, base + 8, flags);
        wr_le<uint64_t>(img, base + 16, addr);
        wr_le<uint64_t>(img, base + 24, off);
        wr_le<uint64_t>(img, base + 32, sz);
        wr_le<uint32_t>(img, base + 40, link);
        wr_le<uint64_t>(img, base + 56, entsz);
    };
    put_sh(1, 1, 1, 0x6, kTextOff, kTextOff, 0x100, 0, 0);          // SHT_PROGBITS .text (ALLOC|EXEC)
    put_sh(2, 7, 11, 0x2, kDynSymOff, kDynSymOff, 72, 3, 24);       // SHT_DYNSYM
    put_sh(3, 15, 3, 0x2, kDynStrOff, kDynStrOff, kDynStrSize, 0, 0);// SHT_STRTAB
    put_sh(4, 23, 3, 0x0, 0, kShStrOff, 40, 0, 0);                  // .shstrtab

    return img;
}

// Builds a minimal PE32+ image with an Export Directory containing the given symbols.
std::vector<uint8_t> build_synthetic_pe64_exports(const std::vector<std::string>& export_names) {
    std::vector<uint8_t> pe(0x2000, 0);
    // DOS header
    wr_le<uint16_t>(pe, 0x00, 0x5A4D); // MZ
    wr_le<uint32_t>(pe, 0x3C, 0x80);   // e_lfanew

    // NT headers @ 0x80
    wr_le<uint32_t>(pe, 0x80, 0x00004550); // "PE\0\0"
    wr_le<uint16_t>(pe, 0x84, 0x8664);     // AMD64
    wr_le<uint16_t>(pe, 0x86, 1);          // NumberOfSections
    wr_le<uint16_t>(pe, 0x94, 0xF0);       // SizeOfOptionalHeader (PE32+)

    // Optional Header @ 0x98
    wr_le<uint16_t>(pe, 0x98, 0x020B);     // Magic PE32+
    wr_le<uint32_t>(pe, 0xA8, 0x1000);     // AddressOfEntryPoint
    wr_le<uint32_t>(pe, 0xC8, 0x2000);     // SizeOfImage
    wr_le<uint32_t>(pe, 0x104, 16);        // NumberOfRvaAndSizes
    // Export DataDirectory @ 0x108
    wr_le<uint32_t>(pe, 0x108, 0x1200);    // Export RVA
    wr_le<uint32_t>(pe, 0x10C, 0x0400);    // Export Size

    // 1 section header (.text) @ 0x98 + 0xF0 = 0x188
    wr_str(pe, 0x188, ".text");
    wr_le<uint32_t>(pe, 0x190, 0x1000);    // VirtualSize
    wr_le<uint32_t>(pe, 0x194, 0x1000);    // VirtualAddress
    wr_le<uint32_t>(pe, 0x198, 0x1000);    // SizeOfRawData
    wr_le<uint32_t>(pe, 0x19C, 0x1000);    // PointerToRawData
    wr_le<uint32_t>(pe, 0x1AC, 0x60000020);// CNT_CODE | MEM_EXECUTE | MEM_READ

    // Export Directory @ 0x1200
    const uint32_t n = static_cast<uint32_t>(export_names.size());
    constexpr uint32_t kFuncRvaBase = 0x1300;
    constexpr uint32_t kNamePtrBase = 0x1380;
    constexpr uint32_t kOrdBase     = 0x1400;
    uint32_t str_cursor = 0x1440;

    wr_le<uint32_t>(pe, 0x1200 + 16, 1);            // Base ordinal
    wr_le<uint32_t>(pe, 0x1200 + 20, n);            // NumberOfFunctions
    wr_le<uint32_t>(pe, 0x1200 + 24, n);            // NumberOfNames
    wr_le<uint32_t>(pe, 0x1200 + 28, kFuncRvaBase); // AddressOfFunctions
    wr_le<uint32_t>(pe, 0x1200 + 32, kNamePtrBase); // AddressOfNames
    wr_le<uint32_t>(pe, 0x1200 + 36, kOrdBase);     // AddressOfNameOrdinals

    for (uint32_t i = 0; i < n; ++i) {
        wr_le<uint32_t>(pe, kFuncRvaBase + i * 4, 0x1020 + i * 0x10);
        wr_le<uint32_t>(pe, kNamePtrBase + i * 4, str_cursor);
        wr_le<uint16_t>(pe, kOrdBase + i * 2, static_cast<uint16_t>(i));
        wr_str(pe, str_cursor, export_names[i]);
        str_cursor += static_cast<uint32_t>(export_names[i].size() + 1);
    }
    return pe;
}

} // namespace

TEST_CASE("Phase 4 ELFAnalyzer: parses ELF64 dynamic symbols, sections, and resolves Session symbols") {
    auto elf_buf = build_synthetic_elf64();

    // 1. Offline byte-buffer parse at base VA 0x7F000000
    auto info = debugger::ELFAnalyzer::analyze_bytes(elf_buf, 0x7F000000);
    REQUIRE(info.has_value());
    CHECK(info->is_valid);
    CHECK(info->is_64bit);
    CHECK(info->is_shared_object);
    CHECK(info->machine == 62);
    CHECK(info->entry_point == 0x7F000400);
    CHECK(info->segments.size() == 2);
    CHECK(info->sections.size() == 5);
    REQUIRE(info->needed_libraries.size() == 1);
    CHECK(info->needed_libraries[0] == "libc.so.6");

    const auto* sec_text = debugger::ELFAnalyzer::find_section(*info, ".text");
    REQUIRE(sec_text != nullptr);
    CHECK(sec_text->is_executable);
    CHECK(sec_text->virtual_address == 0x7F000400);

    const auto* sym_update = debugger::ELFAnalyzer::find_symbol_by_name(*info, "GameUpdate");
    REQUIRE(sym_update != nullptr);
    CHECK(sym_update->va == 0x7F000400);
    CHECK(sym_update->is_exported);

    const auto* sym_health_by_addr = debugger::ELFAnalyzer::find_symbol_by_address(*info, 0x7F000450);
    REQUIRE(sym_health_by_addr != nullptr);
    CHECK(sym_health_by_addr->name == "GetHealth");

    // 2. Live FakeProcess ELF mapping + Session::analyze_module_elf & Session::resolve_symbol
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->write_raw(FakeProcess::kBase + 0x1000, elf_buf.data(), elf_buf.size());
    proc->add_module("libgame.so", 0x1000, elf_buf.size());

    session::Session ses(proc);
    CHECK(ses.attach(1).ok);

    auto mod_elf = ses.analyze_module_elf("libgame.so");
    REQUIRE(mod_elf.has_value());
    CHECK(mod_elf->is_valid);
    CHECK(debugger::ELFAnalyzer::find_symbol_by_name(*mod_elf, "GetHealth") != nullptr);

    const uintptr_t mod_base = FakeProcess::kBase + 0x1000;
    CHECK(ses.resolve_symbol(mod_base + 0x400) == "libgame.so!GameUpdate");
    CHECK(ses.resolve_symbol(mod_base + 0x410) == "libgame.so!GameUpdate+0x10");
    CHECK(ses.resolve_symbol(mod_base + 0x440) == "libgame.so!GetHealth");

    std::vector<debugger::DecodedInstruction> dis(1);
    dis[0].address = mod_base + 0x400;
    ses.annotate_disassembly(dis);
    CHECK(dis[0].resolved_symbol == "libgame.so!GameUpdate");
}

TEST_CASE("Phase 4 ELFAnalyzer: parses ELF32 ET_EXEC header and 32-bit symbols") {
    std::vector<uint8_t> img(0x800, 0);
    img[0] = 0x7F; img[1] = 'E'; img[2] = 'L'; img[3] = 'F';
    img[4] = 1; // ELFCLASS32
    img[5] = 1; // ELFDATA2LSB
    img[6] = 1;
    wr_le<uint16_t>(img, 16, 2);           // ET_EXEC
    wr_le<uint16_t>(img, 18, 3);           // EM_386
    wr_le<uint32_t>(img, 20, 1);
    wr_le<uint32_t>(img, 24, 0x08048100);  // e_entry
    wr_le<uint32_t>(img, 28, 52);          // e_phoff
    wr_le<uint32_t>(img, 32, 0x400);       // e_shoff
    wr_le<uint16_t>(img, 40, 52);          // e_ehsize
    wr_le<uint16_t>(img, 42, 32);          // e_phentsize
    wr_le<uint16_t>(img, 44, 1);           // e_phnum
    wr_le<uint16_t>(img, 46, 40);          // e_shentsize
    wr_le<uint16_t>(img, 48, 4);           // e_shnum
    wr_le<uint16_t>(img, 50, 3);           // e_shstrndx

    // PT_LOAD (32 bytes @ 52)
    wr_le<uint32_t>(img, 52 + 0, 1);
    wr_le<uint32_t>(img, 52 + 4, 0);
    wr_le<uint32_t>(img, 52 + 8, 0x08048000);
    wr_le<uint32_t>(img, 52 + 12, 0x08048000);
    wr_le<uint32_t>(img, 52 + 16, 0x800);
    wr_le<uint32_t>(img, 52 + 20, 0x800);
    wr_le<uint32_t>(img, 52 + 24, 5);

    // .strtab @ 0x200
    wr_str(img, 0x201, "MainLoop32");
    // .symtab @ 0x240 (2 x 16 bytes)
    wr_le<uint32_t>(img, 0x240 + 16 + 0, 1);           // st_name
    wr_le<uint32_t>(img, 0x240 + 16 + 4, 0x08048100);  // st_value
    wr_le<uint32_t>(img, 0x240 + 16 + 8, 0x30);        // st_size
    img[0x240 + 16 + 12] = 0x12;                       // GLOBAL | FUNC
    wr_le<uint16_t>(img, 0x240 + 16 + 14, 1);          // shndx = 1

    // .shstrtab @ 0x300
    wr_str(img, 0x301, ".symtab");
    wr_str(img, 0x309, ".strtab");
    wr_str(img, 0x311, ".shstrtab");

    // 4 Section headers @ 0x400 (40 bytes each)
    auto put_sh32 = [&](size_t idx, uint32_t n, uint32_t t, uint32_t f, uint32_t a, uint32_t o, uint32_t sz, uint32_t l, uint32_t es) {
        size_t b = 0x400 + idx * 40;
        wr_le<uint32_t>(img, b + 0, n);
        wr_le<uint32_t>(img, b + 4, t);
        wr_le<uint32_t>(img, b + 8, f);
        wr_le<uint32_t>(img, b + 12, a);
        wr_le<uint32_t>(img, b + 16, o);
        wr_le<uint32_t>(img, b + 20, sz);
        wr_le<uint32_t>(img, b + 24, l);
        wr_le<uint32_t>(img, b + 36, es);
    };
    put_sh32(1, 1, 2, 0, 0, 0x240, 32, 2, 16);   // SHT_SYMTAB
    put_sh32(2, 9, 3, 0, 0, 0x200, 32, 0, 0);    // SHT_STRTAB
    put_sh32(3, 17, 3, 0, 0, 0x300, 32, 0, 0);   // .shstrtab

    auto info = debugger::ELFAnalyzer::analyze_bytes(img);
    REQUIRE(info.has_value());
    CHECK(info->is_valid);
    CHECK_FALSE(info->is_64bit);
    CHECK(info->type_name == "ET_EXEC");
    CHECK(info->entry_point == 0x08048100);
    const auto* s = debugger::ELFAnalyzer::find_symbol_by_name(*info, "MainLoop32");
    REQUIRE(s != nullptr);
    CHECK(s->va == 0x08048100);
}

TEST_CASE("Phase 4 EngineInspector: Unity IL2CPP detection & global-metadata.dat parser") {
    // 1. Runtime detection with synthetic GameAssembly.dll PE exports
    auto ga_pe = build_synthetic_pe64_exports({"il2cpp_domain_get", "il2cpp_class_from_name"});
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->write_raw(FakeProcess::kBase + 0x2000, ga_pe.data(), ga_pe.size());
    proc->add_module("TestUnityGame.exe", 0x0, 0x1000);
    proc->add_module("GameAssembly.dll", 0x2000, ga_pe.size());
    proc->attach(1);

    auto det = view::EngineInspector::detect(*proc);
    CHECK(det.kind == view::GameEngineKind::UnityIL2CPP);
    CHECK(det.runtime_module == "GameAssembly.dll");
    CHECK(det.api_exports.count("il2cpp_domain_get") == 1);
    CHECK(det.api_exports.count("il2cpp_class_from_name") == 1);

    // 2. Synthetic IL2CPP v29 global-metadata.dat buffer
    std::vector<uint8_t> meta(0x800, 0);
    constexpr uint32_t kStrOff   = 0x120;
    constexpr uint32_t kFieldOff = 0x240;
    constexpr uint32_t kTypeOff  = 0x300;
    constexpr size_t   kTypeStride = 88; // v29 Il2CppTypeDefinition

    wr_str(meta, kStrOff + 1, "Game");
    wr_str(meta, kStrOff + 6, "PlayerController");
    wr_str(meta, kStrOff + 23, "health");
    wr_str(meta, kStrOff + 30, "moveSpeed");
    wr_str(meta, kStrOff + 40, "EnemyAI");
    wr_str(meta, kStrOff + 48, "aggroRadius");
    constexpr uint32_t kStrSize = 64;

    // 3 fields @ kFieldOff (12 bytes each)
    auto put_field = [&](size_t idx, uint32_t name_idx, int32_t type_idx, int32_t token) {
        size_t b = kFieldOff + idx * 12;
        wr_le<uint32_t>(meta, b + 0, name_idx);
        wr_le<int32_t>(meta, b + 4, type_idx);
        wr_le<int32_t>(meta, b + 8, token);
    };
    put_field(0, 23, 1, 0x04000001); // health
    put_field(1, 30, 2, 0x04000002); // moveSpeed
    put_field(2, 48, 2, 0x04000003); // aggroRadius

    // 2 TypeDefinitions @ kTypeOff (v29: fieldStart @ +0x24, field_count @ +0x44, flags @ +0x3C, token @ +0x38)
    auto put_type = [&](size_t idx, uint32_t name_i, uint32_t ns_i, int32_t fstart, uint16_t fcnt, int32_t tok) {
        size_t b = kTypeOff + idx * kTypeStride;
        wr_le<uint32_t>(meta, b + 0x00, name_i);
        wr_le<uint32_t>(meta, b + 0x04, ns_i);
        wr_le<int32_t>(meta,  b + 0x24, fstart);
        wr_le<int32_t>(meta,  b + 0x38, tok);
        wr_le<uint16_t>(meta, b + 0x44, fcnt);
    };
    put_type(0, 6, 1, 0, 2, 0x02000001);   // Game.PlayerController (2 fields)
    put_type(1, 40, 1, 2, 1, 0x02000002);  // Game.EnemyAI (1 field)

    wr_le<uint32_t>(meta, 0x00, 0xFAB11BAF);
    wr_le<int32_t>(meta,  0x04, 29);
    wr_le<uint32_t>(meta, 0x18, kStrOff);
    wr_le<uint32_t>(meta, 0x1C, kStrSize);
    wr_le<uint32_t>(meta, 0x60, kFieldOff);
    wr_le<uint32_t>(meta, 0x64, 3 * 12);
    wr_le<uint32_t>(meta, 0xA0, kTypeOff);
    wr_le<uint32_t>(meta, 0xA4, static_cast<uint32_t>(2 * kTypeStride));

    auto rep = view::EngineInspector::parse_unity_metadata_bytes(meta);
    REQUIRE(rep.valid);
    CHECK(rep.version == 29);
    CHECK(rep.total_types == 2);
    REQUIRE(rep.types.size() == 2);
    CHECK(rep.types[0].namespaze == "Game");
    CHECK(rep.types[0].name == "PlayerController");
    REQUIRE(rep.types[0].fields.size() == 2);
    CHECK(rep.types[0].fields[0].name == "health");
    CHECK(rep.types[0].fields[1].name == "moveSpeed");
    CHECK(rep.types[1].name == "EnemyAI");
    REQUIRE(rep.types[1].fields.size() == 1);
    CHECK(rep.types[1].fields[0].name == "aggroRadius");

    // Filtered disk parse via Session
    const auto tmp_meta = std::filesystem::temp_directory_path() / "nce_test_global_metadata.dat";
    {
        std::ofstream f(tmp_meta, std::ios::binary);
        f.write(reinterpret_cast<const char*>(meta.data()), static_cast<std::streamsize>(meta.size()));
    }
    session::Session ses(proc);
    auto filtered = ses.inspect_unity_metadata(tmp_meta.string(), "Player");
    std::error_code ec;
    std::filesystem::remove(tmp_meta, ec);
    REQUIRE(filtered.valid);
    REQUIRE(filtered.types.size() == 1);
    CHECK(filtered.types[0].name == "PlayerController");
}

TEST_CASE("Phase 4 EngineInspector: Unreal Engine detection, FNamePool, and FUObjectArray") {
    auto ue_pe = build_synthetic_pe64_exports({"GUObjectArray", "NamePoolData"});
    auto proc = std::make_shared<FakeProcess>(0x10000);
    proc->write_raw(FakeProcess::kBase + 0x0, ue_pe.data(), ue_pe.size());
    proc->add_module("SpaceGame-Win64-Shipping.exe", 0x0, ue_pe.size());
    proc->attach(1);

    // 1. Engine detection via Unreal exports
    auto det = view::EngineInspector::detect(*proc);
    CHECK(det.kind == view::GameEngineKind::UnrealEngine);
    CHECK(det.gnames_hint != 0);
    CHECK(det.gobjects_hint != 0);

    // 2. Construct FNamePool @ +0x3000 with Block[0] @ +0x4000
    const uintptr_t gnames_va  = FakeProcess::kBase + 0x3000;
    const uintptr_t block0_va  = FakeProcess::kBase + 0x4000;
    const uintptr_t gobj_va    = FakeProcess::kBase + 0x5000;
    const uintptr_t chunks_va  = FakeProcess::kBase + 0x5200;
    const uintptr_t chunk0_va  = FakeProcess::kBase + 0x5400;
    const uintptr_t uclass_va  = FakeProcess::kBase + 0x6000;
    const uintptr_t uobj0_va   = FakeProcess::kBase + 0x6100;
    const uintptr_t uobj1_va   = FakeProcess::kBase + 0x6200;

    // Populate Block[0] sequential FNameEntries (header = (len << 6) | wide_bit)
    std::vector<uint8_t> blk(0x200, 0);
    auto put_fname = [&](uint32_t byte_off, const std::string& txt) -> uint32_t {
        const uint16_t hdr = static_cast<uint16_t>((txt.size() << 6) | 0u);
        wr_le<uint16_t>(blk, byte_off, hdr);
        std::memcpy(blk.data() + byte_off + 2, txt.data(), txt.size());
        const size_t adv = ((2 + txt.size() + 1) / 2) * 2;
        return static_cast<uint32_t>(byte_off + adv);
    };

    uint32_t cur = 0;
    /* None at index 0 */   cur = put_fname(cur, "None");
    const uint32_t idx_class  = cur / 2; cur = put_fname(cur, "PlayerCharacter");
    const uint32_t idx_hero   = cur / 2; cur = put_fname(cur, "BP_HeroPawn_C");
    const uint32_t idx_wide   = cur / 2;
    {
        // Wide UTF-16LE FNameEntry "WideObj"
        const char16_t wtxt[] = u"WideObj";
        const uint16_t hdr = static_cast<uint16_t>((7u << 6) | 1u);
        wr_le<uint16_t>(blk, cur, hdr);
        std::memcpy(blk.data() + cur + 2, wtxt, 14);
        cur += 16;
    }
    proc->write_raw(block0_va, blk.data(), blk.size());

    // FNamePool header: +0x08 CurrentBlock=0, +0x0C CurrentByteCursor=cur, +0x10 Blocks[0]=block0_va
    proc->put<uint32_t>(0x3000 + 0x08, 0);
    proc->put<uint32_t>(0x3000 + 0x0C, cur);
    proc->put_pointer(0x3000 + 0x10, block0_va);

    // 3. Construct UClass + 2 UObjects
    proc->put<uint32_t>(0x6000 + 0x18, idx_class); // Class Name = "PlayerCharacter"
    proc->put_pointer(0x6100 + 0x10, uclass_va);   // UObject 0 ClassPrivate
    proc->put<uint32_t>(0x6100 + 0x18, idx_hero);  // UObject 0 NamePrivate = "BP_HeroPawn_C"
    proc->put_pointer(0x6200 + 0x10, uclass_va);   // UObject 1 ClassPrivate
    proc->put<uint32_t>(0x6200 + 0x18, idx_wide);  // UObject 1 NamePrivate = "WideObj"

    // FUObjectArray: +0x10 Chunks**, +0x24 NumElements=2, +0x2C NumChunks=1
    proc->put_pointer(0x5000 + 0x10, chunks_va);
    proc->put<uint32_t>(0x5000 + 0x24, 2);
    proc->put<uint32_t>(0x5000 + 0x2C, 1);
    proc->put_pointer(0x5200, chunk0_va);
    // Chunk0 items (stride 24: Object* @ +0)
    proc->put_pointer(0x5400 + 0, uobj0_va);
    proc->put_pointer(0x5400 + 24, uobj1_va);

    session::Session ses(proc);
    CHECK(ses.attach(1).ok);

    auto names = ses.scan_unreal_names(gnames_va);
    REQUIRE(names.size() == 4);
    CHECK(names[0].name == "None");
    CHECK(names[1].name == "PlayerCharacter");
    CHECK(names[2].name == "BP_HeroPawn_C");
    CHECK(names[3].name == "WideObj");

    auto objs = ses.dump_unreal_objects(gobj_va, gnames_va);
    REQUIRE(objs.size() == 2);
    CHECK(objs[0].class_name == "PlayerCharacter");
    CHECK(objs[0].name == "BP_HeroPawn_C");
    CHECK(objs[1].name == "WideObj");

    auto filtered = ses.dump_unreal_objects(gobj_va, gnames_va, {}, "Hero");
    REQUIRE(filtered.size() == 1);
    CHECK(filtered[0].name == "BP_HeroPawn_C");
}

TEST_CASE("Phase 4 ELFAnalyzer: parses DWARF .debug_info/.debug_abbrev/.debug_str subprograms") {
    std::vector<uint8_t> img(0x3000, 0);

    // ELF64 ET_DYN header with 0 program headers and 5 sections:
    // [0] null, [1] .shstrtab, [2] .text, [3] .debug_abbrev, [4] .debug_info, [5] .debug_str
    auto wr_str = [&](size_t off, const std::string& s) {
        std::memcpy(img.data() + off, s.data(), s.size());
        img[off + s.size()] = 0;
    };
    img[0] = 0x7F; img[1] = 'E'; img[2] = 'L'; img[3] = 'F';
    img[4] = 2; img[5] = 1; img[6] = 1;
    wr_le<uint16_t>(img, 16, 3);
    wr_le<uint16_t>(img, 18, 0x3E);
    wr_le<uint32_t>(img, 20, 1);
    wr_le<uint64_t>(img, 40, 0x2000); // e_shoff
    wr_le<uint16_t>(img, 52, 64);
    wr_le<uint16_t>(img, 58, 64);     // e_shentsize
    wr_le<uint16_t>(img, 60, 6);      // e_shnum
    wr_le<uint16_t>(img, 62, 1);      // e_shstrndx = .shstrtab

    // Section data offsets
    constexpr size_t kShstrOff   = 0x0400;
    constexpr size_t kAbbrevOff  = 0x0600;
    constexpr size_t kInfoOff    = 0x0800;
    constexpr size_t kDebugStrOff = 0x0A00;

    // .shstrtab
    size_t shstr_cur = 1;
    auto add_shstr = [&](const std::string& s) -> uint32_t {
        uint32_t off = static_cast<uint32_t>(shstr_cur);
        wr_str(kShstrOff + shstr_cur, s);
        shstr_cur += s.size() + 1;
        return off;
    };
    const uint32_t n_shstr   = add_shstr(".shstrtab");
    const uint32_t n_text    = add_shstr(".text");
    const uint32_t n_dabbrev = add_shstr(".debug_abbrev");
    const uint32_t n_dinfo   = add_shstr(".debug_info");
    const uint32_t n_dstr    = add_shstr(".debug_str");

    // .debug_str
    const std::string fn1 = "CalculateDamage";
    const std::string fn2 = "StaticHelperFn";
    wr_str(kDebugStrOff + 0, fn1);
    const uint32_t fn2_str_off = static_cast<uint32_t>(fn1.size() + 1);
    wr_str(kDebugStrOff + fn2_str_off, fn2);

    // .debug_abbrev:
    // [1] DW_TAG_compile_unit (0x11), has_children=1: DW_AT_name (0x03) DW_FORM_string (0x08)
    // [2] DW_TAG_subprogram   (0x2E), has_children=0:
    //     DW_AT_name (0x03) DW_FORM_strp (0x0E)
    //     DW_AT_low_pc (0x11) DW_FORM_addr (0x01)
    //     DW_AT_high_pc (0x12) DW_FORM_udata (0x0F)
    std::vector<uint8_t> abbrev = {
        1, 0x11, 1,  0x03, 0x08,  0, 0,
        2, 0x2E, 0,  0x03, 0x0E,  0x11, 0x01,  0x12, 0x0F,  0, 0,
        0
    };
    std::memcpy(img.data() + kAbbrevOff, abbrev.data(), abbrev.size());

    // .debug_info (DWARF 4 32-bit CU):
    // header: version=4, abbrev_off=0, addr_size=8
    std::vector<uint8_t> cu_body;
    auto push_u8  = [&](uint8_t v)  { cu_body.push_back(v); };
    auto push_u16 = [&](uint16_t v) { for (int i = 0; i < 2; ++i) cu_body.push_back(static_cast<uint8_t>(v >> (i * 8))); };
    auto push_u32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) cu_body.push_back(static_cast<uint8_t>(v >> (i * 8))); };
    auto push_u64 = [&](uint64_t v) { for (int i = 0; i < 8; ++i) cu_body.push_back(static_cast<uint8_t>(v >> (i * 8))); };

    push_u16(4);     // DWARF version 4
    push_u32(0);     // debug_abbrev_offset
    push_u8(8);      // address_size = 8
    // DIE 1 (CU)
    push_u8(1);
    for (char c : std::string("combat.cpp")) push_u8(static_cast<uint8_t>(c));
    push_u8(0);
    // DIE 2 (subprogram fn1: low_pc=0x1100, size=0x40)
    push_u8(2);
    push_u32(0);
    push_u64(0x1100);
    push_u8(0x40); // uleb128 0x40
    // DIE 3 (subprogram fn2: low_pc=0x1180, size=0x28)
    push_u8(2);
    push_u32(fn2_str_off);
    push_u64(0x1180);
    push_u8(0x28); // uleb128 0x28
    // End of CU children
    push_u8(0);

    wr_le<uint32_t>(img, kInfoOff, static_cast<uint32_t>(cu_body.size()));
    std::memcpy(img.data() + kInfoOff + 4, cu_body.data(), cu_body.size());

    auto put_sh = [&](size_t idx, uint32_t name, uint32_t type, uint64_t flags,
                      uint64_t addr, uint64_t off, uint64_t sz) {
        size_t o = 0x2000 + idx * 64;
        wr_le<uint32_t>(img, o + 0, name);
        wr_le<uint32_t>(img, o + 4, type);
        wr_le<uint64_t>(img, o + 8, flags);
        wr_le<uint64_t>(img, o + 16, addr);
        wr_le<uint64_t>(img, o + 24, off);
        wr_le<uint64_t>(img, o + 32, sz);
    };
    put_sh(1, n_shstr,   3, 0, 0, kShstrOff, shstr_cur);
    put_sh(2, n_text,    1, 6, 0x1000, 0x1000, 0x500);
    put_sh(3, n_dabbrev, 1, 0, 0, kAbbrevOff, abbrev.size());
    put_sh(4, n_dinfo,   1, 0, 0, kInfoOff, 4 + cu_body.size());
    put_sh(5, n_dstr,    1, 0, 0, kDebugStrOff, fn2_str_off + fn2.size() + 1);

    auto elf = debugger::ELFAnalyzer::analyze_bytes(img, 0x500000);
    REQUIRE(elf.has_value());
    CHECK(elf->has_dwarf);
    CHECK(elf->dwarf_function_count == 2);

    const auto* s1 = debugger::ELFAnalyzer::find_symbol_by_name(*elf, "CalculateDamage");
    REQUIRE(s1 != nullptr);
    CHECK(s1->va == 0x501100);
    CHECK(s1->size == 0x40);
    CHECK(s1->section_index == 2);
    CHECK(s1->type == 2);

    const auto* s2 = debugger::ELFAnalyzer::find_symbol_by_address(*elf, 0x501188);
    REQUIRE(s2 != nullptr);
    CHECK(s2->name == "StaticHelperFn");
}
