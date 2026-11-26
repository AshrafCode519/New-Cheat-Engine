#include "doctest/doctest.h"
#include "debugger/micro_emulator.hpp"
#include "debugger/protection_inspector.hpp"
#include "debugger/debug_coordinator.hpp"
#include "session/session.hpp"

#include <cstring>
#include <map>
#include <memory>
#include <vector>

using namespace nce;

namespace {

class EmuMockProcess final : public hal::IProcess {
public:
    std::map<uintptr_t, std::vector<uint8_t>> mem;
    std::vector<hal::MemoryRegion> regions;
    std::vector<hal::ModuleInfo> modules;

    bool attach(uint32_t) override { return true; }
    void detach() override {}
    bool is_attached() const noexcept override { return true; }
    uint32_t get_pid() const noexcept override { return 9001; }

    bool read_raw(uintptr_t addr, void* buf, size_t sz) const override {
        auto* dst = static_cast<uint8_t*>(buf);
        for (size_t i = 0; i < sz; ++i) {
            bool found = false;
            for (const auto& [base, data] : mem) {
                const uintptr_t cur = addr + i;
                if (cur >= base && cur < base + data.size()) {
                    dst[i] = data[cur - base];
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    bool write_raw(uintptr_t, const void*, size_t, bool) const override { return true; }
    std::vector<hal::MemoryRegion> query_regions(uint32_t) const override { return regions; }
    std::vector<hal::ModuleInfo> get_modules() const override { return modules; }
    uintptr_t allocate_memory(size_t, uint32_t, uintptr_t) override { return 0; }
    bool free_memory(uintptr_t, size_t) override { return true; }
    size_t pointer_size() const noexcept override { return 8; }
    bool can_write() const noexcept override { return true; }
    std::string name() const override { return "emu_mock.exe"; }
    bool suspend() override { return true; }
    bool resume() override { return true; }
};

void put_u16_at(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    std::memcpy(b.data() + off, &v, 2);
}
void put_u32_at(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    std::memcpy(b.data() + off, &v, 4);
}
void put_u64_at(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    std::memcpy(b.data() + off, &v, 8);
}

} // namespace

TEST_CASE("MicroEmulator executes arithmetic, branches, COW writes, and RET safely") {
    EmuMockProcess proc;
    const uintptr_t code_base = 0x100000;
    const uintptr_t data_base = 0x200000;

    // Code:
    // 0:  mov eax, 100         ; B8 64 00 00 00
    // 5:  add eax, ecx         ; 01 C8
    // 7:  mov [rdx+0x10], eax  ; 89 42 10
    // 10: ret                  ; C3
    std::vector<uint8_t> code = {
        0xB8, 0x64, 0x00, 0x00, 0x00,
        0x01, 0xC8,
        0x89, 0x42, 0x10,
        0xC3
    };
    proc.mem[code_base] = code;
    proc.mem[data_base] = std::vector<uint8_t>(64, 0x11);

    debugger::Registers init{};
    init.rcx = 50;
    init.rdx = data_base;

    const auto res = debugger::MicroEmulator::emulate(&proc, code_base, init, 32, true);
    CHECK(res.completed);
    CHECK(res.returned_cleanly);
    CHECK(res.steps_executed == 4);
    CHECK(res.final_regs.rax == 150);

    // Ensure COW isolation: original process memory was NEVER mutated!
    uint32_t original_val = 0;
    REQUIRE(proc.read_raw(data_base + 0x10, &original_val, 4));
    CHECK(original_val == 0x11111111u);

    bool saw_write = false;
    for (const auto& acc : res.accesses) {
        if (acc.is_write && acc.address == data_base + 0x10 && acc.value == 150) saw_write = true;
    }
    CHECK(saw_write);
}

TEST_CASE("MicroEmulator caps infinite loops and tests dry_run_hook") {
    EmuMockProcess proc;
    // Infinite self-loop: EB FE (jmp $-2)
    proc.mem[0x400000] = {0xEB, 0xFE};
    debugger::Registers regs{};
    const auto loop_res = debugger::MicroEmulator::emulate(&proc, 0x400000, regs, 12, true);
    CHECK(loop_res.steps_executed == 12);
    CHECK(!loop_res.returned_cleanly);

    // Dry-run hook cave: jmp cave (1) -> xor eax, eax (2) -> add eax, 777 (3) -> ret (4)
    std::vector<uint8_t> cave = {
        0x31, 0xC0,
        0x05, 0x09, 0x03, 0x00, 0x00, // add eax, 777
        0xC3
    };
    regs.rsp = 0x500000;
    const auto hook_res = debugger::MicroEmulator::dry_run_hook(proc, 0x400000, cave, 0x600000, regs, 16);
    CHECK(hook_res.final_regs.rax == 777);
    CHECK(hook_res.returned_cleanly);
    CHECK(hook_res.steps_executed == 4);
}

TEST_CASE("MicroEmulator backward_taint traces register origin chain across CFG") {
    debugger::ControlFlowGraph cfg;
    cfg.entry_address = 0x1000;

    debugger::BasicBlock bb;
    bb.id = 0;
    bb.start_address = 0x1000;
    bb.end_address = 0x100A;
    bb.instructions = {
        {0x1000, 4, "mov", "rax, [rcx+0x10]", "mov rax, [rcx+0x10]", {0x48, 0x8B, 0x41, 0x10}, 0, ""},
        {0x1004, 3, "add", "rax, rdx",        "add rax, rdx",        {0x48, 0x01, 0xD0},       0, ""},
        {0x1007, 3, "mov", "rbx, rax",        "mov rbx, rax",        {0x48, 0x89, 0xC3},       0, ""},
    };
    cfg.blocks.push_back(std::move(bb));

    const auto steps = debugger::MicroEmulator::backward_taint(cfg, 0x1007, "rbx");
    REQUIRE(steps.size() >= 2);
    CHECK(steps.front().address == 0x1000);
    CHECK(steps.back().address == 0x1007);
}

TEST_CASE("ProtectionInspector detects anti-debug APIs, IAT hook, and standalone RWX caves") {
    auto proc = std::make_unique<EmuMockProcess>();
    const uintptr_t base = 0x140000000ULL;
    const uintptr_t mod_size = 0x20000;
    const uintptr_t foreign_hook = 0x7FF000100000ULL;

    // Minimal PE32+ image with 1 section (.text) and 1 import descriptor (kernel32.dll)
    std::vector<uint8_t> pe(0x3000, 0);
    pe[0] = 'M'; pe[1] = 'Z';
    put_u32_at(pe, 0x3C, 0x80);
    pe[0x80] = 'P'; pe[0x81] = 'E';
    put_u16_at(pe, 0x84, 0x8664); // AMD64
    put_u16_at(pe, 0x86, 1);      // NumberOfSections
    put_u16_at(pe, 0x94, 0xF0);   // SizeOfOptionalHeader
    put_u16_at(pe, 0x98, 0x020B); // PE32+

    // DataDirectory[1] = Import Directory @ 0x80 + 24 + 120 = 0x110 (0x98 + 0x78)
    put_u32_at(pe, 0x110, 0x2000); // Import Dir RVA
    put_u32_at(pe, 0x114, 0x40);

    // Section header @ 0x188 (.text covering 0x1000..0x3000)
    std::memcpy(pe.data() + 0x188, ".text\0\0\0", 8);
    put_u32_at(pe, 0x188 + 8, 0x2000);
    put_u32_at(pe, 0x188 + 12, 0x1000);
    put_u32_at(pe, 0x188 + 16, 0x2000);
    put_u32_at(pe, 0x188 + 20, 0x1000);
    put_u32_at(pe, 0x188 + 36, 0x60000020);

    // IMAGE_IMPORT_DESCRIPTOR @ RVA 0x2000
    put_u32_at(pe, 0x2000 + 0,  0x2100); // OriginalFirstThunk (ILT)
    put_u32_at(pe, 0x2000 + 12, 0x2200); // Name ("kernel32.dll")
    put_u32_at(pe, 0x2000 + 16, 0x2180); // FirstThunk (IAT)
    std::memcpy(pe.data() + 0x2200, "kernel32.dll", 13);

    // ILT entries: [0] -> hint/name "IsDebuggerPresent", [1] -> "QueryPerformanceCounter"
    put_u64_at(pe, 0x2100, 0x2300);
    put_u64_at(pe, 0x2108, 0x2320);
    std::memcpy(pe.data() + 0x2302, "IsDebuggerPresent", 18);
    std::memcpy(pe.data() + 0x2322, "QueryPerformanceCounter", 24);

    // IAT entries: [0] patched to foreign_hook outside legitimate module bounds!
    put_u64_at(pe, 0x2180, foreign_hook);
    put_u64_at(pe, 0x2188, 0x7FF910001000ULL);

    proc->mem[base] = std::move(pe);
    proc->modules = {
        {"emu_mock.exe", "emu_mock.exe", base, mod_size},
        {"kernel32.dll", "kernel32.dll", 0x7FF910000000ULL, 0x100000}
    };
    proc->regions = {
        {base, mod_size, 0x20, 0x1000, 0x1000000, true, false, true, false, true, hal::MemoryType::Image, "emu_mock.exe"},
        {0x5000000ULL, 0x1000, 0x40, 0x1000, 0x20000, true, true, true, false, true, hal::MemoryType::Private, ""}
    };

    const auto rep = debugger::ProtectionInspector::inspect(*proc);
    CHECK(rep.has_anti_debug_apis);
    CHECK(rep.has_timing_checks);
    CHECK(rep.has_iat_hooks);
    CHECK(rep.has_rwx_caves);
    CHECK(rep.risk_score >= 50);
    CHECK(rep.findings.size() >= 4);

    // GuardPage watch enum & coordinator safe error handling on detached session
    CHECK(debugger::WatchKind::GuardPage != debugger::WatchKind::Write);
    debugger::DebugCoordinator coord(std::shared_ptr<hal::IProcess>(std::move(proc)));
    CHECK(!coord.remove_guard_watch(0x1234));
    CHECK(coord.active_guard_watch_addresses().empty());
}
