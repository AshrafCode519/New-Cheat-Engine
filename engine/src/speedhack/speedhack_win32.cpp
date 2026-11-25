#include "../../include/speedhack/speedhack.hpp"

#ifdef _WIN32
#include <windows.h>
#include <cstddef>
#include <cstring>
#include <vector>

namespace nce::speedhack {

namespace {

void emit_rip_rel(std::vector<uint8_t>& code, const std::vector<uint8_t>& prefix, uintptr_t current_inst_addr, uintptr_t target_addr) {
    code.insert(code.end(), prefix.begin(), prefix.end());
    const size_t total_inst_len = prefix.size() + 4;
    const uintptr_t next_rip = current_inst_addr + total_inst_len;
    const int32_t disp = static_cast<int32_t>(static_cast<int64_t>(target_addr) - static_cast<int64_t>(next_rip));
    const auto* p = reinterpret_cast<const uint8_t*>(&disp);
    code.insert(code.end(), p, p + 4);
}

uintptr_t resolve_thunk(hal::IProcess* proc, uintptr_t address) {
    uint8_t bytes[16]{};
    if (proc && proc->read_raw(address, bytes, 16)) {
        // 48 FF 25 disp32 -> JMP QWORD PTR [rip + disp32]
        if (bytes[0] == 0x48 && bytes[1] == 0xFF && bytes[2] == 0x25) {
            int32_t disp = 0;
            std::memcpy(&disp, &bytes[3], 4);
            const uintptr_t ptr_addr = address + 7 + disp;
            uintptr_t dest = 0;
            if (proc->read_raw(ptr_addr, &dest, 8) && dest != 0) {
                return resolve_thunk(proc, dest);
            }
        }
        // FF 25 disp32 -> JMP QWORD PTR [rip + disp32]
        if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            int32_t disp = 0;
            std::memcpy(&disp, &bytes[2], 4);
            const uintptr_t ptr_addr = address + 6 + disp;
            uintptr_t dest = 0;
            if (proc->read_raw(ptr_addr, &dest, 8) && dest != 0) {
                return resolve_thunk(proc, dest);
            }
        }
        // E9 rel32 -> JMP rel32
        if (bytes[0] == 0xE9) {
            int32_t rel = 0;
            std::memcpy(&rel, &bytes[1], 4);
            const uintptr_t dest = address + 5 + rel;
            return resolve_thunk(proc, dest);
        }
    }
    return address;
}

} // anonymous namespace

Speedhack::Speedhack(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
    , m_hook_engine(std::make_unique<debugger::HookEngine>(m_process))
{}

Speedhack::~Speedhack() {
    detach();
}

bool Speedhack::attach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_process || !m_process->is_attached()) {
        return false;
    }
    if (m_state.is_installed) {
        return true;
    }
    return install_hooks();
}

void Speedhack::detach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_state.is_installed) {
        return;
    }
    uninstall_hooks();
}

bool Speedhack::set_speed(double multiplier) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (multiplier <= 0.0) return false;
    m_state.speed_multiplier = multiplier;
    if (!m_state.is_installed) {
        return true;
    }
    return update_shared_time(multiplier, m_state.is_enabled);
}

bool Speedhack::enable() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.is_enabled = true;
    if (!m_state.is_installed) {
        return true;
    }
    return update_shared_time(m_state.speed_multiplier, true);
}

bool Speedhack::disable() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.is_enabled = false;
    if (!m_state.is_installed) {
        return true;
    }
    return update_shared_time(m_state.speed_multiplier, false);
}

bool Speedhack::install_hooks() {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return false;

    auto rawQPC = reinterpret_cast<uintptr_t>(GetProcAddress(k32, "QueryPerformanceCounter"));
    auto rawGTC = reinterpret_cast<uintptr_t>(GetProcAddress(k32, "GetTickCount64"));
    if (rawQPC == 0 || rawGTC == 0) return false;

    // Resolve any thunks or API forwarders to the real function code
    const uintptr_t pQPC = resolve_thunk(m_process.get(), rawQPC);
    const uintptr_t pGTC = resolve_thunk(m_process.get(), rawGTC);

    uintptr_t pGTC32 = 0;
    if (auto rawGTC32 = reinterpret_cast<uintptr_t>(GetProcAddress(k32, "GetTickCount"))) {
        const uintptr_t resolved = resolve_thunk(m_process.get(), rawGTC32);
        if (resolved != pQPC && resolved != pGTC) pGTC32 = resolved;
    }

    // Optional winmm!timeGetTime (only if winmm.dll is loaded in this/target module list)
    uintptr_t pTGT = 0;
    if (HMODULE winmm = GetModuleHandleA("winmm.dll")) {
        if (auto rawTGT = reinterpret_cast<uintptr_t>(GetProcAddress(winmm, "timeGetTime"))) {
            const uintptr_t resolved = resolve_thunk(m_process.get(), rawTGT);
            if (resolved != pQPC && resolved != pGTC && resolved != pGTC32) pTGT = resolved;
        }
    }

    // Allocate 4096 bytes code cave in target process near pQPC
    uintptr_t cave_addr = m_process->allocate_memory(4096, 0x40 /* PAGE_EXECUTE_READWRITE */, pQPC);
    if (cave_addr == 0) return false;

    // Prepare initial header (disabled initially for safety during hook setup)
    LARGE_INTEGER qpc_now{};
    QueryPerformanceCounter(&qpc_now);
    ULONGLONG gtc_now = GetTickCount64();

    SpeedhackCaveHeader header{};
    header.real_base_qpc = qpc_now.QuadPart;
    header.sim_base_qpc = qpc_now.QuadPart;
    header.real_base_gtc = gtc_now;
    header.sim_base_gtc = gtc_now;
    header.speed_multiplier = m_state.speed_multiplier;
    header.is_enabled = 0; // starts disabled until trampolines are stored

    const uintptr_t qpc_entry   = cave_addr + 0x80;
    const uintptr_t gtc_entry   = cave_addr + 0x160;
    const uintptr_t tgt_entry   = cave_addr + 0x240;
    const uintptr_t gtc32_entry = cave_addr + 0x320;

    // Construct Hook_QueryPerformanceCounter code
    std::vector<uint8_t> qpc_code;
    {
        uintptr_t cur = qpc_entry;
        // sub rsp, 40
        qpc_code.insert(qpc_code.end(), {0x48, 0x83, 0xEC, 0x28}); cur += 4;
        // mov [rsp + 0x30], rcx (save caller's lpPerformanceCount)
        qpc_code.insert(qpc_code.end(), {0x48, 0x89, 0x4C, 0x24, 0x30}); cur += 5;

        // mov rax, [rip + orig_qpc_trampoline]
        emit_rip_rel(qpc_code, {0x48, 0x8B, 0x05}, cur, cave_addr + offsetof(SpeedhackCaveHeader, orig_qpc_trampoline));
        cur += 7;
        // test rax, rax
        qpc_code.insert(qpc_code.end(), {0x48, 0x85, 0xC0}); cur += 3;
        // jz .failed (skips 71 bytes = 0x47 to .failed)
        qpc_code.insert(qpc_code.end(), {0x74, 0x47}); cur += 2;

        // mov ecx, [rip + is_enabled]
        emit_rip_rel(qpc_code, {0x8B, 0x0D}, cur, cave_addr + offsetof(SpeedhackCaveHeader, is_enabled));
        cur += 6;
        // test ecx, ecx
        qpc_code.insert(qpc_code.end(), {0x85, 0xC9}); cur += 2;
        // jnz .do_speed (skips 11 bytes to .do_speed)
        qpc_code.insert(qpc_code.end(), {0x75, 0x0B}); cur += 2;

        // Bypass:
        // mov rcx, [rsp + 0x30]
        qpc_code.insert(qpc_code.end(), {0x48, 0x8B, 0x4C, 0x24, 0x30}); cur += 5;
        // add rsp, 40
        qpc_code.insert(qpc_code.end(), {0x48, 0x83, 0xC4, 0x28}); cur += 4;
        // jmp rax
        qpc_code.insert(qpc_code.end(), {0xFF, 0xE0}); cur += 2;

        // .do_speed:
        // lea rcx, [rsp + 0x20]
        qpc_code.insert(qpc_code.end(), {0x48, 0x8D, 0x4C, 0x24, 0x20}); cur += 5;
        // call rax
        qpc_code.insert(qpc_code.end(), {0xFF, 0xD0}); cur += 2;
        // test eax, eax
        qpc_code.insert(qpc_code.end(), {0x85, 0xC0}); cur += 2;
        // jz .failed (skips 50 bytes = 0x32 to .failed)
        qpc_code.insert(qpc_code.end(), {0x74, 0x32}); cur += 2;

        // mov rax, [rsp + 0x20]
        qpc_code.insert(qpc_code.end(), {0x48, 0x8B, 0x44, 0x24, 0x20}); cur += 5;
        // mov rdx, [rip + real_base_qpc]
        emit_rip_rel(qpc_code, {0x48, 0x8B, 0x15}, cur, cave_addr + offsetof(SpeedhackCaveHeader, real_base_qpc));
        cur += 7;
        // sub rax, rdx
        qpc_code.insert(qpc_code.end(), {0x48, 0x29, 0xD0}); cur += 3;
        // cvtsi2sd xmm0, rax
        qpc_code.insert(qpc_code.end(), {0xF2, 0x48, 0x0F, 0x2A, 0xC0}); cur += 5;
        // mulsd xmm0, [rip + speed_multiplier]
        emit_rip_rel(qpc_code, {0xF2, 0x0F, 0x59, 0x05}, cur, cave_addr + offsetof(SpeedhackCaveHeader, speed_multiplier));
        cur += 8;
        // cvttsd2si rax, xmm0
        qpc_code.insert(qpc_code.end(), {0xF2, 0x48, 0x0F, 0x2C, 0xC0}); cur += 5;
        // add rax, [rip + sim_base_qpc]
        emit_rip_rel(qpc_code, {0x48, 0x03, 0x05}, cur, cave_addr + offsetof(SpeedhackCaveHeader, sim_base_qpc));
        cur += 7;
        // mov rcx, [rsp + 0x30]
        qpc_code.insert(qpc_code.end(), {0x48, 0x8B, 0x4C, 0x24, 0x30}); cur += 5;
        // mov [rcx], rax
        qpc_code.insert(qpc_code.end(), {0x48, 0x89, 0x01}); cur += 3;
        // mov eax, 1
        qpc_code.insert(qpc_code.end(), {0xB8, 0x01, 0x00, 0x00, 0x00}); cur += 5;
        // add rsp, 40
        qpc_code.insert(qpc_code.end(), {0x48, 0x83, 0xC4, 0x28}); cur += 4;
        // ret
        qpc_code.push_back(0xC3); cur += 1;

        // .failed:
        // xor eax, eax
        qpc_code.insert(qpc_code.end(), {0x31, 0xC0}); cur += 2;
        // add rsp, 40
        qpc_code.insert(qpc_code.end(), {0x48, 0x83, 0xC4, 0x28}); cur += 4;
        // ret
        qpc_code.push_back(0xC3);
    }

    // Construct millisecond-based Hook stub (shared by GetTickCount64 and timeGetTime)
    auto build_ms_hook = [&](uintptr_t entry, size_t tramp_offset) {
        std::vector<uint8_t> code;
        uintptr_t cur = entry;
        // sub rsp, 40
        code.insert(code.end(), {0x48, 0x83, 0xEC, 0x28}); cur += 4;
        // mov rax, [rip + orig_trampoline]
        emit_rip_rel(code, {0x48, 0x8B, 0x05}, cur, cave_addr + tramp_offset);
        cur += 7;
        // test rax, rax
        code.insert(code.end(), {0x48, 0x85, 0xC0}); cur += 3;
        // jz .failed (skips 50 bytes = 0x32 to .failed)
        code.insert(code.end(), {0x74, 0x32}); cur += 2;
        // mov ecx, [rip + is_enabled]
        emit_rip_rel(code, {0x8B, 0x0D}, cur, cave_addr + offsetof(SpeedhackCaveHeader, is_enabled));
        cur += 6;
        // test ecx, ecx
        code.insert(code.end(), {0x85, 0xC9}); cur += 2;
        // jnz .do_ms (skips 6 bytes to .do_ms)
        code.insert(code.end(), {0x75, 0x06}); cur += 2;
        // Bypass: add rsp, 40 ; jmp rax
        code.insert(code.end(), {0x48, 0x83, 0xC4, 0x28}); cur += 4;
        code.insert(code.end(), {0xFF, 0xE0}); cur += 2;
        // .do_ms: call rax
        code.insert(code.end(), {0xFF, 0xD0}); cur += 2;
        // mov rdx, [rip + real_base_gtc]
        emit_rip_rel(code, {0x48, 0x8B, 0x15}, cur, cave_addr + offsetof(SpeedhackCaveHeader, real_base_gtc));
        cur += 7;
        // sub rax, rdx
        code.insert(code.end(), {0x48, 0x29, 0xD0}); cur += 3;
        // cvtsi2sd xmm0, rax
        code.insert(code.end(), {0xF2, 0x48, 0x0F, 0x2A, 0xC0}); cur += 5;
        // mulsd xmm0, [rip + speed_multiplier]
        emit_rip_rel(code, {0xF2, 0x0F, 0x59, 0x05}, cur, cave_addr + offsetof(SpeedhackCaveHeader, speed_multiplier));
        cur += 8;
        // cvttsd2si rax, xmm0
        code.insert(code.end(), {0xF2, 0x48, 0x0F, 0x2C, 0xC0}); cur += 5;
        // add rax, [rip + sim_base_gtc]
        emit_rip_rel(code, {0x48, 0x03, 0x05}, cur, cave_addr + offsetof(SpeedhackCaveHeader, sim_base_gtc));
        cur += 7;
        // add rsp, 40 ; ret
        code.insert(code.end(), {0x48, 0x83, 0xC4, 0x28}); cur += 4;
        code.push_back(0xC3); cur += 1;
        // .failed: xor eax, eax ; add rsp, 40 ; ret
        code.insert(code.end(), {0x31, 0xC0}); cur += 2;
        code.insert(code.end(), {0x48, 0x83, 0xC4, 0x28}); cur += 4;
        code.push_back(0xC3);
        return code;
    };

    const std::vector<uint8_t> gtc_code   = build_ms_hook(gtc_entry, offsetof(SpeedhackCaveHeader, orig_gtc_trampoline));
    const std::vector<uint8_t> tgt_code   = build_ms_hook(tgt_entry, offsetof(SpeedhackCaveHeader, orig_tgt_trampoline));
    const std::vector<uint8_t> gtc32_code = build_ms_hook(gtc32_entry, offsetof(SpeedhackCaveHeader, orig_gtc32_trampoline));

    // Write initial header and code into the cave
    if (!m_process->write_raw(cave_addr, &header, sizeof(header), true) ||
        !m_process->write_raw(qpc_entry, qpc_code.data(), qpc_code.size(), true) ||
        !m_process->write_raw(gtc_entry, gtc_code.data(), gtc_code.size(), true) ||
        !m_process->write_raw(tgt_entry, tgt_code.data(), tgt_code.size(), true) ||
        !m_process->write_raw(gtc32_entry, gtc32_code.data(), gtc32_code.size(), true)) {
        m_process->free_memory(cave_addr);
        return false;
    }

    // Detour QPC and write trampoline pointer immediately
    uintptr_t qpc_tramp = 0;
    if (!m_hook_engine->install_detour(pQPC, qpc_entry, &qpc_tramp)) {
        m_process->free_memory(cave_addr);
        return false;
    }
    header.orig_qpc_trampoline = qpc_tramp;
    m_process->write_raw(cave_addr + offsetof(SpeedhackCaveHeader, orig_qpc_trampoline), &qpc_tramp, sizeof(qpc_tramp), true);

    // Detour GTC and write trampoline pointer immediately
    uintptr_t gtc_tramp = 0;
    if (!m_hook_engine->install_detour(pGTC, gtc_entry, &gtc_tramp)) {
        m_hook_engine->remove_hook(pQPC);
        m_process->free_memory(cave_addr);
        return false;
    }
    header.orig_gtc_trampoline = gtc_tramp;
    m_process->write_raw(cave_addr + offsetof(SpeedhackCaveHeader, orig_gtc_trampoline), &gtc_tramp, sizeof(gtc_tramp), true);

    // Optional detour for winmm!timeGetTime
    if (pTGT != 0) {
        uintptr_t tgt_tramp = 0;
        if (m_hook_engine->install_detour(pTGT, tgt_entry, &tgt_tramp)) {
            header.orig_tgt_trampoline = tgt_tramp;
            m_process->write_raw(cave_addr + offsetof(SpeedhackCaveHeader, orig_tgt_trampoline), &tgt_tramp, sizeof(tgt_tramp), true);
            m_state.tgt_target = pTGT;
        }
    }

    // Optional detour for kernel32!GetTickCount (32-bit DWORD return in EAX)
    if (pGTC32 != 0) {
        uintptr_t gtc32_tramp = 0;
        if (m_hook_engine->install_detour(pGTC32, gtc32_entry, &gtc32_tramp)) {
            header.orig_gtc32_trampoline = gtc32_tramp;
            m_process->write_raw(cave_addr + offsetof(SpeedhackCaveHeader, orig_gtc32_trampoline), &gtc32_tramp, sizeof(gtc32_tramp), true);
            m_state.gtc32_target = pGTC32;
        }
    }

    m_state.is_installed = true;
    m_state.cave_address = cave_addr;
    m_state.qpc_target = pQPC;
    m_state.gtc_target = pGTC;

    // Enable if requested
    if (m_state.is_enabled) {
        update_shared_time(m_state.speed_multiplier, true);
    }

    return true;
}

void Speedhack::uninstall_hooks() {
    if (m_hook_engine) {
        m_hook_engine->remove_all_hooks();
    }
    if (m_process && m_process->is_attached() && m_state.cave_address != 0) {
        m_process->free_memory(m_state.cave_address);
    }
    m_state.is_installed = false;
    m_state.cave_address = 0;
    m_state.qpc_target = 0;
    m_state.gtc_target = 0;
    m_state.tgt_target = 0;
    m_state.gtc32_target = 0;
}

bool Speedhack::update_shared_time(double new_speed, bool enable_flag) {
    if (!m_state.is_installed || !m_process || !m_process->is_attached() || m_state.cave_address == 0) {
        return false;
    }

    SpeedhackCaveHeader header{};
    if (!m_process->read_raw(m_state.cave_address, &header, sizeof(header))) {
        return false;
    }

    LARGE_INTEGER qpc_now{};
    ULONGLONG gtc_now = 0;
    if (m_process->get_pid() == GetCurrentProcessId() && header.orig_qpc_trampoline != 0 && header.orig_gtc_trampoline != 0) {
        auto raw_qpc = reinterpret_cast<BOOL(WINAPI*)(LARGE_INTEGER*)>(header.orig_qpc_trampoline);
        raw_qpc(&qpc_now);
        auto raw_gtc = reinterpret_cast<ULONGLONG(WINAPI*)(void)>(header.orig_gtc_trampoline);
        gtc_now = raw_gtc();
    } else {
        QueryPerformanceCounter(&qpc_now);
        gtc_now = GetTickCount64();
    }

    // Calculate current simulated time using previous speed multiplier
    const int64_t delta_qpc = qpc_now.QuadPart - header.real_base_qpc;
    const int64_t cur_sim_qpc = header.sim_base_qpc + static_cast<int64_t>(delta_qpc * header.speed_multiplier);

    const uint64_t delta_gtc = gtc_now - header.real_base_gtc;
    const uint64_t cur_sim_gtc = header.sim_base_gtc + static_cast<uint64_t>(delta_gtc * header.speed_multiplier);

    // Update base to current time with new multiplier
    header.real_base_qpc = qpc_now.QuadPart;
    header.sim_base_qpc = cur_sim_qpc;
    header.real_base_gtc = gtc_now;
    header.sim_base_gtc = cur_sim_gtc;
    header.speed_multiplier = new_speed;
    header.is_enabled = enable_flag ? 1 : 0;

    if (!m_process->write_raw(m_state.cave_address, &header, sizeof(header), true)) {
        return false;
    }

    m_state.speed_multiplier = new_speed;
    m_state.is_enabled = enable_flag;
    return true;
}

} // namespace nce::speedhack
#else

#include "../../include/debugger/elf_analyzer.hpp"
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <vector>

namespace nce::speedhack {

namespace {

int64_t host_monotonic_ns() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
}

void emit_abs_addr(std::vector<uint8_t>& code, uint64_t val) {
    const auto* p = reinterpret_cast<const uint8_t*>(&val);
    code.insert(code.end(), p, p + 8);
}

} // namespace

Speedhack::Speedhack(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
    , m_hook_engine(std::make_unique<debugger::HookEngine>(m_process))
{}

Speedhack::~Speedhack() {
    detach();
}

bool Speedhack::attach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_process || !m_process->is_attached()) return false;
    if (m_state.is_installed) return true;
    return install_hooks();
}

void Speedhack::detach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_state.is_installed) return;
    uninstall_hooks();
}

bool Speedhack::set_speed(double multiplier) {
    if (multiplier < 0.0) multiplier = 0.0;
    if (multiplier > 100.0) multiplier = 100.0;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_state.is_installed) {
        if (!m_process || !m_process->is_attached() || !install_hooks()) return false;
    }
    return update_shared_time(multiplier, m_state.is_enabled);
}

bool Speedhack::enable() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_state.is_installed) {
        if (!m_process || !m_process->is_attached() || !install_hooks()) return false;
    }
    return update_shared_time(m_state.speed_multiplier, true);
}

bool Speedhack::disable() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_state.is_installed) return false;
    return update_shared_time(m_state.speed_multiplier, false);
}

bool Speedhack::install_hooks() {
    if (!m_process || !m_process->is_attached()) return false;
#if !defined(__x86_64__)
    return false;
#else
    uintptr_t clock_va = 0;
    for (const auto& mod : m_process->get_modules()) {
        std::string lower = mod.name;
        for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower.find("libc.so") != std::string::npos || lower.find("vdso") != std::string::npos) {
            if (auto elf = debugger::ELFAnalyzer::analyze(*m_process, mod.base_address)) {
                if (auto* sym = debugger::ELFAnalyzer::find_symbol_by_name(*elf, "clock_gettime")) {
                    clock_va = sym->va;
                    if (lower.find("libc.so") != std::string::npos) break;
                }
            }
        }
    }
    if (clock_va == 0) return false;

    const uintptr_t data_cave = m_process->allocate_memory(4096, 0x40, clock_va);
    if (data_cave == 0) return false;

    SpeedhackCaveHeader header{};
    header.real_base_qpc = host_monotonic_ns();
    header.sim_base_qpc  = header.real_base_qpc;
    header.speed_multiplier = m_state.speed_multiplier;
    header.is_enabled    = 1;

    if (!m_process->write_raw(data_cave, &header, sizeof(header), true)) {
        m_process->free_memory(data_cave, 4096);
        return false;
    }

    // SysV ABI detour for int clock_gettime(clockid_t clk_id [rdi], struct timespec* tp [rsi])
    // Located at data_cave + 0x80 so install_detour redirects clock_gettime -> stub_entry and gives us a valid trampoline.
    const uintptr_t stub_entry = data_cave + 0x80;
    std::vector<uint8_t> stub;
    auto push_bytes = [&](std::initializer_list<uint8_t> bs) { stub.insert(stub.end(), bs); };
    auto patch_rel8 = [&](size_t jcc_disp_off, size_t target_off) {
        stub[jcc_disp_off] = static_cast<uint8_t>(static_cast<int8_t>(target_off - (jcc_disp_off + 1)));
    };

    // push rbx; push rdi; push rsi
    push_bytes({0x53, 0x57, 0x56});
    // mov rax, <data_cave + offsetof(orig_qpc_trampoline)>
    push_bytes({0x48, 0xB8}); emit_abs_addr(stub, data_cave + offsetof(SpeedhackCaveHeader, orig_qpc_trampoline));
    // mov rax, [rax]; test rax, rax; jz bypass_ret
    push_bytes({0x48, 0x8B, 0x00, 0x48, 0x85, 0xC0, 0x74});
    const size_t jz_null_off = stub.size(); stub.push_back(0);
    // call rax (calls original clock_gettime via real trampoline)
    push_bytes({0xFF, 0xD0});
    // pop rsi; pop rdi; test eax, eax; jnz done
    push_bytes({0x5E, 0x5F, 0x85, 0xC0, 0x75});
    const size_t jnz_err_off = stub.size(); stub.push_back(0);
    // test rsi, rsi; jz done
    push_bytes({0x48, 0x85, 0xF6, 0x74});
    const size_t jz_tp_off = stub.size(); stub.push_back(0);
    // mov rbx, <data_cave>; cmp dword ptr [rbx + is_enabled], 0; jz done
    push_bytes({0x48, 0xBB}); emit_abs_addr(stub, data_cave);
    push_bytes({0x83, 0x7B, static_cast<uint8_t>(offsetof(SpeedhackCaveHeader, is_enabled)), 0x00, 0x74});
    const size_t jz_dis_off = stub.size(); stub.push_back(0);

    // rcx = tp->tv_sec * 1000000000 + tp->tv_nsec
    push_bytes({0x48, 0x8B, 0x0E});                         // mov rcx, [rsi]
    push_bytes({0x48, 0x69, 0xC9, 0x00, 0xCA, 0x9A, 0x3B}); // imul rcx, rcx, 1000000000
    push_bytes({0x48, 0x03, 0x4E, 0x08});                   // add rcx, [rsi + 8]
    push_bytes({0x48, 0x2B, 0x0B});                         // sub rcx, [rbx] (real_base_qpc)
    push_bytes({0xF2, 0x48, 0x0F, 0x2A, 0xC1});             // cvtsi2sd xmm0, rcx
    push_bytes({0xF2, 0x0F, 0x59, 0x43, 0x10});             // mulsd xmm0, qword ptr [rbx + 0x10]
    push_bytes({0xF2, 0x48, 0x0F, 0x2C, 0xC8});             // cvttsd2si rcx, xmm0
    push_bytes({0x48, 0x03, 0x4B, 0x08});                   // add rcx, [rbx + 8] (sim_base_qpc)
    // Divide scaled nanoseconds by 1e9 -> rax=sec, rdx=nsec
    push_bytes({0x48, 0x89, 0xC8, 0x48, 0x99});             // mov rax, rcx; cqo
    push_bytes({0x48, 0xB9}); emit_abs_addr(stub, 1000000000ULL);
    push_bytes({0x48, 0xF7, 0xF9});                         // idiv rcx
    push_bytes({0x48, 0x89, 0x06, 0x48, 0x89, 0x56, 0x08}); // mov [rsi], rax; mov [rsi + 8], rdx
    push_bytes({0x31, 0xC0});                               // xor eax, eax (return 0)

    const size_t done_off = stub.size();
    push_bytes({0x5B, 0xC3});                               // done: pop rbx; ret

    const size_t null_off = stub.size();
    push_bytes({0x5E, 0x5F, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x5B, 0xC3}); // bypass_ret: pop rsi; pop rdi; mov eax, -1; pop rbx; ret

    patch_rel8(jnz_err_off, done_off);
    patch_rel8(jz_tp_off,   done_off);
    patch_rel8(jz_dis_off,  done_off);
    patch_rel8(jz_null_off, null_off);

    if (!m_process->write_raw(stub_entry, stub.data(), stub.size(), true)) {
        m_process->free_memory(data_cave, 4096);
        return false;
    }

    uintptr_t tramp_addr = 0;
    if (!m_hook_engine->install_detour(clock_va, stub_entry, &tramp_addr)) {
        m_process->free_memory(data_cave, 4096);
        return false;
    }

    header.orig_qpc_trampoline = tramp_addr;
    m_process->write_raw(data_cave + offsetof(SpeedhackCaveHeader, orig_qpc_trampoline), &tramp_addr, sizeof(tramp_addr), true);

    m_state.cave_address = data_cave;
    m_state.qpc_target   = clock_va;
    m_state.is_installed = true;
    m_state.is_enabled   = true;
    return true;
#endif
}

void Speedhack::uninstall_hooks() {
    if (m_state.qpc_target != 0) {
        m_hook_engine->remove_hook(m_state.qpc_target);
    }
    if (m_state.cave_address != 0 && m_process && m_process->is_attached()) {
        m_process->free_memory(m_state.cave_address, 4096);
    }
    m_state = SpeedhackState{};
}

bool Speedhack::update_shared_time(double new_speed, bool enable_flag) {
    if (!m_process || !m_process->is_attached() || m_state.cave_address == 0) return false;
    SpeedhackCaveHeader header{};
    if (!m_process->read_raw(m_state.cave_address, &header, sizeof(header))) return false;

    const int64_t now_ns = host_monotonic_ns();
    const int64_t delta_ns = now_ns - header.real_base_qpc;
    const int64_t cur_sim  = header.sim_base_qpc + static_cast<int64_t>(delta_ns * header.speed_multiplier);
    header.real_base_qpc   = now_ns;
    header.sim_base_qpc    = cur_sim;
    header.speed_multiplier = new_speed;
    header.is_enabled      = enable_flag ? 1u : 0u;

    if (!m_process->write_raw(m_state.cave_address, &header, sizeof(header), true)) return false;
    m_state.speed_multiplier = new_speed;
    m_state.is_enabled = enable_flag;
    return true;
}

} // namespace nce::speedhack
#endif
