#include "../../include/debugger/access_watcher.hpp"
#include "../../include/debugger/disassembler.hpp"
#include "../../include/utils/hex_utils.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <sstream>

namespace nce::debugger {

namespace {

// Decodes the memory operand of the hit instruction into a base register + displacement, so the caller can
// see which pointer the value hangs off. Only the simple [reg + disp] / [reg] form is reported.
void find_base(const DecodedInstruction& insn, std::string& base_reg, int64_t& base_off) {
    const std::string& ops = insn.operands;
    const size_t open = ops.find('[');
    const size_t close = ops.find(']', open);
    if (open == std::string::npos || close == std::string::npos) return;
    std::string inside = ops.substr(open + 1, close - open - 1); // "rcx + 0x10", "rax", "rbp - 0x8"
    // no scaled index (contains '*'): those aren't a plain base pointer
    if (inside.find('*') != std::string::npos) return;

    std::string reg;
    size_t i = 0;
    while (i < inside.size() && (std::isalnum(static_cast<unsigned char>(inside[i])))) reg += inside[i++];
    if (reg.empty() || !(reg[0] == 'r' || reg[0] == 'e')) return;
    base_reg = reg;
    base_off = 0;
    while (i < inside.size() && inside[i] == ' ') ++i;
    if (i < inside.size() && (inside[i] == '+' || inside[i] == '-')) {
        const int sign = inside[i] == '-' ? -1 : 1;
        ++i;
        std::string num = inside.substr(i);
        base_off = sign * static_cast<int64_t>(std::strtoll(num.c_str(), nullptr, 0));
    }
}

// A data breakpoint traps after the store, so RIP points past the writing instruction. x86 has no reliable
// backward decode, so this reads the bytes before RIP and finds the instruction stream that lands exactly on
// RIP, taking the last instruction as the writer. `start_address` gets where that instruction begins.
DecodedInstruction writer_before(const hal::IProcess& process, uintptr_t rip, uintptr_t& start_address) {
    constexpr size_t window = 15; // the longest an x86 instruction can be
    if (rip <= window) return {};
    uint8_t buf[window] = {0};
    if (!process.read_raw(rip - window, buf, window)) return {};

    for (size_t back = window; back >= 1; --back) { // try the farthest-back anchor first (least coincidental)
        const uintptr_t anchor = rip - back;
        uintptr_t cur = anchor;
        DecodedInstruction last;
        bool clean = true;
        for (int guard = 0; cur < rip && guard < 16; ++guard) {
            const size_t offset = cur - (rip - window);
            auto d = Disassembler::decode(buf + offset, window - offset, cur);
            if (d.length == 0 || d.mnemonic == "db") { clean = false; break; }
            last = d;
            cur += d.length;
        }
        if (clean && cur == rip && last.length > 0) {
            start_address = rip - last.length;
            return last;
        }
    }
    return {};
}

std::string locate(uintptr_t address, const std::vector<hal::ModuleInfo>& modules) {
    for (const auto& m : modules) {
        if (address >= m.base_address && address - m.base_address < m.size) {
            std::ostringstream ss;
            ss << m.name << "+0x" << std::uppercase << std::hex << (address - m.base_address);
            return ss.str();
        }
    }
    return utils::format_address(address);
}

} // anonymous namespace

uint64_t Registers::by_name(const std::string& name) const {
    static const std::vector<std::pair<const char*, uint64_t Registers::*>> table = {
        {"rax", &Registers::rax}, {"rbx", &Registers::rbx}, {"rcx", &Registers::rcx}, {"rdx", &Registers::rdx},
        {"rsi", &Registers::rsi}, {"rdi", &Registers::rdi}, {"rbp", &Registers::rbp}, {"rsp", &Registers::rsp},
        {"rip", &Registers::rip}, {"r8", &Registers::r8}, {"r9", &Registers::r9}, {"r10", &Registers::r10},
        {"r11", &Registers::r11}, {"r12", &Registers::r12}, {"r13", &Registers::r13}, {"r14", &Registers::r14},
        {"r15", &Registers::r15},
    };
    // 32-bit names (eax..) map to the low half of the 64-bit register
    std::string key = name;
    if (!key.empty() && key[0] == 'e') key = "r" + key.substr(1);
    for (const auto& [n, member] : table) {
        if (key == n) return this->*member;
    }
    return 0;
}

uintptr_t AccessHit::base_pointer() const {
    return base_register.empty() ? 0 : static_cast<uintptr_t>(registers.by_name(base_register));
}

AccessWatcher::~AccessWatcher() { stop(); }

bool AccessWatcher::start(std::shared_ptr<hal::IProcess> process, uintptr_t address, size_t size, WatchKind kind) {
    stop();
    if (!process || !process->is_attached() || address == 0) return false;
    if (size != 1 && size != 2 && size != 4 && size != 8) size = 4;

    m_process = std::move(process);
    m_modules = m_process->get_modules();
    m_address = address;
    m_size = size;
    m_kind = kind;
    m_pid = m_process->get_pid();
    m_stop = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hits.clear();
    }

    // DebugActiveProcess, WaitForDebugEvent and ContinueDebugEvent must all run on one thread, so the attach
    // happens inside the debug thread; start() waits here for it to report success or failure.
    std::promise<bool> attached;
    auto future = attached.get_future();
    m_thread = std::thread([this, p = std::move(attached)]() mutable { run(std::move(p)); });
    const bool ok = future.get();
    if (!ok && m_thread.joinable()) m_thread.join();
    return ok;
}

void AccessWatcher::stop() {
    if (!m_active && !m_thread.joinable()) return;
    m_stop = true;
    if (m_thread.joinable()) m_thread.join();
    m_active = false;
    m_address = 0;
    m_pid = 0;
}

// Sets (or clears) the DR0 hardware breakpoint in one thread's debug registers
void AccessWatcher::arm_thread(void* handle, bool enable) const {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(static_cast<HANDLE>(handle), &ctx)) return;
    if (enable) {
        ctx.Dr0 = m_address;
        ctx.Dr7 |= 1ULL;              // L0: breakpoint 0 enabled for this thread
        ctx.Dr7 &= ~(0xFULL << 16);   // clear RW0 + LEN0
        const uint64_t rw = (m_kind == WatchKind::Access) ? 3 : 1; // 01 = on write, 11 = on read/write
        uint64_t len = 3;             // LEN0: 00=1, 01=2, 11=4, 10=8
        if (m_size == 1) len = 0;
        else if (m_size == 2) len = 1;
        else if (m_size == 8) len = 2;
        ctx.Dr7 |= (rw << 16) | (len << 18);
    } else {
        ctx.Dr0 = 0;
        ctx.Dr7 &= ~1ULL;
    }
    SetThreadContext(static_cast<HANDLE>(handle), &ctx);
}

void AccessWatcher::record_hit(uint32_t thread_id) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id);
    if (!thread) return;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &ctx)) {
        const uintptr_t rip = static_cast<uintptr_t>(ctx.Rip);
        // The write already happened; find the instruction that ends at RIP (the one that did it)
        uintptr_t writer_addr = rip;
        auto decoded = writer_before(*m_process, rip, writer_addr);
        if (decoded.length == 0) { // couldn't back-decode: fall back to the instruction at RIP
            uint8_t code[16] = {0};
            m_process->read_raw(rip, code, sizeof code);
            decoded = Disassembler::decode(code, sizeof code, rip);
            writer_addr = rip;
        }

        Registers r;
        r.rax = ctx.Rax; r.rbx = ctx.Rbx; r.rcx = ctx.Rcx; r.rdx = ctx.Rdx; r.rsi = ctx.Rsi; r.rdi = ctx.Rdi;
        r.rbp = ctx.Rbp; r.rsp = ctx.Rsp; r.rip = ctx.Rip; r.r8 = ctx.R8; r.r9 = ctx.R9; r.r10 = ctx.R10;
        r.r11 = ctx.R11; r.r12 = ctx.R12; r.r13 = ctx.R13; r.r14 = ctx.R14; r.r15 = ctx.R15; r.eflags = ctx.EFlags;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = std::find_if(m_hits.begin(), m_hits.end(), [&](const AccessHit& h) { return h.instruction == writer_addr; });
            if (it != m_hits.end()) {
                ++it->count;
                it->registers = r;
            } else {
                AccessHit hit;
                hit.instruction = writer_addr;
                hit.location = locate(writer_addr, m_modules);
                hit.disassembly = decoded.mnemonic + (decoded.operands.empty() ? "" : " " + decoded.operands);
                hit.bytes = decoded.bytes;
                hit.registers = r;
                hit.count = 1;
                find_base(decoded, hit.base_register, hit.base_offset);
                m_hits.push_back(std::move(hit));
            }
        }

        // A data breakpoint traps AFTER the store, so RIP is already past it: just clear the trigger status
        // and leave the breakpoint armed. (An execute breakpoint would need a single-step dance; writes don't.)
        ctx.Dr6 = 0;
        SetThreadContext(thread, &ctx);
    }
    CloseHandle(thread);
}

void AccessWatcher::run(std::promise<bool> attached) {
    if (!DebugActiveProcess(m_pid)) { attached.set_value(false); return; } // another debugger, or no permission
    DebugSetProcessKillOnExit(FALSE); // detaching must not kill the game
    m_active = true;
    attached.set_value(true);

    // DebugActiveProcess reports the existing threads through CREATE_PROCESS (the main thread) and
    // CREATE_THREAD events right after attaching; new threads come the same way later. Arming the breakpoint
    // as each thread is reported is reliable, unlike setting it before the attach events are consumed.
    DEBUG_EVENT event{};
    while (!m_stop) {
        if (!WaitForDebugEvent(&event, 50)) continue;
        DWORD status = DBG_CONTINUE;

        if (event.dwProcessId == m_pid && event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            arm_thread(event.u.CreateProcessInfo.hThread, true); // the main thread
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
        } else if (event.dwProcessId == m_pid && event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            arm_thread(event.u.CreateThread.hThread, true); // another (or new) thread
        } else if (event.dwProcessId == m_pid && event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const DWORD code = event.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_SINGLE_STEP) {
                record_hit(event.dwThreadId); // a hardware data breakpoint reports as a single-step exception
            } else if (code != EXCEPTION_BREAKPOINT) {
                status = DBG_EXCEPTION_NOT_HANDLED; // leave real exceptions to the target
            }
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && event.dwProcessId == m_pid) {
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            break;
        }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);
    }

    DebugActiveProcessStop(m_pid);
}

std::vector<AccessHit> AccessWatcher::hits() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<AccessHit> out = m_hits;
    std::sort(out.begin(), out.end(), [](const AccessHit& a, const AccessHit& b) { return a.count > b.count; });
    return out;
}

void AccessWatcher::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hits.clear();
}

} // namespace nce::debugger
#endif // _WIN32
