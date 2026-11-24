#pragma once

#include "../hal/process.hpp"
#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace nce::debugger {

// What to catch: a write to the address, or any access (read or write)
enum class WatchKind { Write, Access };

struct Registers {
    uint64_t rax{0}, rbx{0}, rcx{0}, rdx{0}, rsi{0}, rdi{0}, rbp{0}, rsp{0}, rip{0};
    uint64_t r8{0}, r9{0}, r10{0}, r11{0}, r12{0}, r13{0}, r14{0}, r15{0}, eflags{0};
    [[nodiscard]] uint64_t by_name(const std::string& name) const;
};

// One machine instruction caught touching the watched address
struct AccessHit {
    uintptr_t instruction{0};    // the code address (RIP) that did the access
    std::string location;        // "game.exe+0x1234", or the absolute address off any module
    std::string disassembly;     // "mov [rcx+0x10], eax"
    std::vector<uint8_t> bytes;  // the instruction's bytes
    Registers registers;
    size_t count{0};             // how many times this instruction hit the address
    // The register + offset that most likely forms the value's base pointer (from the memory operand),
    // e.g. {"rcx", 0x10} for `mov [rcx+0x10], eax`. Empty name when the instruction has no [reg+disp] operand.
    std::string base_register;
    int64_t base_offset{0};
    [[nodiscard]] uintptr_t base_pointer() const; // registers.by_name(base_register) (0 if none)
};

// "Find what writes/accesses this address": sets a hardware breakpoint (debug registers) on the address in
// every thread of the target and reports the instructions that hit it, with their registers, so a value can
// be traced back to the code that changes it and to its base pointer. Windows only; needs debug access.
class AccessWatcher {
public:
    AccessWatcher() = default;
    ~AccessWatcher();
    AccessWatcher(const AccessWatcher&) = delete;
    AccessWatcher& operator=(const AccessWatcher&) = delete;

    // Watches `size` bytes (1/2/4/8) at `address` for `kind`. The address should be aligned to its size,
    // as the hardware requires. False if the debugger can't attach (another debugger is present, the
    // process exited, or no permission). Replaces any current watch.
    bool start(std::shared_ptr<hal::IProcess> process, uintptr_t address, size_t size, WatchKind kind);
    void stop();

    [[nodiscard]] bool watching() const noexcept { return m_active; }
    [[nodiscard]] uintptr_t address() const noexcept { return m_address; }
    [[nodiscard]] size_t size() const noexcept { return m_size; }
    [[nodiscard]] WatchKind kind() const noexcept { return m_kind; }

    // The instructions caught so far, most-frequent first
    [[nodiscard]] std::vector<AccessHit> hits() const;
    void clear();

private:
    void run(std::promise<bool> attached);      // attaches, then the debug-event loop, on its own thread
    void arm_thread(void* handle, bool enable) const; // sets or clears the breakpoint in one thread's context
    void record_hit(uint32_t thread_id);        // reads the context at a breakpoint and stores the hit

    std::shared_ptr<hal::IProcess> m_process;
    std::vector<hal::ModuleInfo> m_modules;
    uintptr_t m_address{0};
    size_t m_size{4};
    WatchKind m_kind{WatchKind::Write};
    uint32_t m_pid{0};

    std::atomic<bool> m_active{false};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;

    mutable std::mutex m_mutex;
    std::vector<AccessHit> m_hits;
};

} // namespace nce::debugger
