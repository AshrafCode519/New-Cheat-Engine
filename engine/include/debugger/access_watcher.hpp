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

class DebugCoordinator;

// What to catch: a write to the address, any read/write access, or instruction execution
enum class WatchKind { Write, Access, Execute };

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
    std::string base_register;
    int64_t base_offset{0};
    [[nodiscard]] uintptr_t base_pointer() const; // registers.by_name(base_register) (0 if none)
};

// "Find what writes/accesses this address": sets a hardware breakpoint (debug registers DR0-DR3) on the
// address in every thread of the target and reports the instructions that hit it, with their registers.
// Shares a DebugCoordinator with StepDebugger when used inside a Session, eliminating dual-debugger conflicts.
class AccessWatcher {
public:
    AccessWatcher() = default;
    ~AccessWatcher();
    AccessWatcher(const AccessWatcher&) = delete;
    AccessWatcher& operator=(const AccessWatcher&) = delete;

    // Bind a shared DebugCoordinator (used by Session so StepDebugger and AccessWatcher coexist).
    void set_coordinator(std::shared_ptr<DebugCoordinator> coordinator);

    // Watches `size` bytes (1/2/4/8) at `address` for `kind`. Supports up to 4 concurrent addresses (DR0-DR3).
    bool start(std::shared_ptr<hal::IProcess> process, uintptr_t address, size_t size, WatchKind kind);
    void stop();
    void stop_address(uintptr_t address);

    [[nodiscard]] bool watching() const noexcept { return m_active; }
    [[nodiscard]] uintptr_t address() const noexcept { return m_address; }
    [[nodiscard]] std::vector<uintptr_t> watched_addresses() const;
    [[nodiscard]] size_t size() const noexcept { return m_size; }
    [[nodiscard]] WatchKind kind() const noexcept { return m_kind; }

    // The instructions caught so far, most-frequent first
    [[nodiscard]] std::vector<AccessHit> hits() const;
    void clear();

private:
    void on_hw_hit(uint32_t thread_id, uintptr_t rip, const Registers& regs);

    std::shared_ptr<hal::IProcess> m_process;
    std::shared_ptr<DebugCoordinator> m_shared_coordinator;
    std::shared_ptr<DebugCoordinator> m_owned_coordinator;
    std::vector<hal::ModuleInfo> m_modules;
    uintptr_t m_address{0};
    std::vector<uintptr_t> m_watched_addresses;
    size_t m_size{4};
    WatchKind m_kind{WatchKind::Write};

    std::atomic<bool> m_active{false};
    mutable std::mutex m_mutex;
    std::vector<AccessHit> m_hits;
};

} // namespace nce::debugger
