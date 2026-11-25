#pragma once

#include "../hal/process.hpp"
#include "../debugger/hook_engine.hpp"
#include <cstdint>
#include <memory>
#include <mutex>

namespace nce::speedhack {

#pragma pack(push, 1)
struct SpeedhackCaveHeader {
    int64_t  real_base_qpc{0};        // +0x00
    int64_t  sim_base_qpc{0};         // +0x08
    double   speed_multiplier{1.0};    // +0x10
    uint64_t real_base_gtc{0};        // +0x18
    uint64_t sim_base_gtc{0};         // +0x20
    uint64_t orig_qpc_trampoline{0};  // +0x28
    uint64_t orig_gtc_trampoline{0};  // +0x30
    uint32_t is_enabled{0};           // +0x38
    uint32_t padding{0};              // +0x3C
    uint64_t orig_tgt_trampoline{0};  // +0x40 (winmm!timeGetTime)
    uint64_t orig_gtc32_trampoline{0};// +0x48 (kernel32!GetTickCount)
};
#pragma pack(pop)

struct SpeedhackState {
    bool is_installed{false};
    bool is_enabled{false};
    double speed_multiplier{1.0};
    uintptr_t cave_address{0};
    uintptr_t qpc_target{0};
    uintptr_t gtc_target{0};
    uintptr_t tgt_target{0};
    uintptr_t gtc32_target{0};
};

class Speedhack {
public:
    explicit Speedhack(std::shared_ptr<hal::IProcess> process);
    ~Speedhack();

    Speedhack(const Speedhack&) = delete;
    Speedhack& operator=(const Speedhack&) = delete;

    // Attach to the process and install hooks
    bool attach();

    // Detach and restore original functions
    void detach();

    // Change speed multiplier smoothly (e.g. 0.5, 2.0, 5.0)
    bool set_speed(double multiplier);

    // Enable/disable speed scaling without uninstalling
    bool enable();
    bool disable();

    [[nodiscard]] bool is_installed() const noexcept { return m_state.is_installed; }
    [[nodiscard]] bool is_enabled() const noexcept { return m_state.is_enabled; }
    [[nodiscard]] double get_speed() const noexcept { return m_state.speed_multiplier; }
    [[nodiscard]] SpeedhackState get_state() const { return m_state; }

private:
    bool install_hooks();
    void uninstall_hooks();
    bool update_shared_time(double new_speed, bool enable_flag);

    std::shared_ptr<hal::IProcess> m_process;
    std::unique_ptr<debugger::HookEngine> m_hook_engine;
    SpeedhackState m_state;
    mutable std::mutex m_mutex;
};

} // namespace nce::speedhack
