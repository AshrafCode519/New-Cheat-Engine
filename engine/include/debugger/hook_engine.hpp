#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include <string>

namespace nce::debugger {

struct HookInfo {
    uintptr_t target_address{0};
    uintptr_t destination_address{0};
    uintptr_t cave_address{0};
    uintptr_t trampoline_address{0};
    size_t stolen_bytes_count{0};
    std::vector<uint8_t> original_bytes;
    bool is_active{false};
};

class HookEngine {
public:
    explicit HookEngine(std::shared_ptr<hal::IProcess> process);
    ~HookEngine();

    HookEngine(const HookEngine&) = delete;
    HookEngine& operator=(const HookEngine&) = delete;

    // Installs a 64-bit detour from target_address to destination_address.
    // Writes original stolen instructions + return jump to trampoline_out.
    bool install_detour(
        uintptr_t target_address,
        uintptr_t destination_address,
        uintptr_t* trampoline_out = nullptr
    );

    // Installs a payload hook: allocates a code cave, puts custom payload code + stolen bytes + jmp back,
    // and points target_address to the cave.
    std::optional<HookInfo> install_payload_hook(
        uintptr_t target_address,
        const std::vector<uint8_t>& payload
    );

    // Removes the hook at target_address and restores original bytes.
    bool remove_hook(uintptr_t target_address);

    // Removes all active hooks and frees allocated caves/trampolines.
    void remove_all_hooks();

    [[nodiscard]] bool is_hooked(uintptr_t target_address) const;
    [[nodiscard]] const std::vector<HookInfo>& get_active_hooks() const { return m_hooks; }

private:
    std::shared_ptr<hal::IProcess> m_process;
    std::vector<HookInfo> m_hooks;
};

} // namespace nce::debugger
