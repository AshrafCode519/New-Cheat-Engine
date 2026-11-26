#include "../../include/debugger/hook_engine.hpp"
#include "../../include/debugger/disassembler.hpp"
#include <algorithm>
#include <cstring>
#include <iterator>

namespace nce::debugger {

namespace {

std::optional<size_t> find_modrm_rip_disp_offset(const std::vector<uint8_t>& insn_bytes) {
    size_t i = 0;
    while (i < insn_bytes.size()) {
        uint8_t b = insn_bytes[i];
        if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 ||
            b == 0xF0 || b == 0xF2 || b == 0xF3) {
            ++i;
            continue;
        }
        break;
    }
    if (i < insn_bytes.size() && insn_bytes[i] >= 0x40 && insn_bytes[i] <= 0x4F) {
        ++i; // REX prefix
    }
    if (i >= insn_bytes.size()) return std::nullopt;
    if (insn_bytes[i] == 0x0F) {
        ++i;
        if (i < insn_bytes.size() && (insn_bytes[i] == 0x38 || insn_bytes[i] == 0x3A)) ++i;
        if (i >= insn_bytes.size()) return std::nullopt;
        ++i;
    } else {
        ++i;
    }
    if (i >= insn_bytes.size()) return std::nullopt;
    const uint8_t modrm = insn_bytes[i];
    if ((modrm & 0xC7) == 0x05 && i + 5 <= insn_bytes.size()) {
        return i + 1;
    }
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> relocate_stolen_instructions(
    const std::vector<uint8_t>& orig_bytes,
    uintptr_t orig_addr,
    uintptr_t dst_base,
    bool is_64bit)
{
    std::vector<uint8_t> out;
    out.reserve(orig_bytes.size() + 32);

    size_t off = 0;
    while (off < orig_bytes.size()) {
        const uintptr_t src_pc = orig_addr + off;
        const uintptr_t dst_pc = dst_base + out.size();
        auto insn = Disassembler::decode(orig_bytes.data() + off, orig_bytes.size() - off, src_pc, is_64bit);
        if (insn.length == 0 || off + insn.length > orig_bytes.size()) {
            return std::nullopt;
        }

        const uint8_t op0 = insn.bytes[0];
        auto fits_i32 = [](int64_t d) { return d >= INT32_MIN && d <= INT32_MAX; };
        auto append_u64 = [&](uint64_t v) {
            const auto* p = reinterpret_cast<const uint8_t*>(&v);
            out.insert(out.end(), p, p + 8);
        };
        auto append_u32 = [&](uint32_t v) {
            const auto* p = reinterpret_cast<const uint8_t*>(&v);
            out.insert(out.end(), p, p + 4);
        };
        auto append_i32 = [&](int32_t v) {
            const auto* p = reinterpret_cast<const uint8_t*>(&v);
            out.insert(out.end(), p, p + 4);
        };
        auto append_abs_jmp = [&](uintptr_t target) {
            if (is_64bit) {
                const uint8_t jq[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
                out.insert(out.end(), std::begin(jq), std::end(jq));
                append_u64(target);
            } else {
                out.push_back(0x68); // push imm32
                append_u32(static_cast<uint32_t>(target));
                out.push_back(0xC3); // ret
            }
        };

        // 1. Direct JMP (E9 rel32, EB rel8)
        if ((op0 == 0xE9 || op0 == 0xEB) && insn.branch_target != 0) {
            const int64_t delta = static_cast<int64_t>(insn.branch_target) - static_cast<int64_t>(dst_pc + 5);
            if (fits_i32(delta)) {
                out.push_back(0xE9);
                append_i32(static_cast<int32_t>(delta));
            } else {
                append_abs_jmp(insn.branch_target);
            }
            off += insn.length;
            continue;
        }

        // 2. Direct CALL (E8 rel32)
        if (op0 == 0xE8 && insn.branch_target != 0) {
            const int64_t delta = static_cast<int64_t>(insn.branch_target) - static_cast<int64_t>(dst_pc + 5);
            if (fits_i32(delta)) {
                out.push_back(0xE8);
                append_i32(static_cast<int32_t>(delta));
            } else if (is_64bit) {
                // call qword ptr [rip+2]; jmp short +8; dq target
                const uint8_t ci[] = {0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08};
                out.insert(out.end(), std::begin(ci), std::end(ci));
                append_u64(insn.branch_target);
            } else {
                return std::nullopt;
            }
            off += insn.length;
            continue;
        }

        // 3. Conditional Jcc (70..7F rel8, or 0F 80..8F rel32)
        const bool is_jcc8  = (op0 >= 0x70 && op0 <= 0x7F);
        const bool is_jcc32 = (op0 == 0x0F && insn.bytes.size() >= 2 && insn.bytes[1] >= 0x80 && insn.bytes[1] <= 0x8F);
        if ((is_jcc8 || is_jcc32) && insn.branch_target != 0) {
            const uint8_t cond = is_jcc8 ? (op0 & 0x0F) : (insn.bytes[1] & 0x0F);
            const int64_t delta = static_cast<int64_t>(insn.branch_target) - static_cast<int64_t>(dst_pc + 6);
            if (fits_i32(delta)) {
                out.push_back(0x0F);
                out.push_back(static_cast<uint8_t>(0x80 | cond));
                append_i32(static_cast<int32_t>(delta));
            } else {
                // Inverse short jcc over absolute jump
                out.push_back(static_cast<uint8_t>(0x70 | (cond ^ 1)));
                out.push_back(is_64bit ? 14 : 6);
                append_abs_jmp(insn.branch_target);
            }
            off += insn.length;
            continue;
        }

        // 4. ModRM RIP-relative memory reference ([rip + disp32]) (x64 only)
        if (is_64bit && insn.branch_target != 0 && insn.operands.find("rip +") != std::string::npos) {
            auto disp_off = find_modrm_rip_disp_offset(insn.bytes);
            if (!disp_off) return std::nullopt;
            const int64_t new_disp = static_cast<int64_t>(insn.branch_target) - static_cast<int64_t>(dst_pc + insn.length);
            if (!fits_i32(new_disp)) return std::nullopt;

            std::vector<uint8_t> patched = insn.bytes;
            const int32_t nd32 = static_cast<int32_t>(new_disp);
            std::memcpy(patched.data() + *disp_off, &nd32, 4);
            out.insert(out.end(), patched.begin(), patched.end());
            off += insn.length;
            continue;
        }

        // 5. Normal non-PC-relative instruction
        out.insert(out.end(), insn.bytes.begin(), insn.bytes.end());
        off += insn.length;
    }

    return out;
}

} // namespace

HookEngine::HookEngine(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process))
{}

HookEngine::~HookEngine() {
    remove_all_hooks();
}

bool HookEngine::is_hooked(uintptr_t target_address) const {
    for (const auto& h : m_hooks) {
        if (h.target_address == target_address && h.is_active) {
            return true;
        }
    }
    return false;
}

bool HookEngine::install_detour(
    uintptr_t target_address,
    uintptr_t destination_address,
    uintptr_t* trampoline_out
) {
    if (!m_process || !m_process->is_attached() || target_address == 0 || destination_address == 0) {
        return false;
    }
    if (is_hooked(target_address)) {
        return false;
    }

    const bool is_64 = (m_process->pointer_size() != 4);

    // Determine if relative 32-bit jump can be used
    const int64_t diff = static_cast<int64_t>(destination_address) - static_cast<int64_t>(target_address + 5);
    const bool can_use_rel32 = (diff >= -0x7FFF0000LL && diff <= 0x7FFF0000LL);
    const size_t min_bytes = can_use_rel32 ? 5 : (is_64 ? 14 : 6);

    // Read candidate instruction buffer from target
    constexpr size_t kReadBufSize = 64;
    std::vector<uint8_t> buffer(kReadBufSize);
    if (!m_process->read_raw(target_address, buffer.data(), kReadBufSize)) {
        return false;
    }

    // Disassemble instructions until boundary >= min_bytes
    size_t stolen_bytes = 0;
    while (stolen_bytes < min_bytes && stolen_bytes < kReadBufSize) {
        auto inst = Disassembler::decode(buffer.data() + stolen_bytes, kReadBufSize - stolen_bytes, target_address + stolen_bytes, is_64);
        if (inst.length == 0) break;
        stolen_bytes += inst.length;
    }

    if (stolen_bytes < min_bytes) {
        return false; // Could not find safe instruction boundary
    }

    // Save original bytes
    std::vector<uint8_t> original_bytes(buffer.begin(), buffer.begin() + stolen_bytes);

    // Allocate trampoline memory (256 bytes comfortably fits relocated/expanded branches)
    uintptr_t tramp_addr = m_process->allocate_memory(256, 0x40 /* PAGE_EXECUTE_READWRITE */, target_address);
    if (tramp_addr == 0) {
        return false;
    }

    auto relocated = relocate_stolen_instructions(original_bytes, target_address, tramp_addr, is_64);
    if (!relocated) {
        m_process->free_memory(tramp_addr);
        return false;
    }

    // Build trampoline: relocated stolen instructions + jump back to (target_address + stolen_bytes)
    std::vector<uint8_t> tramp_code = std::move(*relocated);
    tramp_code.reserve(tramp_code.size() + 14);

    const uint8_t jmp_qword[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    const uintptr_t return_addr = target_address + stolen_bytes;
    if (is_64) {
        tramp_code.insert(tramp_code.end(), std::begin(jmp_qword), std::end(jmp_qword));
        const auto* ret_ptr = reinterpret_cast<const uint8_t*>(&return_addr);
        tramp_code.insert(tramp_code.end(), ret_ptr, ret_ptr + sizeof(uintptr_t));
    } else {
        const int64_t back_diff = static_cast<int64_t>(return_addr) - static_cast<int64_t>(tramp_addr + tramp_code.size() + 5);
        if (back_diff >= -0x7FFF0000LL && back_diff <= 0x7FFF0000LL) {
            const int32_t rel32 = static_cast<int32_t>(back_diff);
            tramp_code.push_back(0xE9);
            const auto* p = reinterpret_cast<const uint8_t*>(&rel32);
            tramp_code.insert(tramp_code.end(), p, p + 4);
        } else {
            const uint32_t ret32 = static_cast<uint32_t>(return_addr);
            tramp_code.push_back(0x68);
            const auto* p = reinterpret_cast<const uint8_t*>(&ret32);
            tramp_code.insert(tramp_code.end(), p, p + 4);
            tramp_code.push_back(0xC3);
        }
    }

    // Write trampoline into target process
    if (!m_process->write_raw(tramp_addr, tramp_code.data(), tramp_code.size(), true)) {
        m_process->free_memory(tramp_addr);
        return false;
    }

    // Build hook jump at target_address
    std::vector<uint8_t> hook_bytes(stolen_bytes, 0x90); // default NOP pad
    if (can_use_rel32) {
        hook_bytes[0] = 0xE9;
        const int32_t rel32 = static_cast<int32_t>(diff);
        std::memcpy(&hook_bytes[1], &rel32, sizeof(int32_t));
    } else if (is_64) {
        std::memcpy(hook_bytes.data(), jmp_qword, sizeof(jmp_qword));
        std::memcpy(hook_bytes.data() + sizeof(jmp_qword), &destination_address, sizeof(uintptr_t));
    } else {
        const uint32_t dst32 = static_cast<uint32_t>(destination_address);
        hook_bytes[0] = 0x68;
        std::memcpy(&hook_bytes[1], &dst32, 4);
        hook_bytes[5] = 0xC3;
    }

    // Write hook jump to target_address
    if (!m_process->write_raw(target_address, hook_bytes.data(), hook_bytes.size(), true)) {
        m_process->free_memory(tramp_addr);
        return false;
    }

    if (trampoline_out) {
        *trampoline_out = tramp_addr;
    }

    HookInfo info;
    info.target_address = target_address;
    info.destination_address = destination_address;
    info.trampoline_address = tramp_addr;
    info.stolen_bytes_count = stolen_bytes;
    info.original_bytes = std::move(original_bytes);
    info.is_active = true;

    m_hooks.push_back(std::move(info));
    return true;
}

std::optional<HookInfo> HookEngine::install_payload_hook(
    uintptr_t target_address,
    const std::vector<uint8_t>& payload
) {
    if (!m_process || !m_process->is_attached() || target_address == 0 || payload.empty()) {
        return std::nullopt;
    }
    if (is_hooked(target_address)) {
        return std::nullopt;
    }

    // Read candidate instructions
    constexpr size_t kReadBufSize = 64;
    std::vector<uint8_t> buffer(kReadBufSize);
    if (!m_process->read_raw(target_address, buffer.data(), kReadBufSize)) {
        return std::nullopt;
    }

    const bool is_64 = (m_process->pointer_size() != 4);
    const size_t min_stolen = is_64 ? 14 : 5;
    size_t stolen_bytes = 0;
    while (stolen_bytes < min_stolen && stolen_bytes < kReadBufSize) {
        auto inst = Disassembler::decode(buffer.data() + stolen_bytes, kReadBufSize - stolen_bytes, target_address + stolen_bytes, is_64);
        if (inst.length == 0) break;
        stolen_bytes += inst.length;
    }
    if (stolen_bytes < min_stolen) {
        return std::nullopt;
    }

    std::vector<uint8_t> original_bytes(buffer.begin(), buffer.begin() + stolen_bytes);

    // Allocate cave near target_address
    const size_t cave_alloc_size = 1024;
    uintptr_t cave_addr = m_process->allocate_memory(cave_alloc_size, 0x40, target_address);
    if (cave_addr == 0) {
        return std::nullopt;
    }

    // Build cave contents:
    // 1. payload instructions
    // 2. relocated stolen original instructions
    // 3. jump back to target_address + stolen_bytes
    auto relocated = relocate_stolen_instructions(original_bytes, target_address, cave_addr + payload.size(), is_64);
    if (!relocated) {
        m_process->free_memory(cave_addr);
        return std::nullopt;
    }

    std::vector<uint8_t> cave_code;
    cave_code.reserve(payload.size() + relocated->size() + 14);
    cave_code.insert(cave_code.end(), payload.begin(), payload.end());
    cave_code.insert(cave_code.end(), relocated->begin(), relocated->end());

    const uint8_t jmp_qword[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    const uintptr_t return_addr = target_address + stolen_bytes;
    if (is_64) {
        cave_code.insert(cave_code.end(), std::begin(jmp_qword), std::end(jmp_qword));
        const auto* ret_ptr = reinterpret_cast<const uint8_t*>(&return_addr);
        cave_code.insert(cave_code.end(), ret_ptr, ret_ptr + sizeof(uintptr_t));
    } else {
        const int64_t back_diff = static_cast<int64_t>(return_addr) - static_cast<int64_t>(cave_addr + cave_code.size() + 5);
        if (back_diff >= -0x7FFF0000LL && back_diff <= 0x7FFF0000LL) {
            const int32_t rel32 = static_cast<int32_t>(back_diff);
            cave_code.push_back(0xE9);
            const auto* p = reinterpret_cast<const uint8_t*>(&rel32);
            cave_code.insert(cave_code.end(), p, p + 4);
        } else {
            const uint32_t ret32 = static_cast<uint32_t>(return_addr);
            cave_code.push_back(0x68);
            const auto* p = reinterpret_cast<const uint8_t*>(&ret32);
            cave_code.insert(cave_code.end(), p, p + 4);
            cave_code.push_back(0xC3);
        }
    }

    // Write cave code
    if (!m_process->write_raw(cave_addr, cave_code.data(), cave_code.size(), true)) {
        m_process->free_memory(cave_addr);
        return std::nullopt;
    }

    // Write detour jump from target_address to cave_addr
    std::vector<uint8_t> hook_bytes(stolen_bytes, 0x90);
    const int64_t diff = static_cast<int64_t>(cave_addr) - static_cast<int64_t>(target_address + 5);
    if (diff >= -0x7FFF0000LL && diff <= 0x7FFF0000LL) {
        hook_bytes[0] = 0xE9;
        const int32_t rel32 = static_cast<int32_t>(diff);
        std::memcpy(&hook_bytes[1], &rel32, sizeof(int32_t));
    } else if (is_64) {
        std::memcpy(hook_bytes.data(), jmp_qword, sizeof(jmp_qword));
        std::memcpy(hook_bytes.data() + sizeof(jmp_qword), &cave_addr, sizeof(uintptr_t));
    } else if (stolen_bytes >= 6) {
        const uint32_t dst32 = static_cast<uint32_t>(cave_addr);
        hook_bytes[0] = 0x68;
        std::memcpy(&hook_bytes[1], &dst32, 4);
        hook_bytes[5] = 0xC3;
    } else {
        m_process->free_memory(cave_addr);
        return std::nullopt;
    }

    if (!m_process->write_raw(target_address, hook_bytes.data(), hook_bytes.size(), true)) {
        m_process->free_memory(cave_addr);
        return std::nullopt;
    }

    HookInfo info;
    info.target_address = target_address;
    info.destination_address = cave_addr;
    info.cave_address = cave_addr;
    info.stolen_bytes_count = stolen_bytes;
    info.original_bytes = std::move(original_bytes);
    info.is_active = true;

    m_hooks.push_back(info);
    return info;
}

bool HookEngine::remove_hook(uintptr_t target_address) {
    auto it = std::find_if(m_hooks.begin(), m_hooks.end(), [target_address](const HookInfo& h) {
        return h.target_address == target_address && h.is_active;
    });

    if (it == m_hooks.end()) {
        return false;
    }

    // Restore original bytes
    if (m_process && m_process->is_attached() && !it->original_bytes.empty()) {
        m_process->write_raw(it->target_address, it->original_bytes.data(), it->original_bytes.size(), true);
    }

    // Free allocated memory
    if (m_process && m_process->is_attached()) {
        if (it->trampoline_address != 0) {
            m_process->free_memory(it->trampoline_address);
        }
        if (it->cave_address != 0) {
            m_process->free_memory(it->cave_address);
        }
    }

    it->is_active = false;
    m_hooks.erase(it);
    return true;
}

void HookEngine::remove_all_hooks() {
    while (!m_hooks.empty()) {
        remove_hook(m_hooks.back().target_address);
    }
}

} // namespace nce::debugger
