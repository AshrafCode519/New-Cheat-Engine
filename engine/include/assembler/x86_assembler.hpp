#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nce::assembler {

// A tiny x86-64 (and 32-bit) instruction encoder for the common instructions a cheat-table script uses to
// patch a game's own code: moves, arithmetic, jumps, calls, push/pop, nop and raw bytes. It is Intel syntax,
// one instruction per call. Not a full assembler: what it doesn't know, you write with `db` (raw bytes).
class X86Assembler {
public:
    explicit X86Assembler(bool x64 = true) : m_x64(x64) {}

    struct Encoded {
        std::vector<uint8_t> bytes;
        // Set when the instruction's operand is an address the caller resolves later (a jmp/call to a label):
        // bytes[rel_offset .. rel_offset+4) is a rel32 to patch once both addresses are known.
        std::optional<size_t> rel32_offset;
        bool rel_is_absolute{false}; // the operand was an absolute target, not a label
        uintptr_t rel_target{0};     // that absolute target
    };

    // Encodes one instruction at `address` (needed for rel32 jumps/calls to an absolute target). On failure
    // returns nullopt and sets `error`.
    std::optional<Encoded> encode(const std::string& instruction, uintptr_t address, std::string& error);

    [[nodiscard]] bool x64() const noexcept { return m_x64; }

private:
    bool m_x64;
};

} // namespace nce::assembler
