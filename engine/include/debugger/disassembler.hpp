#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace nce::hal { class IProcess; }

namespace nce::debugger {

struct DecodedInstruction {
    uintptr_t address{0};
    size_t length{1};
    std::string mnemonic{"unknown"};
    std::string operands;
    std::string full_text;
    std::vector<uint8_t> bytes;
    uintptr_t branch_target{0};   // Direct call/jmp/jcc target or [rip + disp32] reference address
    std::string resolved_symbol;  // Optional symbol annotation (e.g. "kernel32.dll!Sleep")

    [[nodiscard]] std::string format() const;
};

struct CFGEdge {
    enum class Kind { Unconditional, TrueBranch, FalseBranch };
    size_t from_block{0};
    size_t to_block{0};
    Kind kind{Kind::Unconditional};
};

struct BasicBlock {
    size_t id{0};
    uintptr_t start_address{0};
    uintptr_t end_address{0}; // exclusive
    std::vector<DecodedInstruction> instructions;
    int level{0}; // topological row from entry
    int lane{0};  // horizontal column inside level
};

struct ControlFlowGraph {
    uintptr_t entry_address{0};
    std::vector<BasicBlock> blocks;
    std::vector<CFGEdge> edges;
};

struct CrossReference {
    uintptr_t from_address{0};
    std::string module_name;
    std::string kind;        // "call", "jmp", "jcc", "rip-mem", "abs-mem"
    std::string instruction; // formatted disassembly line
};

class Disassembler {
public:
    static DecodedInstruction decode(const uint8_t* code, size_t max_len, uintptr_t address, bool is_64bit = true);
    static std::vector<DecodedInstruction> disassemble_range(const uint8_t* code, size_t size, uintptr_t base_address, size_t max_instructions = 16, bool is_64bit = true);

    static ControlFlowGraph build_cfg(const hal::IProcess& proc, uintptr_t entry_address, size_t max_instructions = 256, size_t max_blocks = 48);
    static ControlFlowGraph build_cfg_from_bytes(const uint8_t* code, size_t size, uintptr_t entry_address, uintptr_t base_address = 0, size_t max_instructions = 256, size_t max_blocks = 48);

    /// Scans committed executable regions (or a single module) for instructions referencing `target_address`.
    static std::vector<CrossReference> find_references(
        const hal::IProcess& proc, uintptr_t target_address, uintptr_t module_base = 0, size_t max_results = 256);
};

} // namespace nce::debugger
