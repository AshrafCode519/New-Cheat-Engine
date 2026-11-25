#pragma once

#include "disassembler.hpp"
#include "../view/structure_dissector.hpp"
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace nce::debugger {

struct DecompileOptions {
    std::function<std::string(uintptr_t)> symbol_resolver;
    // Maps byte offset -> {type_name, field_name}, e.g. from StructureDissector
    std::map<int64_t, std::pair<std::string, std::string>> struct_fields;
    std::string struct_base_reg; // Register pointing to the struct (e.g. "rcx" or "rdi")
    bool sysv_abi{false};
    bool include_address_comments{false};

    static DecompileOptions from_struct(const view::StructLayout& layout, std::string base_reg = "rcx");
};

struct DecompiledBlock {
    size_t block_id{0};
    uintptr_t start_address{0};
    std::vector<std::string> statements;
};

struct DecompiledFunction {
    uintptr_t entry_address{0};
    std::string name;
    std::string signature;
    std::vector<std::string> locals;
    std::vector<DecompiledBlock> blocks;
    std::string code;
};

// Lifts a Disassembler ControlFlowGraph into readable Pseudo-C by tracking register/stack
// expressions, resolving call/RIP targets to symbols, binding StructureDissector field names,
// and reconstructing if/else and loop blocks.
class PseudoCDecompiler {
public:
    [[nodiscard]] static DecompiledFunction decompile(
        const ControlFlowGraph& cfg,
        const DecompileOptions& options = {}
    );
};

} // namespace nce::debugger
