#pragma once

#include "x86_assembler.hpp"
#include "../hal/process.hpp"
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nce::assembler {

struct ScriptEffect {
    struct Patch {
        uintptr_t address{0};
        std::vector<uint8_t> original;
        std::vector<uint8_t> written;
    };
    struct Allocation {
        uintptr_t address{0};
        size_t size{0};
    };
    std::vector<Patch> patches;
    std::vector<Allocation> allocations;
    std::vector<std::string> symbols;
};

struct AssembleResult {
    bool ok{false};
    std::string message;
    ScriptEffect effect;
};

// Runs a Cheat-Engine-style Auto-Assembler script against an attached process:
// Supports alloc, globalalloc, label, aobscan, aobscanmodule, aobscanregion, assert, define,
// fullaccess, readmem, registersymbol, unregistersymbol, dealloc, db/dw/dd/dq/float/double,
// {$lua}/{$asm} blocks, plus x86-64/32 instructions.
class AutoAssembler {
public:
    using LuaRunner = std::function<bool(const std::string& lua_code, std::string& error_out)>;

    explicit AutoAssembler(std::shared_ptr<hal::IProcess> process);

    void set_lua_runner(LuaRunner runner) { m_lua_runner = std::move(runner); }

    AssembleResult enable(const std::string& script);
    AssembleResult disable(const std::string& script, const ScriptEffect& effect);

    void set_symbol(const std::string& name, uintptr_t address);
    void clear_symbol(const std::string& name);
    [[nodiscard]] std::optional<uintptr_t> symbol(const std::string& name) const;

    [[nodiscard]] std::optional<uintptr_t> resolve(const std::string& expression) const;

    struct Sections {
        std::string enable;
        std::string disable;
        bool had_markers{false};
    };
    [[nodiscard]] static Sections split_sections(const std::string& script);

    /// Generates a complete [ENABLE]/[DISABLE] Auto-Assembler code-cave injection template
    /// for `address`, using SignatureGenerator + Disassembler + X86Assembler validation.
    [[nodiscard]] static std::string generate_aob_hook_script(
        const hal::IProcess& proc,
        uintptr_t address,
        const std::string& label_name = "INJECT",
        size_t min_bytes = 5);

private:
    struct Assembly;

    bool run(const std::string& body, ScriptEffect& effect, std::string& error, bool committing);
    bool first_pass(Assembly& a, std::string& error);
    bool emit_pass(Assembly& a, ScriptEffect& effect, std::string& error);
    bool apply_directive(Assembly& a, const std::string& line, bool first, std::string& error);
    std::string substitute_symbols(const Assembly& a, const std::string& operands) const;
    std::string apply_defines(const Assembly& a, const std::string& line) const;

    std::shared_ptr<hal::IProcess> m_process;
    X86Assembler m_encoder;
    LuaRunner m_lua_runner;
    std::map<std::string, uintptr_t> m_symbols;
    std::map<std::string, size_t> m_symbol_alloc_size;
    std::map<std::string, ScriptEffect::Allocation> m_global_allocs;
};

} // namespace nce::assembler
