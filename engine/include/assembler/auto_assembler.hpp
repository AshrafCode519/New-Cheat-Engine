#pragma once

#include "../hal/process.hpp"
#include "x86_assembler.hpp"
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nce::assembler {

// What a script changed, so it can be undone exactly: the bytes it overwrote, and the memory it allocated.
struct ScriptEffect {
    struct Patch {
        uintptr_t address{0};
        std::vector<uint8_t> original; // the bytes that were there before
        std::vector<uint8_t> written;  // what the script put there
    };
    struct Allocation {
        uintptr_t address{0};
        size_t size{0};
    };
    std::vector<Patch> patches;
    std::vector<Allocation> allocations;
    std::vector<std::string> symbols; // registersymbol names to drop on disable
};

struct AssembleResult {
    bool ok{false};
    std::string message;    // the error when !ok; a short note (bytes written, caves) when ok
    ScriptEffect effect;    // what to pass to disable() for a script that has no [DISABLE] of its own
};

// Runs a Cheat-Engine-style Auto-Assembler script against an attached process: the small set of directives
// games' tables use (alloc, label, aobscanmodule, registersymbol, db) plus the instructions X86Assembler
// knows. Scripts inject or patch the game's OWN code, so this is for offline / single-player games you run
// yourself; anti-cheat treats it as cheating. Symbols registered by one script are visible to the next.
class AutoAssembler {
public:
    explicit AutoAssembler(std::shared_ptr<hal::IProcess> process);

    // Runs the script's [ENABLE] section (or the whole script if it has no sections). On any failure every
    // byte already written is put back and every cave freed, so the target is never left half-patched.
    AssembleResult enable(const std::string& script);

    // Undoes what enable() returned: runs the [DISABLE] section if the script has one, then restores the
    // recorded bytes and frees the caves. A script with no [DISABLE] is undone from `effect` alone.
    AssembleResult disable(const std::string& script, const ScriptEffect& effect);

    // Global symbols, shared across scripts (registersymbol / a cheat table's own entries)
    void set_symbol(const std::string& name, uintptr_t address);
    void clear_symbol(const std::string& name);
    [[nodiscard]] std::optional<uintptr_t> symbol(const std::string& name) const;

    // Resolves "game.exe"+0x1234, mysymbol+0x20, 0x7FF.., or a decimal, using the symbols and the modules
    [[nodiscard]] std::optional<uintptr_t> resolve(const std::string& expression) const;

    // The two sections of a script ("" when absent); the whole body counts as ENABLE if neither is present
    struct Sections {
        std::string enable;
        std::string disable;
        bool had_markers{false};
    };
    [[nodiscard]] static Sections split_sections(const std::string& script);

private:
    struct Assembly; // one run's working state (labels, current address, buffered writes)

    bool run(const std::string& body, ScriptEffect& effect, std::string& error, bool committing);
    bool first_pass(Assembly& a, std::string& error);
    bool emit_pass(Assembly& a, ScriptEffect& effect, std::string& error);
    bool apply_directive(Assembly& a, const std::string& line, bool first, std::string& error);
    std::string substitute_symbols(const Assembly& a, const std::string& operands) const;

    std::shared_ptr<hal::IProcess> m_process;
    X86Assembler m_encoder;
    std::map<std::string, uintptr_t> m_symbols;
    std::map<std::string, size_t> m_symbol_alloc_size; // caves, so disable can free by name if needed
};

} // namespace nce::assembler
