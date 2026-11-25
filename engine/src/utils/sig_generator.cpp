#include "../../include/utils/sig_generator.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/debugger/disassembler.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace nce::utils {

namespace {

// Counts occurrences of an AOB pattern in a memory buffer
size_t count_pattern_matches(
    const uint8_t* data, size_t data_size,
    const std::vector<uint8_t>& pattern_bytes,
    const std::vector<bool>& mask
) {
    if (data_size < pattern_bytes.size() || pattern_bytes.empty()) return 0;
    size_t matches = 0;
    const size_t limit = data_size - pattern_bytes.size();

    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_bytes.size(); ++j) {
            if (mask[j] && data[i + j] != pattern_bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            ++matches;
            if (matches > 1) return matches; // Early exit once we know it's not unique
        }
    }
    return matches;
}

} // anonymous namespace

std::optional<SignatureGenerator::GeneratedSig> SignatureGenerator::generate(
    const hal::IProcess& process,
    uintptr_t address,
    size_t max_bytes
) {
    if (!process.is_attached() || address == 0) return std::nullopt;

    // Find the module containing `address`
    const auto modules = process.get_modules();
    const hal::ModuleInfo* host_module = nullptr;
    for (const auto& m : modules) {
        if (address >= m.base_address && address < m.base_address + m.size) {
            host_module = &m;
            break;
        }
    }

    // Read instructions at `address`
    std::vector<uint8_t> code_buffer(max_bytes + 32, 0);
    if (!process.read_raw(address, code_buffer.data(), code_buffer.size())) {
        return std::nullopt;
    }

    auto instructions = debugger::Disassembler::disassemble_range(
        code_buffer.data(), code_buffer.size(), address, 16
    );

    if (instructions.empty()) return std::nullopt;

    // Read host module code for uniqueness verification
    std::vector<uint8_t> module_memory;
    if (host_module) {
        module_memory.resize(host_module->size);
        if (!process.read_raw(host_module->base_address, module_memory.data(), host_module->size)) {
            module_memory.clear();
        }
    }

    std::vector<uint8_t> pattern_bytes;
    std::vector<bool> pattern_mask;

    GeneratedSig best_sig;

    for (const auto& inst : instructions) {
        if (pattern_bytes.size() >= max_bytes) break;

        // Inspect instruction to mask relative displacements
        bool has_rel32 = false;
        // Check for calls, jumps, or rip-relative memory references
        if (inst.mnemonic == "call" || inst.mnemonic == "jmp" ||
            inst.mnemonic.rfind("j", 0) == 0 || // conditional jumps (je, jne, jg, etc.)
            inst.operands.find("[rip") != std::string::npos) {
            if (inst.bytes.size() >= 5) {
                has_rel32 = true;
            }
        }

        for (size_t b = 0; b < inst.bytes.size(); ++b) {
            if (pattern_bytes.size() >= max_bytes) break;

            pattern_bytes.push_back(inst.bytes[b]);

            // If instruction has rel32, mask the last 4 bytes as wildcards
            if (has_rel32 && b >= inst.bytes.size() - 4) {
                pattern_mask.push_back(false); // wildcard '?'
            } else {
                pattern_mask.push_back(true);  // exact byte
            }
        }

        // Test uniqueness against module memory if available
        size_t matches = 0;
        if (!module_memory.empty()) {
            matches = count_pattern_matches(
                module_memory.data(), module_memory.size(), pattern_bytes, pattern_mask
            );
        }

        // Format pattern string
        std::ostringstream ss;
        size_t wildcards = 0;
        for (size_t i = 0; i < pattern_bytes.size(); ++i) {
            if (i > 0) ss << " ";
            if (!pattern_mask[i]) {
                ss << "?";
                ++wildcards;
            } else {
                ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(pattern_bytes[i]);
            }
        }

        best_sig.pattern = ss.str();
        best_sig.length = pattern_bytes.size();
        best_sig.wildcard_count = wildcards;
        best_sig.module_matches = matches;
        best_sig.is_unique = (matches == 1);

        if (best_sig.is_unique) {
            return best_sig;
        }
    }

    return best_sig;
}

} // namespace nce::utils
