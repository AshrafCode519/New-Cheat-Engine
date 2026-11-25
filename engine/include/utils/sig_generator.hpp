#pragma once

#include "../hal/process.hpp"
#include <string>
#include <cstdint>
#include <optional>

namespace nce::utils {

// Automatically inspects machine code at address and builds the shortest byte pattern
// with wildcards for relative displacements that matches uniquely (exactly 1 time)
// in the host module memory.
class SignatureGenerator {
public:
    struct GeneratedSig {
        std::string pattern;      // e.g. "48 89 5C 24 ?? 57 48 83 EC 20"
        size_t length{0};         // Total bytes
        size_t wildcard_count{0}; // Number of '?' wildcard bytes
        bool is_unique{false};    // True if verified unique in module
        size_t module_matches{0}; // Match count in module
    };

    // Generates a unique AOB signature for the code at `address`.
    // Automatically replaces relative jump/call and RIP-relative displacements with wildcards.
    static std::optional<GeneratedSig> generate(
        const hal::IProcess& process,
        uintptr_t address,
        size_t max_bytes = 64
    );
};

} // namespace nce::utils
