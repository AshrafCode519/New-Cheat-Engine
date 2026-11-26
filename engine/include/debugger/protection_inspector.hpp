#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace nce::debugger {

struct ProtectionFinding {
    std::string category;    // "Anti-Debug", "IAT Hook", "Timing Check", "RWX Cave", "Integrity"
    std::string severity;    // "High", "Medium", "Info"
    uintptr_t address{0};
    std::string module_name;
    std::string description;
    std::string mitigation;
};

struct ProtectionReport {
    int risk_score{0}; // 0..100
    bool has_anti_debug_apis{false};
    bool has_timing_checks{false};
    bool has_iat_hooks{false};
    bool has_rwx_caves{false};
    std::vector<ProtectionFinding> findings;
    std::string summary;
};

// Scans target PE/ELF imports, IAT pointers, executable memory protections, and anti-debug indicators.
class ProtectionInspector {
public:
    [[nodiscard]] static ProtectionReport inspect(hal::IProcess& process);
};

} // namespace nce::debugger
