#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace nce::debugger {

struct PESection {
    std::string name;
    uint32_t virtual_address{0};
    uint32_t virtual_size{0};
    uint32_t raw_size{0};
    uint32_t characteristics{0};
    bool is_executable{false};
    bool is_readable{false};
    bool is_writable{false};
};

struct PEExport {
    std::string name;
    uint16_t ordinal{0};
    uint32_t rva{0};
    uintptr_t va{0};
    bool is_forwarded{false};
    std::string forwarder_name;
};

struct PEImportFunction {
    std::string name;
    uint16_t ordinal{0};
    uint32_t iat_rva{0};
    uintptr_t iat_va{0};
};

struct PEImportModule {
    std::string module_name;
    std::vector<PEImportFunction> functions;
};

struct PEInfo {
    bool is_valid{false};
    bool is_64bit{false};
    uintptr_t image_base{0};
    uintptr_t entry_point{0};
    size_t image_size{0};
    uint32_t checksum{0};
    std::string subsystem;
    std::vector<PESection> sections;
    std::vector<PEExport> exports;
    std::vector<PEImportModule> imports;
};

class PEAnalyzer {
public:
    // Analyze PE headers and exports/imports of a module in the target process
    static std::optional<PEInfo> analyze(hal::IProcess& proc, uintptr_t module_base);

    // Analyze PE headers from a memory buffer
    static std::optional<PEInfo> analyze_bytes(const std::vector<uint8_t>& pe_bytes, uintptr_t base_va = 0);

    // Helper utilities
    static const PESection* find_section(const PEInfo& info, uintptr_t address);
    static const PEExport* find_export_by_name(const PEInfo& info, const std::string& name);
    static const PEExport* find_export_by_address(const PEInfo& info, uintptr_t address);
};

} // namespace nce::debugger
