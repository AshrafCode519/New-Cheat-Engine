#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nce::debugger {

struct ELFSection {
    std::string name;
    uint32_t type{0};
    uint64_t flags{0};
    uintptr_t virtual_address{0};
    uint64_t file_offset{0};
    uint64_t size{0};
    uint32_t link{0};
    uint64_t entry_size{0};
    bool is_executable{false};
    bool is_readable{false};
    bool is_writable{false};
    bool is_alloc{false};
};

struct ELFSegment {
    uint32_t type{0};
    uint32_t flags{0};
    uint64_t offset{0};
    uintptr_t virtual_address{0};
    uintptr_t physical_address{0};
    uint64_t file_size{0};
    uint64_t memory_size{0};
    bool is_readable{false};
    bool is_writable{false};
    bool is_executable{false};
};

struct ELFSymbol {
    std::string name;
    uint16_t section_index{0};
    uint8_t type{0};      // STT_FUNC=2, STT_OBJECT=1, etc.
    uint8_t binding{0};   // STB_LOCAL=0, STB_GLOBAL=1, STB_WEAK=2
    uintptr_t va{0};
    uint64_t value{0};
    uint64_t size{0};
    bool is_exported{false};
};

struct ELFInfo {
    bool is_valid{false};
    bool is_64bit{false};
    bool is_shared_object{false};
    uint16_t type{0};
    uint16_t machine{0};
    std::string type_name;
    std::string machine_name;
    uintptr_t image_base{0};
    uintptr_t entry_point{0};
    size_t image_size{0};
    std::vector<ELFSection> sections;
    std::vector<ELFSegment> segments;
    std::vector<ELFSymbol> symbols;
    std::vector<std::string> needed_libraries;
};

class ELFAnalyzer {
public:
    /// Parses ELF32/ELF64 headers, segments, dynamic tables, and symbols from a live process module.
    static std::optional<ELFInfo> analyze(hal::IProcess& proc, uintptr_t module_base);

    /// Parses ELF32/ELF64 headers, sections, segments, dynamic tables, and symbols from an in-memory buffer.
    static std::optional<ELFInfo> analyze_bytes(const std::vector<uint8_t>& elf_bytes, uintptr_t base_va = 0);

    /// Quick check for ELF magic (`\x7FELF`).
    static bool is_elf_magic(hal::IProcess& proc, uintptr_t module_base);

    static const ELFSection* find_section(const ELFInfo& info, const std::string& name);
    static const ELFSection* find_section_at(const ELFInfo& info, uintptr_t address);
    static const ELFSymbol* find_symbol_by_name(const ELFInfo& info, const std::string& name);
    static const ELFSymbol* find_symbol_by_address(const ELFInfo& info, uintptr_t address);
};

} // namespace nce::debugger
