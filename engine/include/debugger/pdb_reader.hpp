#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace nce::debugger {

struct PDBSymbol {
    std::string name;
    uint16_t section{0};
    uint32_t section_offset{0};
    uint32_t rva{0};
    uint32_t flags{0};
};

// Pure C++ MSF 7.00 / PDB v7 symbol reader (Windows + Linux, zero DbgHelp dependency):
// Parses section headers and DBI public/global symbols (S_PUB32, S_GPROC32, S_LPROC32) from local .pdb files.
class PDBReader {
public:
    bool load_file(const std::string& pdb_path);
    bool load_bytes(const std::vector<uint8_t>& file_bytes);

    [[nodiscard]] bool is_loaded() const noexcept { return m_loaded; }
    [[nodiscard]] const std::string& last_error() const noexcept { return m_last_error; }
    [[nodiscard]] const std::vector<PDBSymbol>& symbols() const noexcept { return m_symbols; }

    // Finds closest symbol at or before `rva` (with optional max displacement)
    [[nodiscard]] std::optional<std::pair<PDBSymbol, uint32_t>> find_by_rva(
        uint32_t rva, uint32_t max_displacement = 0x4000) const;

    // Resolves first matching symbol by exact or substring name
    [[nodiscard]] std::vector<PDBSymbol> find_by_name(
        const std::string& query, size_t max_results = 64) const;

    // Helper: checks for matching `<module_stem>.pdb` next to module_path
    [[nodiscard]] static std::string locate_companion_pdb(const std::string& module_path);

private:
    bool m_loaded{false};
    std::string m_last_error;
    std::vector<PDBSymbol> m_symbols;
};

} // namespace nce::debugger
