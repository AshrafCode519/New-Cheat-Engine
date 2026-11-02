#pragma once

#include "../hal/process.hpp"
#include "../scanner/scan_types.hpp"
#include "../scanner/pointer_scanner.hpp"
#include <optional>
#include <string>
#include <vector>

namespace nce::table {

// One remembered value. Its location is kept in a form that survives a restart of the target when
// possible: a static address (module + offset) or a pointer path (module + offset + offsets).
// Memory that belongs to no module is stored as an absolute address, valid only in the current run.
struct TableEntry {
    std::string description;
    scanner::DataType type{scanner::DataType::Int32};
    scanner::PointerPath location;           // module_name empty = absolute address in base_offset
    size_t length{0};                        // byte length of str / wstr / aob entries
    std::optional<std::string> frozen_value; // value text to keep writing, as the user typed it

    [[nodiscard]] bool is_absolute() const noexcept { return location.module_name.empty(); }

    // Current address, or 0 if it can't be resolved (module not loaded, broken pointer)
    [[nodiscard]] uintptr_t address(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules) const;

    // "game.exe+0x1010A8 -> 0x8 -> 0x4", "game.exe+0x2000", or "0x0000021A5C3F1000"
    [[nodiscard]] std::string location_string() const;
};

struct CheatTable {
    std::string process_name;
    std::vector<TableEntry> entries;
};

// Entry for an address found by a scan: module-relative if the address lies inside a module.
// length is the byte size for str / wstr / aob (ignored for numbers).
TableEntry make_entry(uintptr_t address, scanner::DataType type, const std::vector<hal::ModuleInfo>& modules,
                      std::string description = {}, size_t length = 0);

TableEntry make_entry(const scanner::PointerPath& path, scanner::DataType type, std::string description = {});

// The entry's current value; nullopt if it can't be resolved or read
std::optional<scanner::ScanValue> read_entry(const TableEntry& entry, const hal::IProcess& process,
                                             const std::vector<hal::ModuleInfo>& modules);

// Parses value_text for the entry's type and writes it. Text must fit the entry's length
// (str / wstr); aob entries are read-only. False if parsing, resolving or writing fails.
bool write_entry(const TableEntry& entry, const std::string& value_text, const hal::IProcess& process,
                 const std::vector<hal::ModuleInfo>& modules);

// JSON with readable hex addresses, meant to be diffed and kept in git
std::string to_json(const CheatTable& table);
std::optional<CheatTable> from_json(const std::string& text);

bool save_table(const std::string& path, const CheatTable& table);
std::optional<CheatTable> load_table(const std::string& path);

} // namespace nce::table
