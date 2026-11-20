#pragma once

#include "../hal/process.hpp"
#include "../scanner/scan_types.hpp"
#include "../scanner/pointer_scanner.hpp"
#include <memory>
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

    // Other pointer paths that led to the same value when it was made permanent. After a restart they
    // vote on where the value is now (see reconcile), and the ones that disagree are dropped.
    std::vector<scanner::PointerPath> alternatives;

    // The bytes around the value when it was made permanent: CONTEXT_RADIUS before it, the value, and
    // CONTEXT_RADIUS after it. Votes alone can be fooled (many paths share one route through the heap and
    // move together), so reconcile prefers the address whose surroundings still look like this.
    std::vector<uint8_t> context;
    static constexpr size_t CONTEXT_RADIUS = 64;

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

// Pointer paths that lead to the entry's current address, best first (scanned with small offsets
// first, the default max offset if those find nothing). Slow: run it off the UI thread. Fails (empty)
// if the entry can't be resolved or no static path exists.
std::vector<scanner::PointerPath> find_permanent_paths(const TableEntry& entry, std::shared_ptr<hal::IProcess> process,
                                                       const std::vector<hal::ModuleInfo>& modules);

// Makes the entry survive restarts: remembers the bytes around its value, then the best path becomes
// its location and up to max_alternatives more are kept for reconcile. False if `paths` is empty.
bool make_permanent(TableEntry& entry, const std::vector<scanner::PointerPath>& paths, const hal::IProcess& process,
                    const std::vector<hal::ModuleInfo>& modules, size_t max_alternatives = 1000);

struct ReconcileResult {
    size_t paths{0};          // location + alternatives
    size_t resolved{0};       // paths that could be followed to some address
    size_t agreeing{0};       // paths that lead to the chosen address
    uintptr_t address{0};     // the chosen address (0 = no paths resolved)
    size_t context_words{0};  // non-zero 4-byte words remembered around the value
    size_t context_matches{0};// how many of them the chosen address still has
    bool value_matches{false};// the chosen address holds the remembered value
    bool by_context{false};   // the surroundings decided, not the vote
    bool ambiguous{false};    // no clear choice: nothing was changed, check the value
    bool changed{false};      // the entry's paths were updated
};

// After a restart: follows every path of the entry and chooses among the addresses they lead to. The
// address whose surroundings match the remembered context best wins. A remembered word counts by its
// nearness to the value (1 / distance in words): the value's own object sits right next to it, while words
// further away may be heap block headers that any block of that size has. Holding the remembered value
// counts like a direct neighbour. Among the addresses within 3/4 of the best match, the one most paths agree
// on wins (ties go to the best-ranked path). Keeps only the paths leading to the choice, the best of them
// as the location.
// Entries without alternatives are left alone; on an ambiguous choice nothing changes.
ReconcileResult reconcile(TableEntry& entry, const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules);

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
