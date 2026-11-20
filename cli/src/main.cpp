#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <algorithm>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <optional>
#include <exception>
#include <utility>
#include <charconv>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include "hal/process.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "scanner/grouped_scanner.hpp"
#include "utils/hex_utils.hpp"
#include "utils/text_encoding.hpp"
#include "table/cheat_table.hpp"
#include "scanner/value_tracker.hpp"

using namespace nce;

static std::shared_ptr<hal::IProcess> g_process;
static std::unique_ptr<scanner::MemoryScanner> g_scanner;
static scanner::ScanResults g_results;
static scanner::DataType g_current_type = scanner::DataType::Int32;
static std::shared_ptr<scanner::MemorySnapshot> g_snapshot; // set by an unknown-value first scan
static scanner::FloatMatchMode g_float_mode = scanner::FloatMatchMode::Rounded;

// Undo history: the scan state before each scan
struct ScanState {
    scanner::ScanResults results;
    std::shared_ptr<scanner::MemorySnapshot> snapshot;
    scanner::DataType type{scanner::DataType::Int32};
};

static std::vector<ScanState> g_history;
constexpr size_t MAX_UNDO_STEPS = 5;

// Moves the current state into the undo history and leaves it empty.
// Snapshots can be as large as the scanned memory, so the history keeps only the newest one:
// pushing a snapshot state drops every older entry.
void push_history() {
    const bool pushing_snapshot = static_cast<bool>(g_snapshot);
    if (pushing_snapshot) {
        g_history.clear();
    }
    g_history.push_back({std::move(g_results), std::move(g_snapshot), g_current_type});
    if (g_history.size() > MAX_UNDO_STEPS) {
        g_history.erase(g_history.begin());
    }
    g_results.clear();
    g_snapshot.reset();
}

void clear_scan_state() {
    g_results.clear();
    g_snapshot.reset();
    g_history.clear();
}

bool is_numeric_type(scanner::DataType type) {
    return scanner::dispatch_numeric(type, []<typename T>() {});
}

std::string format_size(size_t bytes) {
    std::ostringstream ss;
    if (bytes >= 1024 * 1024) ss << (bytes / (1024 * 1024)) << " MB";
    else ss << (bytes / 1024) << " KB";
    return ss.str();
}

std::string describe_scan_state() {
    std::ostringstream ss;
    if (g_snapshot) {
        ss << g_snapshot->candidate_count() << " candidates, snapshot " << format_size(g_snapshot->memory_bytes());
    } else {
        ss << g_results.count() << " matches";
    }
    return ss.str();
}

long long elapsed_ms(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
}

// Makes the current scan state `source` filtered by one next-scan step. A snapshot stays a snapshot
// until its candidates would take less memory as a results list.
void filter_into_current(const ScanState& source, scanner::ScanCondition cond,
                         const scanner::ScanValue& val1, const scanner::ScanValue& val2) {
    g_current_type = source.type;
    if (!source.snapshot) {
        g_results = g_scanner->next_scan(source.results, cond, val1, val2);
        g_snapshot.reset();
        return;
    }

    auto filtered = std::make_shared<scanner::MemorySnapshot>(
        g_scanner->filter_snapshot(*source.snapshot, cond, val1, val2));
    const size_t result_bytes = filtered->candidate_count() *
                                (sizeof(uintptr_t) + 2 * scanner::get_data_type_size(filtered->type));
    if (result_bytes <= filtered->memory_bytes()) {
        g_results = scanner::MemoryScanner::snapshot_to_results(*filtered);
        g_snapshot.reset();
    } else {
        g_results.clear();
        g_snapshot = std::move(filtered);
    }
}

// Freeze list support
struct FrozenEntry {
    uintptr_t address{0};
    scanner::DataType type{scanner::DataType::Int32};
    scanner::ScanValue value;
    bool active{true};
};

static std::vector<FrozenEntry> g_frozen_list;
static std::mutex g_freeze_mutex;
static std::atomic<bool> g_freeze_running{true};
static std::thread g_freeze_thread;

// Cheat table and the target's modules (used to resolve its entries). The freeze thread writes frozen
// table entries, so both are only touched under g_freeze_mutex. The table is kept across attach:
// its module-relative entries are meant for the next run of the same program.
static table::CheatTable g_table;
static std::vector<hal::ModuleInfo> g_modules;

void freeze_worker() {
    while (g_freeze_running) {
        {
            std::lock_guard<std::mutex> lock(g_freeze_mutex);
            if (g_process && g_process->is_attached()) {
                for (const auto& entry : g_frozen_list) {
                    if (!entry.active) continue;
                    scanner::dispatch_numeric(entry.type, [&]<typename T>() {
                        g_process->write(entry.address, std::get<T>(entry.value.value));
                    });
                }
                for (const auto& entry : g_table.entries) {
                    if (entry.frozen_value) {
                        table::write_entry(entry, *entry.frozen_value, *g_process, g_modules);
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void print_banner() {
    std::cout << "=========================================================\n";
    std::cout << "      New-Cheat-Engine (NCE) - Next-Gen Memory Scanner   \n";
    std::cout << "        High-Performance Cross-Platform Memory Engine     \n";
    std::cout << "=========================================================\n\n";
}

void print_help() {
    std::cout << "General Commands:\n"
              << "  ps [filter]                     - List running processes (with optional name filter)\n"
              << "  attach <pid>                    - Attach to process by PID\n"
              << "  detach                          - Detach from target process\n"
              << "  modules                         - List loaded modules in target process\n"
              << "  regions                         - Display memory regions summary\n\n"
              << "Scanning Commands:\n"
              << "  scan <type> <value>             - First scan (types: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64,\n"
              << "                                    str, wstr, aob). Use '?' as value for an unknown initial value.\n"
              << "                                    Examples: 'scan i32 1337', 'scan f32 ?', 'scan wstr Player 1',\n"
              << "                                    'scan aob 48 8B ? ? 89'\n"
              << "  next <cond> [val] [val2]        - Next scan (cond: exact, changed, unchanged, inc, dec,\n"
              << "                                    gt, lt, between, incby, decby). Example: 'next between 10 20'\n"
              << "  track <type>                    - Guided search for a value you can change but don't know:\n"
              << "                                    filters out noise while you wait, then asks how it changed\n"
              << "  undo                            - Go back to the results before the last scan (up to 5 steps;\n"
              << "                                    only the newest unknown-value snapshot is kept)\n"
              << "  floatmode [rounded|truncated|exact] - How 'exact' float values match (default: rounded)\n"
              << "  save <file> / load <file>       - Save or load the current results\n"
              << "  group <type1> <val1> ...        - Grouped scan: find multiple values in same struct\n"
              << "                                    Example: 'group i32 100 i32 50 f32 25.5'\n"
              << "  ptrscan <addr> [depth] [offset] [module] - Pointer Scanner: find static base pointer paths\n"
              << "                                    Example: 'ptrscan 0x12345678 4 0x800 game.exe'\n"
              << "  ptrrescan <new_addr>            - Keep only the paths that still lead to the value (after a restart)\n"
              << "  ptrlist [count] / ptrsave <file> / ptrload <file> - Show, save or load pointer paths\n"
              << "  list [count]                    - Display up to [count] scan results (default: 20)\n\n"
              << "Cheat Table (survives restarts: module+offset or pointer paths, saved as JSON):\n"
              << "  add #<result> [description]     - Add a scan result (e.g. 'add #0 Health')\n"
              << "  add <addr> <type> [description] - Add an address; addptr <path#> <type> [desc] adds a pointer path\n"
              << "  table                           - Show entries with their current values\n"
              << "  tset <#> <value> / tdel <#>     - Write a value / remove an entry\n"
              << "  tfreeze <#> [value] / tunfreeze <#> - Lock an entry (default: its current value)\n"
              << "  tsave <file.json> / tload <file.json> - Save or load the table\n\n"
              << "Memory Operations:\n"
              << "  write <addr> <type> <val>       - Write value to memory address\n"
              << "  read <addr> <type>              - Read value from memory address\n"
              << "  dump <addr> [bytes]             - Hex dump memory (default: 64 bytes)\n"
              << "  freeze <addr> <type> <val>      - Lock/freeze value continuously\n"
              << "  frozen                          - List all frozen values\n"
              << "  unfreeze [index|all]            - Remove value from freeze list\n\n"
              << "  help                            - Show this help menu\n"
              << "  quit                            - Exit CLI\n\n";
}

// Numeric types only (no str/wstr/aob); prints an error and returns nullopt for anything else
std::optional<scanner::DataType> parse_numeric_type(const std::string& type_str) {
    auto type = utils::parse_data_type(type_str);
    if (!type || !is_numeric_type(*type)) {
        std::cerr << "[!] Unknown type: '" << type_str << "'. Use i8, i16, i32, i64, u8, u16, u32, u64, f32, f64.\n";
        return std::nullopt;
    }
    return type;
}

std::optional<scanner::ScanValue> parse_value(scanner::DataType type, const std::string& val_str) {
    auto value = utils::parse_scan_value(type, val_str);
    if (!value) {
        std::cerr << "[!] Invalid value: '" << val_str << "' (not a number, or out of range for this type).\n";
    }
    return value;
}

const char* float_mode_name(scanner::FloatMatchMode mode) {
    switch (mode) {
        case scanner::FloatMatchMode::Rounded:   return "rounded";
        case scanner::FloatMatchMode::Truncated: return "truncated";
        case scanner::FloatMatchMode::Exact:     return "exact";
    }
    return "?";
}

// For f32/f64 under the rounded/truncated float mode: the [low, high] range an exact value stands for
std::optional<std::pair<scanner::ScanValue, scanner::ScanValue>> float_exact_range(scanner::DataType type,
                                                                                    const std::string& val_str) {
    if (type != scanner::DataType::Float && type != scanner::DataType::Double) return std::nullopt;
    auto range = utils::float_match_range(val_str, g_float_mode);
    if (!range) return std::nullopt;

    std::cout << "[*] Matching " << utils::format_data_type(type) << " values in [" << range->first << ", "
              << range->second << "] (floatmode " << float_mode_name(g_float_mode) << ")\n";
    if (type == scanner::DataType::Float) {
        return std::make_pair(scanner::ScanValue::of(type, static_cast<float>(range->first)),
                              scanner::ScanValue::of(type, static_cast<float>(range->second)));
    }
    return std::make_pair(scanner::ScanValue::of(type, range->first), scanner::ScanValue::of(type, range->second));
}

void cmd_ps(const std::string& filter) {
    auto procs = hal::IProcess::list_processes();
    std::string lower_filter = filter;
    std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(), ::tolower);

    std::cout << "\n PID       Process Name\n";
    std::cout << "----------------------------------------\n";
    size_t count = 0;
    for (const auto& p : procs) {
        std::string name_lower = p.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        if (lower_filter.empty() || name_lower.find(lower_filter) != std::string::npos) {
            std::cout << " " << std::left << std::setw(10) << p.pid << p.name << "\n";
            count++;
        }
    }
    std::cout << "----------------------------------------\n";
    std::cout << " Found " << count << " process(es).\n\n";
}

void cmd_attach(uint32_t pid) {
    bool attached = false;
    size_t dropped_freezes = 0;
    {
        // The freeze thread writes through g_process while holding this lock, so the handle
        // may only change under it. Frozen addresses belong to the old process: drop them.
        std::lock_guard<std::mutex> lock(g_freeze_mutex);
        dropped_freezes = g_frozen_list.size();
        g_frozen_list.clear();
        // Absolute table addresses also belong to the old process; module-relative ones stay frozen
        // (they only resolve if the new process has the same module)
        for (auto& entry : g_table.entries) {
            if (entry.is_absolute() && entry.frozen_value) {
                entry.frozen_value.reset();
                ++dropped_freezes;
            }
        }
        if (!g_process) {
            g_process = hal::IProcess::create();
        }
        attached = g_process->attach(pid);
        g_modules = attached ? g_process->get_modules() : std::vector<hal::ModuleInfo>{};
    }

    clear_scan_state();
    if (dropped_freezes > 0) {
        std::cout << "[*] Unfroze " << dropped_freezes << " address(es) that belonged to the previous process.\n";
    }

    if (attached) {
        g_scanner = std::make_unique<scanner::MemoryScanner>(g_process);
        std::cout << "[+] Successfully attached to PID: " << pid << "\n";
    } else {
        std::cerr << "[-] Failed to attach to PID: " << pid << ". Run as Administrator or check PID.\n";
    }
}

void cmd_detach() {
    {
        std::lock_guard<std::mutex> lock(g_freeze_mutex);
        g_frozen_list.clear();
        if (g_process) g_process->detach();
        g_modules.clear();
    }
    clear_scan_state();
    std::cout << "[*] Detached.\n";
}

void cmd_modules() {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }
    auto modules = g_process->get_modules();
    std::cout << "\n Base Address        Size (Bytes)   Module Name\n";
    std::cout << "------------------------------------------------------------------\n";
    for (const auto& m : modules) {
        std::cout << " " << utils::format_address(m.base_address) << "   "
                  << std::setw(12) << std::dec << m.size << "   "
                  << m.name << "\n";
    }
    std::cout << "------------------------------------------------------------------\n";
    std::cout << " Total modules: " << modules.size() << "\n\n";
}

void cmd_regions() {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }
    auto regions = g_process->query_regions();
    size_t total_size = 0;
    for (const auto& r : regions) total_size += r.size;

    std::cout << "\nMemory Regions Summary:\n";
    std::cout << " Readable/Writable Regions : " << regions.size() << "\n";
    std::cout << " Total Scannable Memory    : " << (total_size / (1024 * 1024)) << " MB (" 
              << total_size << " bytes)\n\n";
}

// rest = everything after the type: a number, '?' (unknown initial value), text for str/wstr, or an AOB pattern
void cmd_first_scan(const std::string& type_str, const std::string& rest) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Please attach to a process first using 'attach <pid>'.\n";
        return;
    }

    auto type = utils::parse_data_type(type_str);
    if (!type) {
        std::cerr << "[!] Unknown type: '" << type_str
                  << "'. Use i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, str, wstr, aob.\n";
        return;
    }

    std::istringstream rest_stream(rest);
    std::string val_str;
    rest_stream >> val_str;
    const auto start = std::chrono::steady_clock::now();

    if (*type == scanner::DataType::AOB) {
        if (!utils::parse_aob_pattern(rest)) {
            std::cerr << "[!] Invalid AOB pattern. Example: 'scan aob 48 8B ? ? 89'\n";
            return;
        }
        std::cout << "[*] Starting First Scan for type [" << type_str << "] ...\n";
        push_history();
        g_current_type = *type;
        g_results = g_scanner->first_scan_aob(rest, 1);
    } else if (*type == scanner::DataType::String || *type == scanner::DataType::String16) {
        const bool utf16 = (*type == scanner::DataType::String16);
        if (utf16 && !utils::utf8_to_utf16le(rest)) {
            std::cerr << "[!] Text is not valid UTF-8 (non-ASCII input needs a UTF-8 console).\n";
            return;
        }
        std::cout << "[*] Starting First Scan for type [" << type_str << "] \"" << rest << "\" ...\n";
        push_history();
        g_current_type = *type;
        g_results = g_scanner->first_scan_string(rest, utf16, 1);
    } else if (val_str == "?" || val_str == "unknown") {
        std::cout << "[*] Capturing unknown-value snapshot for type [" << type_str << "] ...\n";
        push_history();
        g_current_type = *type;
        g_snapshot = std::make_shared<scanner::MemorySnapshot>(
            g_scanner->first_scan_unknown(*type, scanner::get_data_type_size(*type)));
        std::cout << "[+] Snapshot captured in " << elapsed_ms(start) << " ms: " << describe_scan_state() << ". "
                  << "Change the value in the target, then use 'next changed/unchanged/inc/dec/...'.\n";
        return;
    } else {
        auto val = parse_value(*type, val_str);
        if (!val) return;
        const auto range = float_exact_range(*type, val_str);
        std::cout << "[*] Starting First Scan for type [" << type_str << "] ...\n";
        push_history();
        g_current_type = *type;
        const size_t alignment = scanner::get_data_type_size(*type);
        if (range) {
            g_results = g_scanner->first_scan(*type, scanner::ScanCondition::Between, range->first, range->second, alignment);
        } else {
            g_results = g_scanner->first_scan(*type, scanner::ScanCondition::ExactValue, *val, {}, alignment);
        }
    }

    std::cout << "[+] First Scan complete in " << elapsed_ms(start) << " ms. Found " << g_results.count() << " match(es).\n";
}

void cmd_next_scan(const std::string& cond_str, const std::string& val_str, const std::string& val2_str) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }
    if (g_results.empty() && !g_snapshot) {
        std::cerr << "[-] No active scan results. Run 'scan <type> <value>' first.\n";
        return;
    }

    struct ConditionSpec {
        const char* name;
        scanner::ScanCondition cond;
        int value_count;
    };
    static constexpr ConditionSpec conditions[] = {
        {"exact",     scanner::ScanCondition::ExactValue,  1},
        {"changed",   scanner::ScanCondition::Changed,     0},
        {"unchanged", scanner::ScanCondition::Unchanged,   0},
        {"inc",       scanner::ScanCondition::Increased,   0},
        {"dec",       scanner::ScanCondition::Decreased,   0},
        {"gt",        scanner::ScanCondition::GreaterThan, 1},
        {"lt",        scanner::ScanCondition::LessThan,    1},
        {"between",   scanner::ScanCondition::Between,     2},
        {"incby",     scanner::ScanCondition::IncreasedBy, 1},
        {"decby",     scanner::ScanCondition::DecreasedBy, 1},
    };

    const ConditionSpec* spec = nullptr;
    for (const auto& c : conditions) {
        if (cond_str == c.name) spec = &c;
    }
    if (!spec) {
        std::cerr << "[!] Unknown condition: " << cond_str
                  << ". Use exact/changed/unchanged/inc/dec/gt/lt/between/incby/decby.\n";
        return;
    }

    if (!is_numeric_type(g_current_type) &&
        spec->cond != scanner::ScanCondition::Changed && spec->cond != scanner::ScanCondition::Unchanged) {
        std::cerr << "[!] Text and AOB results only support 'next changed' and 'next unchanged'.\n";
        return;
    }

    scanner::ScanCondition cond = spec->cond;
    scanner::ScanValue val;
    scanner::ScanValue val2;
    if (spec->value_count >= 1) {
        auto parsed = parse_value(g_current_type, val_str);
        if (!parsed) return;
        val = *parsed;
    }
    if (spec->value_count >= 2) {
        auto parsed = parse_value(g_current_type, val2_str);
        if (!parsed) return;
        val2 = *parsed;
    }
    if (cond == scanner::ScanCondition::ExactValue) {
        if (auto range = float_exact_range(g_current_type, val_str)) {
            cond = scanner::ScanCondition::Between;
            val = range->first;
            val2 = range->second;
        }
    }

    std::cout << "[*] Filtering " << describe_scan_state() << " ...\n";
    const auto start = std::chrono::steady_clock::now();
    push_history();
    filter_into_current(g_history.back(), cond, val, val2);
    std::cout << "[+] Next Scan complete in " << elapsed_ms(start) << " ms: " << describe_scan_state() << " remaining.\n";
}

void cmd_undo() {
    if (g_history.empty()) {
        std::cerr << "[-] Nothing to undo.\n";
        return;
    }
    ScanState& previous = g_history.back();
    g_results = std::move(previous.results);
    g_snapshot = std::move(previous.snapshot);
    g_current_type = previous.type;
    g_history.pop_back();
    std::cout << "[*] Restored previous results: " << describe_scan_state() << ".\n";
}

void cmd_floatmode(const std::string& mode) {
    if (mode == "rounded") g_float_mode = scanner::FloatMatchMode::Rounded;
    else if (mode == "truncated") g_float_mode = scanner::FloatMatchMode::Truncated;
    else if (mode == "exact") g_float_mode = scanner::FloatMatchMode::Exact;
    else if (!mode.empty()) {
        std::cerr << "[!] Unknown float mode: '" << mode << "'. Use rounded, truncated or exact.\n";
        return;
    }
    std::cout << "[*] Float mode: " << float_mode_name(g_float_mode) << "\n";
}

void cmd_save(const std::string& path) {
    if (g_snapshot) {
        std::cerr << "[-] An unknown-value snapshot can't be saved. Run a next scan first.\n";
        return;
    }
    if (g_results.empty()) {
        std::cerr << "[-] No results to save.\n";
        return;
    }
    const uint32_t pid = (g_process && g_process->is_attached()) ? g_process->get_pid() : 0;
    if (scanner::save_results(path, pid, g_current_type, g_results)) {
        std::cout << "[+] Saved " << g_results.count() << " result(s) to " << path << "\n";
    } else {
        std::cerr << "[-] Failed to write " << path << "\n";
    }
}

void cmd_load(const std::string& path) {
    auto saved = scanner::load_results(path);
    if (!saved) {
        std::cerr << "[-] Could not read results from " << path << "\n";
        return;
    }
    push_history();
    g_results = std::move(saved->results);
    g_current_type = saved->type;
    std::cout << "[+] Loaded " << g_results.count() << " " << utils::format_data_type(g_current_type)
              << " result(s) from " << path << "\n";

    if (g_process && g_process->is_attached() && saved->pid != g_process->get_pid()) {
        std::cout << "[!] These results were saved from PID " << saved->pid
                  << "; addresses may not be valid in PID " << g_process->get_pid() << ".\n";
    }
}

void cmd_list(size_t max_count);

std::string trim(const std::string& s) {
    const size_t first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

std::string describe_tracker(const scanner::ValueTracker& tracker) {
    std::ostringstream ss;
    ss << tracker.candidate_count() << " candidates";
    if (tracker.is_ranked()) ss << " (ranked)";
    else ss << " (snapshot, " << format_size(tracker.memory_bytes()) << ")";
    return ss.str();
}

void print_ranked(const scanner::ValueTracker& tracker, size_t count) {
    const auto ranked = tracker.top(count);
    std::cout << "        Best candidates:\n";
    for (size_t i = 0; i < ranked.size(); ++i) {
        std::cout << "        [" << i << "] " << utils::format_address(ranked[i].address) << " = " << std::left
                  << std::setw(12) << ranked[i].value.to_string() << std::right << " score " << std::setw(3)
                  << ranked[i].score << "  " << ranked[i].reason << "\n";
    }
}

// Guided unknown-value search with smart ranking. Each round has a quiet phase (the user leaves the
// value alone while values that change on their own lose points) and a change step (the user changes
// the value and says how). Candidates are scored rather than cut on every answer, so one wrong answer
// lowers the right address instead of losing it.
void cmd_track(const std::string& type_str) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Please attach to a process first using 'attach <pid>'.\n";
        return;
    }
    auto type = parse_numeric_type(type_str);
    if (!type) return;

    constexpr size_t SHOW_BEST = 5;
    constexpr size_t MAX_HANDOVER = 5'000'000; // candidates turned into results when tracking stops

    scanner::ValueTracker tracker(g_process, *type);
    std::cout << "[*] Tracking an unknown " << type_str << " value. Capturing snapshot ...\n";
    auto start = std::chrono::steady_clock::now();
    tracker.start();
    std::cout << "[+] Snapshot captured in " << elapsed_ms(start) << " ms: " << describe_tracker(tracker) << ".\n";

    for (int round = 1;; ++round) {
        std::cout << "\n[track] Round " << round << " - " << describe_tracker(tracker) << ".\n"
                  << "        Leave the value alone: values that change on their own lose points.\n"
                  << "        Press Enter when you are ready to change it (or type 'done').\n";

        // Quiet phase. The main thread only waits for input here, so the noise thread owns the tracker.
        std::atomic<bool> stop{false};
        std::exception_ptr noise_error;
        std::thread noise([&] {
            try {
                size_t last_count = SIZE_MAX;
                do {
                    tracker.observe_quiet();
                    const size_t count = tracker.candidate_count();
                    if (count != last_count) {
                        std::cout << "        [noise filter] " << describe_tracker(tracker) << "\n";
                        last_count = count;
                    }
                    for (int i = 0; i < 5 && !stop; ++i) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                } while (!stop);
            } catch (...) {
                noise_error = std::current_exception();
            }
        });

        std::string line;
        const bool got_line = static_cast<bool>(std::getline(std::cin, line));
        stop = true;
        noise.join();
        if (noise_error) std::rethrow_exception(noise_error);
        if (!got_line || trim(line) == "done") break;

        // Change step
        std::cout << "[track] Change the value now, then type how it changed:\n"
                  << "        + (increased), - (decreased), c (changed), a number (its new value), or 'done'\n> "
                  << std::flush;
        if (!std::getline(std::cin, line)) break;
        line = trim(line);
        if (line == "done") break;

        auto expected = scanner::parse_expectation(*type, line, g_float_mode);
        if (!expected) {
            std::cout << "[track] '" << line << "' is not +, -, c or a valid " << type_str
                      << " value. Skipping this round.\n";
            continue;
        }

        start = std::chrono::steady_clock::now();
        tracker.observe_event(*expected);
        std::cout << "[+] Checked in " << elapsed_ms(start) << " ms: " << describe_tracker(tracker) << ".\n";

        if (tracker.candidate_count() == 0) {
            std::cout << "[-] No candidates left: the value did not change when you said it did.\n";
            break;
        }
        if (tracker.is_ranked()) print_ranked(tracker, SHOW_BEST);
        if (tracker.candidate_count() == 1) break;
    }

    // Hand the candidates over as normal results, best first
    if (tracker.candidate_count() > MAX_HANDOVER) {
        std::cout << "[track] Stopped with " << describe_tracker(tracker)
                  << ": too many to list. Run 'track' again and change the value a few times.\n";
        return;
    }
    push_history();
    g_current_type = *type;
    g_results = tracker.to_results();
    std::cout << "[track] Stopped with " << g_results.count() << " result(s), best first. "
              << "'list' shows them, 'add #0 <name>' adds the best one.\n";
}

void cmd_grouped_scan(const std::vector<std::string>& tokens) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    if (tokens.size() < 2 || tokens.size() % 2 != 0) {
        std::cout << "Usage: group <type1> <val1> <type2> <val2> ...\n"
                  << "Example: group i32 100 i32 50 f32 25.5\n";
        return;
    }

    std::vector<scanner::GroupedEntry> entries;
    for (size_t i = 0; i < tokens.size(); i += 2) {
        auto type = parse_numeric_type(tokens[i]);
        if (!type) return;
        auto val = parse_value(*type, tokens[i + 1]);
        if (!val) return;
        entries.push_back({*type, *val, 0, false});
    }

    std::cout << "[*] Running Grouped Scan with " << entries.size() << " members in 0x100 byte window...\n";
    scanner::GroupedScanner gscanner(g_process);
    auto matches = gscanner.scan(entries, 0x100);

    std::cout << "[+] Found " << matches.size() << " matching struct(s):\n";
    for (size_t i = 0; i < matches.size(); ++i) {
        std::cout << "  [" << i << "] Struct Base: " << utils::format_address(matches[i].base_address) << "\n";
        for (size_t m = 0; m < matches[i].member_addresses.size(); ++m) {
            std::cout << "       Member " << m << ": " << utils::format_address(matches[i].member_addresses[m])
                      << " (offset +0x" << std::hex << (matches[i].member_addresses[m] - matches[i].base_address) << std::dec << ")\n";
        }
    }
}

// Pointer paths from the last ptrscan / ptrload. Kept across attach/detach on purpose: paths are
// module-relative, so they are meant to be rescanned in the restarted target.
static std::vector<scanner::PointerPath> g_pointer_paths;

void cmd_ptrlist(size_t max_count = 20) {
    if (g_pointer_paths.empty()) {
        std::cout << "[-] No pointer paths. Run 'ptrscan <addr>' or 'ptrload <file>' first.\n";
        return;
    }

    const bool attached = g_process && g_process->is_attached();
    const auto modules = attached ? g_process->get_modules() : std::vector<hal::ModuleInfo>{};
    const size_t count = std::min(max_count, g_pointer_paths.size());
    for (size_t i = 0; i < count; ++i) {
        std::cout << "  [" << std::right << std::setw(3) << i << "] " << g_pointer_paths[i].to_string();
        if (attached) {
            const uintptr_t now = g_pointer_paths[i].resolve(*g_process, modules);
            std::cout << "  => " << (now ? utils::format_address(now) : std::string("(unresolved)"));
        }
        std::cout << "\n";
    }
    std::cout << " Showing " << count << " of " << g_pointer_paths.size() << " path(s).\n";
}

void cmd_pointer_scan(const std::string& addr_str, size_t max_depth, size_t max_offset, const std::string& base_module) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    uintptr_t target_addr = utils::parse_address(addr_str);
    if (target_addr == 0) {
        std::cerr << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    scanner::PointerScanOptions options;
    options.max_depth = max_depth;
    options.max_offset = max_offset;
    options.base_module = base_module;

    std::cout << "[*] Starting Pointer Scanner for " << utils::format_address(target_addr)
              << " (Max Depth: " << max_depth << ", Max Offset: 0x" << std::hex << max_offset << std::dec
              << ", Base: " << (base_module.empty() ? "any module" : base_module)
              << ", " << (g_process->pointer_size() * 8) << "-bit target) ...\n";

    const auto start = std::chrono::steady_clock::now();
    scanner::PointerScanner ptr_scanner(g_process);
    auto result = ptr_scanner.scan(target_addr, options, [](size_t depth, size_t count) {
        std::cout << "  -> Depth " << depth << " explored: " << count << " static path(s) found.\n";
    });
    g_pointer_paths = std::move(result.paths);

    std::cout << "\n[+] Pointer Scan complete in " << elapsed_ms(start) << " ms: " << g_pointer_paths.size()
              << " path(s) (pointer map: " << result.pointer_map_size << " pointers, "
              << result.nodes_explored << " nodes searched).\n";
    if (result.truncated) {
        std::cout << "[!] The search hit its limit, so some paths are missing. Narrow it with a lower depth,\n"
                  << "    a smaller max offset, or a base module.\n";
    }
    cmd_ptrlist(20);
    if (!g_pointer_paths.empty()) {
        std::cout << "[*] Restart the target, find the value's new address, then run 'ptrrescan <new addr>'\n"
                  << "    to keep only the paths that survive. 'ptrsave <file>' keeps them across sessions.\n";
    }
}

void cmd_ptrrescan(const std::string& addr_str) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }
    if (g_pointer_paths.empty()) {
        std::cerr << "[-] No pointer paths to rescan. Run 'ptrscan' or 'ptrload' first.\n";
        return;
    }
    uintptr_t target_addr = utils::parse_address(addr_str);
    if (target_addr == 0) {
        std::cerr << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    const size_t before = g_pointer_paths.size();
    g_pointer_paths = scanner::PointerScanner::verify_paths(*g_process, g_pointer_paths, target_addr);
    std::cout << "[+] Rescan: " << g_pointer_paths.size() << " of " << before << " path(s) still lead to "
              << utils::format_address(target_addr) << ".\n";
    cmd_ptrlist(20);
}

void cmd_ptrsave(const std::string& path) {
    if (g_pointer_paths.empty()) {
        std::cerr << "[-] No pointer paths to save.\n";
        return;
    }
    if (scanner::save_pointer_paths(path, g_pointer_paths)) {
        std::cout << "[+] Saved " << g_pointer_paths.size() << " pointer path(s) to " << path << "\n";
    } else {
        std::cerr << "[-] Failed to write " << path << "\n";
    }
}

void cmd_ptrload(const std::string& path) {
    auto loaded = scanner::load_pointer_paths(path);
    if (!loaded) {
        std::cerr << "[-] Could not read pointer paths from " << path << "\n";
        return;
    }
    g_pointer_paths = std::move(*loaded);
    std::cout << "[+] Loaded " << g_pointer_paths.size() << " pointer path(s) from " << path << "\n";
}

// ---- Cheat table -------------------------------------------------------------------------------

// A value as the user would type it back (text without quotes)
std::string value_text(const scanner::ScanValue& value) {
    if (value.type == scanner::DataType::String) return std::get<std::string>(value.value);
    if (value.type == scanner::DataType::String16) {
        const auto& bytes = std::get<std::vector<uint8_t>>(value.value);
        return utils::utf16le_to_utf8(bytes.data(), bytes.size());
    }
    return value.to_string();
}

// Parses "3" into a valid index of a list of `size` items, or prints an error
std::optional<size_t> parse_index(const std::string& text, size_t size, const char* what) {
    size_t index = 0;
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), index);
    if (ec != std::errc() || ptr != text.data() + text.size() || text.empty() || index >= size) {
        std::cerr << "[-] No " << what << " #" << text << " (there are " << size << ").\n";
        return std::nullopt;
    }
    return index;
}

// add <addr|#result> <type> [description]
void cmd_table_add(const std::string& where, const std::string& type_str, const std::string& description) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    std::optional<table::TableEntry> entry;
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    if (!where.empty() && where[0] == '#') {
        // From the scan results: address, type and text length come from the result itself
        auto index = parse_index(where.substr(1), g_results.count(), "result");
        if (!index) return;
        entry = table::make_entry(g_results.address(*index), g_results.type(), g_modules, description,
                                  g_results.value_size());
    } else {
        auto type = parse_numeric_type(type_str);
        if (!type) return;
        const uintptr_t address = utils::parse_address(where);
        if (address == 0) {
            std::cerr << "[-] Invalid address: " << where << "\n";
            return;
        }
        entry = table::make_entry(address, *type, g_modules, description);
    }

    g_table.entries.push_back(*entry);
    std::cout << "[+] Added #" << g_table.entries.size() - 1 << ": " << entry->location_string()
              << (entry->is_absolute() ? "  (heap address: only valid until the target restarts)" : "") << "\n";
}

// addptr <path#> <type> [description]
void cmd_table_add_pointer(const std::string& path_index, const std::string& type_str, const std::string& description) {
    auto index = parse_index(path_index, g_pointer_paths.size(), "pointer path");
    if (!index) return;
    auto type = parse_numeric_type(type_str);
    if (!type) return;

    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    g_table.entries.push_back(table::make_entry(g_pointer_paths[*index], *type, description));
    std::cout << "[+] Added #" << g_table.entries.size() - 1 << ": " << g_table.entries.back().location_string() << "\n";
}

void cmd_table_list() {
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    if (g_table.entries.empty()) {
        std::cout << "[-] The table is empty. Add values with 'add #<result>' or 'add <addr> <type>'.\n";
        return;
    }
    const bool attached = g_process && g_process->is_attached();
    if (attached) g_modules = g_process->get_modules();

    std::cout << "\n Index  Description           Type  Value              Location\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    for (size_t i = 0; i < g_table.entries.size(); ++i) {
        const auto& e = g_table.entries[i];
        std::string value = "??";
        if (attached) {
            if (auto v = table::read_entry(e, *g_process, g_modules)) value = v->to_string();
        }
        if (e.frozen_value) value += " [frozen]";
        std::cout << " [" << std::right << std::setw(3) << i << "]  " << std::left << std::setw(20) << e.description
                  << "  " << std::setw(4) << utils::format_data_type(e.type) << "  " << std::setw(17) << value
                  << "  " << e.location_string() << "\n";
    }
    std::cout << std::right << "--------------------------------------------------------------------------------\n";
}

void cmd_table_set(const std::string& index_text, const std::string& value) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    auto index = parse_index(index_text, g_table.entries.size(), "table entry");
    if (!index) return;
    auto& e = g_table.entries[*index];
    if (table::write_entry(e, value, *g_process, g_modules)) {
        if (e.frozen_value) e.frozen_value = value; // keep a frozen entry at the new value
        std::cout << "[+] #" << *index << " set to " << value << "\n";
    } else {
        std::cerr << "[-] Could not write '" << value << "' to #" << *index
                  << " (invalid value, text too long, aob entry, or address not resolvable).\n";
    }
}

void cmd_table_freeze(const std::string& index_text, const std::string& value, bool freeze) {
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    auto index = parse_index(index_text, g_table.entries.size(), "table entry");
    if (!index) return;
    auto& e = g_table.entries[*index];

    if (!freeze) {
        e.frozen_value.reset();
        std::cout << "[*] #" << *index << " unfrozen.\n";
        return;
    }

    std::string frozen = value;
    if (frozen.empty()) {
        // Default: keep the value it has right now
        auto current = (g_process && g_process->is_attached()) ? table::read_entry(e, *g_process, g_modules) : std::nullopt;
        if (!current) {
            std::cerr << "[-] Can't read #" << *index << " to freeze it; give a value: tfreeze " << *index << " <value>\n";
            return;
        }
        frozen = value_text(*current);
    }
    e.frozen_value = frozen;
    std::cout << "[+] #" << *index << " frozen at " << frozen << "\n";
}

void cmd_table_delete(const std::string& index_text) {
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    auto index = parse_index(index_text, g_table.entries.size(), "table entry");
    if (!index) return;
    g_table.entries.erase(g_table.entries.begin() + static_cast<std::ptrdiff_t>(*index));
    std::cout << "[*] Removed #" << *index << ".\n";
}

void cmd_table_save(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    if (g_table.process_name.empty() && !g_modules.empty()) g_table.process_name = g_modules.front().name;
    if (table::save_table(path, g_table)) {
        std::cout << "[+] Saved " << g_table.entries.size() << " table entr(ies) to " << path << "\n";
    } else {
        std::cerr << "[-] Failed to write " << path << "\n";
    }
}

void cmd_table_load(const std::string& path) {
    auto loaded = table::load_table(path);
    if (!loaded) {
        std::cerr << "[-] Could not read a table from " << path << "\n";
        return;
    }
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    g_table = std::move(*loaded);
    size_t frozen = 0;
    for (const auto& e : g_table.entries) frozen += e.frozen_value ? 1 : 0;
    std::cout << "[+] Loaded " << g_table.entries.size() << " entr(ies) for '" << g_table.process_name << "' from "
              << path << (frozen ? " (" + std::to_string(frozen) + " frozen)" : std::string()) << "\n";
}

void cmd_freeze(const std::string& addr_str, const std::string& type_str, const std::string& val_str) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    uintptr_t addr = utils::parse_address(addr_str);
    if (addr == 0) {
        std::cerr << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    auto type = parse_numeric_type(type_str);
    if (!type) return;
    auto val = parse_value(*type, val_str);
    if (!val) return;

    {
        std::lock_guard<std::mutex> lock(g_freeze_mutex);
        g_frozen_list.push_back({addr, *type, *val, true});
    }

    std::cout << "[+] Frozen " << utils::format_address(addr) << " to value [" << val->to_string() << "].\n";
}

void cmd_list_frozen() {
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    if (g_frozen_list.empty()) {
        std::cout << "[-] No frozen addresses.\n";
        return;
    }

    std::cout << "\n Index   Address              Locked Value\n";
    std::cout << "--------------------------------------------------\n";
    for (size_t i = 0; i < g_frozen_list.size(); ++i) {
        const auto& f = g_frozen_list[i];
        std::cout << " [" << std::right << std::setw(3) << i << "]  "
                  << utils::format_address(f.address) << "   "
                  << f.value.to_string() << (f.active ? " (Active)" : " (Paused)") << "\n";
    }
    std::cout << "--------------------------------------------------\n\n";
}

void cmd_unfreeze(const std::string& param) {
    std::lock_guard<std::mutex> lock(g_freeze_mutex);
    if (param == "all") {
        g_frozen_list.clear();
        std::cout << "[*] Unfroze all addresses.\n";
    } else {
        try {
            size_t idx = std::stoul(param);
            if (idx < g_frozen_list.size()) {
                g_frozen_list.erase(g_frozen_list.begin() + idx);
                std::cout << "[*] Removed index " << idx << " from freeze list.\n";
            } else {
                std::cerr << "[-] Index out of bounds.\n";
            }
        } catch (...) {
            std::cerr << "[-] Invalid index: " << param << "\n";
        }
    }
}

void cmd_list(size_t max_count = 20) {
    if (g_snapshot) {
        std::cout << "[*] Current state is an " << describe_scan_state()
                  << ". Run 'next changed/unchanged/inc/dec/...' to get addresses.\n";
        return;
    }
    if (g_results.empty()) {
        std::cout << "[-] No results found.\n";
        return;
    }

    size_t count = std::min(max_count, g_results.count());
    std::cout << "\n Index   Address              Current Value     Previous Value\n";
    std::cout << "------------------------------------------------------------------\n";
    for (size_t i = 0; i < count; ++i) {
        const auto& m = g_results[i];
        std::cout << " [" << std::right << std::setw(3) << i << "]  " 
                  << utils::format_address(m.address) << "   "
                  << std::setw(16) << std::left << m.current_value.to_string() << "  "
                  << m.previous_value.to_string() << "\n";
    }
    std::cout << "------------------------------------------------------------------\n";
    std::cout << " Showing " << count << " of " << g_results.count() << " match(es).\n\n";
}

void cmd_write(const std::string& addr_str, const std::string& type_str, const std::string& val_str) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    uintptr_t addr = utils::parse_address(addr_str);
    if (addr == 0) {
        std::cerr << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    auto type = parse_numeric_type(type_str);
    if (!type) return;
    auto val = parse_value(*type, val_str);
    if (!val) return;

    bool success = false;
    scanner::dispatch_numeric(*type, [&]<typename T>() {
        success = g_process->write(addr, std::get<T>(val->value));
    });

    if (success) {
        std::cout << "[+] Successfully wrote value [" << val->to_string() << "] to "
                  << utils::format_address(addr) << "\n";
    } else {
        std::cerr << "[-] Failed to write to " << utils::format_address(addr) << "\n";
    }
}

void cmd_read(const std::string& addr_str, const std::string& type_str) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    uintptr_t addr = utils::parse_address(addr_str);
    if (addr == 0) {
        std::cerr << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    auto type = parse_numeric_type(type_str);
    if (!type) return;
    std::cout << "Address: " << utils::format_address(addr) << " = ";

    scanner::dispatch_numeric(*type, [&]<typename T>() {
        T v{};
        if (g_process->read(addr, v)) {
            scanner::ScanValue sv;
            sv.type = *type;
            sv.value = v;
            std::cout << sv.to_string() << "\n";
        } else {
            std::cout << "?? (Read failed)\n";
        }
    });
}

void cmd_dump(const std::string& addr_str, size_t size = 64) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    uintptr_t addr = utils::parse_address(addr_str);
    if (addr == 0) {
        std::cerr << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    constexpr size_t MAX_DUMP_SIZE = 64 * 1024;
    if (size == 0 || size > MAX_DUMP_SIZE) {
        std::cerr << "[-] Dump size must be between 1 and " << MAX_DUMP_SIZE << " bytes.\n";
        return;
    }

    std::vector<uint8_t> buffer(size);
    if (g_process->read_raw(addr, buffer.data(), size)) {
        std::cout << "\n" << utils::format_hex_dump(addr, buffer.data(), size) << "\n";
    } else {
        std::cerr << "[-] Failed to read " << size << " bytes from " << utils::format_address(addr) << "\n";
    }
}

// Runs one command line. Returns false when the user asked to quit.
bool handle_command(const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;

    if (cmd == "quit" || cmd == "exit") {
        return false;
    } else if (cmd == "help" || cmd == "?") {
        print_help();
    } else if (cmd == "ps") {
        std::string filter;
        iss >> filter;
        cmd_ps(filter);
    } else if (cmd == "attach") {
        uint32_t pid = 0;
        if (iss >> pid) {
            cmd_attach(pid);
        } else {
            std::cout << "Usage: attach <pid>\n";
        }
    } else if (cmd == "detach") {
        cmd_detach();
    } else if (cmd == "modules") {
        cmd_modules();
    } else if (cmd == "regions") {
        cmd_regions();
    } else if (cmd == "scan") {
        std::string type, rest;
        if (iss >> type && std::getline(iss >> std::ws, rest) && !rest.empty()) {
            cmd_first_scan(type, rest);
        } else {
            std::cout << "Usage: scan <type> <value|?|text|aob pattern>\n";
        }
    } else if (cmd == "next") {
        std::string cond, val, val2;
        if (iss >> cond) {
            iss >> val >> val2;
            cmd_next_scan(cond, val, val2);
        } else {
            std::cout << "Usage: next <exact/changed/unchanged/inc/dec/gt/lt/between/incby/decby> [value] [value2]\n";
        }
    } else if (cmd == "undo") {
        cmd_undo();
    } else if (cmd == "track") {
        std::string type;
        if (iss >> type) {
            cmd_track(type);
        } else {
            std::cout << "Usage: track <type>   (e.g. 'track i32', 'track f32')\n";
        }
    } else if (cmd == "floatmode") {
        std::string mode;
        iss >> mode;
        cmd_floatmode(mode);
    } else if (cmd == "save" || cmd == "load") {
        std::string path;
        if (std::getline(iss >> std::ws, path) && !path.empty()) {
            if (cmd == "save") cmd_save(path);
            else cmd_load(path);
        } else {
            std::cout << "Usage: " << cmd << " <file>\n";
        }
    } else if (cmd == "group") {
        std::vector<std::string> tokens;
        std::string t;
        while (iss >> t) tokens.push_back(t);
        cmd_grouped_scan(tokens);
    } else if (cmd == "ptrscan") {
        std::string addr_str, module;
        size_t depth = 4, offset = 0x800;
        if (iss >> addr_str) {
            iss >> depth >> std::hex >> offset >> module;
            cmd_pointer_scan(addr_str, depth, offset, module);
        } else {
            std::cout << "Usage: ptrscan <addr> [max_depth=4] [max_offset=0x800] [base_module]\n";
        }
    } else if (cmd == "add" || cmd == "addptr") {
        std::string where, rest;
        iss >> where;
        std::getline(iss >> std::ws, rest);
        if (cmd == "add" && !where.empty() && where[0] == '#') {
            cmd_table_add(where, "", rest); // the result already knows its type
        } else {
            std::istringstream rest_stream(rest);
            std::string type, description;
            rest_stream >> type;
            std::getline(rest_stream >> std::ws, description);
            if (where.empty() || type.empty()) {
                std::cout << "Usage: add #<result> [description] | add <addr> <type> [description] | "
                             "addptr <path#> <type> [description]\n";
            } else if (cmd == "add") {
                cmd_table_add(where, type, description);
            } else {
                cmd_table_add_pointer(where, type, description);
            }
        }
    } else if (cmd == "table") {
        cmd_table_list();
    } else if (cmd == "tset") {
        std::string index, value;
        if (iss >> index && std::getline(iss >> std::ws, value) && !value.empty()) {
            cmd_table_set(index, value);
        } else {
            std::cout << "Usage: tset <#> <value>\n";
        }
    } else if (cmd == "tfreeze" || cmd == "tunfreeze") {
        std::string index, value;
        if (iss >> index) {
            std::getline(iss >> std::ws, value);
            cmd_table_freeze(index, value, cmd == "tfreeze");
        } else {
            std::cout << "Usage: " << cmd << " <#>" << (cmd == "tfreeze" ? " [value]" : "") << "\n";
        }
    } else if (cmd == "tdel") {
        std::string index;
        if (iss >> index) cmd_table_delete(index);
        else std::cout << "Usage: tdel <#>\n";
    } else if (cmd == "tsave" || cmd == "tload") {
        std::string path;
        if (std::getline(iss >> std::ws, path) && !path.empty()) {
            if (cmd == "tsave") cmd_table_save(path);
            else cmd_table_load(path);
        } else {
            std::cout << "Usage: " << cmd << " <file.json>\n";
        }
    } else if (cmd == "ptrlist") {
        size_t count = 20;
        iss >> count;
        cmd_ptrlist(count);
    } else if (cmd == "ptrrescan") {
        std::string addr_str;
        if (iss >> addr_str) {
            cmd_ptrrescan(addr_str);
        } else {
            std::cout << "Usage: ptrrescan <new_addr>\n";
        }
    } else if (cmd == "ptrsave" || cmd == "ptrload") {
        std::string path;
        if (std::getline(iss >> std::ws, path) && !path.empty()) {
            if (cmd == "ptrsave") cmd_ptrsave(path);
            else cmd_ptrload(path);
        } else {
            std::cout << "Usage: " << cmd << " <file>\n";
        }
    } else if (cmd == "freeze") {
        std::string addr, type, val;
        if (iss >> addr >> type >> val) {
            cmd_freeze(addr, type, val);
        } else {
            std::cout << "Usage: freeze <addr> <type> <val>\n";
        }
    } else if (cmd == "frozen") {
        cmd_list_frozen();
    } else if (cmd == "unfreeze") {
        std::string param = "all";
        iss >> param;
        cmd_unfreeze(param);
    } else if (cmd == "list") {
        size_t count = 20;
        iss >> count;
        cmd_list(count);
    } else if (cmd == "write") {
        std::string addr, type, val;
        if (iss >> addr >> type >> val) {
            cmd_write(addr, type, val);
        } else {
            std::cout << "Usage: write <addr> <type> <val>\n";
        }
    } else if (cmd == "read") {
        std::string addr, type;
        if (iss >> addr >> type) {
            cmd_read(addr, type);
        } else {
            std::cout << "Usage: read <addr> <type>\n";
        }
    } else if (cmd == "dump") {
        std::string addr;
        size_t size = 64;
        if (iss >> addr) {
            iss >> size;
            cmd_dump(addr, size);
        } else {
            std::cout << "Usage: dump <addr> [size]\n";
        }
    } else {
        std::cout << "[!] Unknown command: '" << cmd << "'. Type 'help' for command list.\n";
    }
    return true;
}

int main() {
#ifdef _WIN32
    // Found text (str/wstr) is printed as UTF-8
    SetConsoleOutputCP(CP_UTF8);
#endif
    print_banner();
    print_help();

    // Start background thread for continuous value freezing
    g_freeze_thread = std::thread(freeze_worker);

    std::string line;
    while (true) {
        if (g_process && g_process->is_attached()) {
            std::cout << "[NCE PID:" << g_process->get_pid() << " (" << describe_scan_state() << ")] > ";
        } else {
            std::cout << "[NCE (Detached)] > ";
        }

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        try {
            if (!handle_command(line)) break;
        } catch (const std::exception& e) {
            std::cerr << "[!] Command failed: " << e.what() << "\n";
        }
    }

    g_freeze_running = false;
    if (g_freeze_thread.joinable()) {
        g_freeze_thread.join();
    }

    if (g_process) {
        g_process->detach();
    }
    return 0;
}
