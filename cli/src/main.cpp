#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>
#include <optional>
#include <exception>
#include <utility>
#include <charconv>
#include <cctype>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include "session/session.hpp"
#include "scanner/grouped_scanner.hpp"
#include "utils/hex_utils.hpp"

using namespace nce;

// The attached target with its search, noise map, cheat table (and the thread that keeps frozen
// entries at their values) and pointer paths. This file only parses commands and prints.
session::Session& ses() {
    static session::Session s;
    return s;
}

static scanner::FloatMatchMode g_float_mode = scanner::FloatMatchMode::Rounded;

bool is_numeric_type(scanner::DataType type) {
    return scanner::dispatch_numeric(type, []<typename T>() {});
}

long long elapsed_ms(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
}

std::string sentence(std::string text) {
    if (!text.empty()) text[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(text[0])));
    return text;
}

// Prints what an engine operation did: its note when it worked, the reason when it didn't
bool report(const session::Outcome& outcome) {
    if (!outcome.ok) std::cerr << "[-] " << outcome.message << "\n";
    else if (!outcome.message.empty()) std::cout << "[+] " << outcome.message << "\n";
    return outcome.ok;
}

bool require_attached() {
    if (ses().attached()) return true;
    if (ses().exited()) {
        std::cerr << "[-] " << ses().process().name() << " exited. 'reattach' waits for it to start again.\n";
    } else {
        std::cerr << "[-] Not attached to any process. Use 'attach <pid>'.\n";
    }
    return false;
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
              << "  reattach [seconds]              - After the target exits: wait for it to start again and attach\n"
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
              << "  track <type|auto>               - Guided search for a value you can change but don't know:\n"
              << "                                    ranks addresses by how they follow your changes;\n"
              << "                                    'auto' tries i32, f32 and f64 and picks the type\n"
              << "  noise [learn [seconds] | clear] - Addresses that change on their own (learned for 4 s on attach)\n"
              << "                                    are ignored by every scan; show, relearn or stop ignoring them\n"
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
              << "  tperm <#>                       - Make an entry permanent: keeps its best pointer paths, which\n"
              << "                                    vote on the value's new address after every restart\n"
              << "  tsave <file.json> / tload <file.json> - Save or load the table\n"
              << "  thotkey <#> <keys> toggle | set <value> | add <amount> | remove - A key that works while the game\n"
              << "                                    is in front: 'thotkey 0 F1 toggle' freezes/unfreezes #0,\n"
              << "                                    'thotkey 0 Ctrl+F2 set 999', 'thotkey 1 Num5 add -10'. Saved with the table\n"
              << "  thotkeys / tpress <keys>        - List the hotkeys / do what a key does now, without the keyboard\n\n"
              << "Memory Operations:\n"
              << "  write <addr> <type> <val>       - Write value to memory address\n"
              << "  read <addr> <type>              - Read value from memory address\n"
              << "  dump <addr> [bytes]             - Hex dump memory (default: 64 bytes)\n"
              << "  view <addr|#result|t#> [before] [after] - The memory around a value, each 4 bytes read as what\n"
              << "                                    they most likely are (int, float, double, pointer, text).\n"
              << "                                    'view' again marks what changed (default: 8 slots before, 24 after)\n"
              << "  freeze <addr> <type> <val>      - Add an address to the table, frozen at a value\n"
              << "  frozen                          - List the frozen table entries\n"
              << "  unfreeze [#|all]                - Stop freezing a table entry (default: all)\n\n"
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

std::optional<uintptr_t> parse_address_arg(const std::string& text) {
    const uintptr_t address = utils::parse_address(text);
    if (address == 0) {
        std::cerr << "[-] Invalid address: " << text << "\n";
        return std::nullopt;
    }
    return address;
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

std::optional<size_t> parse_table_index(const std::string& text) {
    return parse_index(text, ses().table().size(), "table entry");
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

// Samples the target 4 times a second; addresses that change in most samples are ignored by every scan
void learn_noise(int seconds) {
    if (!require_attached()) return;
    scanner::NoiseOptions options;
    options.samples = static_cast<size_t>(std::max(3, seconds * 4));

    std::cout << "[*] Learning noise for " << seconds << " s - leave the target alone ..." << std::flush;
    const auto start = std::chrono::steady_clock::now();
    ses().set_noise(ses().learn_noise(options));
    std::cout << " done in " << elapsed_ms(start) << " ms: " << ses().describe_noise() << ".\n";
}

void cmd_noise(const std::string& action, const std::string& argument) {
    if (action == "learn") {
        int seconds = 4;
        if (!argument.empty()) {
            auto [ptr, ec] = std::from_chars(argument.data(), argument.data() + argument.size(), seconds);
            if (ec != std::errc() || seconds < 1 || seconds > 60) {
                std::cerr << "[!] Seconds must be between 1 and 60.\n";
                return;
            }
        }
        learn_noise(seconds);
    } else if (action == "clear") {
        ses().set_noise(nullptr);
        std::cout << "[*] Noise cleared: scans look at every address again.\n";
    } else if (action.empty()) {
        std::cout << "[*] Noise: " << ses().describe_noise() << ".\n";
    } else {
        std::cout << "Usage: noise [learn [seconds] | clear]\n";
    }
}

// Permanent entries carry several pointer paths; after a restart they vote on where the value is now
void print_reconciled(const std::vector<session::TableKeeper::ReconcileLine>& lines) {
    for (const auto& line : lines) {
        std::cout << "[*] #" << line.index << " " << line.description << ": " << session::describe_reconcile(line.result)
                  << ".\n";
    }
}

// The window of the last 'view' (addresses of the attached process)
static view::MemoryView g_view;
static size_t g_view_before = 8;
static size_t g_view_after = 24;

void cmd_attach(uint32_t pid) {
    g_view.clear();
    const auto attached = ses().attach(pid);
    if (attached.unfrozen > 0) {
        std::cout << "[*] Unfroze " << attached.unfrozen << " table entr(ies) at heap addresses of the previous process.\n";
    }
    if (!attached.ok) {
        std::cerr << "[-] Failed to attach to PID: " << pid << ". Run as Administrator or check PID.\n";
        return;
    }
    std::cout << "[+] Successfully attached to PID: " << pid << " (" << ses().process().name() << ", "
              << ses().process().pointer_size() * 8 << "-bit)\n";
    if (attached.read_only) {
        std::cout << "[!] Only read access was granted: writing and freezing won't work. Run as Administrator.\n";
    }
    learn_noise(4);
    print_reconciled(attached.reconciled);
}

// After the target exits: waits for the same program to start again, gives it a moment to set up,
// then attaches (which relearns noise, re-finds permanent table entries and resumes freezing)
void cmd_reattach(int seconds) {
    const std::string name = ses().process().name();
    if (name.empty()) {
        std::cerr << "[-] Attach to a program first; reattach waits for that program to restart.\n";
        return;
    }
    if (ses().attached()) {
        std::cout << "[*] Still attached to " << name << " (PID " << ses().process().get_pid() << ").\n";
        return;
    }

    std::cout << "[*] Waiting up to " << seconds << " s for " << name << " to start again ..." << std::flush;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto restarted = ses().find_restart()) {
            std::cout << " found PID " << restarted->pid << ".\n";
            std::this_thread::sleep_for(std::chrono::seconds(3)); // let it set up its objects
            cmd_attach(restarted->pid);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    std::cout << " not seen. Try 'reattach' again once it is running.\n";
}

void cmd_detach() {
    g_view.clear();
    ses().detach();
    std::cout << "[*] Detached.\n";
}

void cmd_modules() {
    if (!require_attached()) return;
    auto modules = ses().process().get_modules();
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
    if (!require_attached()) return;
    auto regions = ses().process().query_regions();
    size_t total_size = 0;
    for (const auto& r : regions) total_size += r.size;

    std::cout << "\nMemory Regions Summary:\n";
    std::cout << " Readable/Writable Regions : " << regions.size() << "\n";
    std::cout << " Total Scannable Memory    : " << (total_size / (1024 * 1024)) << " MB ("
              << total_size << " bytes)\n\n";
}

// rest = everything after the type: a number, '?' (unknown initial value), text for str/wstr, or an AOB pattern
void cmd_first_scan(const std::string& type_str, const std::string& rest) {
    if (!require_attached()) return;

    std::istringstream rest_stream(rest);
    std::string first_word;
    rest_stream >> first_word;
    const bool unknown = first_word == "?" || first_word == "unknown";
    std::cout << (unknown ? "[*] Capturing unknown-value snapshot for type [" : "[*] Starting First Scan for type [")
              << type_str << "] ...\n";

    const auto start = std::chrono::steady_clock::now();
    auto& scans = ses().scans();
    const auto outcome = scans.first_scan(type_str, rest, g_float_mode);
    if (!outcome.ok) {
        std::cerr << "[!] " << outcome.message << "\n";
        return;
    }
    if (!outcome.message.empty()) std::cout << "[*] " << sentence(outcome.message) << "\n";

    if (scans.state().snapshot) {
        std::cout << "[+] Snapshot captured in " << elapsed_ms(start) << " ms: " << scans.describe() << ". "
                  << "Change the value in the target, then use 'next changed/unchanged/inc/dec/...'.\n";
    } else {
        std::cout << "[+] First Scan complete in " << elapsed_ms(start) << " ms. Found " << scans.state().results.count()
                  << " match(es).\n";
    }
}

void cmd_next_scan(const std::string& cond_str, const std::string& val_str, const std::string& val2_str) {
    if (!require_attached()) return;
    auto& scans = ses().scans();
    if (scans.empty()) {
        std::cerr << "[-] No active scan results. Run 'scan <type> <value>' first.\n";
        return;
    }

    std::cout << "[*] Filtering " << scans.describe() << " ...\n";
    const auto start = std::chrono::steady_clock::now();
    const auto outcome = scans.next_scan(cond_str, val_str, val2_str, g_float_mode);
    if (!outcome.ok) {
        std::cerr << "[!] " << outcome.message << "\n";
        return;
    }
    if (!outcome.message.empty()) std::cout << "[*] " << sentence(outcome.message) << "\n";
    std::cout << "[+] Next Scan complete in " << elapsed_ms(start) << " ms: " << scans.describe() << " remaining.\n";
}

void cmd_undo() {
    if (!ses().scans().undo()) {
        std::cerr << "[-] Nothing to undo.\n";
        return;
    }
    std::cout << "[*] Restored previous results: " << ses().scans().describe() << ".\n";
}

void cmd_floatmode(const std::string& mode) {
    if (mode == "rounded") g_float_mode = scanner::FloatMatchMode::Rounded;
    else if (mode == "truncated") g_float_mode = scanner::FloatMatchMode::Truncated;
    else if (mode == "exact") g_float_mode = scanner::FloatMatchMode::Exact;
    else if (!mode.empty()) {
        std::cerr << "[!] Unknown float mode: '" << mode << "'. Use rounded, truncated or exact.\n";
        return;
    }
    std::cout << "[*] Float mode: " << session::float_mode_name(g_float_mode) << "\n";
}

void cmd_save(const std::string& path) {
    const auto& state = ses().scans().state();
    if (state.snapshot) {
        std::cerr << "[-] An unknown-value snapshot can't be saved. Run a next scan first.\n";
        return;
    }
    if (state.results.empty()) {
        std::cerr << "[-] No results to save.\n";
        return;
    }
    const uint32_t pid = ses().attached() ? ses().process().get_pid() : 0;
    if (scanner::save_results(path, pid, state.type, state.results)) {
        std::cout << "[+] Saved " << state.results.count() << " result(s) to " << path << "\n";
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
    ses().scans().replace(std::move(saved->results), saved->type);
    std::cout << "[+] Loaded " << ses().scans().state().results.count() << " " << utils::format_data_type(saved->type)
              << " result(s) from " << path << "\n";

    if (ses().attached() && saved->pid != ses().process().get_pid()) {
        std::cout << "[!] These results were saved from PID " << saved->pid
                  << "; addresses may not be valid in PID " << ses().process().get_pid() << ".\n";
    }
}

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
    else ss << " (snapshot, " << session::format_size(tracker.memory_bytes()) << ")";
    return ss.str();
}

void print_ranked(const scanner::ValueTracker& tracker, size_t count) {
    const auto ranked = tracker.top(count);
    std::cout << "        Best candidates:\n";
    for (size_t i = 0; i < ranked.size(); ++i) {
        std::cout << "        [" << i << "] " << utils::format_address(ranked[i].address) << " "
                  << std::left << std::setw(4) << utils::format_data_type(ranked[i].value.type) << "= "
                  << std::setw(12) << ranked[i].value.to_string() << std::right << " score " << std::setw(3)
                  << ranked[i].score << "  " << ranked[i].reason << "\n";
    }
}

// Guided unknown-value search with smart ranking. Each round has a quiet phase (the user leaves the
// value alone while values that change on their own lose points) and a change step (the user changes
// the value and says how). Candidates are scored rather than cut on every answer, so one wrong answer
// lowers the right address instead of losing it.
void cmd_track(const std::string& type_str) {
    if (!require_attached()) return;
    // 'auto' follows i32, f32 and f64 together and lets the scoring pick the type
    std::vector<scanner::DataType> types;
    if (type_str == "auto") {
        types = scanner::ValueTracker::auto_types();
    } else {
        auto type = parse_numeric_type(type_str);
        if (!type) return;
        types = {*type};
    }

    constexpr size_t SHOW_BEST = 5;
    constexpr size_t MAX_HANDOVER = 5'000'000; // candidates turned into results when tracking stops

    auto tracker = ses().new_tracker(types);
    std::cout << "[*] Tracking an unknown " << type_str << " value. Capturing snapshot ...\n";
    auto start = std::chrono::steady_clock::now();
    tracker->start();
    std::cout << "[+] Snapshot captured in " << elapsed_ms(start) << " ms: " << describe_tracker(*tracker) << ".\n";

    for (int round = 1;; ++round) {
        std::cout << "\n[track] Round " << round << " - " << describe_tracker(*tracker) << ".\n"
                  << "        Leave the value alone: values that change on their own lose points.\n"
                  << "        Press Enter when you are ready to change it (or type 'done').\n";

        // Quiet phase. The main thread only waits for input here, so the noise thread owns the tracker.
        std::atomic<bool> stop{false};
        std::exception_ptr noise_error;
        std::thread noise([&] {
            try {
                size_t last_count = SIZE_MAX;
                do {
                    tracker->observe_quiet();
                    const size_t count = tracker->candidate_count();
                    if (count != last_count) {
                        std::cout << "        [noise filter] " << describe_tracker(*tracker) << "\n";
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

        auto expected = scanner::parse_expectation(line, g_float_mode);
        if (!expected) {
            std::cout << "[track] '" << line << "' is not +, -, c or a number. Skipping this round.\n";
            continue;
        }

        start = std::chrono::steady_clock::now();
        tracker->observe_event(*expected);
        std::cout << "[+] Checked in " << elapsed_ms(start) << " ms: " << describe_tracker(*tracker) << ".\n";

        if (tracker->candidate_count() == 0) {
            std::cout << "[-] No candidates left: the value did not change when you said it did.\n";
            break;
        }
        if (tracker->is_ranked()) print_ranked(*tracker, SHOW_BEST);
        if (tracker->candidate_count() == 1) break;
    }

    // Hand the candidates over as normal results, best first
    if (tracker->candidate_count() > MAX_HANDOVER) {
        std::cout << "[track] Stopped with " << describe_tracker(*tracker)
                  << ": too many to list. Run 'track' again and change the value a few times.\n";
        return;
    }
    const auto best_type = tracker->best_type();
    ses().scans().replace(tracker->to_results(), best_type);
    std::cout << "[track] Stopped with " << ses().scans().state().results.count() << " "
              << utils::format_data_type(best_type) << " result(s), best first"
              << (types.size() > 1 ? " (most likely type)" : "") << ". "
              << "'list' shows them, 'add #0 <name>' adds the best one.\n";
}

void cmd_grouped_scan(const std::vector<std::string>& tokens) {
    if (!require_attached()) return;

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
    scanner::GroupedScanner gscanner(ses().process_ptr());
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

// ---- Pointer paths (from the last ptrscan / ptrload; kept across attach, meant for the restarted target)

void cmd_ptrlist(size_t max_count = 20) {
    const auto& paths = ses().pointer_paths();
    if (paths.empty()) {
        std::cout << "[-] No pointer paths. Run 'ptrscan <addr>' or 'ptrload <file>' first.\n";
        return;
    }

    const bool attached = ses().attached();
    const auto modules = attached ? ses().process().get_modules() : std::vector<hal::ModuleInfo>{};
    const size_t count = std::min(max_count, paths.size());
    for (size_t i = 0; i < count; ++i) {
        std::cout << "  [" << std::right << std::setw(3) << i << "] " << paths[i].to_string();
        if (attached) {
            const uintptr_t now = paths[i].resolve(ses().process(), modules);
            std::cout << "  => " << (now ? utils::format_address(now) : std::string("(unresolved)"));
        }
        std::cout << "\n";
    }
    std::cout << " Showing " << count << " of " << paths.size() << " path(s).\n";
}

void cmd_pointer_scan(const std::string& addr_str, size_t max_depth, size_t max_offset, const std::string& base_module) {
    if (!require_attached()) return;
    auto target_addr = parse_address_arg(addr_str);
    if (!target_addr) return;

    scanner::PointerScanOptions options;
    options.max_depth = max_depth;
    options.max_offset = max_offset;
    options.base_module = base_module;

    std::cout << "[*] Starting Pointer Scanner for " << utils::format_address(*target_addr)
              << " (Max Depth: " << max_depth << ", Max Offset: 0x" << std::hex << max_offset << std::dec
              << ", Base: " << (base_module.empty() ? "any module" : base_module)
              << ", " << (ses().process().pointer_size() * 8) << "-bit target) ...\n";

    const auto start = std::chrono::steady_clock::now();
    scanner::PointerScanner ptr_scanner(ses().process_ptr());
    auto result = ptr_scanner.scan(*target_addr, options, [](size_t depth, size_t count) {
        std::cout << "  -> Depth " << depth << " explored: " << count << " static path(s) found.\n";
    });
    auto& paths = ses().pointer_paths();
    paths = std::move(result.paths);

    std::cout << "\n[+] Pointer Scan complete in " << elapsed_ms(start) << " ms: " << paths.size()
              << " path(s) (pointer map: " << result.pointer_map_size << " pointers, "
              << result.nodes_explored << " nodes searched).\n";
    if (result.truncated) {
        std::cout << "[!] The search hit its limit, so some paths are missing. Narrow it with a lower depth,\n"
                  << "    a smaller max offset, or a base module.\n";
    }
    cmd_ptrlist(20);
    if (!paths.empty()) {
        std::cout << "[*] Restart the target, find the value's new address, then run 'ptrrescan <new addr>'\n"
                  << "    to keep only the paths that survive. 'ptrsave <file>' keeps them across sessions.\n";
    }
}

void cmd_ptrrescan(const std::string& addr_str) {
    if (!require_attached()) return;
    auto& paths = ses().pointer_paths();
    if (paths.empty()) {
        std::cerr << "[-] No pointer paths to rescan. Run 'ptrscan' or 'ptrload' first.\n";
        return;
    }
    auto target_addr = parse_address_arg(addr_str);
    if (!target_addr) return;

    const size_t before = paths.size();
    paths = scanner::PointerScanner::verify_paths(ses().process(), paths, *target_addr);
    std::cout << "[+] Rescan: " << paths.size() << " of " << before << " path(s) still lead to "
              << utils::format_address(*target_addr) << ".\n";
    cmd_ptrlist(20);
}

void cmd_ptrsave(const std::string& path) {
    const auto& paths = ses().pointer_paths();
    if (paths.empty()) {
        std::cerr << "[-] No pointer paths to save.\n";
        return;
    }
    if (scanner::save_pointer_paths(path, paths)) {
        std::cout << "[+] Saved " << paths.size() << " pointer path(s) to " << path << "\n";
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
    ses().pointer_paths() = std::move(*loaded);
    std::cout << "[+] Loaded " << ses().pointer_paths().size() << " pointer path(s) from " << path << "\n";
}

// ---- Cheat table -------------------------------------------------------------------------------

// add <addr|#result> <type> [description]
void cmd_table_add(const std::string& where, const std::string& type_str, const std::string& description) {
    if (!require_attached()) return;

    if (!where.empty() && where[0] == '#') {
        // From the scan results: address, type and text length come from the result itself
        const auto& results = ses().scans().state().results;
        auto index = parse_index(where.substr(1), results.count(), "result");
        if (!index) return;
        report(ses().table().add_result(results, *index, description));
        return;
    }

    auto type = parse_numeric_type(type_str);
    if (!type) return;
    auto address = parse_address_arg(where);
    if (!address) return;
    report(ses().table().add_address(*address, *type, description));
}

// addptr <path#> <type> [description]
void cmd_table_add_pointer(const std::string& path_index, const std::string& type_str, const std::string& description) {
    const auto& paths = ses().pointer_paths();
    auto index = parse_index(path_index, paths.size(), "pointer path");
    if (!index) return;
    auto type = parse_numeric_type(type_str);
    if (!type) return;
    report(ses().table().add_pointer(paths[*index], *type, description));
}

void cmd_table_list() {
    ses().table().refresh_modules(); // the target may have loaded modules since attach
    const bool attached = ses().attached();
    auto& process = ses().process();

    ses().table().with([&](const table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules) {
        if (t.entries.empty()) {
            std::cout << "[-] The table is empty. Add values with 'add #<result>' or 'add <addr> <type>'.\n";
            return;
        }
        std::cout << "\n Index  Description           Type  Value              Location\n";
        std::cout << "--------------------------------------------------------------------------------\n";
        for (size_t i = 0; i < t.entries.size(); ++i) {
            const auto& e = t.entries[i];
            std::string value = "??";
            if (attached) {
                if (auto v = table::read_entry(e, process, modules)) value = v->to_string();
            }
            if (e.frozen_value) value += " [frozen]";
            std::cout << " [" << std::right << std::setw(3) << i << "]  " << std::left << std::setw(20) << e.description
                      << "  " << std::setw(4) << utils::format_data_type(e.type) << "  " << std::setw(17) << value
                      << "  " << e.location_string();
            for (size_t k = 0; k < e.hotkeys.size(); ++k) std::cout << (k == 0 ? "   keys: " : ", ") << e.hotkeys[k].keys;
            std::cout << "\n";
        }
        std::cout << std::right << "--------------------------------------------------------------------------------\n";
    });
}

void cmd_table_set(const std::string& index_text, const std::string& value) {
    if (!require_attached()) return;
    auto index = parse_table_index(index_text);
    if (index) report(ses().table().set_value(*index, value));
}

void cmd_table_freeze(const std::string& index_text, const std::string& value, bool freeze) {
    auto index = parse_table_index(index_text);
    if (!index) return;
    if (!freeze) {
        report(ses().table().unfreeze(*index));
        return;
    }
    // Default: keep the value it has right now
    report(ses().table().freeze(*index, value.empty() ? std::nullopt : std::optional<std::string>(value)));
}

void cmd_table_delete(const std::string& index_text) {
    auto index = parse_table_index(index_text);
    if (index) report(ses().table().remove(*index));
}

void cmd_table_save(const std::string& path) {
    report(ses().table().save(path));
}

// thotkey <#> <keys> toggle | set <value> | add <amount> | remove
void cmd_table_hotkey(const std::string& index_text, const std::string& keys, const std::string& action,
                      const std::string& value) {
    auto index = parse_table_index(index_text);
    if (!index) return;
    using Action = table::Hotkey::Action;
    if (action == "remove") report(ses().table().remove_hotkey(*index, keys));
    else if (action == "toggle") report(ses().table().add_hotkey(*index, keys, Action::ToggleFreeze, ""));
    else if (action == "set") report(ses().table().add_hotkey(*index, keys, Action::Set, value));
    else if (action == "add") report(ses().table().add_hotkey(*index, keys, Action::Add, value));
    else std::cout << "Usage: thotkey <#> <keys> toggle | set <value> | add <amount> | remove\n";
}

void cmd_table_hotkeys() {
    const auto taken = ses().table().hotkeys_taken();
    ses().table().with([&](const table::CheatTable& t, const std::vector<hal::ModuleInfo>&) {
        size_t count = 0;
        for (size_t i = 0; i < t.entries.size(); ++i) {
            for (const auto& h : t.entries[i].hotkeys) {
                if (count++ == 0) {
                    std::cout << "\n Index  Description           Hotkey\n"
                              << "--------------------------------------------------------------------------------\n";
                }
                const bool is_taken = std::find(taken.begin(), taken.end(), h.keys) != taken.end();
                std::cout << " [" << std::right << std::setw(3) << i << "]  " << std::left << std::setw(20)
                          << t.entries[i].description << "  " << h.to_string()
                          << (is_taken ? "   (another program holds it: it won't fire)" : "") << std::right << "\n";
            }
        }
        if (count == 0) {
            std::cout << "[-] No hotkeys. 'thotkey <#> F1 toggle' makes F1 freeze and unfreeze an entry while you play.\n";
        } else {
            std::cout << "--------------------------------------------------------------------------------\n"
                      << " They work while the game is in front; a high beep means done, a low one failed.\n\n";
        }
    });
}

void cmd_table_load(const std::string& path) {
    if (report(ses().table().load(path))) print_reconciled(ses().table().reconcile());
}

// tperm <#>: turns an entry into pointer paths that survive restarts
void cmd_table_permanent(const std::string& index_text) {
    if (!require_attached()) return;
    auto index = parse_table_index(index_text);
    if (!index) return;
    const auto entry = ses().table().entry(*index);
    if (!entry) return;
    if (!entry->is_absolute() && entry->location.offsets.empty()) {
        std::cout << "[*] #" << *index << " is a static address (" << entry->location_string()
                  << "): it already survives restarts.\n";
        return;
    }

    // The pointer scan runs without the table lock, so frozen values keep being written meanwhile
    std::cout << "[*] Searching pointer paths to #" << *index << " ...\n";
    const auto start = std::chrono::steady_clock::now();
    const auto paths = ses().find_permanent_paths(*entry);
    if (!report(ses().table().make_permanent(*index, *entry, paths))) return;
    std::cout << "    Found in " << elapsed_ms(start) << " ms. Save the table ('tsave'); after a restart,\n"
              << "    'attach' + 'tload' find the value again.\n";
}

// freeze <addr> <type> <value>: a frozen table entry, so 'table', 'tsave' and 'tperm' work on it too
void cmd_freeze(const std::string& addr_str, const std::string& type_str, const std::string& val_str) {
    if (!require_attached()) return;
    auto address = parse_address_arg(addr_str);
    if (!address) return;
    auto type = parse_numeric_type(type_str);
    if (!type) return;
    if (!parse_value(*type, val_str)) return;

    if (!report(ses().table().add_address(*address, *type, ""))) return;
    const size_t index = ses().table().size() - 1;
    if (report(ses().table().freeze(index, val_str))) {
        std::cout << "    'unfreeze " << index << "' stops it, 'tdel " << index << "' removes it from the table.\n";
    }
}

void cmd_list_frozen() {
    ses().table().with([](const table::CheatTable& t, const std::vector<hal::ModuleInfo>&) {
        const auto frozen = std::count_if(t.entries.begin(), t.entries.end(), [](const auto& e) { return e.frozen_value.has_value(); });
        if (frozen == 0) {
            std::cout << "[-] No frozen entries. 'freeze <addr> <type> <value>' or 'tfreeze <#>' adds one.\n";
            return;
        }
        std::cout << "\n Index  Description           Frozen at          Location\n";
        std::cout << "--------------------------------------------------------------------------------\n";
        for (size_t i = 0; i < t.entries.size(); ++i) {
            const auto& e = t.entries[i];
            if (!e.frozen_value) continue;
            std::cout << " [" << std::right << std::setw(3) << i << "]  " << std::left << std::setw(20) << e.description
                      << "  " << std::setw(17) << *e.frozen_value << "  " << e.location_string() << "\n";
        }
        std::cout << std::right << "--------------------------------------------------------------------------------\n";
    });
}

void cmd_unfreeze(const std::string& param) {
    if (param == "all") {
        std::cout << "[*] Unfroze " << ses().table().unfreeze_all() << " entr(ies).\n";
        return;
    }
    auto index = parse_table_index(param);
    if (index) report(ses().table().unfreeze(*index));
}

void cmd_list(size_t max_count = 20) {
    const auto& scans = ses().scans();
    if (scans.state().snapshot) {
        std::cout << "[*] Current state is an " << scans.describe()
                  << ". Run 'next changed/unchanged/inc/dec/...' to get addresses.\n";
        return;
    }
    const auto& results = scans.state().results;
    if (results.empty()) {
        std::cout << "[-] No results found.\n";
        return;
    }

    size_t count = std::min(max_count, results.count());
    std::cout << "\n Index   Address              Current Value     Previous Value\n";
    std::cout << "------------------------------------------------------------------\n";
    for (size_t i = 0; i < count; ++i) {
        const auto& m = results[i];
        std::cout << " [" << std::right << std::setw(3) << i << "]  "
                  << utils::format_address(m.address) << "   "
                  << std::setw(16) << std::left << m.current_value.to_string() << "  "
                  << m.previous_value.to_string() << "\n";
    }
    std::cout << std::right << "------------------------------------------------------------------\n";
    std::cout << " Showing " << count << " of " << results.count() << " match(es).\n\n";
}

void cmd_write(const std::string& addr_str, const std::string& type_str, const std::string& val_str) {
    if (!require_attached()) return;
    auto addr = parse_address_arg(addr_str);
    if (!addr) return;
    auto type = parse_numeric_type(type_str);
    if (!type) return;
    auto val = parse_value(*type, val_str);
    if (!val) return;

    bool success = false;
    scanner::dispatch_numeric(*type, [&]<typename T>() {
        success = ses().process().write(*addr, std::get<T>(val->value));
    });

    if (success) {
        std::cout << "[+] Successfully wrote value [" << val->to_string() << "] to "
                  << utils::format_address(*addr) << "\n";
    } else {
        std::cerr << "[-] Failed to write to " << utils::format_address(*addr) << "\n";
    }
}

void cmd_read(const std::string& addr_str, const std::string& type_str) {
    if (!require_attached()) return;
    auto addr = parse_address_arg(addr_str);
    if (!addr) return;
    auto type = parse_numeric_type(type_str);
    if (!type) return;
    std::cout << "Address: " << utils::format_address(*addr) << " = ";

    scanner::dispatch_numeric(*type, [&]<typename T>() {
        T v{};
        if (ses().process().read(*addr, v)) {
            std::cout << scanner::ScanValue::of(*type, v).to_string() << "\n";
        } else {
            std::cout << "?? (Read failed)\n";
        }
    });
}

void cmd_dump(const std::string& addr_str, size_t size = 64) {
    if (!require_attached()) return;
    auto addr = parse_address_arg(addr_str);
    if (!addr) return;

    constexpr size_t MAX_DUMP_SIZE = 64 * 1024;
    if (size == 0 || size > MAX_DUMP_SIZE) {
        std::cerr << "[-] Dump size must be between 1 and " << MAX_DUMP_SIZE << " bytes.\n";
        return;
    }

    std::vector<uint8_t> buffer(size);
    if (ses().process().read_raw(*addr, buffer.data(), size)) {
        std::cout << "\n" << utils::format_hex_dump(*addr, buffer.data(), size) << "\n";
    } else {
        std::cerr << "[-] Failed to read " << size << " bytes from " << utils::format_address(*addr) << "\n";
    }
}

// view <addr|#result|t#entry> [before] [after]: the memory around a value, like a structure dissector.
// The same window again (or 'view' alone) reads it again and marks what changed in between.
void cmd_view(const std::string& where, std::optional<size_t> before, std::optional<size_t> after) {
    if (!require_attached()) return;

    std::optional<uintptr_t> address;
    if (where.empty()) {
        if (g_view.empty()) {
            std::cout << "Usage: view <addr|#result|t#> [slots before] [slots after]\n";
            return;
        }
        address = g_view.address();
    } else if (where[0] == '#') {
        const auto& results = ses().scans().state().results;
        auto index = parse_index(where.substr(1), results.count(), "result");
        if (!index) return;
        address = results.address(*index);
    } else if (where[0] == 't' || where[0] == 'T') {
        auto index = parse_table_index(where.substr(1));
        if (!index) return;
        address = ses().table().with([&](const table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules) {
            return t.entries[*index].address(ses().process(), modules);
        });
        if (*address == 0) {
            std::cerr << "[-] Table entry #" << *index << " doesn't lead to an address in this process.\n";
            return;
        }
    } else {
        address = parse_address_arg(where);
        if (!address) return;
    }

    const size_t want_before = std::min<size_t>(before.value_or(g_view_before), 256);
    const size_t want_after = std::clamp<size_t>(after.value_or(g_view_after), 1, 1024);
    if (*address != g_view.address() || want_before != g_view_before || want_after != g_view_after) {
        g_view_before = want_before;
        g_view_after = want_after;
        g_view.set_address(*address, g_view_before, g_view_after);
    }
    ses().refresh(g_view);
    const bool again = g_view.refreshes() > 1;

    std::cout << "\n  Offset  Address             Bytes        Type  Value\n";
    std::cout << "------------------------------------------------------------------------------------\n";
    const auto& slots = g_view.slots();
    for (size_t i = 0; i < slots.size(); ++i) {
        const auto& s = slots[i];
        std::string value = s.value_text();
        if (s.guess == view::Guess::Pointer && s.target != utils::format_address(static_cast<uintptr_t>(s.wide))) {
            value += " (" + utils::format_address(static_cast<uintptr_t>(s.wide)) + ")";
        }
        std::cout << (i == g_view.focus() ? ">" : " ") << std::right << std::setw(7) << view::format_offset(s.offset) << "  "
                  << utils::format_address(s.address) << "  " << s.bytes_text() << "  " << std::left << std::setw(4)
                  << s.type_name() << "  " << value;
        const size_t changes = std::max(s.changes, i + 1 < slots.size() && slots[i + 1].guess == view::Guess::Continued
                                                       ? slots[i + 1].changes : size_t{0});
        if (s.noisy) {
            std::cout << "   (changes on its own)"; // a '*' on every view would only hide the real changes
        } else {
            if (again && g_view.value_age(i) == 0) std::cout << "   * changed";
            if (changes > 1) std::cout << " (" << changes << "x)";
        }
        std::cout << std::right << "\n";
    }
    std::cout << "------------------------------------------------------------------------------------\n";
    std::cout << (again ? " '*': changed since the last 'view'." : " Change something in the target, then 'view' again to see what changed.")
              << " 'add <addr> <type>' puts a value in the table.\n\n";
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
    } else if (cmd == "reattach") {
        int seconds = 120;
        iss >> seconds;
        cmd_reattach(seconds);
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
    } else if (cmd == "noise") {
        std::string action, argument;
        iss >> action >> argument;
        cmd_noise(action, argument);
    } else if (cmd == "undo") {
        cmd_undo();
    } else if (cmd == "track") {
        std::string type;
        if (iss >> type) {
            cmd_track(type);
        } else {
            std::cout << "Usage: track <type|auto>   (e.g. 'track auto', 'track i32', 'track f32')\n";
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
    } else if (cmd == "thotkey") {
        std::string index, keys, action, value;
        if (iss >> index >> keys >> action) {
            iss >> value;
            cmd_table_hotkey(index, keys, action, value);
        } else {
            std::cout << "Usage: thotkey <#> <keys> toggle | set <value> | add <amount> | remove\n";
        }
    } else if (cmd == "thotkeys") {
        cmd_table_hotkeys();
    } else if (cmd == "tpress") {
        std::string keys;
        if (iss >> keys) report(ses().table().press(keys));
        else std::cout << "Usage: tpress <keys>\n";
    } else if (cmd == "tperm") {
        std::string index;
        if (iss >> index) cmd_table_permanent(index);
        else std::cout << "Usage: tperm <#>\n";
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
    } else if (cmd == "view") {
        std::string where;
        std::optional<size_t> before, after;
        size_t number = 0;
        iss >> where;
        if (iss >> number) before = number;
        if (iss >> number) after = number;
        cmd_view(where, before, after);
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

    // Hotkeys fire while the game is in front: say what they did, and beep (the console may be hidden)
    ses().table().on_hotkey([](const std::string& combo, const session::Outcome& outcome) {
        std::cout << "\n[hotkey " << combo << "] " << outcome.message << "\n" << std::flush;
#ifdef _WIN32
        std::thread([ok = outcome.ok] { Beep(ok ? 1320 : 220, ok ? 90 : 200); }).detach();
#endif
    });

    std::string line;
    while (true) {
        if (ses().attached()) {
            std::cout << "[NCE PID:" << ses().process().get_pid() << " (" << ses().scans().describe() << ")] > ";
        } else if (ses().exited()) {
            std::cout << "[NCE (" << ses().process().name() << " exited - 'reattach' waits for it)] > ";
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

    ses().detach();
    return 0;
}
