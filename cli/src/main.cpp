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
#include <filesystem>
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
#include "scanner/strings_scanner.hpp"
#include "table/standalone_generator.hpp"
#include "view/structure_dissector.hpp"
#include "view/vector_detector.hpp"
#include "utils/sig_generator.hpp"
#include "debugger/access_watcher.hpp"
#include "debugger/disassembler.hpp"
#include "assembler/x86_assembler.hpp"
#include <fstream>
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
              << "                                    i16be, i32be, i64be, f32be (Big-Endian for Emulators), str, wstr, aob).\n"
              << "                                    Examples: 'scan i32 1337', 'scan f32 ?', 'scan wstr Player 1',\n"
              << "                                    'scan aob 48 8B ? ? 89'\n"
              << "  scanxor <type> <val> [key|auto] - Scan for XOR-encrypted values (e.g. 'scanxor u32 777 auto' or '0xA5A5A5A5')\n"
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
              << "  ptrmap <save <f> | scan <f> <addr> | cmp <f1> <a1> <f2> <a2>> - Binary .ncem PointerMap I/O & comparison\n"
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
              << "  ctsave <file.ct> / ctload <file.ct>   - Save or load in Cheat Engine (.CT) XML format\n"
              << "  thotkey <#> <keys> toggle | set <value> | add <amount> | remove - A key that works while the game\n"
              << "                                    is in front: 'thotkey 0 F1 toggle' freezes/unfreezes #0,\n"
              << "                                    'thotkey 0 Ctrl+F2 set 999', 'thotkey 1 Num5 add -10'. Saved with the table\n"
              << "  thotkeys / tpress <keys>        - List the hotkeys / do what a key does now, without the keyboard\n"
              << "  library [folder|off|save]       - Each program's table is kept in a library folder and opens by itself\n"
              << "                                    when you attach to the program; show it, use another folder, turn it\n"
              << "                                    off, or save now (it saves by itself every 2 s while it changes)\n\n"
              << "Memory Operations:\n"
              << "  write <addr> <type> <val>       - Write value to memory address\n"
              << "  read <addr> <type>              - Read value from memory address\n"
              << "  dump <addr> [bytes]             - Hex dump memory (default: 64 bytes)\n"
              << "  view <addr|#result|t#> [before] [after] - The memory around a value, each 4 bytes read as what\n"
              << "                                    they most likely are (int, float, double, pointer, text).\n"
              << "                                    'view' again marks what changed (default: 8 slots before, 24 after)\n"
              << "  dissect <addr|#result|t#> [bytes] - Read an object as a C++ struct: finds the vtable and the class\n"
              << "                                    name from RTTI, and names each field by what it is (default 128 bytes)\n"
              << "  dissectcmp <a1> <a2> [a3..] [diff] - Compare multiple struct instances side-by-side\n"
              << "  disasm <addr|#result|t#> [count]  - Disassemble instructions (default: 10 instructions, with symbols)\n"
              << "  xrefs <addr|#result|t#> [module]  - Find executable call/jmp/RIP references targeting address\n"
              << "  assemble <addr> <instruction>     - Assemble & patch an instruction in place into memory\n"
              << "  strings [filter] [min_len] [max]  - Scan memory for ASCII and UTF-16 strings\n"
              << "  gentrainer <file.cpp> [proc] [gui|linux] - Generate standalone C++ trainer (Win32 GUI/Console or Linux)\n"
              << "  speed [val|off|status]          - Speedhack: dilate time progression (e.g. 'speed 2.0', 'speed 0.5', 'speed off')\n"
              << "  diff snap <addr> [bytes] / diff - Memory Snapshot Diff: compare memory region before and after\n"
              << "  pe <module|addr> [exp|imp]      - PE Analyzer: inspect sections, exported and imported functions\n"
              << "  elf <module|addr> [sym|sec]     - ELF Analyzer: inspect ELF32/ELF64 segments, sections & symbols\n"
              << "  engine                          - Detect Unity (Mono/IL2CPP) or Unreal Engine runtime & exports\n"
              << "  unity <file|mem|obj> [arg]      - Inspect Unity IL2CPP metadata (file or RAM) or live object fields\n"
              << "  unreal <find|names|objects|dissect|actors> [...] - Unreal auto-finder, FNames, FField struct, GWorld Actors\n"
              << "  cfg <addr> [max_insns]          - Build Control-Flow Graph (basic blocks & branch edges) of function\n"
              << "  ultimap <discover|idle|action|reset|list|arm|disarm> - Track & rank functions triggered by an action\n"
              << "  hexedit <addr> <hex_bytes...>   - In-place raw hex write (e.g. 'hexedit 0x1234 90 90 90')\n"
              << "  bp <addr> [if <cond>]           - Software BP (INT 3) with optional condition (e.g. 'bp 0x1000 if rax == 10')\n"
              << "  tracebp <addr> [if <cond>]      - Non-blocking tracepoint (logs hits & registers without pausing)\n"
              << "  delbp <addr> / bplist           - Remove or list active breakpoints / tracepoints\n"
              << "  tracelog [clear]                - View or clear captured tracepoint execution log\n"
              << "  dbgattach [win32|veh] / dbgdetach - Attach/detach debugger backend (Win32 DebugAPI or In-Process VEH)\n"
              << "  step / stepover / stepout       - Step Into (F7), Step Over (F8), or Step Out (run to return)\n"
              << "  cont / pause / callstack        - Resume, pause, or view unwound call stack frames\n"
              << "  threads / inject <dll_path>     - List target threads or inject a DLL into the process\n"
              << "  lua <code...>                   - Execute inline Lua 5.4 script (e.g. 'lua print(toHex(readInteger(0x1000)))')\n"
              << "  runlua <file.lua>               - Execute Lua 5.4 script file from disk (supports AOBScan, firstScan,\n"
              << "                                    installHook, createTimer, createHotkey, debugger_onBreakpoint)\n"
              << "  aobscan <pattern...>            - Scan committed memory for an AOB pattern (supports '?' wildcards)\n"
              << "  aobscanm <module> <pattern...>  - Scan a specific module for an AOB pattern\n"
              << "  aa <file.cea>                   - Run an Auto-Assembler script file (supports {$lua}, define, assert, aobscan)\n"
              << "  aobscript <addr|#r|t#> [out.cea] - Generate one-click [ENABLE]/[DISABLE] AOB code-cave hook script\n"
              << "  hook <addr> <hex bytes...>      - Install a HookEngine inline cave hook with custom machine-code bytes\n"
              << "  detour <target> <dest>          - Install a HookEngine detour jump from target address to destination\n"
              << "  unhook <addr|all>               - Remove a specific HookEngine hook or all active hooks\n"
              << "  hooks                           - List active HookEngine hooks (target, cave, trampoline, stolen bytes)\n"
              << "  findwrites <addr|#result|t#> [size] / findaccess ... - Watch what code writes/reads an address\n"
              << "                                    (hardware breakpoint). Change the value in the game, then 'hits';\n"
              << "                                    each hit shows the instruction and its base pointer. 'watchstop' ends it\n"
              << "  script list | add <name> <file> | on <#> | off <#> | show <#> | del <#> - Auto-Assembler scripts kept\n"
              << "                                    in the table (patch the game's code; offline games only). 'add' reads a\n"
              << "                                    script file with [ENABLE]/[DISABLE]; 'on'/'off' apply and undo it\n"
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
    // Support module!symbol notation, e.g. "kernel32.dll!Sleep" or "libgame.so!GameUpdate"
    size_t bang_pos = text.find('!');
    if (bang_pos != std::string::npos && ses().attached()) {
        std::string mod_name = text.substr(0, bang_pos);
        std::string sym_name = text.substr(bang_pos + 1);
        if (auto elf = ses().analyze_module_elf(mod_name)) {
            if (const auto* s = debugger::ELFAnalyzer::find_symbol_by_name(*elf, sym_name)) {
                return s->va;
            }
        }
        if (auto pe = ses().analyze_module(mod_name)) {
            if (const auto* exp = debugger::PEAnalyzer::find_export_by_name(*pe, sym_name)) {
                return exp->va;
            }
        }
    }

    // Support module+offset notation, e.g. "target_dummy.exe+0x1000"
    size_t plus_pos = text.find('+');
    if (plus_pos != std::string::npos && ses().attached()) {
        std::string mod_name = text.substr(0, plus_pos);
        // Strip quotes if present
        if (mod_name.size() >= 2 && mod_name.front() == '"' && mod_name.back() == '"') {
            mod_name = mod_name.substr(1, mod_name.size() - 2);
        }
        std::string off_str = text.substr(plus_pos + 1);
        uintptr_t offset = utils::parse_address(off_str);
        for (const auto& m : ses().process().get_modules()) {
            if (m.name == mod_name) {
                return m.base_address + offset;
            }
        }
    }

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
    if (!attached.table_note.empty()) std::cout << "[*] Table: " << attached.table_note << "\n";
    if (!attached.scripts_note.empty()) std::cout << "[*] Scripts: " << attached.scripts_note << "\n";
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

void cmd_ptrmap(const std::string& sub, const std::string& a1, const std::string& a2, const std::string& a3, const std::string& a4) {
    if (sub == "save") {
        if (!require_attached() || a1.empty()) { std::cout << "Usage: ptrmap save <file.ncem>\n"; return; }
        if (ses().build_and_save_pointer_map(a1)) {
            std::cout << "[+] Saved binary PointerMap to " << a1 << "\n";
        } else {
            std::cerr << "[-] Failed to build or save PointerMap: " << a1 << "\n";
        }
    } else if (sub == "scan") {
        if (!require_attached() || a1.empty() || a2.empty()) { std::cout << "Usage: ptrmap scan <file.ncem> <addr>\n"; return; }
        auto target = parse_address_arg(a2);
        if (!target) return;
        auto res = ses().scan_saved_pointer_map(a1, *target);
        ses().pointer_paths() = std::move(res.paths);
        std::cout << "[+] Scanned saved PointerMap (" << res.pointer_map_size << " pointers): found "
                  << ses().pointer_paths().size() << " path(s).\n";
        cmd_ptrlist(20);
    } else if (sub == "cmp") {
        if (!require_attached() || a1.empty() || a2.empty() || a3.empty() || a4.empty()) {
            std::cout << "Usage: ptrmap cmp <map1.ncem> <addr1> <map2.ncem> <addr2>\n";
            return;
        }
        auto t1 = parse_address_arg(a2);
        auto t2 = parse_address_arg(a4);
        if (!t1 || !t2) return;
        auto r1 = ses().scan_saved_pointer_map(a1, *t1);
        auto r2 = ses().scan_saved_pointer_map(a3, *t2);
        ses().pointer_paths() = scanner::PointerScanner::intersect_paths(r1.paths, r2.paths);
        std::cout << "[+] Map Compare: " << r1.paths.size() << " vs " << r2.paths.size()
                  << " -> " << ses().pointer_paths().size() << " surviving path(s).\n";
        cmd_ptrlist(20);
    } else {
        std::cout << "Usage: ptrmap save <f.ncem> | ptrmap scan <f.ncem> <addr> | ptrmap cmp <f1> <a1> <f2> <a2>\n";
    }
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

// library [folder|off|save]
void cmd_library(const std::string& argument) {
    namespace fs = std::filesystem;
    if (argument == "off") {
        ses().table().set_library({});
        std::cout << "[*] Table library off: tables are only saved with 'tsave'.\n";
        return;
    }
    if (argument == "save") {
        report(ses().table().save_to_library());
        return;
    }
    if (!argument.empty()) {
        ses().table().set_library(fs::path(std::u8string(argument.begin(), argument.end())));
        std::cout << "[*] Table library: " << argument << "\n";
    }

    const fs::path folder = ses().table().library();
    if (folder.empty()) {
        std::cout << "[*] The table library is off. 'library <folder>' turns it on.\n";
        return;
    }
    const fs::path open = ses().table().library_file();
    std::cout << "[*] Each program's table is kept in " << folder.string() << "\n"
              << "    (it opens when you attach to the program, and saves by itself while it changes):\n";
    size_t count = 0;
    std::error_code ec;
    for (const auto& item : fs::directory_iterator(folder, ec)) {
        if (item.path().extension() != ".json") continue;
        const auto t = table::load_table(item.path().string());
        std::cout << "    " << std::left << std::setw(32) << item.path().filename().string() << std::right
                  << (t ? std::to_string(t->entries.size()) + " entries" : std::string("(can't be read)"))
                  << (item.path() == open ? "   (open now)" : "") << "\n";
        ++count;
    }
    if (count == 0) std::cout << "    (no tables yet)\n";
}

void cmd_table_load(const std::string& path) {
    std::vector<session::TableKeeper::ReconcileLine> reconciled;
    if (report(ses().table().load(path, &reconciled))) print_reconciled(reconciled);
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
        T v = std::get<T>(val->value);
        if (scanner::is_big_endian(*type)) v = scanner::swap_bytes(v);
        success = ses().process().write(*addr, v);
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
            if (scanner::is_big_endian(*type)) v = scanner::swap_bytes(v);
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

// Resolves <addr|#result|t#entry> to an address in the target (prints the error and returns nullopt)
std::optional<uintptr_t> resolve_target(const std::string& where) {
    if (where.empty()) { std::cerr << "[-] Give an address, #result or t<entry>.\n"; return std::nullopt; }
    if (where[0] == '#') {
        const auto& results = ses().scans().state().results;
        auto index = parse_index(where.substr(1), results.count(), "result");
        if (!index) return std::nullopt;
        return results.address(*index);
    }
    if ((where[0] == 't' || where[0] == 'T') && where.size() > 1 && std::isdigit(static_cast<unsigned char>(where[1]))) {
        auto index = parse_table_index(where.substr(1));
        if (!index) return std::nullopt;
        const uintptr_t addr = ses().table().with([&](const table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules) {
            return t.entries[*index].address(ses().process(), modules);
        });
        if (addr == 0) { std::cerr << "[-] Table entry #" << *index << " doesn't lead to an address now.\n"; return std::nullopt; }
        return addr;
    }
    return parse_address_arg(where);
}

// dissect <addr|#result|t#> [bytes]: reads an object as a C++ struct
void cmd_dissect(const std::string& where, size_t bytes) {
    if (!require_attached()) return;
    auto address = resolve_target(where);
    if (!address) return;

    view::StructureDissector dissector(ses().process_ptr());
    const auto layout = dissector.dissect(*address, std::clamp<size_t>(bytes, 8, 4096), ses().process().get_modules());
    if (!layout.class_name.empty()) {
        std::cout << "[*] RTTI class: " << layout.class_name;
        if (layout.vtable_functions) std::cout << "  (vtable: " << layout.vtable_functions << " functions)";
        std::cout << "\n";
    } else if (layout.vtable_functions) {
        std::cout << "[*] Has a vtable with " << layout.vtable_functions << " functions (no RTTI name).\n";
    }
    std::cout << "\n" << layout.to_cpp() << "\n";
}

// findwrites / findaccess <addr|#result|t#> [size]: watch what touches an address
void cmd_find_access(const std::string& where, size_t size, debugger::WatchKind kind) {
    if (!require_attached()) return;
    auto address = resolve_target(where);
    if (!address) return;
    if (size != 1 && size != 2 && size != 4 && size != 8) size = 4;
    if (!ses().watch(*address, size, kind)) {
        std::cerr << "[-] Could not start the watch. Another debugger may be attached, or run as Administrator.\n";
        return;
    }
    std::cout << "[*] Watching " << utils::format_address(*address) << " for "
              << (kind == debugger::WatchKind::Access ? "reads/writes" : "writes") << ".\n"
              << "    Change the value in the game, then run 'hits'. 'watchstop' ends it.\n";
}

void cmd_hits() {
    if (!ses().watching()) {
        std::cout << "[-] Not watching anything. 'findwrites <addr>' starts a watch.\n";
        return;
    }
    const auto hits = ses().watch_hits();
    std::cout << "\n[*] " << hits.size() << " instruction(s) touched " << utils::format_address(ses().watched_address())
              << " so far (change the value again for more):\n";
    for (const auto& h : hits) {
        std::cout << "  " << std::left << std::setw(26) << h.location << "  " << std::setw(32) << h.disassembly
                  << std::right << "  x" << h.count << "\n";
        if (!h.base_register.empty() && h.base_pointer()) {
            std::cout << "      base: " << h.base_register << " = " << utils::format_address(h.base_pointer())
                      << " (+0x" << std::hex << h.base_offset << std::dec << ") - pointer-scan this for a stable path\n";
        }
    }
    std::cout << "\n";
}

// strings [filter] [min_len=4] [max=50]
void cmd_strings(const std::string& filter, size_t min_len, size_t max_results) {
    if (!require_attached()) return;
    scanner::StringsScanner scanner(ses().process_ptr());
    auto results = scanner.scan(min_len, filter, max_results);
    if (results.empty()) {
        std::cout << "[-] No strings found matching the criteria.\n";
        return;
    }
    std::cout << "\n Address             Encoding   Len   Text\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    for (const auto& s : results) {
        std::cout << " " << utils::format_address(s.address) << "  "
                  << std::left << std::setw(10) << (s.encoding == scanner::StringEncoding::ASCII ? "ASCII" : "UTF-16")
                  << std::right << std::setw(4) << s.text.size() << "  "
                  << s.text << "\n";
    }
    std::cout << "--------------------------------------------------------------------------------\n";
    std::cout << "[*] Found " << results.size() << " string(s).\n\n";
}

// disasm <addr|#result|t#> [count=10]
void cmd_disasm(const std::string& where, size_t count) {
    if (!require_attached()) return;
    auto address = resolve_target(where);
    if (!address) return;
    if (count == 0) count = 10;
    count = std::min<size_t>(count, 100);

    size_t buffer_size = count * 15;
    std::vector<uint8_t> code(buffer_size);
    if (!ses().process().read_raw(*address, code.data(), buffer_size)) {
        std::cerr << "[-] Could not read memory at " << utils::format_address(*address) << ".\n";
        return;
    }

    auto insts = debugger::Disassembler::disassemble_range(
        code.data(), buffer_size, *address, count, ses().process().pointer_size() != 4);
    ses().annotate_disassembly(insts);
    std::cout << "\n Address             Bytes                  Instruction\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    for (const auto& inst : insts) {
        std::cout << " " << utils::format_address(inst.address) << "  ";
        std::ostringstream bytes_ss;
        for (size_t b = 0; b < std::min<size_t>(inst.bytes.size(), 6); ++b) {
            bytes_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inst.bytes[b]) << " ";
        }
        std::cout << std::left << std::setw(22) << bytes_ss.str() << " "
                  << std::setw(8) << inst.mnemonic << " " << inst.operands;
        if (!inst.resolved_symbol.empty()) {
            std::cout << "  ; " << inst.resolved_symbol;
        }
        std::cout << "\n";
    }
    std::cout << "--------------------------------------------------------------------------------\n\n";
}

void cmd_xrefs(const std::string& where, const std::string& mod_filter) {
    if (!require_attached()) return;
    auto target = resolve_target(where);
    if (!target) {
        std::cout << "Usage: xrefs <addr|#result|t#> [module]\n";
        return;
    }
    uintptr_t mod_base = 0;
    if (!mod_filter.empty()) {
        mod_base = utils::parse_address(mod_filter);
        if (mod_base == 0) {
            for (const auto& m : ses().process().get_modules()) {
                std::string ml = m.name, fl = mod_filter;
                std::transform(ml.begin(), ml.end(), ml.begin(), ::tolower);
                std::transform(fl.begin(), fl.end(), fl.begin(), ::tolower);
                if (ml.find(fl) != std::string::npos) { mod_base = m.base_address; break; }
            }
        }
    }
    const auto refs = ses().find_references(*target, mod_base, 256);
    std::cout << "\n[*] Cross-References to " << utils::format_address(*target)
              << " (" << refs.size() << " hit(s)):\n";
    for (size_t i = 0; i < refs.size(); ++i) {
        std::cout << "  [" << i << "] " << utils::format_address(refs[i].from_address)
                  << "  (" << std::setw(7) << refs[i].kind << ") "
                  << (refs[i].module_name.empty() ? "" : (refs[i].module_name + "  "))
                  << refs[i].instruction << "\n";
    }
    std::cout << "\n";
}

void cmd_dissect_compare(const std::vector<std::string>& args) {
    if (!require_attached()) return;
    bool only_diff = false;
    size_t bytes = 128;
    std::vector<uintptr_t> addrs;
    for (const auto& tok : args) {
        if (tok == "diff" || tok == "--diff") { only_diff = true; continue; }
        if (auto resolved = resolve_target(tok)) {
            if (*resolved > 0x1000) addrs.push_back(*resolved);
            else bytes = std::clamp<size_t>(*resolved, 16, 4096);
        } else {
            size_t sz = 0;
            auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), sz);
            if (ec == std::errc() && ptr == tok.data() + tok.size() && sz >= 8 && sz <= 4096) {
                bytes = sz;
            }
        }
    }
    if (addrs.size() < 2) {
        std::cout << "Usage: dissectcmp <addr1> <addr2> [addr3...] [bytes] [diff]\n";
        return;
    }
    view::StructureDissector d(ses().process_ptr());
    const auto cmp = d.compare(addrs, bytes, ses().process().get_modules(), only_diff);
    std::cout << "\n" << cmp.to_report(only_diff) << "\n";
}

void cmd_scan_xor(const std::string& type, const std::string& val, const std::string& key) {
    if (!require_attached()) return;
    const auto out = ses().scans().first_scan_xor(type, val, key);
    if (!out.ok) {
        std::cout << "[-] " << out.message << "\n";
        return;
    }
    std::cout << "[+] XOR scan: " << ses().scans().describe();
    if (!out.message.empty()) std::cout << " (" << out.message << ")";
    std::cout << "\n";
    cmd_list(20);
}

// assemble <addr|#result|t#> <instruction>
void cmd_assemble(const std::string& where, const std::string& instruction) {
    if (!require_attached()) return;
    auto address = resolve_target(where);
    if (!address) return;

    assembler::X86Assembler encoder;
    std::string err;
    auto encoded = encoder.encode(instruction, *address, err);
    if (!encoded || !err.empty()) {
        std::cerr << "[-] Assembly error: " << (err.empty() ? "Unsupported instruction" : err) << "\n";
        return;
    }

    if (!ses().process().write_raw(*address, encoded->bytes.data(), encoded->bytes.size())) {
        std::cerr << "[-] Failed to write to " << utils::format_address(*address) << ".\n";
        return;
    }

    std::cout << "[+] Assembled and patched " << encoded->bytes.size() << " byte(s) at "
              << utils::format_address(*address) << ": ";
    for (uint8_t b : encoded->bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << "\n";
}

// gentrainer <output.cpp> [proc_name] [gui|console]
void cmd_gentrainer(const std::string& output_path, const std::string& proc_name, table::TrainerKind kind = table::TrainerKind::Console) {
    std::string err;
    bool ok = false;
    ses().table().with([&](const table::CheatTable& t, const auto&) {
        std::string p = proc_name.empty() ? (ses().attached() ? ses().process().name() : t.process_name) : proc_name;
        ok = table::export_standalone_trainer_file(output_path, t, p, err, kind);
    });

    if (ok) {
        const char* kind_lbl = "Console";
        if (kind == table::TrainerKind::GUI) kind_lbl = "Native Win32 GUI";
        else if (kind == table::TrainerKind::LinuxConsole) kind_lbl = "Linux Console";
        std::cout << "[+] Standalone " << kind_lbl
                  << " trainer source exported to: " << output_path << "\n";
        if (kind == table::TrainerKind::GUI) {
            std::cout << "    Compile with: g++ -O2 -mwindows " << output_path << " -o trainer_gui.exe\n";
        } else if (kind == table::TrainerKind::LinuxConsole) {
            std::cout << "    Compile with: g++ -O2 -pthread " << output_path << " -o trainer_linux\n";
        } else {
            std::cout << "    Compile with: g++ -O2 -mconsole " << output_path << " -o trainer.exe\n";
        }
    } else {
        std::cerr << "[-] Failed to export trainer: " << err << "\n";
    }
}

static view::VectorDetector g_vector_detector;
static std::vector<view::VectorCandidate> g_last_coord_hits;

// sig <addr|#result|t#> [max_bytes=48]
void cmd_sig(const std::string& where, size_t max_bytes = 48) {
    if (!require_attached()) return;
    auto target = resolve_target(where);
    if (!target) {
        std::cout << "[!] Could not resolve target: " << where << "\n";
        return;
    }
    auto sig = utils::SignatureGenerator::generate(ses().process(), *target, max_bytes);
    if (!sig) {
        std::cout << "[-] Failed to generate signature for " << utils::format_address(*target) << ".\n";
        return;
    }
    std::cout << "\n[+] Generated Unique AOB Signature for " << utils::format_address(*target) << ":\n";
    std::cout << "    Pattern:  " << sig->pattern << "\n";
    std::cout << "    Length:   " << sig->length << " bytes (" << sig->wildcard_count << " wildcards)\n";
    std::cout << "    Status:   " << (sig->is_unique ? "100% Unique in Module ✓" : "Multiple matches in module")
              << " (" << sig->module_matches << " matches)\n\n";
}

// coords snapshot | detect | set <x> <y> <z> <addr> | nudge <dx> <dy> <dz> <addr> | save <name> <addr> | tp <name> <addr> | list
void cmd_coords(const std::string& sub, const std::string& a1, const std::string& a2, const std::string& a3, const std::string& a4) {
    if (!require_attached()) return;

    auto resolve_coord_addr = [&](const std::string& s) -> std::optional<uintptr_t> {
        if (!s.empty() && s[0] == '#' && !g_last_coord_hits.empty()) {
            try {
                size_t idx = std::stoul(s.substr(1));
                if (idx < g_last_coord_hits.size()) return g_last_coord_hits[idx].address;
            } catch (...) {}
        }
        return resolve_target(s);
    };

    if (sub == "snapshot") {
        view::VectorFormat fmt = (a1 == "f64" || a1 == "double" || a1 == "ue5")
            ? view::VectorFormat::Double3 : view::VectorFormat::Float3;
        size_t c = g_vector_detector.take_snapshot(ses().process(), hal::FilterFlags::DefaultScanFilter, fmt);
        g_last_coord_hits.clear();
        std::cout << "[*] Snapshotted " << c << " candidate 3D vectors ("
                  << (fmt == view::VectorFormat::Double3 ? "Double3/UE5 24B" : "Float3 12B") << ").\n"
                  << "    Move character, then run: coords detect   (or 'coords moved' / 'coords still')\n";
    } else if (sub == "detect" || sub == "moved") {
        const double min_d = a1.empty() ? 0.5 : std::stod(a1);
        const double max_d = a2.empty() ? 2000.0 : std::stod(a2);
        auto hits = (sub == "moved")
            ? g_vector_detector.filter_moved(ses().process(), min_d, max_d)
            : g_vector_detector.detect_motion(ses().process(), static_cast<float>(min_d), static_cast<float>(max_d));
        g_last_coord_hits = hits;
        if (hits.empty()) {
            std::cout << "[-] No moving vectors found. Move your character and try again.\n";
            return;
        }
        std::cout << "\n #    Address             Displacement  Current (X, Y, Z)\n";
        std::cout << "------------------------------------------------------------------------------------\n";
        for (size_t i = 0; i < std::min<size_t>(hits.size(), 25); ++i) {
            std::cout << " " << std::left << std::setw(4) << i << std::right
                      << utils::format_address(hits[i].address) << "   "
                      << std::fixed << std::setprecision(2) << std::setw(12) << hits[i].delta_dist_d << "   ("
                      << hits[i].current_d.x << ", " << hits[i].current_d.y << ", " << hits[i].current_d.z << ")\n";
        }
        std::cout << "------------------------------------------------------------------------------------\n";
        std::cout << "[*] Found " << hits.size() << " moving 3D vector(s). Remaining snapshot: "
                  << g_vector_detector.snapshot_count() << ". Use #0.. as address.\n\n";
    } else if (sub == "still") {
        const double eps = a1.empty() ? 0.05 : std::stod(a1);
        size_t rem = g_vector_detector.filter_stationary(ses().process(), eps);
        std::cout << "[+] Filtered stationary candidates (epsilon=" << eps << "): " << rem << " remaining.\n";
    } else if (sub == "set") {
        if (a1.empty() || a2.empty() || a3.empty()) {
            std::cout << "Usage: coords set <x> <y> <z> <addr|#idx|t#>\n";
            return;
        }
        double x = std::stod(a1), y = std::stod(a2), z = std::stod(a3);
        auto target = resolve_coord_addr(a4);
        if (!target) { std::cout << "[!] Could not resolve target: " << a4 << "\n"; return; }
        bool ok = (g_vector_detector.snapshot_format() == view::VectorFormat::Double3)
            ? view::VectorDetector::write_vector_d(ses().process(), *target, {x, y, z})
            : view::VectorDetector::write_vector(ses().process(), *target, {static_cast<float>(x), static_cast<float>(y), static_cast<float>(z)});
        if (ok) {
            std::cout << "[+] Set coordinates at " << utils::format_address(*target) << " to (" << x << ", " << y << ", " << z << ")\n";
        } else {
            std::cout << "[-] Failed writing coordinates.\n";
        }
    } else if (sub == "nudge") {
        if (a1.empty() || a2.empty() || a3.empty()) {
            std::cout << "Usage: coords nudge <dx> <dy> <dz> <addr|#idx|t#>\n";
            return;
        }
        double dx = std::stod(a1), dy = std::stod(a2), dz = std::stod(a3);
        auto target = resolve_coord_addr(a4);
        if (!target) { std::cout << "[!] Could not resolve target: " << a4 << "\n"; return; }
        bool ok = (g_vector_detector.snapshot_format() == view::VectorFormat::Double3)
            ? view::VectorDetector::nudge_d(ses().process(), *target, dx, dy, dz)
            : view::VectorDetector::nudge(ses().process(), *target, static_cast<float>(dx), static_cast<float>(dy), static_cast<float>(dz));
        if (ok) {
            std::cout << "[+] Nudged coordinates by (" << dx << ", " << dy << ", " << dz << ")\n";
        } else {
            std::cout << "[-] Failed nudging coordinates.\n";
        }
    } else if (sub == "save") {
        if (a1.empty() || a2.empty()) {
            std::cout << "Usage: coords save <name> <addr|#idx|t#>\n";
            return;
        }
        auto target = resolve_coord_addr(a2);
        if (!target) { std::cout << "[!] Could not resolve target: " << a2 << "\n"; return; }
        if (g_vector_detector.snapshot_format() == view::VectorFormat::Double3) {
            if (auto v = view::VectorDetector::read_vector_d(ses().process(), *target)) {
                g_vector_detector.add_waypoint_d(a1, *v, view::VectorFormat::Double3);
                std::cout << "[+] Saved UE5 Double3 waypoint '" << a1 << "' at (" << v->x << ", " << v->y << ", " << v->z << ")\n";
                return;
            }
        } else if (auto v = view::VectorDetector::read_vector(ses().process(), *target)) {
            g_vector_detector.add_waypoint(a1, *v);
            std::cout << "[+] Saved waypoint '" << a1 << "' at (" << v->x << ", " << v->y << ", " << v->z << ")\n";
            return;
        }
        std::cout << "[-] Failed reading coordinates at " << utils::format_address(*target) << "\n";
    } else if (sub == "tp") {
        if (a1.empty() || a2.empty()) {
            std::cout << "Usage: coords tp <name> <addr|#idx|t#>\n";
            return;
        }
        auto target = resolve_coord_addr(a2);
        if (!target) { std::cout << "[!] Could not resolve target: " << a2 << "\n"; return; }
        const auto& wps = g_vector_detector.waypoints();
        bool found = false;
        for (const auto& wp : wps) {
            if (wp.name == a1) {
                bool ok = (wp.format == view::VectorFormat::Double3)
                    ? view::VectorDetector::write_vector_d(ses().process(), *target, wp.position_d)
                    : view::VectorDetector::write_vector(ses().process(), *target, wp.position);
                if (ok) {
                    std::cout << "[+] Teleported to '" << wp.name << "' at (" << wp.position_d.x << ", " << wp.position_d.y << ", " << wp.position_d.z << ")\n";
                }
                found = true;
                break;
            }
        }
        if (!found) std::cout << "[-] Waypoint '" << a1 << "' not found.\n";
    } else if (sub == "list") {
        const auto& wps = g_vector_detector.waypoints();
        if (wps.empty()) { std::cout << "[-] No saved waypoints.\n"; return; }
        std::cout << "\n Waypoint Name        Position (X, Y, Z)\n";
        std::cout << "--------------------------------------------------------\n";
        for (const auto& wp : wps) {
            std::cout << " " << std::left << std::setw(20) << wp.name << " ("
                      << wp.position_d.x << ", " << wp.position_d.y << ", " << wp.position_d.z << ")\n";
        }
        std::cout << "--------------------------------------------------------\n\n";
    } else {
        std::cout << "Usage: coords snapshot [f32|f64] | detect [min] [max] | still [eps] | moved [min] [max]\n"
                  << "       coords set <x> <y> <z> <addr|#idx> | nudge <dx> <dy> <dz> <addr|#idx> | save/tp/list\n";
    }
}

// script list | add <name> <file> | on <#> | off <#> | show <#> | del <#>
void cmd_script(const std::string& sub, const std::string& arg1, const std::string& arg2) {
    auto& table = ses().table();
    if (sub == "list" || sub.empty()) {
        if (table.script_count() == 0) {
            std::cout << "[-] No scripts. 'script add <name> <file>' adds one from a file with [ENABLE]/[DISABLE].\n";
            return;
        }
        std::cout << "\n Index  State  Name\n----------------------------------------\n";
        for (size_t i = 0; i < table.script_count(); ++i) {
            const auto s = table.script(i);
            std::cout << " [" << std::right << std::setw(3) << i << "]  " << (s->enabled ? "ON " : "off")
                      << "    " << s->name << "\n";
        }
        std::cout << "----------------------------------------\n";
        std::cout << " These patch the game's own code: use them with offline games only.\n\n";
        return;
    }
    if (sub == "add") {
        if (arg1.empty() || arg2.empty()) { std::cout << "Usage: script add <name> <file>\n"; return; }
        std::ifstream in(arg2, std::ios::binary);
        if (!in) { std::cerr << "[-] Can't read " << arg2 << "\n"; return; }
        std::ostringstream body;
        body << in.rdbuf();
        report(table.add_script(arg1, body.str()));
        return;
    }
    auto index = parse_index(arg1, table.script_count(), "script");
    if (sub == "on") { if (index) report(table.set_script_enabled(*index, true)); }
    else if (sub == "off") { if (index) report(table.set_script_enabled(*index, false)); }
    else if (sub == "del") { if (index) report(table.remove_script(*index)); }
    else if (sub == "show") {
        if (!index) return;
        const auto s = table.script(*index);
        std::cout << "\n--- " << s->name << " (" << (s->enabled ? "on" : "off") << ") ---\n" << s->body << "\n";
    } else {
        std::cout << "Usage: script list | add <name> <file> | on <#> | off <#> | show <#> | del <#>\n";
    }
}

void cmd_speed(const std::string& arg) {
    if (!require_attached()) return;

    if (arg.empty() || arg == "status") {
        const bool inst = ses().speedhack_installed();
        const bool enabled = ses().speedhack_enabled();
        const double spd = ses().speedhack_speed();
        std::cout << "[*] Speedhack status: "
                  << (inst ? (enabled ? "ENABLED" : "PAUSED/DISABLED") : "STANDBY (not yet hooked)")
                  << " (multiplier: " << spd << "x)\n";
        return;
    }

    if (arg == "off" || arg == "disable" || arg == "stop") {
        if (!ses().speedhack_installed()) {
            std::cout << "[-] Speedhack is not active.\n";
            return;
        }
        if (ses().disable_speedhack()) {
            std::cout << "[+] Speedhack disabled. Normal 1.0x time progression restored.\n";
        } else {
            std::cerr << "[-] Failed to disable speedhack.\n";
        }
        return;
    }

    if (arg == "on" || arg == "enable" || arg == "start") {
        if (ses().enable_speedhack()) {
            std::cout << "[+] Speedhack enabled at " << ses().speedhack_speed() << "x speed.\n";
        } else {
            std::cerr << "[-] Failed to enable speedhack.\n";
        }
        return;
    }

    try {
        double val = std::stod(arg);
        if (val <= 0.0 || val > 100.0) {
            std::cerr << "[-] Speed multiplier must be between 0.01 and 100.0\n";
            return;
        }
        if (ses().set_speed(val)) {
            ses().enable_speedhack();
            std::cout << "[+] Speedhack set to " << val << "x and enabled.\n";
        } else {
            std::cerr << "[-] Failed to set speed.\n";
        }
    } catch (...) {
        std::cerr << "[-] Invalid speed argument: '" << arg << "'. Use 'speed <number>', 'speed off', or 'speed status'.\n";
    }
}

void cmd_diff(std::istringstream& iss) {
    if (!require_attached()) return;
    std::string sub;
    iss >> sub;

    if (sub == "snap" || sub == "snap1" || sub == "a") {
        std::string addr_str;
        size_t size = 64;
        if (iss >> addr_str) {
            iss >> size;
            const uintptr_t addr = utils::parse_address(addr_str);
            if (!addr) {
                std::cout << "[-] Invalid address: " << addr_str << "\n";
                return;
            }
            if (ses().diff_snapshot_a(addr, size)) {
                std::cout << "[+] Captured Snapshot A (" << size << " bytes at "
                          << utils::format_address(addr) << "). Change game state then run 'diff compare'.\n";
            } else {
                std::cerr << "[-] Failed to read memory region for Snapshot A.\n";
            }
        } else {
            std::cout << "Usage: diff snap <address> [size=64]\n";
        }
        return;
    }

    if (sub == "compare" || sub == "snap2" || sub == "b" || sub.empty()) {
        if (!ses().memory_diff().has_snapshot_a()) {
            std::cout << "[-] No Snapshot A captured yet. Use 'diff snap <address> [size=64]' first.\n";
            return;
        }
        if (!ses().diff_snapshot_b()) {
            std::cerr << "[-] Failed to read memory region for Snapshot B.\n";
            return;
        }

        auto summary = ses().diff_compare();
        std::cout << "\n=== Memory Diff: " << utils::format_address(summary.address)
                  << " (" << summary.total_bytes << " bytes) ===\n";
        std::cout << "[*] Changes detected: " << summary.changed_bytes << " / " << summary.total_bytes
                  << " bytes (" << std::fixed << std::setprecision(1) << summary.changed_percentage << "%)\n";

        if (summary.diffs.empty()) {
            std::cout << "    (No byte differences found between Snapshot A and B)\n";
        } else {
            std::cout << " Offset     Address            Snapshot A (Old)  Snapshot B (New)\n";
            std::cout << "------------------------------------------------------------------\n";
            for (const auto& d : summary.diffs) {
                uintptr_t off = d.address - summary.address;
                std::cout << " +0x" << std::hex << std::setw(4) << std::setfill('0') << off
                          << "   " << utils::format_address(d.address)
                          << "   0x" << std::setw(2) << static_cast<int>(d.old_val)
                          << " ('" << (std::isprint(d.old_val) ? static_cast<char>(d.old_val) : '.') << "')"
                          << "          0x" << std::setw(2) << static_cast<int>(d.new_val)
                          << " ('" << (std::isprint(d.new_val) ? static_cast<char>(d.new_val) : '.') << "')\n";
            }
            std::cout << std::dec << std::setfill(' ');
        }
        return;
    }

    if (sub == "clear" || sub == "reset") {
        ses().diff_clear();
        std::cout << "[*] Memory diff cleared.\n";
        return;
    }

    std::cout << "Usage: diff snap <addr> [bytes=64]  - Capture baseline Snapshot A\n"
              << "       diff [compare]                - Capture Snapshot B and print delta byte diff\n"
              << "       diff clear                    - Reset snapshots\n";
}

void cmd_pe(std::istringstream& iss) {
    if (!require_attached()) return;
    std::string target;
    iss >> target;

    if (target.empty()) {
        std::cout << "Usage: pe <module_name|0xAddress> [exports|imports]\n"
                  << "Examples: 'pe game.exe', 'pe kernel32.dll exports', 'pe 0x7FF700000000'\n";
        return;
    }

    std::string sub;
    iss >> sub;

    std::optional<debugger::PEInfo> info;
    const uintptr_t parsed_addr = utils::parse_address(target);
    if (parsed_addr != 0) {
        info = ses().analyze_pe(parsed_addr);
    } else {
        info = ses().analyze_module(target);
    }

    if (!info || !info->is_valid) {
        std::cerr << "[-] Failed to parse PE headers for: " << target << "\n";
        return;
    }

    if (sub == "exports" || sub == "exp") {
        std::cout << "\n=== Export Directory for " << target << " (" << info->exports.size() << " exports) ===\n";
        std::cout << " Ordinal   RVA          VA                   Function Name\n";
        std::cout << "----------------------------------------------------------------------\n";
        for (const auto& exp : info->exports) {
            std::cout << " " << std::setw(7) << std::dec << exp.ordinal << "   "
                      << "0x" << std::hex << std::setw(8) << std::setfill('0') << exp.rva << "   "
                      << utils::format_address(exp.va) << "   "
                      << exp.name
                      << (exp.is_forwarded ? (" -> " + exp.forwarder_name) : "") << "\n";
        }
        std::cout << std::dec << std::setfill(' ');
        return;
    }

    if (sub == "imports" || sub == "imp") {
        std::cout << "\n=== Import Directory for " << target << " (" << info->imports.size() << " modules) ===\n";
        for (const auto& imp : info->imports) {
            std::cout << "\n [*] " << imp.module_name << " (" << imp.functions.size() << " functions):\n";
            for (size_t i = 0; i < std::min<size_t>(imp.functions.size(), 20); ++i) {
                const auto& fn = imp.functions[i];
                std::cout << "     IAT: " << utils::format_address(fn.iat_va) << "  " << fn.name << "\n";
            }
            if (imp.functions.size() > 20) {
                std::cout << "     ... (" << (imp.functions.size() - 20) << " more functions)\n";
            }
        }
        return;
    }

    std::cout << "\n=== Portable Executable (PE) Summary: " << target << " ===\n";
    std::cout << " Architecture:      " << (info->is_64bit ? "x86-64 (PE32+)" : "x86 (PE32)") << "\n";
    std::cout << " Subsystem:         " << info->subsystem << "\n";
    std::cout << " Image Base:        " << utils::format_address(info->image_base) << "\n";
    std::cout << " Entry Point:       " << utils::format_address(info->entry_point) << "\n";
    std::cout << " Image Size:        " << session::format_size(info->image_size) << " (" << info->image_size << " bytes)\n";
    std::cout << " Exported Symbols:  " << info->exports.size() << " (use 'pe " << target << " exports')\n";
    std::cout << " Imported Modules:  " << info->imports.size() << " (use 'pe " << target << " imports')\n";

    std::cout << "\n Sections (" << info->sections.size() << "):\n";
    std::cout << " Name       VirtAddr     VirtSize     RawSize      Flags\n";
    std::cout << "------------------------------------------------------------------\n";
    for (const auto& sec : info->sections) {
        std::string flags;
        if (sec.is_readable) flags += "R";
        if (sec.is_writable) flags += "W";
        if (sec.is_executable) flags += "X";
        std::cout << " " << std::left << std::setw(10) << sec.name
                  << "0x" << std::hex << std::setw(8) << std::setfill('0') << sec.virtual_address << "   "
                  << "0x" << std::setw(8) << sec.virtual_size << "   "
                  << "0x" << std::setw(8) << sec.raw_size << "   "
                  << flags << "\n";
    }
    std::cout << std::dec << std::setfill(' ') << std::right;
}

void cmd_elf(std::istringstream& iss) {
    if (!require_attached()) return;
    std::string target, sub;
    iss >> target >> sub;
    if (target.empty()) {
        std::cout << "Usage: elf <module_name|0xAddress> [sym|sec]\n";
        return;
    }

    std::optional<debugger::ELFInfo> info;
    const uintptr_t parsed_addr = utils::parse_address(target);
    info = (parsed_addr != 0) ? ses().analyze_elf(parsed_addr) : ses().analyze_module_elf(target);
    if (!info || !info->is_valid) {
        std::cerr << "[-] Failed to parse ELF headers for: " << target << "\n";
        return;
    }

    if (sub == "sym" || sub == "symbols" || sub == "exp") {
        std::cout << "\n=== ELF Symbols for " << target << " (" << info->symbols.size() << " entries) ===\n";
        for (const auto& s : info->symbols) {
            std::cout << "  " << utils::format_address(s.va)
                      << "  " << (s.is_exported ? "[EXP] " : "[LOC] ")
                      << std::setw(6) << std::dec << s.size << "  " << s.name << "\n";
        }
        return;
    }

    if (sub == "sec" || sub == "sections") {
        std::cout << "\n=== ELF Sections (" << info->sections.size() << ") ===\n";
        for (const auto& sec : info->sections) {
            std::string flags;
            if (sec.is_readable) flags += "R";
            if (sec.is_writable) flags += "W";
            if (sec.is_executable) flags += "X";
            std::cout << "  " << std::left << std::setw(18) << sec.name << std::right
                      << " VA=" << utils::format_address(sec.virtual_address)
                      << " Size=" << std::dec << sec.size << " [" << flags << "]\n";
        }
        return;
    }

    std::cout << "\n=== ELF Binary Summary: " << target << " ===\n";
    std::cout << " Format:       " << (info->is_64bit ? "ELF64" : "ELF32") << " (" << info->type_name << ")\n";
    std::cout << " Machine:      " << info->machine_name << "\n";
    std::cout << " Image Base:   " << utils::format_address(info->image_base) << "\n";
    std::cout << " Entry Point:  " << utils::format_address(info->entry_point) << "\n";
    std::cout << " Segments:     " << info->segments.size() << " | Sections: " << info->sections.size()
              << " | Symbols: " << info->symbols.size() << "\n";
    if (!info->needed_libraries.empty()) {
        std::cout << " Needed Libs:  ";
        for (size_t i = 0; i < info->needed_libraries.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << info->needed_libraries[i];
        }
        std::cout << "\n";
    }
}

void cmd_engine() {
    if (!require_attached()) return;
    auto det = ses().detect_game_engine();
    std::cout << "\n=== Game Engine Detection ===\n";
    std::cout << " Engine:  " << det.engine_name << "\n";
    if (!det.runtime_module.empty()) {
        std::cout << " Module:  " << det.runtime_module << " @ " << utils::format_address(det.runtime_base) << "\n";
    }
    if (!det.details.empty()) {
        std::cout << " Details: " << det.details << "\n";
    }
    if (!det.api_exports.empty()) {
        std::cout << " Resolved Runtime APIs (" << det.api_exports.size() << "):\n";
        for (const auto& [name, va] : det.api_exports) {
            std::cout << "   " << utils::format_address(va) << "  " << name << "\n";
        }
    }
}

void cmd_unity(std::istringstream& iss) {
    std::string sub, arg2;
    iss >> sub;
    std::getline(iss >> std::ws, arg2);
    if (sub.empty()) {
        std::cout << "Usage: unity mem [filter] | unity obj <0xObjAddr> | unity <global-metadata.dat> [filter]\n";
        return;
    }

    if (sub == "obj") {
        if (!require_attached()) return;
        uintptr_t obj = utils::parse_address(arg2);
        if (!obj) { std::cout << "Usage: unity obj <0xObjAddr>\n"; return; }
        auto lay = ses().dissect_unity_object(obj);
        if (lay.fields.empty()) {
            std::cerr << "[-] Could not reflect IL2CPP class fields at " << utils::format_address(obj) << "\n";
            return;
        }
        std::cout << "[+] Live Unity IL2CPP Class: " << lay.class_name << " (" << lay.fields.size() << " fields)\n";
        for (const auto& f : lay.fields) {
            std::cout << "  +0x" << std::hex << std::setw(4) << std::setfill('0') << f.offset << std::dec << std::setfill(' ')
                      << "  " << std::left << std::setw(26) << f.name << std::right << " = " << f.value << "\n";
        }
        return;
    }

    view::UnityMetadataReport rep;
    if (sub == "mem") {
        if (!require_attached()) return;
        rep = ses().inspect_unity_metadata_memory(0, arg2, 64);
    } else {
        rep = ses().inspect_unity_metadata(sub, arg2, 64);
    }

    if (!rep.valid) {
        std::cerr << "[-] Unity metadata parse failed: " << rep.error << "\n";
        return;
    }
    std::cout << "[+] Unity IL2CPP Metadata v" << rep.version << " (" << rep.total_types
              << " types, " << rep.total_fields << " fields)\n";
    for (const auto& t : rep.types) {
        std::cout << " class " << (t.namespaze.empty() ? "" : (t.namespaze + "::")) << t.name
                  << " (" << t.fields.size() << " fields)\n";
        for (size_t i = 0; i < std::min<size_t>(t.fields.size(), 12); ++i) {
            std::cout << "   ." << t.fields[i].name << " (token=0x" << std::hex << t.fields[i].token << std::dec << ")\n";
        }
    }
}

void cmd_unreal(std::istringstream& iss) {
    if (!require_attached()) return;
    std::string sub;
    iss >> sub;
    if (sub == "find") {
        std::string mod_str;
        iss >> mod_str;
        uintptr_t mod_base = utils::parse_address(mod_str);
        auto res = ses().find_unreal_globals(mod_base);
        std::cout << "[*] Unreal Auto-Finder (" << (res.source_module.empty() ? "all modules" : res.source_module) << "):\n";
        std::cout << "  FNamePool / GNames:     " << (res.found_names ? utils::format_address(res.fname_pool_va) : "(not found)") << "\n";
        std::cout << "  FUObjectArray / GObj:   " << (res.found_objects ? utils::format_address(res.guobject_array_va) : "(not found)") << "\n";
        std::cout << "  GWorld / UWorld*:       " << (res.found_world ? utils::format_address(res.gworld_va) : "(not found)") << "\n";
    } else if (sub == "names") {
        std::string gnames_str;
        size_t max_names = 128;
        iss >> gnames_str;
        if (iss >> max_names) {}
        uintptr_t gnames = utils::parse_address(gnames_str);
        if (!gnames) { std::cout << "Usage: unreal names <gnames_addr> [max=128]\n"; return; }
        auto names = ses().scan_unreal_names(gnames, {}, 8, max_names);
        std::cout << "[+] Decoded " << names.size() << " FNamePool entries:\n";
        for (const auto& n : names) {
            std::cout << "  [0x" << std::hex << std::setw(6) << std::setfill('0') << n.index << std::dec
                      << std::setfill(' ') << "] " << n.name << "\n";
        }
    } else if (sub == "objects") {
        std::string gobj_str, gnames_str, filter;
        iss >> gobj_str >> gnames_str;
        std::getline(iss >> std::ws, filter);
        uintptr_t gobj = utils::parse_address(gobj_str);
        uintptr_t gnames = utils::parse_address(gnames_str);
        if (!gobj || !gnames) {
            std::cout << "Usage: unreal objects <gobjects_addr> <gnames_addr> [filter]\n";
            return;
        }
        auto objs = ses().dump_unreal_objects(gobj, gnames, {}, filter, 128);
        std::cout << "[+] Dumped " << objs.size() << " UObject entries:\n";
        for (const auto& o : objs) {
            std::cout << "  [" << o.index << "] " << utils::format_address(o.address)
                      << "  " << (o.class_name.empty() ? "UObject" : o.class_name)
                      << "  " << o.name << "\n";
        }
    } else if (sub == "dissect") {
        std::string obj_str, gnames_str;
        iss >> obj_str >> gnames_str;
        uintptr_t obj = utils::parse_address(obj_str);
        uintptr_t gnames = utils::parse_address(gnames_str);
        if (!obj || !gnames) {
            std::cout << "Usage: unreal dissect <uobject_addr> <gnames_addr>\n";
            return;
        }
        auto lay = ses().dissect_unreal_object(obj, gnames);
        std::cout << "[+] Unreal Class " << (lay.class_name.empty() ? "UObject" : lay.class_name)
                  << " (" << lay.fields.size() << " reflected fields)\n";
        for (const auto& f : lay.fields) {
            std::cout << "  +0x" << std::hex << std::setw(4) << std::setfill('0') << f.offset << std::dec << std::setfill(' ')
                      << "  " << std::left << std::setw(12) << f.type << std::setw(24) << f.name << std::right << " = " << f.value << "\n";
        }
    } else if (sub == "actors") {
        std::string world_str, gnames_str;
        iss >> world_str >> gnames_str;
        uintptr_t world = utils::parse_address(world_str);
        uintptr_t gnames = utils::parse_address(gnames_str);
        if (!world || !gnames) {
            std::cout << "Usage: unreal actors <uworld_addr> <gnames_addr>\n";
            return;
        }
        auto actors = ses().dump_unreal_actors(world, gnames);
        std::cout << "[+] Dumped " << actors.size() << " UWorld Actors:\n";
        for (const auto& a : actors) {
            std::cout << "  [" << a.index << "] " << utils::format_address(a.address)
                      << "  " << a.class_name << "  " << a.name;
            if (a.has_location) {
                std::cout << "  Pos(" << std::fixed << std::setprecision(1) << a.x << ", " << a.y << ", " << a.z << ")";
            }
            std::cout << "\n";
        }
    } else if (sub == "calibrate") {
        std::string obj_str, gnames_str;
        iss >> obj_str >> gnames_str;
        uintptr_t obj = utils::parse_address(obj_str);
        uintptr_t gn = utils::parse_address(gnames_str);
        if (!obj || !gn) {
            std::cout << "Usage: unreal calibrate <world_or_actor_addr> <gnames_addr>\n";
            return;
        }
        auto cal = ses().calibrate_unreal_offsets(obj, gn);
        std::cout << (cal.ok ? "[+] Unreal Offset Calibration:\n" : "[-] Could not calibrate Unreal offsets via FField.\n");
        for (const auto& n : cal.notes) std::cout << "  * " << n << "\n";
    } else {
        std::cout << "Usage: unreal find | names <gnames> | objects <gobj> <gnames> | dissect <obj> <gnames> | actors <uworld> <gnames> | calibrate <obj> <gnames>\n";
    }
}

void cmd_cfg(std::istringstream& iss) {
    if (!require_attached()) return;
    std::string addr_str;
    size_t max_insns = 128;
    iss >> addr_str;
    if (iss >> max_insns) {}
    uintptr_t entry = utils::parse_address(addr_str);
    if (!entry) { std::cout << "Usage: cfg <0xEntryAddr> [max_insns=128]\n"; return; }
    auto cfg = ses().build_cfg(entry, max_insns, 32);
    if (cfg.blocks.empty()) { std::cerr << "[-] Failed to decode CFG at " << addr_str << "\n"; return; }
    std::cout << "[+] Control Flow Graph for " << utils::format_address(entry)
              << " (" << cfg.blocks.size() << " blocks, " << cfg.edges.size() << " edges):\n";
    for (const auto& blk : cfg.blocks) {
        std::cout << "\n [Block #" << blk.id << " L" << blk.level << ":C" << blk.lane
                  << " | " << utils::format_address(blk.start_address) << " .. " << utils::format_address(blk.end_address) << "]\n";
        for (const auto& in : blk.instructions) {
            std::cout << "   " << utils::format_address(in.address) << "  " << in.full_text << "\n";
        }
    }
    if (!cfg.edges.empty()) {
        std::cout << "\n Edges:\n";
        for (const auto& e : cfg.edges) {
            const char* k = (e.kind == debugger::CFGEdge::Kind::TrueBranch) ? "TRUE"
                          : (e.kind == debugger::CFGEdge::Kind::FalseBranch) ? "FALSE" : "FLOW";
            std::cout << "   Block #" << e.from_block << " --[" << k << "]--> Block #" << e.to_block << "\n";
        }
    }
}

void cmd_ultimap(std::istringstream& iss) {
    if (!require_attached()) return;
    std::string sub, arg;
    iss >> sub;
    std::getline(iss >> std::ws, arg);
    auto& um = ses().ultimap();
    if (sub == "discover") {
        size_t added = um.discover_functions(ses().process(), arg, 256);
        std::cout << "[+] Ultimap discovered " << added << " functions (total: " << um.total_count() << ")\n";
    } else if (sub == "idle") {
        if (auto* dc = ses().debug_coordinator()) um.sync_from_debugger(*dc);
        size_t elim = um.mark_idle_noisy();
        std::cout << "[+] Eliminated " << elim << " noisy/idle functions; remaining: " << um.active_count() << "\n";
    } else if (sub == "action") {
        if (auto* dc = ses().debug_coordinator()) um.sync_from_debugger(*dc);
        size_t kept = um.keep_only_executed();
        std::cout << "[+] Filtered to " << kept << " functions executed during action\n";
    } else if (sub == "window") {
        um.begin_action_window();
        std::cout << "[+] Started clean Ultimap capture window (" << um.active_count() << " active candidates)\n";
    } else if (sub == "arm") {
        auto* dc = ses().debug_coordinator();
        if (!dc || !dc->is_attached()) { std::cerr << "[-] Attach debugger first ('dbgattach').\n"; return; }
        size_t n = um.arm_tracepoints(*dc);
        std::cout << "[+] Armed " << n << " Ultimap tracepoints\n";
    } else if (sub == "disarm") {
        if (auto* dc = ses().debug_coordinator()) um.disarm_tracepoints(*dc);
        std::cout << "[+] Disarmed Ultimap tracepoints\n";
    } else if (sub == "reset") {
        um.reset();
        std::cout << "[+] Ultimap counters & exclusions reset (" << um.total_count() << " candidates)\n";
    } else if (sub == "list") {
        if (auto* dc = ses().debug_coordinator()) um.sync_from_debugger(*dc);
        auto cands = um.ranked_candidates();
        std::cout << "[*] Active Ultimap Candidates (" << cands.size() << "):\n";
        for (size_t i = 0; i < std::min<size_t>(cands.size(), 32); ++i) {
            const auto& f = cands[i];
            std::cout << "  " << utils::format_address(f.address) << "  hits=" << f.window_hits
                      << "  " << f.module_name << "!" << f.name << "\n";
        }
    } else {
        std::cout << "Usage: ultimap <discover [mod]|arm|window|idle|action|list|disarm|reset>\n";
    }
}

void cmd_hexedit(const std::string& addr_str, const std::string& hex_bytes_str) {
    if (!require_attached()) return;
    if (!ses().process().can_write()) {
        std::cerr << "[-] Target process is read-only. Run as Administrator to write memory.\n";
        return;
    }

    const uintptr_t addr = utils::parse_address(addr_str);
    if (!addr) {
        std::cout << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    std::vector<uint8_t> bytes;
    std::string clean;
    for (char c : hex_bytes_str) {
        if (!std::isspace(static_cast<unsigned char>(c))) clean += c;
    }
    if (clean.empty() || clean.size() % 2 != 0) {
        std::cout << "[-] Hex bytes must consist of pairs of hex digits (e.g. '90 90' or 'DEADBEEF').\n";
        return;
    }
    for (size_t i = 0; i < clean.size(); i += 2) {
        std::string byte_str = clean.substr(i, 2);
        char* end = nullptr;
        unsigned long val = std::strtoul(byte_str.c_str(), &end, 16);
        if (end != byte_str.c_str() + 2) {
            std::cout << "[-] Invalid hex character in: '" << byte_str << "'\n";
            return;
        }
        bytes.push_back(static_cast<uint8_t>(val));
    }

    if (ses().process().write_raw(addr, bytes.data(), bytes.size(), true)) {
        std::cout << "[+] Wrote " << bytes.size() << " bytes at " << utils::format_address(addr) << "\n";
    } else {
        std::cerr << "[-] Failed to write bytes to " << utils::format_address(addr) << "\n";
    }
}

void cmd_bp(const std::string& addr_str, const std::string& rest, bool tracepoint = false) {
    if (!require_attached()) return;
    auto resolved = resolve_target(addr_str);
    if (!resolved) {
        std::cout << "Usage: " << (tracepoint ? "tracebp" : "bp") << " <address|module+off|module!sym|#result|t#> [if <condition> | note]\n";
        return;
    }
    const uintptr_t addr = *resolved;

    std::string note;
    std::string condition;
    if (!rest.empty()) {
        if (rest.rfind("if ", 0) == 0 || rest.rfind("IF ", 0) == 0) {
            condition = rest.substr(3);
        } else {
            auto if_pos = rest.find(" if ");
            if (if_pos != std::string::npos) {
                note = rest.substr(0, if_pos);
                condition = rest.substr(if_pos + 4);
            } else {
                note = rest;
            }
        }
    }

    if (ses().dbg_set_bp(addr, note, condition, tracepoint)) {
        std::cout << "[+] " << (tracepoint ? "Tracepoint" : "Software breakpoint (INT 3)")
                  << " set at " << utils::format_address(addr);
        if (!condition.empty()) std::cout << " [if " << condition << "]";
        if (!note.empty()) std::cout << " (" << note + ")";
        std::cout << "\n";
    } else {
        auto* dbg = ses().step_debugger();
        std::cerr << "[-] Failed to set breakpoint at " << utils::format_address(addr)
                  << (dbg && !dbg->last_error().empty() ? ": " + dbg->last_error() : "") << "\n";
    }
}

void cmd_delbp(const std::string& addr_str) {
    if (!require_attached()) return;
    auto resolved = resolve_target(addr_str);
    if (!resolved) {
        std::cout << "Usage: delbp <address|module+off|module!sym>\n";
        return;
    }
    const uintptr_t addr = *resolved;
    if (ses().dbg_remove_bp(addr)) {
        std::cout << "[+] Removed breakpoint at " << utils::format_address(addr) << "\n";
    } else {
        std::cerr << "[-] Breakpoint not found at " << utils::format_address(addr) << "\n";
    }
}

void cmd_bplist() {
    if (!require_attached()) return;
    auto* dbg = ses().step_debugger();
    if (!dbg) {
        std::cout << "[-] Debugger not initialized.\n";
        return;
    }
    auto bps = dbg->get_breakpoints();
    if (bps.empty()) {
        std::cout << "[*] No active breakpoints.\n";
        return;
    }
    std::cout << "\n Address            Mode    Orig  Enabled  Hits   Condition / Note\n";
    std::cout << "------------------------------------------------------------------------\n";
    for (const auto& bp : bps) {
        std::cout << " " << utils::format_address(bp.address) << "   "
                  << (bp.is_tracepoint ? "TRACE " : "BREAK ") << "  "
                  << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bp.original_byte) << "  "
                  << (bp.is_enabled ? "Yes" : "No ") << "      "
                  << std::dec << std::setw(5) << std::setfill(' ') << bp.hit_count << "  ";
        if (!bp.condition.empty()) std::cout << "[if " << bp.condition << "] ";
        std::cout << bp.note << "\n";
    }
}

void cmd_tracelog(const std::string& arg) {
    if (!require_attached()) return;
    auto* dbg = ses().step_debugger();
    if (!dbg) return;
    if (arg == "clear") {
        dbg->clear_trace_log();
        std::cout << "[*] Trace log cleared.\n";
        return;
    }
    auto entries = dbg->get_trace_log();
    if (entries.empty()) {
        std::cout << "[*] Trace log is empty. Use 'tracebp <addr>' first.\n";
        return;
    }
    std::cout << "\n Seq   TID     Address            Symbol              RAX               RCX               Disassembly\n";
    std::cout << "------------------------------------------------------------------------------------------------------------\n";
    for (const auto& e : entries) {
        std::cout << " #" << std::left << std::setw(5) << e.sequence
                  << std::setw(8) << e.thread_id
                  << utils::format_address(e.address) << "   "
                  << std::setw(18) << e.symbol.substr(0, 17) << "  "
                  << utils::format_address(e.registers.rax) << "  "
                  << utils::format_address(e.registers.rcx) << "  "
                  << e.disassembly << "\n";
    }
    std::cout << std::right;
}

void cmd_callstack() {
    if (!require_attached()) return;
    auto* dbg = ses().step_debugger();
    if (!dbg) return;
    auto stack = dbg->get_call_stack();
    if (stack.empty()) {
        std::cout << "[*] Call stack empty (debugger not paused or frame pointer omitted).\n";
        return;
    }
    std::cout << "\n Frame  RBP                 Return Address      Symbol / Location\n";
    std::cout << "------------------------------------------------------------------\n";
    for (size_t i = 0; i < stack.size(); ++i) {
        std::cout << " #" << std::left << std::setw(4) << i
                  << utils::format_address(stack[i].rbp) << "   "
                  << utils::format_address(stack[i].return_address) << "   "
                  << stack[i].symbol_name << "\n";
    }
    std::cout << std::right;
}

bool parse_hex_bytes_text(const std::string& text, std::vector<uint8_t>& out) {
    out.clear();
    std::string hex;
    for (size_t i = 0; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (std::isspace(c) || c == ',' || c == ';') continue;
        if ((c == '0' || c == '\\') && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            ++i;
            continue;
        }
        if (!std::isxdigit(c)) return false;
        hex.push_back(static_cast<char>(c));
    }
    if (hex.empty() || (hex.size() % 2) != 0) return false;
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return true;
}

void cmd_aobscan_impl(const std::string& pattern_str, const std::optional<std::string>& module_name) {
    if (!require_attached()) return;
    auto pat_opt = utils::parse_aob_pattern(pattern_str);
    if (!pat_opt || pat_opt->bytes.empty()) {
        std::cout << "[-] Invalid AOB pattern.\n";
        return;
    }
    const auto& pat = *pat_opt;
    const size_t pat_len = pat.bytes.size();

    auto to_low = [](std::string s) {
        for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        return s;
    };

    const auto mods = ses().process().get_modules();
    struct Interval { uintptr_t start; uintptr_t end; std::string name; };
    std::vector<Interval> mod_ivs;
    if (module_name && !module_name->empty()) {
        const std::string want = to_low(*module_name);
        for (const auto& m : mods) {
            if (to_low(m.name) == want) mod_ivs.push_back({m.base_address, m.base_address + m.size, m.name});
        }
        if (mod_ivs.empty()) {
            for (const auto& m : mods) {
                if (to_low(m.name).find(want) != std::string::npos) {
                    mod_ivs.push_back({m.base_address, m.base_address + m.size, m.name});
                }
            }
        }
        if (mod_ivs.empty()) {
            std::cout << "[-] Module not found: " << *module_name << "\n";
            return;
        }
    }

    constexpr uint32_t kFlags =
        hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess | hal::FilterFlags::ExcludeGuardPages;
    const auto regions = ses().process().query_regions(kFlags);
    std::vector<uintptr_t> hits;
    constexpr size_t kMaxShow = 64;
    constexpr size_t kChunk = 2 * 1024 * 1024;
    std::vector<uint8_t> buf;

    auto scan_slice = [&](uintptr_t s, uintptr_t e) {
        uintptr_t cur = s;
        while (cur < e && hits.size() < kMaxShow) {
            const size_t rem = static_cast<size_t>(e - cur);
            if (rem < pat_len) break;
            const size_t n = std::min(kChunk, rem);
            buf.resize(n);
            if (!ses().process().read_raw(cur, buf.data(), n)) break;
            for (size_t i = 0; i + pat_len <= n; ++i) {
                bool ok = true;
                for (size_t j = 0; j < pat_len; ++j) {
                    if (pat.mask[j] && buf[i + j] != pat.bytes[j]) { ok = false; break; }
                }
                if (ok && (hits.empty() || hits.back() != cur + i)) {
                    hits.push_back(cur + i);
                    if (hits.size() >= kMaxShow) break;
                }
            }
            const size_t step = (n > pat_len - 1 && cur + n < e) ? (n - (pat_len - 1)) : n;
            cur += std::max<size_t>(1, step);
        }
    };

    for (const auto& r : regions) {
        if (!r.is_committed || !r.is_readable || r.is_guard || r.size < pat_len) continue;
        if (!mod_ivs.empty()) {
            for (const auto& iv : mod_ivs) {
                const uintptr_t s = std::max(r.base_address, iv.start);
                const uintptr_t e = std::min(r.end_address(), iv.end);
                if (e > s) scan_slice(s, e);
            }
        } else {
            scan_slice(r.base_address, r.end_address());
        }
        if (hits.size() >= kMaxShow) break;
    }

    std::cout << "[*] AOB scan found " << hits.size() << (hits.size() == kMaxShow ? "+" : "") << " match(es):\n";
    for (size_t i = 0; i < hits.size(); ++i) {
        std::string loc = utils::format_address(hits[i]);
        for (const auto& m : mods) {
            if (hits[i] >= m.base_address && hits[i] < m.base_address + m.size) {
                std::ostringstream ss;
                ss << m.name << "+0x" << std::hex << std::uppercase << (hits[i] - m.base_address);
                loc += " (" + ss.str() + ")";
                break;
            }
        }
        std::cout << "  [" << i << "] " << loc << "\n";
    }
}

void cmd_aa_file(const std::string& path) {
    if (!require_attached()) return;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cout << "[-] Could not open AA script file: " << path << "\n";
        return;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    assembler::AutoAssembler aa(ses().process_ptr());
    aa.set_lua_runner([](const std::string& code, std::string& out_msg) -> bool {
        auto r = ses().run_lua(code);
        out_msg = r.success ? r.output : r.error;
        return r.success;
    });
    const auto res = aa.enable(ss.str());
    if (res.ok) {
        std::cout << "[+] AA enabled: " << res.message << "\n";
        for (size_t i = 0; i < res.effect.allocations.size(); ++i) {
            const auto& a = res.effect.allocations[i];
            std::cout << "    alloc[" << i << "] -> " << utils::format_address(a.address)
                      << " (" << a.size << " bytes)\n";
        }
        for (const auto& sym : res.effect.symbols) {
            if (auto addr = aa.symbol(sym)) {
                std::cout << "    symbol '" << sym << "' -> " << utils::format_address(*addr) << "\n";
            }
        }
    } else {
        std::cout << "[-] AA failed: " << res.message << "\n";
    }
}

void cmd_aobscript(const std::string& where, const std::string& out_path) {
    if (!require_attached()) return;
    auto target = resolve_target(where);
    if (!target) {
        std::cout << "[!] Could not resolve target: " << where << "\n";
        return;
    }
    const std::string script = ses().generate_aob_hook_script(*target);
    if (script.empty()) {
        std::cout << "[-] Failed to generate AOB hook script for " << utils::format_address(*target) << ".\n";
        return;
    }
    std::cout << "\n" << script << "\n";
    if (!out_path.empty()) {
        std::ofstream out(out_path, std::ios::trunc);
        if (out && (out << script)) {
            std::cout << "[+] Saved generated Auto-Assembler script to: " << out_path << "\n";
        } else {
            std::cerr << "[-] Failed to write script to: " << out_path << "\n";
        }
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
    } else if (cmd == "scanxor") {
        std::string type, val, key = "auto";
        if (iss >> type >> val) {
            iss >> key;
            cmd_scan_xor(type, val, key);
        } else {
            std::cout << "Usage: scanxor <type> <val> [key_hex|auto]\n";
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
            std::getline(iss >> std::ws, value);
            cmd_table_hotkey(index, keys, action, value);
        } else {
            std::cout << "Usage: thotkey <#> <keys> toggle | set <value> | add <amount> | remove\n";
        }
    } else if (cmd == "library") {
        std::string argument;
        std::getline(iss >> std::ws, argument);
        cmd_library(argument);
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
    } else if (cmd == "tsave" || cmd == "tload" || cmd == "ctsave" || cmd == "ctload") {
        std::string path;
        if (std::getline(iss >> std::ws, path) && !path.empty()) {
            if (cmd == "tsave" || cmd == "ctsave") cmd_table_save(path);
            else cmd_table_load(path);
        } else {
            std::cout << "Usage: " << cmd << " <file" << (cmd[0] == 'c' ? ".ct" : ".json") << ">\n";
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
    } else if (cmd == "ptrmap") {
        std::string sub, a1, a2, a3, a4;
        iss >> sub >> a1 >> a2 >> a3 >> a4;
        cmd_ptrmap(sub, a1, a2, a3, a4);
    } else if (cmd == "xrefs") {
        std::string where, mod_filter;
        if (iss >> where) {
            iss >> mod_filter;
            cmd_xrefs(where, mod_filter);
        } else {
            std::cout << "Usage: xrefs <addr|#result|t#> [module]\n";
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
    } else if (cmd == "dissect") {
        std::string where;
        size_t bytes = 128;
        if (iss >> where) {
            iss >> bytes;
            cmd_dissect(where, bytes);
        } else {
            std::cout << "Usage: dissect <addr|#result|t#> [bytes]\n";
        }
    } else if (cmd == "dissectcmp") {
        std::vector<std::string> args;
        std::string tok;
        while (iss >> tok) args.push_back(std::move(tok));
        cmd_dissect_compare(args);
    } else if (cmd == "findwrites" || cmd == "findaccess") {
        std::string where;
        size_t size = 4;
        if (iss >> where) {
            iss >> size;
            cmd_find_access(where, size, cmd == "findaccess" ? debugger::WatchKind::Access : debugger::WatchKind::Write);
        } else {
            std::cout << "Usage: " << cmd << " <addr|#result|t#> [size=4]\n";
        }
    } else if (cmd == "hits") {
        cmd_hits();
    } else if (cmd == "watchstop") {
        ses().stop_watch();
        std::cout << "[*] Watch stopped.\n";
    } else if (cmd == "script") {
        std::string sub, arg1, arg2;
        iss >> sub >> arg1;
        std::getline(iss >> std::ws, arg2);
        cmd_script(sub, arg1, arg2);
    } else if (cmd == "disasm" || cmd == "u") {
        std::string where;
        size_t count = 10;
        if (iss >> where) {
            iss >> count;
            cmd_disasm(where, count);
        } else {
            std::cout << "Usage: disasm <addr|#result|t#> [count=10]\n";
        }
    } else if (cmd == "assemble" || cmd == "a") {
        std::string where, instruction;
        if (iss >> where && std::getline(iss >> std::ws, instruction) && !instruction.empty()) {
            cmd_assemble(where, instruction);
        } else {
            std::cout << "Usage: assemble <addr|#result|t#> <instruction>\n";
        }
    } else if (cmd == "strings") {
        std::string filter;
        size_t min_len = 4;
        size_t max_results = 50;
        iss >> filter >> min_len >> max_results;
        cmd_strings(filter, min_len, max_results);
    } else if (cmd == "gentrainer") {
        std::string path, proc, mode;
        if (iss >> path) {
            if (iss >> proc) {
                if (proc == "gui" || proc == "console" || proc == "linux") {
                    mode = proc;
                    proc = "";
                } else {
                    iss >> mode;
                }
            }
            table::TrainerKind kind = table::TrainerKind::Console;
            if (mode == "gui") kind = table::TrainerKind::GUI;
            else if (mode == "linux") kind = table::TrainerKind::LinuxConsole;
            cmd_gentrainer(path, proc, kind);
        } else {
            std::cout << "Usage: gentrainer <output.cpp> [process_name] [gui|console|linux]\n"
                      << "       gentrainer <output.cpp> [gui|console|linux]\n";
        }
    } else if (cmd == "speed") {
        std::string arg;
        iss >> arg;
        cmd_speed(arg);
    } else if (cmd == "sig") {
        std::string where;
        size_t max_bytes = 48;
        if (iss >> where) {
            iss >> max_bytes;
            cmd_sig(where, max_bytes);
        } else {
            std::cout << "Usage: sig <addr|#result|t#> [max_bytes=48]\n";
        }
    } else if (cmd == "coords") {
        std::string sub, a1, a2, a3, a4;
        iss >> sub >> a1 >> a2 >> a3 >> a4;
        cmd_coords(sub, a1, a2, a3, a4);
    } else if (cmd == "view") {
        std::string where;
        std::optional<size_t> before, after;
        size_t number = 0;
        iss >> where;
        if (iss >> number) before = number;
        if (iss >> number) after = number;
        cmd_view(where, before, after);
    } else if (cmd == "diff") {
        cmd_diff(iss);
    } else if (cmd == "pe") {
        cmd_pe(iss);
    } else if (cmd == "elf") {
        cmd_elf(iss);
    } else if (cmd == "engine") {
        cmd_engine();
    } else if (cmd == "unity") {
        cmd_unity(iss);
    } else if (cmd == "unreal") {
        cmd_unreal(iss);
    } else if (cmd == "cfg") {
        cmd_cfg(iss);
    } else if (cmd == "ultimap") {
        cmd_ultimap(iss);
    } else if (cmd == "hexedit") {
        std::string where, hex_str;
        if (iss >> where && std::getline(iss >> std::ws, hex_str) && !hex_str.empty()) {
            cmd_hexedit(where, hex_str);
        } else {
            std::cout << "Usage: hexedit <addr|#result|t#> <hex_bytes...>\n";
        }
    } else if (cmd == "bp") {
        std::string addr_str, rest;
        if (iss >> addr_str) {
            std::getline(iss >> std::ws, rest);
            cmd_bp(addr_str, rest, false);
        } else {
            std::cout << "Usage: bp <addr> [if <condition> | note]\n";
        }
    } else if (cmd == "tracebp") {
        std::string addr_str, rest;
        if (iss >> addr_str) {
            std::getline(iss >> std::ws, rest);
            cmd_bp(addr_str, rest, true);
        } else {
            std::cout << "Usage: tracebp <addr> [if <condition> | note]\n";
        }
    } else if (cmd == "tracelog") {
        std::string arg;
        iss >> arg;
        cmd_tracelog(arg);
    } else if (cmd == "dbgattach") {
        if (!require_attached()) return true;
        std::string mode;
        iss >> mode;
        auto backend = (mode == "veh") ? debugger::DebugBackend::VEH : debugger::DebugBackend::Win32DebugAPI;
        if (ses().dbg_attach(backend)) {
            std::cout << "[+] Debugger attached (" << (mode == "veh" ? "VEH In-Process" : "Win32 DebugAPI") << ").\n";
        } else {
            std::cerr << "[-] Failed to attach debugger: " << ses().step_debugger()->last_error() << "\n";
        }
    } else if (cmd == "dbgdetach") {
        ses().dbg_detach();
        std::cout << "[+] Debugger detached.\n";
    } else if (cmd == "threads") {
        if (!require_attached()) return true;
        auto threads = ses().list_threads();
        std::cout << "[*] Active threads (" << threads.size() << "):\n";
        for (const auto& t : threads) {
            std::cout << "  TID: " << std::setw(8) << t.tid << "  Priority: " << t.base_priority << "\n";
        }
    } else if (cmd == "inject") {
        if (!require_attached()) return true;
        std::string dll_path;
        std::getline(iss >> std::ws, dll_path);
        if (dll_path.empty()) {
            std::cout << "Usage: inject <path/to/module.dll>\n";
        } else {
            std::string err;
            if (ses().inject_dll(dll_path, err)) {
                std::cout << "[+] Injected DLL: " << dll_path << "\n";
            } else {
                std::cerr << "[-] Injection failed: " << err << "\n";
            }
        }
    } else if (cmd == "delbp") {
        std::string addr_str;
        if (iss >> addr_str) cmd_delbp(addr_str);
        else std::cout << "Usage: delbp <addr>\n";
    } else if (cmd == "bplist") {
        cmd_bplist();
    } else if (cmd == "step" || cmd == "si") {
        if (!require_attached()) return true;
        if (ses().dbg_step_into()) {
            std::cout << "[+] Stepped 1 instruction.\n";
        } else {
            std::cout << "[-] Debugger is not paused. Hit a breakpoint first or run 'pause'.\n";
        }
    } else if (cmd == "stepover" || cmd == "so") {
        if (!require_attached()) return true;
        if (ses().dbg_step_over()) {
            std::cout << "[+] Stepped over.\n";
        } else {
            std::cout << "[-] Debugger is not paused.\n";
        }
    } else if (cmd == "stepout") {
        if (!require_attached()) return true;
        if (ses().dbg_step_out()) {
            std::cout << "[+] Stepping out to caller...\n";
        } else {
            std::cout << "[-] Debugger is not paused.\n";
        }
    } else if (cmd == "cont" || cmd == "resume") {
        if (!require_attached()) return true;
        if (ses().dbg_resume()) {
            std::cout << "[+] Resumed execution.\n";
        } else {
            std::cout << "[-] Target is already running.\n";
        }
    } else if (cmd == "pause") {
        if (!require_attached()) return true;
        if (ses().dbg_pause()) {
            std::cout << "[+] Target paused at RIP: " << utils::format_address(ses().step_debugger()->current_rip()) << "\n";
        } else {
            std::cout << "[-] Failed to pause target.\n";
        }
    } else if (cmd == "callstack") {
        cmd_callstack();
    } else if (cmd == "lua") {
        std::string code;
        std::getline(iss >> std::ws, code);
        if (!code.empty()) {
            auto res = ses().run_lua(code);
            if (!res.output.empty()) std::cout << res.output;
            if (!res.success) std::cout << "[-] Lua Error: " << res.error << "\n";
        } else {
            std::cout << "Usage: lua <code...>\n"
                      << "Example: lua print('Health:', readInteger(0x140001000))\n";
        }
    } else if (cmd == "runlua") {
        std::string filepath;
        if (iss >> filepath) {
            auto res = ses().run_lua_file(filepath);
            if (!res.output.empty()) std::cout << res.output;
            if (!res.success) std::cout << "[-] Lua Error: " << res.error << "\n";
        } else {
            std::cout << "Usage: runlua <filepath.lua>\n";
        }
    } else if (cmd == "aobscan") {
        std::string pattern;
        std::getline(iss >> std::ws, pattern);
        if (!pattern.empty()) cmd_aobscan_impl(pattern, std::nullopt);
        else std::cout << "Usage: aobscan <pattern...> (e.g. aobscan 48 8B ? 89)\n";
    } else if (cmd == "aobscanm") {
        std::string mod, pattern;
        if (iss >> mod && std::getline(iss >> std::ws, pattern) && !pattern.empty()) {
            cmd_aobscan_impl(pattern, mod);
        } else {
            std::cout << "Usage: aobscanm <module> <pattern...>\n";
        }
    } else if (cmd == "aa") {
        std::string path;
        if (iss >> path) cmd_aa_file(path);
        else std::cout << "Usage: aa <script_file.cea>\n";
    } else if (cmd == "aobscript") {
        std::string where, out_path;
        if (iss >> where) {
            iss >> out_path;
            cmd_aobscript(where, out_path);
        } else {
            std::cout << "Usage: aobscript <addr|#result|t#> [out_file.cea]\n";
        }
    } else if (cmd == "hook") {
        if (!require_attached()) return true;
        std::string addr_str, hex_rest;
        if (iss >> addr_str && std::getline(iss >> std::ws, hex_rest) && !hex_rest.empty()) {
            auto target = parse_address_arg(addr_str);
            std::vector<uint8_t> payload;
            if (target && parse_hex_bytes_text(hex_rest, payload)) {
                if (auto info = ses().hook_payload(*target, payload)) {
                    std::cout << "[+] Hook installed at " << utils::format_address(info->target_address)
                              << " -> cave " << utils::format_address(info->cave_address)
                              << " (stolen " << info->stolen_bytes_count << " bytes)\n";
                } else {
                    std::cout << "[-] Failed to install payload hook.\n";
                }
            } else {
                std::cout << "[-] Invalid address or hex payload.\n";
            }
        } else {
            std::cout << "Usage: hook <addr> <hex bytes...>\n";
        }
    } else if (cmd == "detour") {
        if (!require_attached()) return true;
        std::string target_str, dest_str;
        if (iss >> target_str >> dest_str) {
            auto target = parse_address_arg(target_str);
            auto dest = parse_address_arg(dest_str);
            if (target && dest) {
                if (auto info = ses().hook_detour(*target, *dest)) {
                    std::cout << "[+] Detour installed: " << utils::format_address(info->target_address)
                              << " -> " << utils::format_address(info->destination_address)
                              << " (trampoline " << utils::format_address(info->trampoline_address)
                              << ", stolen " << info->stolen_bytes_count << " bytes)\n";
                } else {
                    std::cout << "[-] Failed to install detour.\n";
                }
            }
        } else {
            std::cout << "Usage: detour <target_addr> <dest_addr>\n";
        }
    } else if (cmd == "unhook") {
        if (!require_attached()) return true;
        std::string arg;
        if (!(iss >> arg)) {
            std::cout << "Usage: unhook <addr|all>\n";
        } else if (arg == "all") {
            ses().unhook_all();
            std::cout << "[+] Removed all active hooks.\n";
        } else if (auto target = parse_address_arg(arg)) {
            std::cout << (ses().unhook(*target) ? "[+] Hook removed.\n" : "[-] No active hook at address.\n");
        }
    } else if (cmd == "hooks") {
        if (!require_attached()) return true;
        const auto list = ses().active_hooks();
        if (list.empty()) {
            std::cout << "[*] No active HookEngine hooks.\n";
        } else {
            for (size_t i = 0; i < list.size(); ++i) {
                std::cout << "  [" << i << "] target=" << utils::format_address(list[i].target_address)
                          << " dest=" << utils::format_address(list[i].destination_address)
                          << " cave=" << utils::format_address(list[i].cave_address)
                          << " tramp=" << utils::format_address(list[i].trampoline_address)
                          << " stolen=" << list[i].stolen_bytes_count << "\n";
            }
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

    // Hotkeys fire while the game is in front: say what they did, and beep (the console may be hidden)
    // Each program's table opens by itself on attach and is saved while it changes
    ses().table().set_library(session::default_library_folder());

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
