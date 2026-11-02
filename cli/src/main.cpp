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

#include "hal/process.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "scanner/grouped_scanner.hpp"
#include "utils/hex_utils.hpp"

using namespace nce;

static std::shared_ptr<hal::IProcess> g_process;
static std::unique_ptr<scanner::MemoryScanner> g_scanner;
static scanner::ScanResults g_results;
static scanner::DataType g_current_type = scanner::DataType::Int32;

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

void freeze_worker() {
    while (g_freeze_running) {
        {
            std::lock_guard<std::mutex> lock(g_freeze_mutex);
            if (g_process && g_process->is_attached()) {
                for (const auto& entry : g_frozen_list) {
                    if (!entry.active) continue;
                    switch (entry.type) {
                        case scanner::DataType::Int8:   g_process->write(entry.address, std::get<int8_t>(entry.value.value)); break;
                        case scanner::DataType::Int16:  g_process->write(entry.address, std::get<int16_t>(entry.value.value)); break;
                        case scanner::DataType::Int32:  g_process->write(entry.address, std::get<int32_t>(entry.value.value)); break;
                        case scanner::DataType::Int64:  g_process->write(entry.address, std::get<int64_t>(entry.value.value)); break;
                        case scanner::DataType::Float:  g_process->write(entry.address, std::get<float>(entry.value.value)); break;
                        case scanner::DataType::Double: g_process->write(entry.address, std::get<double>(entry.value.value)); break;
                        default: break;
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
              << "  scan <type> <value>             - First scan (types: i8, i16, i32, i64, f32, f64, aob)\n"
              << "                                    Examples: 'scan i32 1337', 'scan aob 48 8B ? ? 89'\n"
              << "  next <cond> [val]               - Next scan (cond: exact, changed, unchanged, inc, dec)\n"
              << "  group <type1> <val1> ...        - Grouped scan: find multiple values in same struct\n"
              << "                                    Example: 'group i32 100 i32 50 f32 25.5'\n"
              << "  ptrscan <addr> [depth] [offset] - Pointer Scanner: find static base pointer paths\n"
              << "                                    Example: 'ptrscan 0x12345678 4 0x800'\n"
              << "  list [count]                    - Display up to [count] scan results (default: 20)\n\n"
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

scanner::DataType parse_type(const std::string& type_str) {
    if (type_str == "i8") return scanner::DataType::Int8;
    if (type_str == "i16") return scanner::DataType::Int16;
    if (type_str == "i32" || type_str == "int") return scanner::DataType::Int32;
    if (type_str == "i64") return scanner::DataType::Int64;
    if (type_str == "f32" || type_str == "float") return scanner::DataType::Float;
    if (type_str == "f64" || type_str == "double") return scanner::DataType::Double;
    if (type_str == "aob") return scanner::DataType::AOB;
    return scanner::DataType::Int32;
}

scanner::ScanValue parse_value(scanner::DataType type, const std::string& val_str) {
    scanner::ScanValue sv;
    sv.type = type;
    try {
        switch (type) {
            case scanner::DataType::Int8:   sv.value = static_cast<int8_t>(std::stoi(val_str)); break;
            case scanner::DataType::Int16:  sv.value = static_cast<int16_t>(std::stoi(val_str)); break;
            case scanner::DataType::Int32:  sv.value = std::stoi(val_str); break;
            case scanner::DataType::Int64:  sv.value = std::stoll(val_str); break;
            case scanner::DataType::Float:  sv.value = std::stof(val_str); break;
            case scanner::DataType::Double: sv.value = std::stod(val_str); break;
            default: break;
        }
    } catch (...) {
        std::cerr << "[!] Error parsing value: " << val_str << "\n";
    }
    return sv;
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
    if (!g_process) {
        g_process = hal::IProcess::create();
    }
    if (g_process->attach(pid)) {
        g_scanner = std::make_unique<scanner::MemoryScanner>(g_process);
        g_results.clear();
        std::cout << "[+] Successfully attached to PID: " << pid << "\n";
    } else {
        std::cerr << "[-] Failed to attach to PID: " << pid << ". Run as Administrator or check PID.\n";
    }
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

void cmd_first_scan(const std::string& type_str, const std::string& val_str, const std::string& full_line) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Please attach to a process first using 'attach <pid>'.\n";
        return;
    }

    g_current_type = parse_type(type_str);
    size_t alignment = (g_current_type == scanner::DataType::AOB) ? 1 : scanner::get_data_type_size(g_current_type);

    std::cout << "[*] Starting First Scan for type [" << type_str << "] ...\n";

    if (g_current_type == scanner::DataType::AOB) {
        size_t pos = full_line.find("aob");
        std::string pattern = (pos != std::string::npos) ? full_line.substr(pos + 3) : val_str;
        g_results = g_scanner->first_scan_aob(pattern, alignment);
    } else {
        auto val = parse_value(g_current_type, val_str);
        g_results = g_scanner->first_scan(g_current_type, scanner::ScanCondition::ExactValue, val, {}, alignment);
    }

    std::cout << "[+] First Scan complete. Found " << g_results.count() << " match(es).\n";
}

void cmd_next_scan(const std::string& cond_str, const std::string& val_str) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }
    if (g_results.empty()) {
        std::cerr << "[-] No active scan results. Run 'scan <type> <value>' first.\n";
        return;
    }

    scanner::ScanCondition cond = scanner::ScanCondition::ExactValue;
    if (cond_str == "exact") cond = scanner::ScanCondition::ExactValue;
    else if (cond_str == "changed") cond = scanner::ScanCondition::Changed;
    else if (cond_str == "unchanged") cond = scanner::ScanCondition::Unchanged;
    else if (cond_str == "inc") cond = scanner::ScanCondition::Increased;
    else if (cond_str == "dec") cond = scanner::ScanCondition::Decreased;
    else {
        std::cerr << "[!] Unknown condition: " << cond_str << ". Use exact/changed/unchanged/inc/dec.\n";
        return;
    }

    scanner::ScanValue val;
    if (cond == scanner::ScanCondition::ExactValue) {
        val = parse_value(g_current_type, val_str);
    }

    std::cout << "[*] Filtering " << g_results.count() << " results ...\n";
    g_results = g_scanner->next_scan(g_results, cond, val);
    std::cout << "[+] Next Scan complete. " << g_results.count() << " match(es) remaining.\n";
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
        auto type = parse_type(tokens[i]);
        auto val = parse_value(type, tokens[i + 1]);
        entries.push_back({type, val, 0, false});
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

void cmd_pointer_scan(const std::string& addr_str, size_t max_depth = 4, size_t max_offset = 0x800) {
    if (!g_process || !g_process->is_attached()) {
        std::cerr << "[-] Not attached to any process.\n";
        return;
    }

    uintptr_t target_addr = utils::parse_address(addr_str);
    if (target_addr == 0) {
        std::cerr << "[-] Invalid address: " << addr_str << "\n";
        return;
    }

    std::cout << "[*] Starting Pointer Scanner for " << utils::format_address(target_addr) 
              << " (Max Depth: " << max_depth << ", Max Offset: 0x" << std::hex << max_offset << std::dec << ") ...\n";

    scanner::PointerScanner ptr_scanner(g_process);
    auto paths = ptr_scanner.scan(target_addr, max_depth, max_offset, 100, [](size_t depth, size_t count) {
        std::cout << "  -> Depth " << depth << " explored: " << count << " static path(s) found.\n";
    });

    std::cout << "\n[+] Pointer Scan complete. Total valid static paths found: " << paths.size() << "\n";
    for (size_t i = 0; i < std::min(size_t(20), paths.size()); ++i) {
        std::cout << "  [" << std::setw(2) << i << "] " << paths[i].to_string() << "\n";
    }
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

    auto type = parse_type(type_str);
    auto val = parse_value(type, val_str);

    {
        std::lock_guard<std::mutex> lock(g_freeze_mutex);
        g_frozen_list.push_back({addr, type, val, true});
    }

    std::cout << "[+] Frozen " << utils::format_address(addr) << " to value [" << val.to_string() << "].\n";
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
        std::cout << " [" << std::setw(3) << i << "]  "
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
    if (g_results.empty()) {
        std::cout << "[-] No results found.\n";
        return;
    }

    size_t count = std::min(max_count, g_results.count());
    std::cout << "\n Index   Address              Current Value     Previous Value\n";
    std::cout << "------------------------------------------------------------------\n";
    for (size_t i = 0; i < count; ++i) {
        const auto& m = g_results[i];
        std::cout << " [" << std::setw(3) << i << "]  " 
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

    auto type = parse_type(type_str);
    auto val = parse_value(type, val_str);

    bool success = false;
    switch (type) {
        case scanner::DataType::Int8:   success = g_process->write(addr, std::get<int8_t>(val.value)); break;
        case scanner::DataType::Int16:  success = g_process->write(addr, std::get<int16_t>(val.value)); break;
        case scanner::DataType::Int32:  success = g_process->write(addr, std::get<int32_t>(val.value)); break;
        case scanner::DataType::Int64:  success = g_process->write(addr, std::get<int64_t>(val.value)); break;
        case scanner::DataType::Float:  success = g_process->write(addr, std::get<float>(val.value)); break;
        case scanner::DataType::Double: success = g_process->write(addr, std::get<double>(val.value)); break;
        default: break;
    }

    if (success) {
        std::cout << "[+] Successfully wrote value [" << val.to_string() << "] to " 
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

    auto type = parse_type(type_str);
    std::cout << "Address: " << utils::format_address(addr) << " = ";

    switch (type) {
        case scanner::DataType::Int8: {
            int8_t v = 0;
            if (g_process->read(addr, v)) std::cout << static_cast<int>(v) << "\n";
            else std::cout << "?? (Read failed)\n";
            break;
        }
        case scanner::DataType::Int16: {
            int16_t v = 0;
            if (g_process->read(addr, v)) std::cout << v << "\n";
            else std::cout << "?? (Read failed)\n";
            break;
        }
        case scanner::DataType::Int32: {
            int32_t v = 0;
            if (g_process->read(addr, v)) std::cout << v << "\n";
            else std::cout << "?? (Read failed)\n";
            break;
        }
        case scanner::DataType::Int64: {
            int64_t v = 0;
            if (g_process->read(addr, v)) std::cout << v << "\n";
            else std::cout << "?? (Read failed)\n";
            break;
        }
        case scanner::DataType::Float: {
            float v = 0.0f;
            if (g_process->read(addr, v)) std::cout << v << "\n";
            else std::cout << "?? (Read failed)\n";
            break;
        }
        case scanner::DataType::Double: {
            double v = 0.0;
            if (g_process->read(addr, v)) std::cout << v << "\n";
            else std::cout << "?? (Read failed)\n";
            break;
        }
        default:
            std::cout << "Unsupported read type.\n";
            break;
    }
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

    std::vector<uint8_t> buffer(size);
    if (g_process->read_raw(addr, buffer.data(), size)) {
        std::cout << "\n" << utils::format_hex_dump(addr, buffer.data(), size) << "\n";
    } else {
        std::cerr << "[-] Failed to read " << size << " bytes from " << utils::format_address(addr) << "\n";
    }
}

int main() {
    print_banner();
    print_help();

    // Start background thread for continuous value freezing
    g_freeze_thread = std::thread(freeze_worker);

    std::string line;
    while (true) {
        if (g_process && g_process->is_attached()) {
            std::cout << "[NCE PID:" << g_process->get_pid() << " (" << g_results.count() << " matches)] > ";
        } else {
            std::cout << "[NCE (Detached)] > ";
        }

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit" || cmd == "exit") {
            break;
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
            if (g_process) g_process->detach();
            g_results.clear();
            std::cout << "[*] Detached.\n";
        } else if (cmd == "modules") {
            cmd_modules();
        } else if (cmd == "regions") {
            cmd_regions();
        } else if (cmd == "scan") {
            std::string type, val;
            if (iss >> type >> val) {
                cmd_first_scan(type, val, line);
            } else {
                std::cout << "Usage: scan <type> <value>\n";
            }
        } else if (cmd == "next") {
            std::string cond, val;
            if (iss >> cond) {
                iss >> val;
                cmd_next_scan(cond, val);
            } else {
                std::cout << "Usage: next <exact/changed/unchanged/inc/dec> [value]\n";
            }
        } else if (cmd == "group") {
            std::vector<std::string> tokens;
            std::string t;
            while (iss >> t) tokens.push_back(t);
            cmd_grouped_scan(tokens);
        } else if (cmd == "ptrscan") {
            std::string addr_str;
            size_t depth = 4, offset = 0x800;
            if (iss >> addr_str) {
                iss >> depth >> std::hex >> offset;
                cmd_pointer_scan(addr_str, depth, offset);
            } else {
                std::cout << "Usage: ptrscan <addr> [max_depth=4] [max_offset=0x800]\n";
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
