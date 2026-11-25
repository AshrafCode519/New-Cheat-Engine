#include "table/standalone_generator.hpp"
#include <fstream>
#include <sstream>

#ifndef VK_NUMPAD0
#define VK_NUMPAD0 0x60
#endif
#ifndef VK_F1
#define VK_F1 0x70
#endif

namespace nce::table {

namespace {

void append_common_helpers(std::ostringstream& ss, const std::string& proc, const CheatTable& table);

void append_init_items(std::ostringstream& ss, const CheatTable& table) {
    ss << "void InitItems() {\n";
    int hotkey_idx = 1;
    for (size_t i = 0; i < table.entries.size(); ++i) {
        const auto& e = table.entries[i];
        int vk = (hotkey_idx <= 9) ? (VK_NUMPAD0 + hotkey_idx) : (VK_F1 + (hotkey_idx - 10));
        std::string vk_name = (hotkey_idx <= 9) ? ("NUMPAD " + std::to_string(hotkey_idx)) : ("F" + std::to_string(hotkey_idx - 9));
        hotkey_idx++;

        int type_id = 0;
        if (e.type == scanner::DataType::Int64 || e.type == scanner::DataType::UInt64) type_id = 1;
        else if (e.type == scanner::DataType::Float) type_id = 2;
        else if (e.type == scanner::DataType::Double) type_id = 3;
        else if (e.type == scanner::DataType::Int16 || e.type == scanner::DataType::UInt16) type_id = 4;
        else if (e.type == scanner::DataType::Int8 || e.type == scanner::DataType::UInt8) type_id = 5;

        int64_t parsed_int = 99999;
        double parsed_flt = 9999.0;
        if (e.frozen_value && !e.frozen_value->empty()) {
            try {
                if (type_id == 2 || type_id == 3) parsed_flt = std::stod(*e.frozen_value);
                else parsed_int = std::stoll(*e.frozen_value, nullptr, 0);
            } catch (...) {}
        }

        ss << "    {\n";
        ss << "        TrainerItem item;\n";
        ss << "        item.description = \"" << (e.description.empty() ? ("Item_" + std::to_string(i)) : e.description) << "\";\n";
        ss << "        item.moduleName = \"" << e.location.module_name << "\";\n";
        ss << "        item.baseOffset = 0x" << std::hex << e.location.base_offset << std::dec << ";\n";
        if (!e.location.offsets.empty()) {
            ss << "        item.offsets = {";
            for (size_t k = 0; k < e.location.offsets.size(); ++k) {
                ss << "0x" << std::hex << e.location.offsets[k] << std::dec << (k + 1 < e.location.offsets.size() ? ", " : "");
            }
            ss << "};\n";
        }
        ss << "        item.typeId = " << type_id << ";\n";
        ss << "        item.hotkeyVk = " << vk << ";\n";
        ss << "        item.hotkeyText = \"" << vk_name << "\";\n";
        ss << "        item.freezeValI32 = static_cast<int32_t>(" << parsed_int << "LL);\n";
        ss << "        item.freezeValI64 = static_cast<int64_t>(" << parsed_int << "LL);\n";
        ss << "        item.freezeValFloat = static_cast<float>(" << parsed_flt << ");\n";
        ss << "        item.freezeValDouble = static_cast<double>(" << parsed_flt << ");\n";
        ss << "        item.freezeValI16 = static_cast<int16_t>(" << (parsed_int > 32767 ? 9999 : parsed_int) << ");\n";
        ss << "        item.freezeValI8 = static_cast<int8_t>(" << (parsed_int > 127 ? 99 : parsed_int) << ");\n";
        ss << "        g_items.push_back(std::move(item));\n";
        ss << "    }\n";
    }
    ss << "}\n\n";
}

void append_common_helpers(std::ostringstream& ss, const std::string& proc, const CheatTable& table) {
    ss << "namespace {\n\n";
    ss << "const char* kTargetProcess = \"" << proc << "\";\n\n";

    ss << R"(DWORD FindProcessId(const std::string& processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32First(snapshot, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

uintptr_t GetModuleBase(DWORD pid, const std::string& moduleName) {
    MODULEENTRY32 entry;
    entry.dwSize = sizeof(MODULEENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    uintptr_t base = 0;
    if (Module32First(snapshot, &entry)) {
        do {
            if (moduleName == entry.szModule) {
                base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return base;
}

uintptr_t ResolveAddress(HANDLE hProcess, DWORD pid, const std::string& modName, uintptr_t baseOffset, const std::vector<int64_t>& offsets) {
    uintptr_t current = 0;
    if (!modName.empty()) {
        uintptr_t modBase = GetModuleBase(pid, modName);
        if (modBase == 0) return 0;
        current = modBase + baseOffset;
    } else {
        current = baseOffset;
    }

    for (int64_t off : offsets) {
        uintptr_t nextPtr = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current), &nextPtr, sizeof(nextPtr), &read) || read == 0) {
            return 0;
        }
        current = nextPtr + static_cast<uintptr_t>(off);
    }
    return current;
}

struct TrainerItem {
    std::string description;
    std::string moduleName;
    uintptr_t baseOffset;
    std::vector<int64_t> offsets;
    int typeId; // 0=int32, 1=int64, 2=float, 3=double, 4=int16, 5=int8
    int hotkeyVk;
    const char* hotkeyText;
    std::atomic<bool> enabled{false};
    int32_t freezeValI32{99999};
    int64_t freezeValI64{99999};
    float freezeValFloat{9999.0f};
    double freezeValDouble{9999.0};
    int16_t freezeValI16{9999};
    int8_t freezeValI8{99};
};

std::vector<TrainerItem> g_items;
HANDLE g_hProcess = NULL;
DWORD g_pid = 0;
std::atomic<bool> g_running{true};

)";

    append_init_items(ss, table);

    ss << R"(void FreezeWorker() {
    while (g_running) {
        if (g_hProcess != NULL) {
            for (auto& it : g_items) {
                if (it.enabled) {
                    uintptr_t targetAddr = ResolveAddress(g_hProcess, g_pid, it.moduleName, it.baseOffset, it.offsets);
                    if (targetAddr != 0) {
                        SIZE_T written = 0;
                        if (it.typeId == 0) {
                            WriteProcessMemory(g_hProcess, reinterpret_cast<LPVOID>(targetAddr), &it.freezeValI32, sizeof(int32_t), &written);
                        } else if (it.typeId == 1) {
                            WriteProcessMemory(g_hProcess, reinterpret_cast<LPVOID>(targetAddr), &it.freezeValI64, sizeof(int64_t), &written);
                        } else if (it.typeId == 2) {
                            WriteProcessMemory(g_hProcess, reinterpret_cast<LPVOID>(targetAddr), &it.freezeValFloat, sizeof(float), &written);
                        } else if (it.typeId == 3) {
                            WriteProcessMemory(g_hProcess, reinterpret_cast<LPVOID>(targetAddr), &it.freezeValDouble, sizeof(double), &written);
                        } else if (it.typeId == 4) {
                            WriteProcessMemory(g_hProcess, reinterpret_cast<LPVOID>(targetAddr), &it.freezeValI16, sizeof(int16_t), &written);
                        } else if (it.typeId == 5) {
                            WriteProcessMemory(g_hProcess, reinterpret_cast<LPVOID>(targetAddr), &it.freezeValI8, sizeof(int8_t), &written);
                        }
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}
)";

    ss << "} // anonymous namespace\n\n";
}

} // anonymous namespace

std::string generate_standalone_trainer_cpp(
    const CheatTable& table,
    const std::string& target_process_name,
    TrainerKind kind
) {
    std::string proc = target_process_name.empty() ? table.process_name : target_process_name;
    if (proc.empty()) proc = "game.exe";

    std::ostringstream ss;
    ss << "// =======================================================================\n";
    ss << "// Standalone Trainer Generated by New-Cheat-Engine (NCE)\n";
    ss << "// Target Process: " << proc << "\n";
    if (kind == TrainerKind::LinuxConsole) {
        ss << "// Type: Standalone Linux / Steam Deck Console Trainer (process_vm_writev)\n";
        ss << "// Compile with: g++ -O2 -pthread trainer.cpp -o trainer_linux\n";
        ss << "// =======================================================================\n\n";
        ss << "#include <atomic>\n#include <chrono>\n#include <cstdint>\n#include <cstdlib>\n"
           << "#include <cstring>\n#include <dirent.h>\n#include <fstream>\n#include <iostream>\n"
           << "#include <sstream>\n#include <string>\n#include <sys/uio.h>\n#include <thread>\n#include <vector>\n\n";
        ss << "namespace {\nconst char* kTargetProcess = \"" << proc << "\";\n\n";
        ss << R"LINUX_TR(struct TrainerItem {
    std::string description;
    std::string moduleName;
    uintptr_t baseOffset{0};
    std::vector<int64_t> offsets;
    int typeId{0};
    int hotkeyVk{0};
    const char* hotkeyText{""};
    std::atomic<bool> enabled{false};
    int32_t freezeValI32{99999};
    int64_t freezeValI64{99999};
    float freezeValFloat{9999.0f};
    double freezeValDouble{9999.0};
    int16_t freezeValI16{9999};
    int8_t freezeValI8{99};
};

std::vector<TrainerItem> g_items;
pid_t g_pid = 0;
std::atomic<bool> g_running{true};

pid_t FindLinuxPid(const std::string& name) {
    DIR* dir = opendir("/proc");
    if (!dir) return 0;
    struct dirent* ent = nullptr;
    pid_t found = 0;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t p = static_cast<pid_t>(std::strtol(ent->d_name, nullptr, 10));
        std::ifstream f(std::string("/proc/") + ent->d_name + "/comm");
        std::string comm;
        if (f.is_open() && std::getline(f, comm) && comm == name) { found = p; break; }
    }
    closedir(dir);
    return found;
}

uintptr_t GetLinuxModuleBase(pid_t pid, const std::string& mod) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(f, line)) {
        if (mod.empty() || line.find(mod) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                return static_cast<uintptr_t>(std::strtoull(line.substr(0, dash).c_str(), nullptr, 16));
            }
        }
    }
    return 0;
}

bool ReadProc(pid_t pid, uintptr_t addr, void* out, size_t sz) {
    struct iovec l{out, sz}, r{reinterpret_cast<void*>(addr), sz};
    return process_vm_readv(pid, &l, 1, &r, 1, 0) == static_cast<ssize_t>(sz);
}

bool WriteProc(pid_t pid, uintptr_t addr, const void* src, size_t sz) {
    struct iovec l{const_cast<void*>(src), sz}, r{reinterpret_cast<void*>(addr), sz};
    return process_vm_writev(pid, &l, 1, &r, 1, 0) == static_cast<ssize_t>(sz);
}

uintptr_t ResolveAddress(pid_t pid, const std::string& mod, uintptr_t baseOff, const std::vector<int64_t>& offs) {
    uintptr_t cur = mod.empty() ? baseOff : (GetLinuxModuleBase(pid, mod) + baseOff);
    if (cur == 0) return 0;
    for (int64_t o : offs) {
        uintptr_t nxt = 0;
        if (!ReadProc(pid, cur, &nxt, sizeof(nxt)) || nxt == 0) return 0;
        cur = nxt + static_cast<uintptr_t>(o);
    }
    return cur;
}
)LINUX_TR";
        append_init_items(ss, table);
        ss << R"LINUX_MAIN(void FreezeWorker() {
    while (g_running) {
        if (g_pid > 0) {
            for (auto& it : g_items) {
                if (!it.enabled) continue;
                uintptr_t a = ResolveAddress(g_pid, it.moduleName, it.baseOffset, it.offsets);
                if (!a) continue;
                if (it.typeId == 0) WriteProc(g_pid, a, &it.freezeValI32, 4);
                else if (it.typeId == 1) WriteProc(g_pid, a, &it.freezeValI64, 8);
                else if (it.typeId == 2) WriteProc(g_pid, a, &it.freezeValFloat, 4);
                else if (it.typeId == 3) WriteProc(g_pid, a, &it.freezeValDouble, 8);
                else if (it.typeId == 4) WriteProc(g_pid, a, &it.freezeValI16, 2);
                else if (it.typeId == 5) WriteProc(g_pid, a, &it.freezeValI8, 1);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}
} // namespace

int main() {
    InitItems();
    std::cout << "[*] Waiting for Linux process: " << kTargetProcess << " ...\n";
    while (g_pid == 0) {
        g_pid = FindLinuxPid(kTargetProcess);
        if (g_pid == 0) std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    std::cout << "[+] Attached PID " << g_pid << ". Type item index (0.." << g_items.size() << ") to toggle, or 'q' to quit.\n";
    for (size_t i = 0; i < g_items.size(); ++i) {
        std::cout << "  [" << i << "] " << g_items[i].description << "\n";
    }
    std::thread fw(FreezeWorker);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "q" || line == "quit") break;
        try {
            size_t idx = std::stoul(line);
            if (idx < g_items.size()) {
                g_items[idx].enabled = !g_items[idx].enabled;
                std::cout << "[*] " << g_items[idx].description << ": " << (g_items[idx].enabled ? "ON" : "OFF") << "\n";
            }
        } catch (...) {}
    }
    g_running = false;
    fw.join();
    return 0;
}
)LINUX_MAIN";
        return ss.str();
    }

    if (kind == TrainerKind::GUI) {
        ss << "// Type: Native Win32 GUI Trainer (Zero Dependencies)\n";
        ss << "// Compile with: g++ -O2 -mwindows trainer.cpp -o trainer.exe\n";
    } else {
        ss << "// Type: Interactive Console Trainer\n";
        ss << "// Compile with: g++ -O2 -mconsole trainer.cpp -o trainer.exe\n";
    }
    ss << "// =======================================================================\n\n";

    ss << "#define WIN32_LEAN_AND_MEAN\n";
    ss << "#include <windows.h>\n";
    ss << "#include <tlhelp32.h>\n";
    if (kind == TrainerKind::Console) {
        ss << "#include <iostream>\n";
        ss << "#include <iomanip>\n";
    }
    ss << "#include <vector>\n";
    ss << "#include <string>\n";
    ss << "#include <cstdint>\n";
    ss << "#include <thread>\n";
    ss << "#include <atomic>\n";
    ss << "#include <chrono>\n\n";

    append_common_helpers(ss, proc, table);

    if (kind == TrainerKind::LinuxConsole) {
        ss << "// Type: Standalone Linux / Steam Deck Console Trainer (process_vm_writev)\n";
        ss << "// Compile with: g++ -O2 -pthread trainer.cpp -o trainer_linux\n";
        ss << "// =======================================================================\n\n";
        ss << "#include <atomic>\n#include <chrono>\n#include <cstdint>\n#include <cstdlib>\n"
           << "#include <cstring>\n#include <dirent.h>\n#include <fstream>\n#include <iostream>\n"
           << "#include <sstream>\n#include <string>\n#include <sys/uio.h>\n#include <thread>\n#include <vector>\n\n";
        ss << "namespace {\nconst char* kTargetProcess = \"" << proc << "\";\n\n";
        ss << R"LINUX_TR(struct TrainerItem {
    std::string description;
    std::string moduleName;
    uintptr_t baseOffset{0};
    std::vector<int64_t> offsets;
    int typeId{0};
    int hotkeyVk{0};
    const char* hotkeyText{""};
    std::atomic<bool> enabled{false};
    int32_t freezeValI32{99999};
    int64_t freezeValI64{99999};
    float freezeValFloat{9999.0f};
    double freezeValDouble{9999.0};
    int16_t freezeValI16{9999};
    int8_t freezeValI8{99};
};

std::vector<TrainerItem> g_items;
pid_t g_pid = 0;
std::atomic<bool> g_running{true};

pid_t FindLinuxPid(const std::string& name) {
    DIR* dir = opendir("/proc");
    if (!dir) return 0;
    struct dirent* ent = nullptr;
    pid_t found = 0;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t p = static_cast<pid_t>(std::strtol(ent->d_name, nullptr, 10));
        std::ifstream f(std::string("/proc/") + ent->d_name + "/comm");
        std::string comm;
        if (f.is_open() && std::getline(f, comm) && comm == name) { found = p; break; }
    }
    closedir(dir);
    return found;
}

uintptr_t GetLinuxModuleBase(pid_t pid, const std::string& mod) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(f, line)) {
        if (mod.empty() || line.find(mod) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                return static_cast<uintptr_t>(std::strtoull(line.substr(0, dash).c_str(), nullptr, 16));
            }
        }
    }
    return 0;
}

bool ReadProc(pid_t pid, uintptr_t addr, void* out, size_t sz) {
    struct iovec l{out, sz}, r{reinterpret_cast<void*>(addr), sz};
    return process_vm_readv(pid, &l, 1, &r, 1, 0) == static_cast<ssize_t>(sz);
}

bool WriteProc(pid_t pid, uintptr_t addr, const void* src, size_t sz) {
    struct iovec l{const_cast<void*>(src), sz}, r{reinterpret_cast<void*>(addr), sz};
    return process_vm_writev(pid, &l, 1, &r, 1, 0) == static_cast<ssize_t>(sz);
}

uintptr_t ResolveAddress(pid_t pid, const std::string& mod, uintptr_t baseOff, const std::vector<int64_t>& offs) {
    uintptr_t cur = mod.empty() ? baseOff : (GetLinuxModuleBase(pid, mod) + baseOff);
    if (cur == 0) return 0;
    for (int64_t o : offs) {
        uintptr_t nxt = 0;
        if (!ReadProc(pid, cur, &nxt, sizeof(nxt)) || nxt == 0) return 0;
        cur = nxt + static_cast<uintptr_t>(o);
    }
    return cur;
}
)LINUX_TR";
        append_init_items(ss, table);
        ss << R"LINUX_MAIN(void FreezeWorker() {
    while (g_running) {
        if (g_pid > 0) {
            for (auto& it : g_items) {
                if (!it.enabled) continue;
                uintptr_t a = ResolveAddress(g_pid, it.moduleName, it.baseOffset, it.offsets);
                if (!a) continue;
                if (it.typeId == 0) WriteProc(g_pid, a, &it.freezeValI32, 4);
                else if (it.typeId == 1) WriteProc(g_pid, a, &it.freezeValI64, 8);
                else if (it.typeId == 2) WriteProc(g_pid, a, &it.freezeValFloat, 4);
                else if (it.typeId == 3) WriteProc(g_pid, a, &it.freezeValDouble, 8);
                else if (it.typeId == 4) WriteProc(g_pid, a, &it.freezeValI16, 2);
                else if (it.typeId == 5) WriteProc(g_pid, a, &it.freezeValI8, 1);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}
} // namespace

int main() {
    InitItems();
    std::cout << "[*] Waiting for Linux process: " << kTargetProcess << " ...\n";
    while (g_pid == 0) {
        g_pid = FindLinuxPid(kTargetProcess);
        if (g_pid == 0) std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    std::cout << "[+] Attached PID " << g_pid << ". Type item index (0.." << g_items.size() << ") to toggle, or 'q' to quit.\n";
    for (size_t i = 0; i < g_items.size(); ++i) {
        std::cout << "  [" << i << "] " << g_items[i].description << "\n";
    }
    std::thread fw(FreezeWorker);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "q" || line == "quit") break;
        try {
            size_t idx = std::stoul(line);
            if (idx < g_items.size()) {
                g_items[idx].enabled = !g_items[idx].enabled;
                std::cout << "[*] " << g_items[idx].description << ": " << (g_items[idx].enabled ? "ON" : "OFF") << "\n";
            }
        } catch (...) {}
    }
    g_running = false;
    fw.join();
    return 0;
}
)LINUX_MAIN";
        return ss.str();
    }

    if (kind == TrainerKind::GUI) {
        ss << R"TRAINER_GUI(#define WM_UPDATE_CHECKBOX (WM_USER + 101)

HWND g_hwnd = NULL;
HWND g_statusLabel = NULL;
std::vector<HWND> g_checkboxes;

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);
            if (wmEvent == BN_CLICKED && wmId >= 200 && wmId < 200 + static_cast<int>(g_items.size())) {
                int idx = wmId - 200;
                LRESULT checked = SendMessage(g_checkboxes[idx], BM_GETCHECK, 0, 0);
                g_items[idx].enabled = (checked == BST_CHECKED);
                MessageBeep(g_items[idx].enabled ? MB_OK : MB_ICONASTERISK);
            }
            break;
        }
        case WM_UPDATE_CHECKBOX: {
            int idx = static_cast<int>(wParam);
            bool state = (lParam != 0);
            if (idx >= 0 && idx < static_cast<int>(g_checkboxes.size())) {
                SendMessage(g_checkboxes[idx], BM_SETCHECK, state ? BST_CHECKED : BST_UNCHECKED, 0);
            }
            break;
        }
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetTextColor(hdcStatic, RGB(220, 230, 240));
            SetBkColor(hdcStatic, RGB(35, 39, 46));
            static HBRUSH hbrBkgnd = CreateSolidBrush(RGB(35, 39, 46));
            return (INT_PTR)hbrBkgnd;
        }
        case WM_DESTROY:
            g_running = false;
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    InitItems();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(35, 39, 46));
    wc.lpszClassName = L"NCETrainerGUI";
    RegisterClassExW(&wc);

    int winHeight = 110 + static_cast<int>(g_items.size()) * 36;
    std::string winTitle = std::string("NCE Standalone Trainer - ") + kTargetProcess;
    std::wstring wWinTitle(winTitle.begin(), winTitle.end());
    g_hwnd = CreateWindowExW(
        0, L"NCETrainerGUI", wWinTitle.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 380, winHeight,
        NULL, NULL, hInstance, NULL
    );

    if (!g_hwnd) return 1;

    g_statusLabel = CreateWindowExW(
        0, L"STATIC", L"Searching for game process...",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        15, 12, 340, 20,
        g_hwnd, NULL, hInstance, NULL
    );

    for (size_t i = 0; i < g_items.size(); ++i) {
        std::string label = "[" + std::string(g_items[i].hotkeyText) + "] " + g_items[i].description;
        std::wstring wlabel(label.begin(), label.end());
        HWND hChk = CreateWindowExW(
            0, L"BUTTON", wlabel.c_str(),
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            25, 42 + static_cast<int>(i) * 34, 320, 26,
            g_hwnd, (HMENU)(UINT_PTR)(200 + i), hInstance, NULL
        );
        g_checkboxes.push_back(hChk);
    }

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    std::thread freezeThread(FreezeWorker);

    // Background process monitor and hotkey thread
    std::thread monitorThread([&]() {
        while (g_running) {
            if (g_hProcess == NULL) {
                g_pid = FindProcessId(kTargetProcess);
                if (g_pid != 0) {
                    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_pid);
                    if (g_hProcess) {
                        SetWindowTextW(g_statusLabel, L"Status: CONNECTED (Active)");
                    }
                }
            } else {
                DWORD exitCode = 0;
                if (!GetExitCodeProcess(g_hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
                    CloseHandle(g_hProcess);
                    g_hProcess = NULL;
                    g_pid = 0;
                    SetWindowTextW(g_statusLabel, L"Status: Waiting for game process...");
                }
            }

            // Check hotkeys
            for (size_t i = 0; i < g_items.size(); ++i) {
                if (GetAsyncKeyState(g_items[i].hotkeyVk) & 1) {
                    g_items[i].enabled = !g_items[i].enabled;
                    MessageBeep(g_items[i].enabled ? MB_OK : MB_ICONASTERISK);
                    PostMessage(g_hwnd, WM_UPDATE_CHECKBOX, i, g_items[i].enabled ? 1 : 0);
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    });

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_running = false;
    if (monitorThread.joinable()) monitorThread.join();
    if (freezeThread.joinable()) freezeThread.join();
    if (g_hProcess) CloseHandle(g_hProcess);

    return 0;
}
)TRAINER_GUI";
    } else {
        // Console mode main
        ss << R"(int main() {
    SetConsoleTitleA("NCE Standalone Trainer");
    InitItems();

    std::cout << "========================================================\n";
    std::cout << "          NCE Standalone Trainer - " << kTargetProcess << "\n";
    std::cout << "========================================================\n\n";

    std::cout << "[*] Waiting for " << kTargetProcess << " ...\n";
    while (g_pid == 0) {
        g_pid = FindProcessId(kTargetProcess);
        if (g_pid == 0) std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "[+] Found " << kTargetProcess << " (PID: " << g_pid << ")\n";
    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_pid);
    if (!g_hProcess) {
        std::cerr << "[-] Failed to open process. Run as Administrator!\n";
        system("pause");
        return 1;
    }

    std::cout << "[+] Attached successfully!\n\n";
    std::cout << "Trainer Options:\n";
    for (const auto& it : g_items) {
        std::cout << "  [" << it.hotkeyText << "] Toggle: " << it.description << "\n";
    }
    std::cout << "  [END] Exit Trainer\n\n";

    std::thread freezeThread(FreezeWorker);

    while (g_running) {
        if (GetAsyncKeyState(VK_END) & 1) {
            g_running = false;
            break;
        }

        for (auto& it : g_items) {
            if (GetAsyncKeyState(it.hotkeyVk) & 1) {
                it.enabled = !it.enabled;
                Beep(it.enabled ? 1200 : 600, 100);
                std::cout << "[*] " << it.description << " is now: " << (it.enabled ? "ACTIVATED" : "DEACTIVATED") << "\n";
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (freezeThread.joinable()) freezeThread.join();
    CloseHandle(g_hProcess);
    std::cout << "[*] Trainer terminated.\n";
    return 0;
}
)";
    }

    return ss.str();
}

bool export_standalone_trainer_file(
    const std::string& output_file_path,
    const CheatTable& table,
    const std::string& target_process_name,
    std::string& error_msg,
    TrainerKind kind
) {
    std::ofstream out(output_file_path, std::ios::binary);
    if (!out.is_open()) {
        error_msg = "Could not open file for writing: " + output_file_path;
        return false;
    }
    std::string cpp_code = generate_standalone_trainer_cpp(table, target_process_name, kind);
    out.write(cpp_code.data(), static_cast<std::streamsize>(cpp_code.size()));
    if (!out.good()) {
        error_msg = "Failed writing to: " + output_file_path;
        return false;
    }
    return true;
}

} // namespace nce::table
