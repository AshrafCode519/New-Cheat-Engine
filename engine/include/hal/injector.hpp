#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nce::hal {

struct ThreadInfo {
    uint32_t tid{0};
    uint32_t owner_pid{0};
    int32_t base_priority{0};
};

class ProcessInjector {
public:
    // Enumerates active OS threads belonging to `pid`.
    static std::vector<ThreadInfo> list_threads(uint32_t pid);

    // Injects a native DLL into `pid` via VirtualAllocEx + WriteProcessMemory + LoadLibraryW.
    // Returns true if LoadLibraryW succeeded inside the remote process.
    static bool inject_dll(uint32_t pid, const std::string& dll_path, std::string& error_out);

    // Directory containing the currently running NCE executable (used to locate helper DLLs like nce_veh.dll).
    static std::string executable_directory();
};

} // namespace nce::hal
