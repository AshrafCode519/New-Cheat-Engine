#include "../../include/hal/injector.hpp"
#include <filesystem>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#else
#include "../../include/hal/process_linux.hpp"
#include "../../include/debugger/elf_analyzer.hpp"
#include <dirent.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#endif

namespace nce::hal {

std::vector<ThreadInfo> ProcessInjector::list_threads(uint32_t pid) {
    std::vector<ThreadInfo> threads;
    if (pid == 0) return threads;

#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return threads;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                threads.push_back({te.th32ThreadID, te.th32OwnerProcessID, te.tpBasePri});
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
#else
    std::string task_dir = "/proc/" + std::to_string(pid) + "/task";
    DIR* dir = opendir(task_dir.c_str());
    if (!dir) return threads;

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        char* endptr = nullptr;
        unsigned long tid = std::strtoul(entry->d_name, &endptr, 10);
        if (endptr && *endptr == '\0' && tid > 0) {
            threads.push_back({static_cast<uint32_t>(tid), pid, 0});
        }
    }
    closedir(dir);
#endif
    return threads;
}

std::string ProcessInjector::executable_directory() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH]{};
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        std::filesystem::path p(buf);
        return p.parent_path().string();
    }
#else
    char buf[4096]{};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        std::filesystem::path p(buf);
        return p.parent_path().string();
    }
#endif
    return ".";
}

bool ProcessInjector::inject_dll(uint32_t pid, const std::string& dll_path, std::string& error_out) {
#ifdef _WIN32
    if (pid == 0 || dll_path.empty()) {
        error_out = "Invalid PID or empty DLL path.";
        return false;
    }

    std::error_code ec;
    std::filesystem::path full_path = std::filesystem::absolute(std::filesystem::path(dll_path), ec);
    if (!std::filesystem::exists(full_path, ec)) {
        error_out = "DLL file not found: " + full_path.string();
        return false;
    }

    std::wstring wide_path = full_path.wstring();
    const size_t byte_len = (wide_path.size() + 1) * sizeof(wchar_t);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (!hProc) {
        error_out = "OpenProcess failed (error " + std::to_string(GetLastError()) + ").";
        return false;
    }

    void* remote_mem = VirtualAllocEx(hProc, nullptr, byte_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        error_out = "VirtualAllocEx failed (error " + std::to_string(GetLastError()) + ").";
        CloseHandle(hProc);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remote_mem, wide_path.c_str(), byte_len, &written) || written != byte_len) {
        error_out = "WriteProcessMemory failed (error " + std::to_string(GetLastError()) + ").";
        VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load_lib = k32 ? GetProcAddress(k32, "LoadLibraryW") : nullptr;
    if (!load_lib) {
        error_out = "Could not resolve kernel32!LoadLibraryW.";
        VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
    auto start_routine = reinterpret_cast<LPTHREAD_START_ROUTINE>(load_lib);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, start_routine, remote_mem, 0, nullptr);
    if (!hThread) {
        error_out = "CreateRemoteThread failed (error " + std::to_string(GetLastError()) + ").";
        VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    DWORD wait_res = WaitForSingleObject(hThread, 5000);
    DWORD exit_code = 0;
    if (wait_res == WAIT_OBJECT_0) {
        GetExitCodeThread(hThread, &exit_code);
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (wait_res != WAIT_OBJECT_0) {
        error_out = "Remote LoadLibraryW thread timed out.";
        return false;
    }
    if (exit_code == 0) {
        error_out = "LoadLibraryW returned NULL inside target process (architecture mismatch or missing dependency).";
        return false;
    }

    error_out.clear();
    return true;
#else
    if (pid == 0 || dll_path.empty()) {
        error_out = "Invalid PID or empty shared object path.";
        return false;
    }

    std::error_code ec;
    std::filesystem::path full_path = std::filesystem::absolute(std::filesystem::path(dll_path), ec);
    if (!std::filesystem::exists(full_path, ec)) {
        error_out = "Shared object file does not exist: " + full_path.string();
        return false;
    }

#if defined(__x86_64__)
    LinuxProcess proc;
    if (!proc.attach(pid)) {
        error_out = "Failed to attach to Linux target process (check ptrace_scope / permissions).";
        return false;
    }

    uintptr_t dlopen_va = 0;
    for (const auto& mod : proc.get_modules()) {
        const std::string lower = [&]() {
            std::string s = mod.name;
            for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return s;
        }();
        if (lower.find("libc.so") != std::string::npos || lower.find("libdl.so") != std::string::npos) {
            if (auto elf = debugger::ELFAnalyzer::analyze(proc, mod.base_address)) {
                if (auto* sym = debugger::ELFAnalyzer::find_symbol_by_name(*elf, "dlopen")) {
                    dlopen_va = sym->va;
                    break;
                }
                if (auto* sym = debugger::ELFAnalyzer::find_symbol_by_name(*elf, "__libc_dlopen_mode")) {
                    dlopen_va = sym->va;
                    break;
                }
            }
        }
    }

    if (dlopen_va == 0) {
        error_out = "Unable to locate dlopen / __libc_dlopen_mode export inside target process.";
        return false;
    }

    const std::string path_utf8 = full_path.string();
    const uintptr_t remote_page = proc.allocate_memory(4096, 0x40); // RWX scratch page (trap stub + path string)
    if (remote_page == 0) {
        error_out = "Remote mmap allocation for .so path failed.";
        return false;
    }

    // Offset 0: `int3` (`0xCC`) return trampoline; Offset 16: null-terminated .so path
    const uint8_t int3 = 0xCC;
    const uintptr_t remote_path = remote_page + 16;
    if (!proc.write_raw(remote_page, &int3, 1, true) ||
        !proc.write_raw(remote_path, path_utf8.c_str(), path_utf8.size() + 1, true)) {
        proc.free_memory(remote_page, 4096);
        error_out = "Failed to write .so path into target memory.";
        return false;
    }

    const pid_t tpid = static_cast<pid_t>(pid);
    if (ptrace(PTRACE_ATTACH, tpid, nullptr, nullptr) != 0) {
        proc.free_memory(remote_page, 4096);
        error_out = "PTRACE_ATTACH failed (errno " + std::to_string(errno) + ").";
        return false;
    }

    int status = 0;
    if (waitpid(tpid, &status, __WALL) < 0 || !WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, tpid, nullptr, nullptr);
        proc.free_memory(remote_page, 4096);
        error_out = "waitpid failed waiting for initial ptrace stop.";
        return false;
    }

    struct user_regs_struct orig_regs{};
    if (ptrace(PTRACE_GETREGS, tpid, nullptr, &orig_regs) != 0) {
        ptrace(PTRACE_DETACH, tpid, nullptr, nullptr);
        proc.free_memory(remote_page, 4096);
        error_out = "PTRACE_GETREGS failed.";
        return false;
    }

    struct user_regs_struct call_regs = orig_regs;
    // SysV x86_64 ABI call to dlopen(remote_path, RTLD_NOW | RTLD_GLOBAL) with RSP aligned and return addr = remote_page (int3)
    uintptr_t fake_rsp = (orig_regs.rsp - 128) & ~0xFULL;
    fake_rsp -= 8;
    const uint64_t ret_addr = static_cast<uint64_t>(remote_page);
    proc.write_raw(fake_rsp, &ret_addr, sizeof(ret_addr), true);

    call_regs.rip = static_cast<unsigned long long>(dlopen_va);
    call_regs.rsp = static_cast<unsigned long long>(fake_rsp);
    call_regs.rdi = static_cast<unsigned long long>(remote_path);
    call_regs.rsi = static_cast<unsigned long long>(RTLD_NOW | RTLD_GLOBAL);

    bool ok = false;
    if (ptrace(PTRACE_SETREGS, tpid, nullptr, &call_regs) == 0 &&
        ptrace(PTRACE_CONT, tpid, nullptr, nullptr) == 0) {
        if (waitpid(tpid, &status, __WALL) >= 0 && WIFSTOPPED(status)) {
            struct user_regs_struct ret_regs{};
            if (ptrace(PTRACE_GETREGS, tpid, nullptr, &ret_regs) == 0) {
                ok = (ret_regs.rax != 0);
                if (!ok) error_out = "Remote dlopen returned NULL.";
            }
        }
    }

    ptrace(PTRACE_SETREGS, tpid, nullptr, &orig_regs);
    ptrace(PTRACE_DETACH, tpid, nullptr, nullptr);
    proc.free_memory(remote_page, 4096);
    if (ok) error_out.clear();
    return ok;
#else
    error_out = "Linux .so injection currently supports x86_64 targets only.";
    return false;
#endif
#endif
}

} // namespace nce::hal
