#include "../../include/hal/process.hpp"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cwchar>

namespace nce::hal {

namespace {

std::string to_utf8(const wchar_t* text) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    std::string out(size > 0 ? size - 1 : 0, '\0');
    if (size > 1) WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), size, nullptr, nullptr);
    return out;
}

} // anonymous namespace

// Function pointers for NtSuspendProcess and NtResumeProcess
using pfnNtSuspendProcess = LONG(NTAPI*)(HANDLE ProcessHandle);
using pfnNtResumeProcess  = LONG(NTAPI*)(HANDLE ProcessHandle);

class Win32Process : public IProcess {
public:
    Win32Process() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
            m_ntSuspend = reinterpret_cast<pfnNtSuspendProcess>(GetProcAddress(ntdll, "NtSuspendProcess"));
            m_ntResume  = reinterpret_cast<pfnNtResumeProcess>(GetProcAddress(ntdll, "NtResumeProcess"));
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
        }
    }

    ~Win32Process() override {
        detach();
    }

    bool attach(uint32_t pid) override {
        detach();
        // SYNCHRONIZE lets is_attached notice when the target exits
        m_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                PROCESS_SUSPEND_RESUME | SYNCHRONIZE,
            FALSE,
            pid
        );
        m_can_write = (m_handle != nullptr);

        if (!m_handle) {
            // Fall back to read-only access; callers can tell through can_write()
            m_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
                FALSE,
                pid
            );
        }

        if (m_handle) {
            m_pid = pid;
            m_pointer_size = sizeof(uintptr_t);
            BOOL is_wow64 = FALSE;
            if (IsWow64Process(m_handle, &is_wow64) && is_wow64) {
                m_pointer_size = 4; // 32-bit process on 64-bit Windows
            }

            m_name.clear();
            wchar_t path[MAX_PATH];
            DWORD length = MAX_PATH;
            if (QueryFullProcessImageNameW(m_handle, 0, path, &length)) {
                const wchar_t* file = wcsrchr(path, L'\\');
                m_name = to_utf8(file ? file + 1 : path);
            }
            return true;
        }

        m_can_write = false;
        return false;
    }

    void detach() override {
        if (m_is_suspended) {
            resume();
        }
        if (m_handle) {
            CloseHandle(m_handle);
            m_handle = nullptr;
            m_pid = 0;
        }
    }

    // False once the target has exited, even though the handle is still open
    [[nodiscard]] bool is_attached() const noexcept override {
        return m_handle != nullptr && WaitForSingleObject(m_handle, 0) == WAIT_TIMEOUT;
    }

    [[nodiscard]] bool can_write() const noexcept override {
        return m_handle != nullptr && m_can_write;
    }

    [[nodiscard]] std::string name() const override {
        return m_name;
    }

    [[nodiscard]] uint32_t get_pid() const noexcept override {
        return m_pid;
    }

    [[nodiscard]] size_t pointer_size() const noexcept override {
        return m_pointer_size;
    }

    bool read_raw(uintptr_t address, void* buffer, size_t size) const override {
        if (!m_handle || !buffer || size == 0) return false;
        SIZE_T bytes_read = 0;
        return ReadProcessMemory(m_handle, reinterpret_cast<LPCVOID>(address), buffer, size, &bytes_read) && bytes_read == size;
    }

    // Writes without touching page protection when it can (the usual case). Only if that fails and
    // force_protection is set, each region the write touches is made writable on its own (keeping its
    // execute bit) and restored right after, so a write over two regions can't give one the other's
    // protection and nothing is left RWX.
    bool write_raw(uintptr_t address, const void* buffer, size_t size, bool force_protection = true) const override {
        if (!m_handle || !buffer || size == 0) return false;

        SIZE_T bytes_written = 0;
        if (WriteProcessMemory(m_handle, reinterpret_cast<LPVOID>(address), buffer, size, &bytes_written) &&
            bytes_written == size) {
            return true;
        }
        if (!force_protection) return false;

        uintptr_t current = address;
        const auto* source = static_cast<const uint8_t*>(buffer);
        size_t remaining = size;
        while (remaining > 0) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(m_handle, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi)) != sizeof(mbi) ||
                mbi.State != MEM_COMMIT) {
                return false;
            }
            const uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const size_t chunk = std::min<size_t>(remaining, region_end - current);
            const bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                                    PAGE_EXECUTE_WRITECOPY)) != 0;

            DWORD old_protect = 0;
            if (!VirtualProtectEx(m_handle, reinterpret_cast<LPVOID>(current), chunk,
                                  executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &old_protect)) {
                return false;
            }
            const bool ok = WriteProcessMemory(m_handle, reinterpret_cast<LPVOID>(current), source, chunk,
                                               &bytes_written) && bytes_written == chunk;
            DWORD ignored = 0;
            VirtualProtectEx(m_handle, reinterpret_cast<LPVOID>(current), chunk, old_protect, &ignored);
            if (!ok) return false;

            current += chunk;
            source += chunk;
            remaining -= chunk;
        }
        return true;
    }

    [[nodiscard]] std::vector<MemoryRegion> query_regions(uint32_t filter_flags = FilterFlags::DefaultScanFilter) const override {
        std::vector<MemoryRegion> regions;
        if (!m_handle) return regions;

        uintptr_t current_addr = 0;
        MEMORY_BASIC_INFORMATION mbi{};

        while (VirtualQueryEx(m_handle, reinterpret_cast<LPCVOID>(current_addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            MemoryRegion region;
            region.base_address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            region.size = mbi.RegionSize;
            region.raw_protection = mbi.Protect;
            region.raw_state = mbi.State;
            region.raw_type = mbi.Type;

            region.is_committed = (mbi.State == MEM_COMMIT);
            region.is_guard = (mbi.Protect & PAGE_GUARD) != 0;

            const bool is_no_access = (mbi.Protect & PAGE_NOACCESS) != 0;
            region.is_readable = region.is_committed && !is_no_access && !region.is_guard &&
                ((mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE) ||
                 (mbi.Protect & PAGE_WRITECOPY) || (mbi.Protect & PAGE_EXECUTE_READ) ||
                 (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY));

            region.is_writable = region.is_committed && !is_no_access && !region.is_guard &&
                ((mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) ||
                 (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY));

            region.is_executable = region.is_committed && !is_no_access && !region.is_guard &&
                ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) ||
                 (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY));

            if (mbi.Type == MEM_PRIVATE) region.type = MemoryType::Private;
            else if (mbi.Type == MEM_IMAGE) region.type = MemoryType::Image;
            else if (mbi.Type == MEM_MAPPED) region.type = MemoryType::Mapped;

            // Apply filter flags
            bool include = true;

            if ((filter_flags & FilterFlags::OnlyCommitted) && !region.is_committed) include = false;
            if ((filter_flags & FilterFlags::ExcludeNoAccess) && is_no_access) include = false;
            if ((filter_flags & FilterFlags::ExcludeGuardPages) && region.is_guard) include = false;
            if ((filter_flags & FilterFlags::WritableOnly) && !region.is_writable) include = false;
            if ((filter_flags & FilterFlags::ExecutableOnly) && !region.is_executable) include = false;
            if ((filter_flags & FilterFlags::PrivateOnly) && region.type != MemoryType::Private) include = false;
            if ((filter_flags & FilterFlags::ImageOnly) && region.type != MemoryType::Image) include = false;

            if (include && region.is_readable && region.size > 0) {
                regions.push_back(region);
            }

            // Move to next region
            uintptr_t next_addr = region.base_address + region.size;
            if (next_addr <= current_addr) break; // Overflow protection
            current_addr = next_addr;
        }

        return regions;
    }

    [[nodiscard]] std::vector<ModuleInfo> get_modules() const override {
        std::vector<ModuleInfo> modules;
        if (!m_handle) return modules;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
        if (snap == INVALID_HANDLE_VALUE) return modules;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        if (Module32FirstW(snap, &me)) {
            do {
                ModuleInfo info;
                // Convert wchar to std::string
                int name_len = WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nullptr, 0, nullptr, nullptr);
                if (name_len > 0) {
                    info.name.resize(name_len - 1);
                    WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, info.name.data(), name_len, nullptr, nullptr);
                }

                int path_len = WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, nullptr, 0, nullptr, nullptr);
                if (path_len > 0) {
                    info.path.resize(path_len - 1);
                    WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, info.path.data(), path_len, nullptr, nullptr);
                }

                info.base_address = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                info.size = me.modBaseSize;
                modules.push_back(info);
            } while (Module32NextW(snap, &me));
        }

        CloseHandle(snap);
        return modules;
    }

    bool suspend() override {
        if (!m_handle || !m_ntSuspend || m_is_suspended) return false;
        if (m_ntSuspend(m_handle) >= 0) {
            m_is_suspended = true;
            return true;
        }
        return false;
    }

    bool resume() override {
        if (!m_handle || !m_ntResume || !m_is_suspended) return false;
        if (m_ntResume(m_handle) >= 0) {
            m_is_suspended = false;
            return true;
        }
        return false;
    }

    uintptr_t allocate_memory(size_t size, uint32_t protection, uintptr_t near_addr) override {
        if (!m_handle || size == 0) return 0;
        // With a `near` hint, try to land within ±2GB of it so a 5-byte rel32 jmp can reach the cave: walk
        // outward from the next 64KB-aligned address until VirtualAllocEx takes one.
        if (near_addr != 0) {
            constexpr uintptr_t k64k = 0x10000;
            constexpr uintptr_t reach = 0x7FFF0000; // just under 2GB, leaving room for the cave + a jump
            const uintptr_t anchor = (near_addr + k64k - 1) & ~(k64k - 1);
            for (uintptr_t delta = 0; delta <= reach; delta += k64k) {
                for (int dir : {1, -1}) {
                    const uintptr_t probe = dir > 0 ? anchor + delta : anchor - delta;
                    if (probe < k64k) continue;
                    void* p = VirtualAllocEx(m_handle, reinterpret_cast<void*>(probe), size,
                                             MEM_COMMIT | MEM_RESERVE, protection);
                    if (p) return reinterpret_cast<uintptr_t>(p);
                    if (delta == 0) break; // +0 and -0 are the same probe
                }
            }
        }
        void* p = VirtualAllocEx(m_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
        return reinterpret_cast<uintptr_t>(p);
    }

    bool free_memory(uintptr_t address, size_t) override {
        if (!m_handle || address == 0) return false;
        return VirtualFreeEx(m_handle, reinterpret_cast<void*>(address), 0, MEM_RELEASE) != FALSE;
    }

private:
    HANDLE m_handle{nullptr};
    uint32_t m_pid{0};
    size_t m_pointer_size{sizeof(uintptr_t)};
    bool m_is_suspended{false};
    bool m_can_write{false};
    std::string m_name;
    pfnNtSuspendProcess m_ntSuspend{nullptr};
    pfnNtResumeProcess  m_ntResume{nullptr};
};

std::vector<ProcessInfo> IProcess::list_processes() {
    std::vector<ProcessInfo> list;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return list;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;

            int name_len = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            if (name_len > 0) {
                info.name.resize(name_len - 1);
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, info.name.data(), name_len, nullptr, nullptr);
            }

            if (info.pid != 0) {
                list.push_back(info);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return list;
}

std::unique_ptr<IProcess> IProcess::create() {
    return std::make_unique<Win32Process>();
}

} // namespace nce::hal
#endif
