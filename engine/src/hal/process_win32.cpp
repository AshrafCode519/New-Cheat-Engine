#include "../../include/hal/process.hpp"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>

namespace nce::hal {

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
        // Request comprehensive rights: PROCESS_ALL_ACCESS or VM_READ | VM_WRITE | VM_OPERATION | QUERY_INFORMATION | SUSPEND_RESUME
        m_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME,
            FALSE,
            pid
        );

        if (!m_handle) {
            // Fallback to read/query if full access is denied
            m_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pid
            );
        }

        if (m_handle) {
            m_pid = pid;
            return true;
        }

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

    [[nodiscard]] bool is_attached() const noexcept override {
        return m_handle != nullptr;
    }

    [[nodiscard]] uint32_t get_pid() const noexcept override {
        return m_pid;
    }

    bool read_raw(uintptr_t address, void* buffer, size_t size) const override {
        if (!m_handle || !buffer || size == 0) return false;
        SIZE_T bytes_read = 0;
        return ReadProcessMemory(m_handle, reinterpret_cast<LPCVOID>(address), buffer, size, &bytes_read) && bytes_read == size;
    }

    bool write_raw(uintptr_t address, const void* buffer, size_t size, bool force_protection = true) const override {
        if (!m_handle || !buffer || size == 0) return false;

        DWORD old_protect = 0;
        bool protection_changed = false;

        if (force_protection) {
            protection_changed = VirtualProtectEx(
                m_handle,
                reinterpret_cast<LPVOID>(address),
                size,
                PAGE_EXECUTE_READWRITE,
                &old_protect
            ) != FALSE;
        }

        SIZE_T bytes_written = 0;
        BOOL result = WriteProcessMemory(
            m_handle,
            reinterpret_cast<LPVOID>(address),
            buffer,
            size,
            &bytes_written
        );

        if (protection_changed) {
            DWORD temp = 0;
            VirtualProtectEx(
                m_handle,
                reinterpret_cast<LPVOID>(address),
                size,
                old_protect,
                &temp
            );
        }

        return result && bytes_written == size;
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

private:
    HANDLE m_handle{nullptr};
    uint32_t m_pid{0};
    bool m_is_suspended{false};
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
