#include "../../include/hal/process_linux.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <filesystem>
#include <fstream>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <cstring>
#endif

namespace nce::hal {

namespace linux_utils {

uint32_t permissions_to_protect(bool r, bool w, bool x) {
    if (x && w) return 0x40; // PAGE_EXECUTE_READWRITE
    if (x && r) return 0x20; // PAGE_EXECUTE_READ
    if (x)      return 0x10; // PAGE_EXECUTE
    if (w)      return 0x04; // PAGE_READWRITE
    if (r)      return 0x02; // PAGE_READONLY
    return 0x01;             // PAGE_NOACCESS
}

std::optional<LinuxMapsEntry> parse_maps_line(const std::string& line) {
    if (line.empty()) return std::nullopt;

    std::istringstream iss(line);
    std::string addr_range, perms, offset_str, dev_str;
    uint64_t inode = 0;

    if (!(iss >> addr_range >> perms >> offset_str >> dev_str >> inode)) {
        return std::nullopt;
    }

    std::string pathname;
    std::getline(iss >> std::ws, pathname);

    auto dash = addr_range.find('-');
    if (dash == std::string::npos) return std::nullopt;

    LinuxMapsEntry entry;
    try {
        entry.start_addr = std::stoull(addr_range.substr(0, dash), nullptr, 16);
        entry.end_addr   = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
        entry.offset     = std::stoull(offset_str, nullptr, 16);
    } catch (...) {
        return std::nullopt;
    }

    entry.dev = dev_str;
    entry.inode = inode;
    entry.pathname = pathname;

    if (perms.size() >= 4) {
        entry.readable   = (perms[0] == 'r');
        entry.writable   = (perms[1] == 'w');
        entry.executable = (perms[2] == 'x');
        entry.is_private = (perms[3] == 'p');
    }

    return entry;
}

std::vector<MemoryRegion> parse_maps_to_regions(const std::string& maps_content, uint32_t filter_flags) {
    std::vector<MemoryRegion> regions;
    std::istringstream stream(maps_content);
    std::string line;

    while (std::getline(stream, line)) {
        auto parsed = parse_maps_line(line);
        if (!parsed) continue;

        MemoryRegion reg;
        reg.base_address = parsed->start_addr;
        reg.size = parsed->end_addr - parsed->start_addr;
        reg.raw_protection = permissions_to_protect(parsed->readable, parsed->writable, parsed->executable);
        reg.raw_state = 0x1000; // MEM_COMMIT
        reg.is_readable = parsed->readable;
        reg.is_writable = parsed->writable;
        reg.is_executable = parsed->executable;
        reg.is_guard = false;
        reg.is_committed = true;

        if (!parsed->is_private) {
            reg.type = MemoryType::Mapped;
            reg.raw_type = 0x40000;
        } else if (!parsed->pathname.empty() && parsed->pathname[0] == '/') {
            reg.type = MemoryType::Image;
            reg.raw_type = 0x1000000;
        } else {
            reg.type = MemoryType::Private;
            reg.raw_type = 0x20000;
        }
        reg.module_name = parsed->pathname;

        // Apply scan filter flags
        if ((filter_flags & FilterFlags::ExcludeNoAccess) && !parsed->readable && !parsed->writable && !parsed->executable) {
            continue;
        }
        if ((filter_flags & FilterFlags::WritableOnly) && !parsed->writable) {
            continue;
        }
        if ((filter_flags & FilterFlags::ExecutableOnly) && !parsed->executable) {
            continue;
        }
        if ((filter_flags & FilterFlags::PrivateOnly) && reg.type != MemoryType::Private) {
            continue;
        }
        if ((filter_flags & FilterFlags::ImageOnly) && reg.type != MemoryType::Image) {
            continue;
        }

        regions.push_back(reg);
    }

    return regions;
}

std::vector<ModuleInfo> parse_maps_to_modules(const std::string& maps_content) {
    struct ModAgg {
        uintptr_t min_addr{UINT64_MAX};
        uintptr_t max_addr{0};
        std::string full_path;
    };

    std::map<std::string, ModAgg> map_modules;
    std::istringstream stream(maps_content);
    std::string line;

    while (std::getline(stream, line)) {
        auto parsed = parse_maps_line(line);
        if (!parsed || parsed->pathname.empty()) continue;

        const std::string& path = parsed->pathname;
        // Modules are mapped files or special Proton Windows DLLs
        if (path[0] != '/' && path.find(".dll") == std::string::npos && path.find(".exe") == std::string::npos) {
            continue;
        }

        auto& agg = map_modules[path];
        agg.full_path = path;
        agg.min_addr = std::min(agg.min_addr, parsed->start_addr);
        agg.max_addr = std::max(agg.max_addr, parsed->end_addr);
    }

    std::vector<ModuleInfo> modules;
    for (const auto& [path, agg] : map_modules) {
        if (agg.min_addr == UINT64_MAX || agg.max_addr <= agg.min_addr) continue;

        ModuleInfo info;
        info.path = agg.full_path;
        info.base_address = agg.min_addr;
        info.size = agg.max_addr - agg.min_addr;

        // Extract filename
        auto last_slash = agg.full_path.find_last_of("/\\");
        if (last_slash != std::string::npos) {
            info.name = agg.full_path.substr(last_slash + 1);
        } else {
            info.name = agg.full_path;
        }

        modules.push_back(info);
    }

    // Sort by base address
    std::sort(modules.begin(), modules.end(), [](const auto& a, const auto& b) {
        return a.base_address < b.base_address;
    });

    return modules;
}

bool is_proton_or_wine(const std::string& cmdline) {
    std::string lower_cmd = cmdline;
    std::transform(lower_cmd.begin(), lower_cmd.end(), lower_cmd.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    return lower_cmd.find("wine") != std::string::npos ||
           lower_cmd.find("proton") != std::string::npos ||
           lower_cmd.find("steam.exe") != std::string::npos ||
           lower_cmd.find("wine64-preloader") != std::string::npos ||
           lower_cmd.find("pressure-vessel") != std::string::npos;
}

std::string extract_game_name_from_cmdline(const std::string& cmdline) {
    std::string lower_cmd = cmdline;
    std::transform(lower_cmd.begin(), lower_cmd.end(), lower_cmd.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    // Look for ".exe"
    auto exe_pos = lower_cmd.rfind(".exe");
    if (exe_pos != std::string::npos) {
        // Find beginning of filename
        size_t start = exe_pos;
        while (start > 0 && cmdline[start - 1] != '/' && cmdline[start - 1] != '\\' && cmdline[start - 1] != ' ') {
            --start;
        }
        return cmdline.substr(start, exe_pos + 4 - start);
    }

    // Fallback: extract last token
    auto last_space = cmdline.find_last_of(" \t");
    if (last_space != std::string::npos && last_space + 1 < cmdline.size()) {
        auto last_slash = cmdline.find_last_of("/\\", last_space);
        if (last_slash != std::string::npos) {
            return cmdline.substr(last_slash + 1);
        }
        return cmdline.substr(last_space + 1);
    }

    return cmdline;
}

} // namespace linux_utils

#ifndef _WIN32
LinuxProcess::LinuxProcess() = default;

LinuxProcess::~LinuxProcess() {
    detach();
}

bool LinuxProcess::attach(uint32_t pid) {
    detach();

    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        return false;
    }
    maps_file.close();

    std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
    m_mem_fd = open(mem_path.c_str(), O_RDWR);
    if (m_mem_fd < 0) {
        // Fallback to read-only
        m_mem_fd = open(mem_path.c_str(), O_RDONLY);
        m_can_write = false;
    } else {
        m_can_write = true;
    }

    m_pid = pid;
    m_attached = true;
    m_pointer_size = sizeof(uintptr_t);

    // Read process name from cmdline or comm
    std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmd_file(cmdline_path, std::ios::binary);
    std::string cmdline;
    if (cmd_file.is_open()) {
        std::getline(cmd_file, cmdline, '\0');
        cmd_file.close();
    }

    if (linux_utils::is_proton_or_wine(cmdline)) {
        m_is_proton = true;
        m_name = linux_utils::extract_game_name_from_cmdline(cmdline);
    } else {
        std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream comm_file(comm_path);
        if (comm_file.is_open()) {
            std::getline(comm_file, m_name);
            comm_file.close();
        } else {
            m_name = std::to_string(pid);
        }
    }

    return true;
}

void LinuxProcess::detach() {
    if (m_suspended) {
        resume();
    }
    if (m_mem_fd >= 0) {
        close(m_mem_fd);
        m_mem_fd = -1;
    }
    m_attached = false;
    m_pid = 0;
    m_name.clear();
}

bool LinuxProcess::is_attached() const noexcept {
    if (!m_attached || m_pid == 0) return false;
    return (kill(static_cast<pid_t>(m_pid), 0) == 0);
}

uint32_t LinuxProcess::get_pid() const noexcept {
    return m_pid;
}

bool LinuxProcess::read_raw(uintptr_t address, void* buffer, size_t size) const {
    if (!m_attached || !buffer || size == 0) return false;

    // Use fast process_vm_readv
    struct iovec local_iov{buffer, size};
    struct iovec remote_iov{reinterpret_cast<void*>(address), size};

    ssize_t nread = process_vm_readv(static_cast<pid_t>(m_pid), &local_iov, 1, &remote_iov, 1, 0);
    if (nread == static_cast<ssize_t>(size)) {
        return true;
    }

    // Fallback to /proc/[pid]/mem
    if (m_mem_fd >= 0) {
        ssize_t res = pread(m_mem_fd, buffer, size, static_cast<off_t>(address));
        return (res == static_cast<ssize_t>(size));
    }

    return false;
}

namespace {

#if defined(__x86_64__)
uint32_t win32_prot_to_mmap_prot(uint32_t prot) {
    switch (prot) {
        case 0x40:
        case 0x80: return PROT_READ | PROT_WRITE | PROT_EXEC;
        case 0x20: return PROT_READ | PROT_EXEC;
        case 0x10: return PROT_EXEC;
        case 0x04:
        case 0x08: return PROT_READ | PROT_WRITE;
        case 0x02: return PROT_READ;
        default:   return PROT_READ | PROT_WRITE | PROT_EXEC;
    }
}

bool ptrace_remote_syscall(
    pid_t pid,
    long sysno,
    long arg1, long arg2, long arg3,
    long arg4, long arg5, long arg6,
    long& out_ret)
{
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        return false;
    }

    int status = 0;
    if (waitpid(pid, &status, __WALL) < 0 || !WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    struct user_regs_struct orig_regs{};
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &orig_regs) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    errno = 0;
    long orig_word = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(orig_regs.rip), nullptr);
    if (errno != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    // Write `syscall` (0x0F 0x05) at current RIP preserving upper bytes
    long patched_word = (orig_word & ~0xFFFFL) | 0x050FL;
    if (ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(orig_regs.rip), reinterpret_cast<void*>(patched_word)) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    struct user_regs_struct call_regs = orig_regs;
    call_regs.rax = static_cast<unsigned long long>(sysno);
    call_regs.rdi = static_cast<unsigned long long>(arg1);
    call_regs.rsi = static_cast<unsigned long long>(arg2);
    call_regs.rdx = static_cast<unsigned long long>(arg3);
    call_regs.r10 = static_cast<unsigned long long>(arg4);
    call_regs.r8  = static_cast<unsigned long long>(arg5);
    call_regs.r9  = static_cast<unsigned long long>(arg6);

    bool ok = false;
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &call_regs) == 0 &&
        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == 0) {
        if (waitpid(pid, &status, __WALL) >= 0 && WIFSTOPPED(status)) {
            struct user_regs_struct res_regs{};
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &res_regs) == 0) {
                out_ret = static_cast<long>(res_regs.rax);
                ok = true;
            }
        }
    }

    // Restore original instruction word and registers cleanly
    ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(orig_regs.rip), reinterpret_cast<void*>(orig_word));
    ptrace(PTRACE_SETREGS, pid, nullptr, &orig_regs);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return ok;
}

bool ptrace_force_write(pid_t pid, uintptr_t address, const uint8_t* src, size_t size) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) return false;
    int status = 0;
    if (waitpid(pid, &status, __WALL) < 0 || !WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    bool ok = true;
    size_t pos = 0;
    const size_t word_sz = sizeof(long);
    while (pos < size) {
        uintptr_t cur = address + pos;
        uintptr_t aligned = cur & ~(word_sz - 1);
        size_t in_word_off = cur - aligned;
        size_t chunk = std::min(word_sz - in_word_off, size - pos);

        long word = 0;
        if (chunk < word_sz) {
            errno = 0;
            word = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(aligned), nullptr);
            if (errno != 0) { ok = false; break; }
        }
        uint8_t bytes[sizeof(long)];
        std::memcpy(bytes, &word, word_sz);
        std::memcpy(bytes + in_word_off, src + pos, chunk);
        std::memcpy(&word, bytes, word_sz);

        if (ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(aligned), reinterpret_cast<void*>(word)) != 0) {
            ok = false;
            break;
        }
        pos += chunk;
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return ok;
}
#endif

} // namespace

bool LinuxProcess::write_raw(uintptr_t address, const void* buffer, size_t size, bool force_protection) const {
    if (!m_attached || !buffer || size == 0 || !m_can_write) return false;

    // Use fast process_vm_writev
    struct iovec local_iov{const_cast<void*>(buffer), size};
    struct iovec remote_iov{reinterpret_cast<void*>(address), size};

    ssize_t nwritten = process_vm_writev(static_cast<pid_t>(m_pid), &local_iov, 1, &remote_iov, 1, 0);
    if (nwritten == static_cast<ssize_t>(size)) {
        return true;
    }

    // Fallback to /proc/[pid]/mem
    if (m_mem_fd >= 0) {
        ssize_t res = pwrite(m_mem_fd, buffer, size, static_cast<off_t>(address));
        if (res == static_cast<ssize_t>(size)) {
            return true;
        }
    }

#if defined(__x86_64__)
    if (force_protection) {
        return ptrace_force_write(static_cast<pid_t>(m_pid), address, static_cast<const uint8_t*>(buffer), size);
    }
#else
    (void)force_protection;
#endif
    return false;
}

std::vector<MemoryRegion> LinuxProcess::query_regions(uint32_t filter_flags) const {
    if (!m_attached) return {};

    std::string maps_path = "/proc/" + std::to_string(m_pid) + "/maps";
    std::ifstream f(maps_path);
    if (!f.is_open()) return {};

    std::ostringstream ss;
    ss << f.rdbuf();
    return linux_utils::parse_maps_to_regions(ss.str(), filter_flags);
}

std::vector<ModuleInfo> LinuxProcess::get_modules() const {
    if (!m_attached) return {};

    std::string maps_path = "/proc/" + std::to_string(m_pid) + "/maps";
    std::ifstream f(maps_path);
    if (!f.is_open()) return {};

    std::ostringstream ss;
    ss << f.rdbuf();
    return linux_utils::parse_maps_to_modules(ss.str());
}

bool LinuxProcess::suspend() {
    if (!m_attached || m_suspended) return false;
    if (kill(static_cast<pid_t>(m_pid), SIGSTOP) == 0) {
        m_suspended = true;
        return true;
    }
    return false;
}

bool LinuxProcess::resume() {
    if (!m_attached || !m_suspended) return false;
    if (kill(static_cast<pid_t>(m_pid), SIGCONT) == 0) {
        m_suspended = false;
        return true;
    }
    return false;
}

uintptr_t LinuxProcess::allocate_memory(size_t size, uint32_t protection, uintptr_t near_addr) {
    if (!m_attached || !m_can_write || size == 0) return 0;
#if defined(__x86_64__)
    const uint32_t prot = win32_prot_to_mmap_prot(protection);
    long ret = -1;
    if (ptrace_remote_syscall(
            static_cast<pid_t>(m_pid),
            SYS_mmap,
            static_cast<long>(near_addr),
            static_cast<long>(size),
            static_cast<long>(prot),
            static_cast<long>(MAP_PRIVATE | MAP_ANONYMOUS),
            -1L,
            0L,
            ret)) {
        const uint64_t uret = static_cast<uint64_t>(ret);
        if (uret != 0 && uret < 0xFFFFFFFFFFFFF000ULL) {
            return static_cast<uintptr_t>(uret);
        }
    }
#else
    (void)size; (void)protection; (void)near_addr;
#endif
    return 0;
}

bool LinuxProcess::free_memory(uintptr_t address, size_t size) {
    if (!m_attached || !m_can_write || address == 0) return false;
#if defined(__x86_64__)
    const size_t len = (size > 0) ? size : 4096;
    long ret = -1;
    if (ptrace_remote_syscall(
            static_cast<pid_t>(m_pid),
            SYS_munmap,
            static_cast<long>(address),
            static_cast<long>(len),
            0L, 0L, 0L, 0L,
            ret)) {
        return ret == 0;
    }
#else
    (void)address; (void)size;
#endif
    return false;
}

std::vector<ProcessInfo> LinuxProcess::list_processes() {
    std::vector<ProcessInfo> list;
    DIR* dir = opendir("/proc");
    if (!dir) return list;

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        std::string name = entry->d_name;
        if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;

        uint32_t pid = static_cast<uint32_t>(std::stoul(name));
        std::string comm_path = "/proc/" + name + "/comm";
        std::ifstream comm_file(comm_path);
        std::string proc_name;
        if (comm_file.is_open()) {
            std::getline(comm_file, proc_name);
        } else {
            proc_name = name;
        }

        // Check if Proton/Wine
        std::string cmdline_path = "/proc/" + name + "/cmdline";
        std::ifstream cmd_file(cmdline_path, std::ios::binary);
        if (cmd_file.is_open()) {
            std::string cmd;
            std::getline(cmd_file, cmd, '\0');
            if (linux_utils::is_proton_or_wine(cmd)) {
                proc_name = linux_utils::extract_game_name_from_cmdline(cmd);
            }
        }

        list.push_back({ pid, proc_name });
    }

    closedir(dir);
    return list;
}

std::unique_ptr<IProcess> IProcess::create() {
    return std::make_unique<LinuxProcess>();
}

#endif

} // namespace nce::hal
