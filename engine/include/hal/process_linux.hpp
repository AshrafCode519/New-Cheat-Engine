#pragma once

#include "process.hpp"
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace nce::hal {

struct LinuxMapsEntry {
    uintptr_t start_addr{0};
    uintptr_t end_addr{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool is_private{true}; // 'p' for private (COW), 's' for shared
    uint64_t offset{0};
    std::string dev;
    uint64_t inode{0};
    std::string pathname;
};

// Utilities for parsing Linux /proc filesystem (callable on all platforms for cross-target tooling and testing)
namespace linux_utils {

// Parses a single line from /proc/[pid]/maps
std::optional<LinuxMapsEntry> parse_maps_line(const std::string& line);

// Parses the full content of /proc/[pid]/maps into MemoryRegions
std::vector<MemoryRegion> parse_maps_to_regions(const std::string& maps_content, uint32_t filter_flags = FilterFlags::DefaultScanFilter);

// Parses the full content of /proc/[pid]/maps into ModuleInfo list
std::vector<ModuleInfo> parse_maps_to_modules(const std::string& maps_content);

// Translates rwxp permissions to Win32-style PAGE_* protection flags used across NCE
uint32_t permissions_to_protect(bool r, bool w, bool x);

// Detects if a process command line belongs to Wine, Proton, or Steam Play
bool is_proton_or_wine(const std::string& cmdline);

// Extracts the Windows executable name from a Proton command line e.g. "Proton ... /drive_c/game/eldenring.exe" -> "eldenring.exe"
std::string extract_game_name_from_cmdline(const std::string& cmdline);

} // namespace linux_utils

#ifndef _WIN32
class LinuxProcess : public IProcess {
public:
    LinuxProcess();
    ~LinuxProcess() override;

    bool attach(uint32_t pid) override;
    void detach() override;
    [[nodiscard]] bool is_attached() const noexcept override;
    [[nodiscard]] uint32_t get_pid() const noexcept override;

    bool read_raw(uintptr_t address, void* buffer, size_t size) const override;
    bool write_raw(uintptr_t address, const void* buffer, size_t size, bool force_protection = true) const override;

    [[nodiscard]] std::vector<MemoryRegion> query_regions(uint32_t filter_flags = FilterFlags::DefaultScanFilter) const override;
    [[nodiscard]] std::vector<ModuleInfo> get_modules() const override;

    [[nodiscard]] size_t pointer_size() const noexcept override { return m_pointer_size; }
    [[nodiscard]] bool can_write() const noexcept override { return m_can_write; }
    [[nodiscard]] std::string name() const override { return m_name; }

    bool suspend() override;
    bool resume() override;

    uintptr_t allocate_memory(size_t size, uint32_t protection = 0x40, uintptr_t near_addr = 0) override;
    bool free_memory(uintptr_t address, size_t size = 0) override;

    static std::vector<ProcessInfo> list_processes();

private:
    uint32_t m_pid{0};
    std::string m_name;
    size_t m_pointer_size{sizeof(uintptr_t)};
    bool m_attached{false};
    bool m_can_write{true};
    bool m_suspended{false};
    bool m_is_proton{false};
    int m_mem_fd{-1};
};
#endif

} // namespace nce::hal
