#pragma once

#include "memory_region.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <cstring>

namespace nce::hal {

struct ProcessInfo {
    uint32_t pid{0};
    std::string name;
};

struct ModuleInfo {
    std::string name;
    std::string path;
    uintptr_t base_address{0};
    size_t size{0};
};

class IProcess {
public:
    virtual ~IProcess() = default;

    virtual bool attach(uint32_t pid) = 0;
    virtual void detach() = 0;
    [[nodiscard]] virtual bool is_attached() const noexcept = 0;
    [[nodiscard]] virtual uint32_t get_pid() const noexcept = 0;

    virtual bool read_raw(uintptr_t address, void* buffer, size_t size) const = 0;
    virtual bool write_raw(uintptr_t address, const void* buffer, size_t size, bool force_protection = true) const = 0;

    [[nodiscard]] virtual std::vector<MemoryRegion> query_regions(uint32_t filter_flags = FilterFlags::DefaultScanFilter) const = 0;
    [[nodiscard]] virtual std::vector<ModuleInfo> get_modules() const = 0;

    // Size of a pointer in the target: 4 for 32-bit processes (WOW64 on 64-bit Windows), 8 otherwise
    [[nodiscard]] virtual size_t pointer_size() const noexcept { return sizeof(uintptr_t); }

    // False when the attach only got read access (writes and freezing will fail)
    [[nodiscard]] virtual bool can_write() const noexcept { return true; }

    // The target's executable name ("game.exe"), used to find it again after it restarts
    [[nodiscard]] virtual std::string name() const { return {}; }

    virtual bool suspend() = 0;
    virtual bool resume() = 0;

    template <typename T>
    bool read(uintptr_t address, T& out_value) const {
        return read_raw(address, &out_value, sizeof(T));
    }

    template <typename T>
    bool write(uintptr_t address, const T& in_value, bool force_protection = true) const {
        return write_raw(address, &in_value, sizeof(T), force_protection);
    }

    static std::vector<ProcessInfo> list_processes();
    static std::unique_ptr<IProcess> create();
};

} // namespace nce::hal

