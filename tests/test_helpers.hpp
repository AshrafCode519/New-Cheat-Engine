#pragma once

#include "hal/process.hpp"
#include "scanner/scan_results.hpp"
#include <algorithm>
#include <cstring>
#include <tuple>
#include <vector>

namespace nce::test {

// In-memory IProcess: `size` bytes of committed, writable memory starting at kBase.
// make_unreadable() punches holes: reads touching a hole fail. A listed hole is also left out of
// query_regions; an unlisted one simulates memory freed after the regions were queried.
class FakeProcess : public hal::IProcess {
public:
    static constexpr uintptr_t kBase = 0x10000;

    explicit FakeProcess(size_t size) : m_memory(size, 0) {}

    void make_unreadable(size_t offset, size_t size, bool listed = true) {
        m_holes.push_back({offset, offset + size, listed});
    }

    // Modules are given as offsets into the fake memory; the first one plays the executable
    void add_module(const std::string& name, size_t offset, size_t size) {
        m_modules.push_back({name, name, kBase + offset, size});
    }

    void set_pointer_size(size_t size) { m_pointer_size = size; }

    // The program's name ("game.exe"); the table library keys on it. Changing it plays another program.
    void set_name(std::string name) { m_name = std::move(name); }
    [[nodiscard]] std::string name() const override { return m_name; }

    // Writes a pointer of the configured size
    void put_pointer(size_t offset, uintptr_t value) {
        if (m_pointer_size == 4) put<uint32_t>(offset, static_cast<uint32_t>(value));
        else put<uintptr_t>(offset, value);
    }

    bool attach(uint32_t) override { m_attached = true; return true; }
    void detach() override { m_attached = false; }
    [[nodiscard]] bool is_attached() const noexcept override { return m_attached; }
    [[nodiscard]] uint32_t get_pid() const noexcept override { return 1; }

    bool read_raw(uintptr_t address, void* buffer, size_t size) const override {
        if (!contains(address, size)) return false;
        std::memcpy(buffer, m_memory.data() + (address - kBase), size);
        return true;
    }

    bool write_raw(uintptr_t address, const void* buffer, size_t size, bool = true) const override {
        if (!contains(address, size)) return false;
        std::memcpy(m_memory.data() + (address - kBase), buffer, size);
        return true;
    }

    [[nodiscard]] std::vector<hal::MemoryRegion> query_regions(uint32_t = hal::FilterFlags::DefaultScanFilter) const override {
        std::vector<hal::MemoryRegion> regions;
        size_t start = 0;
        while (start < m_memory.size()) {
            // Skip holes, then extend the region up to the next hole
            size_t end = m_memory.size();
            bool in_hole = false;
            for (const auto& [h_begin, h_end, listed] : m_holes) {
                if (!listed) continue;
                if (start >= h_begin && start < h_end) { start = h_end; in_hole = true; break; }
                if (h_begin > start) end = std::min(end, h_begin);
            }
            if (in_hole) continue;

            hal::MemoryRegion region;
            region.base_address = kBase + start;
            region.size = end - start;
            region.is_committed = true;
            region.is_readable = true;
            region.is_writable = true;
            region.type = hal::MemoryType::Private;
            regions.push_back(region);
            start = end;
        }
        return regions;
    }

    [[nodiscard]] std::vector<hal::ModuleInfo> get_modules() const override { return m_modules; }
    [[nodiscard]] size_t pointer_size() const noexcept override { return m_pointer_size; }

    bool suspend() override { return true; }
    bool resume() override { return true; }

    template <typename T>
    void put(size_t offset, T value) {
        std::memcpy(m_memory.data() + offset, &value, sizeof(T));
    }

private:
    [[nodiscard]] bool contains(uintptr_t address, size_t size) const {
        if (address < kBase || address - kBase + size > m_memory.size()) return false;
        const size_t begin = address - kBase;
        for (const auto& [h_begin, h_end, listed] : m_holes) {
            if (begin < h_end && begin + size > h_begin) return false;
        }
        return true;
    }

    mutable std::vector<uint8_t> m_memory;
    std::vector<std::tuple<size_t, size_t, bool>> m_holes;
    std::vector<hal::ModuleInfo> m_modules;
    size_t m_pointer_size{sizeof(uintptr_t)};
    bool m_attached{true};
    std::string m_name;
};

inline bool contains_address(const scanner::ScanResults& results, uintptr_t address) {
    for (size_t i = 0; i < results.count(); ++i) {
        if (results.address(i) == address) return true;
    }
    return false;
}

inline bool sorted_by_address(const scanner::ScanResults& results) {
    for (size_t i = 1; i < results.count(); ++i) {
        if (results.address(i - 1) >= results.address(i)) return false;
    }
    return true;
}

} // namespace nce::test
