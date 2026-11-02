#pragma once

#include "hal/process.hpp"
#include "scanner/scan_results.hpp"
#include <cstring>
#include <vector>

namespace nce::test {

// In-memory IProcess: one committed, writable region of `size` bytes starting at kBase.
class FakeProcess : public hal::IProcess {
public:
    static constexpr uintptr_t kBase = 0x10000;

    explicit FakeProcess(size_t size) : m_memory(size, 0) {}

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
        hal::MemoryRegion region;
        region.base_address = kBase;
        region.size = m_memory.size();
        region.is_committed = true;
        region.is_readable = true;
        region.is_writable = true;
        region.type = hal::MemoryType::Private;
        return {region};
    }

    [[nodiscard]] std::vector<hal::ModuleInfo> get_modules() const override { return {}; }

    bool suspend() override { return true; }
    bool resume() override { return true; }

    template <typename T>
    void put(size_t offset, T value) {
        std::memcpy(m_memory.data() + offset, &value, sizeof(T));
    }

private:
    [[nodiscard]] bool contains(uintptr_t address, size_t size) const {
        return address >= kBase && address - kBase + size <= m_memory.size();
    }

    mutable std::vector<uint8_t> m_memory;
    bool m_attached{true};
};

inline bool contains_address(const scanner::ScanResults& results, uintptr_t address) {
    for (const auto& m : results.get_matches()) {
        if (m.address == address) return true;
    }
    return false;
}

} // namespace nce::test
