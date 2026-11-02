#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace nce::hal {

enum class RegionProtection : uint32_t {
    None         = 0,
    NoAccess     = 1 << 0,
    ReadOnly     = 1 << 1,
    ReadWrite    = 1 << 2,
    WriteCopy    = 1 << 3,
    Execute      = 1 << 4,
    ExecuteRead  = 1 << 5,
    ExecuteReadWrite = 1 << 6,
    ExecuteWriteCopy = 1 << 7,
    Guard        = 1 << 8
};

enum class MemoryType : uint32_t {
    Unknown = 0,
    Private = 1 << 0,
    Mapped  = 1 << 1,
    Image   = 1 << 2
};

struct MemoryRegion {
    uintptr_t base_address{0};
    size_t size{0};
    uint32_t raw_protection{0};
    uint32_t raw_state{0};
    uint32_t raw_type{0};

    bool is_readable{false};
    bool is_writable{false};
    bool is_executable{false};
    bool is_guard{false};
    bool is_committed{false};

    MemoryType type{MemoryType::Unknown};
    std::string module_name;

    [[nodiscard]] uintptr_t end_address() const noexcept {
        return base_address + size;
    }
};

namespace FilterFlags {
    constexpr uint32_t OnlyCommitted       = 1 << 0;
    constexpr uint32_t ExcludeNoAccess     = 1 << 1;
    constexpr uint32_t ExcludeGuardPages   = 1 << 2;
    constexpr uint32_t WritableOnly        = 1 << 3;
    constexpr uint32_t ExecutableOnly      = 1 << 4;
    constexpr uint32_t PrivateOnly         = 1 << 5;
    constexpr uint32_t ImageOnly           = 1 << 6;

    constexpr uint32_t DefaultScanFilter   = OnlyCommitted | ExcludeNoAccess | ExcludeGuardPages | WritableOnly;
}

} // namespace nce::hal

