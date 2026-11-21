#pragma once

#include "../hal/process.hpp"
#include "../scanner/noise_map.hpp"
#include "../scanner/scan_types.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nce::view {

// What a 4-byte slot of memory most likely holds. 8-byte values (pointers on a 64-bit target, doubles,
// 64-bit integers) start at an 8-aligned slot; the slot after it is Continued.
enum class Guess {
    Unreadable,
    Zero,
    Int,       // a 32-bit integer up to 100,000,000 either way: counts, ids, health, money
    Float,     // a float between 0.0001 and 10,000,000 either way
    Double,    // a double between 0.01 and 1,000,000,000 either way, where the halves make no sense alone
    Int64,     // a 64-bit integer whose upper half is small and lower half makes no sense alone
    Pointer,   // a pointer into readable memory of the target
    Text,      // four printable ASCII characters
    Other,     // none of these: flags, hashes, packed data
    Continued, // the upper half of the 8-byte value in the slot before
};

struct Slot {
    uintptr_t address{0};
    int64_t offset{0};      // from the viewed address
    bool readable{false};
    uint32_t raw{0};
    uint64_t wide{0};       // Double / Int64 / Pointer: the whole 8 (or pointer-size) bytes
    Guess guess{Guess::Unreadable};
    std::string target;     // Pointer: "game.exe+0x1A0", or the address for heap memory
    bool noisy{false};      // the noise map says it changes on its own
    size_t changes{0};      // refreshes in which it changed
    size_t age{SIZE_MAX};   // refreshes since it last changed (SIZE_MAX: not seen changing)

    // The value as its guess reads it: "100", "25.5", "-> game.exe+0x1A0", "'Cybe'", "0x8000F00D"
    [[nodiscard]] std::string value_text() const;
    // "39 05 00 00" ("?? ?? ?? ??" when unreadable)
    [[nodiscard]] std::string bytes_text() const;
    // "i32", "f32", "f64", "i64", "ptr", "text", "hex" (empty for Continued / Unreadable)
    [[nodiscard]] const char* type_name() const;
    // The type to put it in a cheat table as
    [[nodiscard]] scanner::DataType data_type() const;
};

// A live view of the memory around an address, like a structure dissector: each slot read as what it
// most likely is, with the slots that change marked. Used by the GUI's Memory tab and the CLI's 'view'.
class MemoryView {
public:
    static constexpr size_t SLOT_SIZE = 4;

    // Watches `before` slots before the address and `after` slots from it on (the slots are 4-aligned).
    // A new address starts over: what changed is forgotten.
    void set_address(uintptr_t address, size_t before = 16, size_t after = 48);
    void clear() { set_address(0, 0, 0); }

    // Reads the slots again: guesses, pointer targets, and which slots changed since the last refresh
    void refresh(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules,
                 const scanner::NoiseMap* noise = nullptr);

    [[nodiscard]] uintptr_t address() const noexcept { return m_address; }
    [[nodiscard]] bool empty() const noexcept { return m_slots.empty(); }
    [[nodiscard]] const std::vector<Slot>& slots() const noexcept { return m_slots; }
    [[nodiscard]] size_t refreshes() const noexcept { return m_refreshes; }
    // The slot holding the viewed address
    [[nodiscard]] size_t focus() const noexcept { return m_focus; }
    // Refreshes since the value starting at slot i last changed, both halves of an 8-byte value included
    [[nodiscard]] size_t value_age(size_t i) const;

private:
    uintptr_t m_address{0};
    size_t m_focus{0};
    size_t m_refreshes{0};
    std::vector<Slot> m_slots;
};

// "+0x1C", "-0x8"
std::string format_offset(int64_t offset);

// "game.exe+0x1A0" if the address lies in a module, else empty
std::string module_offset(uintptr_t address, const std::vector<hal::ModuleInfo>& modules);

} // namespace nce::view
