#include "../../include/view/memory_view.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace nce::view {

namespace {

constexpr int64_t kMaxInt = 100'000'000;

bool small_int(uint32_t raw) {
    const int64_t v = static_cast<int32_t>(raw);
    return v >= -kMaxInt && v <= kMaxInt;
}

// Any float with a magnitude in this range has an integer reading above 900,000,000, so the two never overlap
bool plausible_float(uint32_t raw) {
    float f = 0;
    std::memcpy(&f, &raw, sizeof f);
    if (!std::isnormal(f)) return false;
    const float a = std::fabs(f);
    return a >= 1e-4f && a <= 1e7f;
}

bool plausible_double(uint64_t wide) {
    double d = 0;
    std::memcpy(&d, &wide, sizeof d);
    if (!std::isnormal(d)) return false;
    const double a = std::fabs(d);
    return a >= 1e-2 && a <= 1e9;
}

bool printable(uint32_t raw) {
    for (int i = 0; i < 4; ++i) {
        const auto c = static_cast<uint8_t>(raw >> (8 * i));
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

// What the 4 bytes look like on their own
Guess guess_alone(uint32_t raw) {
    if (raw == 0) return Guess::Zero;
    if (small_int(raw)) return Guess::Int;
    if (plausible_float(raw)) return Guess::Float;
    if (printable(raw)) return Guess::Text;
    return Guess::Other;
}

// Inside the user part of the address space (the first 64 KB are never mapped on Windows)
bool user_address(uint64_t value, size_t pointer_size) {
    if (value < 0x10000) return false;
    return pointer_size == 4 ? value <= 0xFFFFFFFFull : value <= 0x7FFFFFFEFFFFull;
}

bool readable_at(const hal::IProcess& process, uint64_t address) {
    uint8_t byte = 0;
    return process.read_raw(static_cast<uintptr_t>(address), &byte, 1);
}

std::string pointer_target(uint64_t address, const std::vector<hal::ModuleInfo>& modules) {
    auto in_module = module_offset(static_cast<uintptr_t>(address), modules);
    return in_module.empty() ? utils::format_address(static_cast<uintptr_t>(address)) : in_module;
}

} // anonymous namespace

std::string module_offset(uintptr_t address, const std::vector<hal::ModuleInfo>& modules) {
    for (const auto& m : modules) {
        if (address >= m.base_address && address - m.base_address < m.size) {
            std::ostringstream ss;
            ss << m.name << "+0x" << std::uppercase << std::hex << (address - m.base_address);
            return ss.str();
        }
    }
    return {};
}

std::string format_offset(int64_t offset) {
    std::ostringstream ss;
    const uint64_t magnitude = offset < 0 ? 0 - static_cast<uint64_t>(offset) : static_cast<uint64_t>(offset);
    ss << (offset < 0 ? "-0x" : "+0x") << std::uppercase << std::hex << magnitude;
    return ss.str();
}

std::string Slot::bytes_text() const {
    if (!readable) return "?? ?? ?? ??";
    char text[16];
    std::snprintf(text, sizeof text, "%02X %02X %02X %02X", raw & 0xFF, (raw >> 8) & 0xFF, (raw >> 16) & 0xFF, raw >> 24);
    return text;
}

std::string Slot::value_text() const {
    switch (guess) {
        case Guess::Unreadable: return "??";
        case Guess::Zero: return "0";
        case Guess::Int: return std::to_string(static_cast<int32_t>(raw));
        case Guess::Float: {
            float f = 0;
            std::memcpy(&f, &raw, sizeof f);
            return scanner::ScanValue::of(scanner::DataType::Float, f).to_string();
        }
        case Guess::Double: {
            double d = 0;
            std::memcpy(&d, &wide, sizeof d);
            return scanner::ScanValue::of(scanner::DataType::Double, d).to_string();
        }
        case Guess::Int64: return std::to_string(static_cast<int64_t>(wide));
        case Guess::Pointer: return "-> " + target;
        case Guess::Text: {
            std::string text(4, ' ');
            for (size_t i = 0; i < 4; ++i) text[i] = static_cast<char>(raw >> (8 * i));
            return "'" + text + "'";
        }
        case Guess::Other: {
            char hex[16];
            std::snprintf(hex, sizeof hex, "0x%08X", static_cast<unsigned>(raw));
            return hex;
        }
        case Guess::Continued: return "";
    }
    return "";
}

const char* Slot::type_name() const {
    switch (guess) {
        case Guess::Zero:
        case Guess::Int: return "i32";
        case Guess::Float: return "f32";
        case Guess::Double: return "f64";
        case Guess::Int64: return "i64";
        case Guess::Pointer: return "ptr";
        case Guess::Text: return "text";
        case Guess::Other: return "hex";
        case Guess::Unreadable:
        case Guess::Continued: return "";
    }
    return "";
}

scanner::DataType Slot::data_type() const {
    switch (guess) {
        case Guess::Float: return scanner::DataType::Float;
        case Guess::Double: return scanner::DataType::Double;
        case Guess::Int64: return scanner::DataType::Int64;
        case Guess::Pointer: return wide > 0xFFFFFFFFull ? scanner::DataType::UInt64 : scanner::DataType::UInt32;
        case Guess::Other: return scanner::DataType::UInt32;
        default: return scanner::DataType::Int32;
    }
}

size_t MemoryView::value_age(size_t i) const {
    if (i >= m_slots.size()) return SIZE_MAX;
    size_t age = m_slots[i].age;
    if (i + 1 < m_slots.size() && m_slots[i + 1].guess == Guess::Continued) age = std::min(age, m_slots[i + 1].age);
    return age;
}

void MemoryView::set_address(uintptr_t address, size_t before, size_t after) {
    m_address = address;
    m_focus = 0;
    m_refreshes = 0;
    m_slots.clear();
    if (address == 0) return;

    const uintptr_t aligned = address & ~static_cast<uintptr_t>(SLOT_SIZE - 1);
    before = std::min(before, static_cast<size_t>(aligned / SLOT_SIZE)); // don't wrap below address 0
    after = std::max<size_t>(after, 1);                                  // the viewed address itself
    const uintptr_t start = aligned - before * SLOT_SIZE;
    m_focus = before;
    m_slots.resize(before + after);
    for (size_t i = 0; i < m_slots.size(); ++i) {
        m_slots[i].address = start + i * SLOT_SIZE;
        m_slots[i].offset = static_cast<int64_t>(m_slots[i].address) - static_cast<int64_t>(address);
    }
}

void MemoryView::refresh(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules,
                         const scanner::NoiseMap* noise) {
    const size_t n = m_slots.size();
    if (n == 0) return;

    // One read for the whole window; slot by slot only if part of it can't be read
    std::vector<uint8_t> bytes(n * SLOT_SIZE);
    std::vector<bool> ok(n, true);
    if (!process.read_raw(m_slots.front().address, bytes.data(), bytes.size())) {
        for (size_t i = 0; i < n; ++i) {
            ok[i] = process.read_raw(m_slots[i].address, bytes.data() + i * SLOT_SIZE, SLOT_SIZE);
        }
    }

    for (size_t i = 0; i < n; ++i) {
        auto& s = m_slots[i];
        uint32_t raw = 0;
        if (ok[i]) std::memcpy(&raw, bytes.data() + i * SLOT_SIZE, SLOT_SIZE);
        if (m_refreshes > 0 && s.readable && ok[i] && raw != s.raw) {
            ++s.changes;
            s.age = 0;
        } else if (s.age != SIZE_MAX) {
            ++s.age;
        }
        s.readable = ok[i];
        s.raw = raw;
        s.wide = 0;
        s.target.clear();
        s.guess = ok[i] ? guess_alone(raw) : Guess::Unreadable;
        s.noisy = noise && ok[i] && noise->is_noisy(s.address, SLOT_SIZE);
    }

    // 8-byte values: pointers (pointer-size), doubles and 64-bit integers start at 8-aligned slots
    const size_t pointer_size = process.pointer_size();
    for (size_t i = 0; i < n; ++i) {
        auto& s = m_slots[i];
        if (!s.readable) continue;
        if (pointer_size == 4 && user_address(s.raw, 4) && readable_at(process, s.raw)) {
            s.guess = Guess::Pointer; // on a 32-bit target any 4-aligned slot can hold one
            s.wide = s.raw;
            s.target = pointer_target(s.raw, modules);
            continue;
        }
        if (s.address % 8 != 0 || i + 1 >= n || !m_slots[i + 1].readable) continue;

        auto& high = m_slots[i + 1];
        const uint64_t wide = s.raw | (static_cast<uint64_t>(high.raw) << 32);
        const bool low_alone_odd = s.guess == Guess::Zero || s.guess == Guess::Other;
        Guess whole = Guess::Unreadable;
        if (pointer_size == 8 && user_address(wide, 8) && readable_at(process, wide)) {
            whole = Guess::Pointer;
        } else if (low_alone_odd && high.guess != Guess::Int && high.guess != Guess::Zero && plausible_double(wide)) {
            whole = Guess::Double;
        } else if (s.guess == Guess::Other && high.raw >= 1 && high.raw <= 0xFFFF) {
            whole = Guess::Int64;
        }
        if (whole == Guess::Unreadable) continue;

        s.guess = whole;
        s.wide = wide;
        if (whole == Guess::Pointer) s.target = pointer_target(wide, modules);
        high.guess = Guess::Continued;
        high.noisy = high.noisy || s.noisy;
        s.noisy = high.noisy;
        ++i;
    }
    ++m_refreshes;
}

} // namespace nce::view
