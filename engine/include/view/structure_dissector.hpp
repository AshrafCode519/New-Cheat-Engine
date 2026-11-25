#pragma once

#include "../hal/process.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nce::view {

// One member of a dissected object: where it is, how big, what it most likely is, and its value now.
struct StructField {
    size_t offset{0};
    size_t size{4};         // 1, 2, 4 or 8
    std::string type;       // "void*", "float", "int32_t", "Player*", "char[16]", "uint8_t[4]"
    std::string name;       // "vtable", "field_10", or a guess from a nearby string
    std::string value;      // the current value as text
    std::string note;       // "-> game.exe+0x1A0", "vtable (12 funcs)", "points to Weapon", a string preview
    bool changed{false};
    uintptr_t child_pointer{0};
};

// A C++ view of an object in the target: its class name if RTTI gives one, its vtable, and its fields.
struct StructLayout {
    uintptr_t address{0};
    size_t size{0};
    std::string class_name;    // from RTTI (MSVC or Itanium), empty if none found
    size_t vtable_functions{0}; // functions in the first vtable, 0 if the object has none
    std::vector<StructField> fields;

    // Refreshes the values of all fields in-place from the live target process.
    // Sets `changed = true` on fields whose values differed.
    void refresh_values(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules = {});

    // Manually change a field's type and name, re-reading its value formatted accordingly
    bool set_field_type(size_t field_index, const std::string& new_type, const hal::IProcess& process);

    // A C++ struct the user can paste into a header (fields named field_<hexoffset> unless guessed)
    [[nodiscard]] std::string to_cpp() const;
};

// Side-by-side comparison of the same field layout across multiple live object instances
struct StructCompareRow {
    size_t offset{0};
    size_t size{4};
    std::string type;
    std::string name;
    std::vector<std::string> values;
    bool all_equal{true};
    bool differs{false};
};

struct StructComparison {
    std::vector<uintptr_t> addresses;
    std::vector<std::string> labels;
    size_t size{0};
    std::vector<StructCompareRow> rows;

    void refresh(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules = {});
    [[nodiscard]] std::string to_report(bool only_differences = false) const;
};

// Turns a raw object or pointer in the game into a named C++ struct: reads each slot as what it most likely
// is, finds the vtable, and recovers the class name from RTTI. Built on the same idea as MemoryView, aimed
// at one object rather than a window of memory.
class StructureDissector {
public:
    explicit StructureDissector(std::shared_ptr<hal::IProcess> process);

    // Dissects `size` bytes at `address`. `modules` lets it name pointers and read RTTI; when empty it asks
    // the process for them.
    [[nodiscard]] StructLayout dissect(uintptr_t address, size_t size = 0x100,
                                       std::vector<hal::ModuleInfo> modules = {}) const;

    // Compares multiple object addresses side-by-side using the primary object's inferred layout.
    [[nodiscard]] StructComparison compare(const std::vector<uintptr_t>& addresses, size_t size = 0x100,
                                           std::vector<hal::ModuleInfo> modules = {},
                                           bool only_differences = false) const;

    // The C++ class name a vtable pointer belongs to (MSVC's RTTICompleteObjectLocator, or the Itanium
    // type_info both unmangled to a readable name), or nullopt if the pointer is not a vtable with RTTI.
    [[nodiscard]] std::optional<std::string> class_from_vtable(uintptr_t vtable_ptr,
                                                               const std::vector<hal::ModuleInfo>& modules) const;

    // How many consecutive function pointers sit at a vtable (0 if it isn't one)
    [[nodiscard]] size_t vtable_function_count(uintptr_t vtable_ptr,
                                               const std::vector<hal::ModuleInfo>& modules) const;

private:
    std::shared_ptr<hal::IProcess> m_process;
};

// Unmangles an MSVC RTTI type name (".?AVFoo@Bar@@" -> "Bar::Foo", ".?AUName@@" -> "Name"), or returns
// empty if it isn't one. Exposed for testing.
std::string demangle_msvc(const std::string& decorated);
// Unmangles a simple Itanium name ("7MyClass" -> "MyClass", "N3Foo3BarE" -> "Foo::Bar"), or the input
// unchanged if it can't.
std::string demangle_itanium(const std::string& mangled);

} // namespace nce::view
