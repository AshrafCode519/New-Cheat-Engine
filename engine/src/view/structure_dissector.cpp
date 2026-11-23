#include "../../include/view/structure_dissector.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <sstream>

namespace nce::view {

namespace {

const hal::ModuleInfo* module_of(uintptr_t address, const std::vector<hal::ModuleInfo>& modules) {
    for (const auto& m : modules) {
        if (address >= m.base_address && address - m.base_address < m.size) return &m;
    }
    return nullptr;
}

std::string module_offset(uintptr_t address, const std::vector<hal::ModuleInfo>& modules) {
    if (const auto* m = module_of(address, modules)) {
        std::ostringstream ss;
        ss << m->name << "+0x" << std::uppercase << std::hex << (address - m->base_address);
        return ss.str();
    }
    return {};
}

bool user_address(uint64_t v) { return v >= 0x10000 && v <= 0x7FFFFFFEFFFFull; }

template <typename T>
std::optional<T> read(const hal::IProcess& p, uintptr_t address) {
    T v{};
    if (!p.read_raw(address, &v, sizeof(T))) return std::nullopt;
    return v;
}

// Reads a null-terminated ASCII string (up to `max` bytes) at `address`
std::string read_cstr(const hal::IProcess& p, uintptr_t address, size_t max = 128) {
    std::string out;
    std::vector<uint8_t> buf(max);
    if (!p.read_raw(address, buf.data(), max)) {
        // try byte by byte in case the tail is unreadable
        for (size_t i = 0; i < max; ++i) {
            auto c = read<uint8_t>(p, address + i);
            if (!c || *c == 0) break;
            out += static_cast<char>(*c);
        }
        return out;
    }
    for (size_t i = 0; i < max && buf[i]; ++i) out += static_cast<char>(buf[i]);
    return out;
}

bool printable_run(const uint8_t* bytes, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (bytes[i] < 0x20 || bytes[i] > 0x7E) return false;
    }
    return true;
}

} // anonymous namespace

std::string demangle_msvc(const std::string& decorated) {
    // ".?AVClassName@@", ".?AUStructName@@", ".?AVName@Namespace@@" (segments are namespaces, inner first)
    if (decorated.compare(0, 4, ".?AV") != 0 && decorated.compare(0, 4, ".?AU") != 0) return {};
    const size_t end = decorated.find("@@");
    if (end == std::string::npos) return {};
    const std::string body = decorated.substr(4, end - 4);
    std::vector<std::string> segments;
    std::string seg;
    for (char c : body) {
        if (c == '@') { segments.push_back(seg); seg.clear(); }
        else seg += c;
    }
    segments.push_back(seg);
    // segments are inner-most first: Class@Namespace -> Namespace::Class
    std::string out;
    for (auto it = segments.rbegin(); it != segments.rend(); ++it) {
        if (it->empty()) continue;
        if (!out.empty()) out += "::";
        out += *it;
    }
    return out;
}

std::string demangle_itanium(const std::string& mangled) {
    // "7MyClass" (length-prefixed) or "N3Foo3BarE" (nested, each component length-prefixed)
    auto read_len_name = [](const std::string& s, size_t& i) -> std::string {
        size_t n = 0;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) { n = n * 10 + (s[i] - '0'); ++i; }
        if (n == 0 || i + n > s.size()) return {};
        const std::string name = s.substr(i, n);
        i += n;
        return name;
    };
    size_t i = 0;
    if (i < mangled.size() && mangled[i] == 'N') { // nested name
        ++i;
        std::vector<std::string> parts;
        while (i < mangled.size() && mangled[i] != 'E') {
            auto part = read_len_name(mangled, i);
            if (part.empty()) return mangled;
            parts.push_back(part);
        }
        std::string out;
        for (const auto& p : parts) { if (!out.empty()) out += "::"; out += p; }
        return out.empty() ? mangled : out;
    }
    if (i < mangled.size() && std::isdigit(static_cast<unsigned char>(mangled[i]))) {
        auto name = read_len_name(mangled, i);
        return name.empty() ? mangled : name;
    }
    return mangled;
}

StructureDissector::StructureDissector(std::shared_ptr<hal::IProcess> process) : m_process(std::move(process)) {}

size_t StructureDissector::vtable_function_count(uintptr_t vtable_ptr,
                                                 const std::vector<hal::ModuleInfo>& modules) const {
    if (!module_of(vtable_ptr, modules)) return 0; // a vtable lives in the module's read-only data
    const size_t ptr_size = m_process->pointer_size();
    size_t count = 0;
    for (size_t i = 0; i < 1024; ++i) { // a sane cap
        uint64_t entry = 0;
        if (!m_process->read_raw(vtable_ptr + i * ptr_size, &entry, ptr_size)) break;
        if (!user_address(entry) || !module_of(static_cast<uintptr_t>(entry), modules)) break; // not a code pointer
        ++count;
    }
    return count;
}

std::optional<std::string> StructureDissector::class_from_vtable(uintptr_t vtable_ptr,
                                                                 const std::vector<hal::ModuleInfo>& modules) const {
    const auto* module = module_of(vtable_ptr, modules);
    if (!module) return std::nullopt;
    const bool x64 = m_process->pointer_size() == 8;

    // --- MSVC: the pointer just before the vtable is the RTTICompleteObjectLocator ---
    if (auto col_ptr = read<uint64_t>(*m_process, vtable_ptr - m_process->pointer_size())) {
        const uintptr_t col = static_cast<uintptr_t>(*col_ptr);
        if (module_of(col, modules)) {
            if (x64) {
                // 64-bit: the COL's fields are image-relative (RVA). pSelf (at +0x14) is the COL's own RVA, so
                // module_base = col - pSelf, and the TypeDescriptor is at module_base + pTypeDescriptor (+0xC).
                auto self_rva = read<uint32_t>(*m_process, col + 0x14);
                auto td_rva = read<uint32_t>(*m_process, col + 0x0C);
                if (self_rva && td_rva && *self_rva != 0) {
                    const uintptr_t base = col - *self_rva;
                    const uintptr_t td = base + *td_rva;
                    const std::string name = read_cstr(*m_process, td + 0x10); // TypeDescriptor.name
                    if (auto demangled = demangle_msvc(name); !demangled.empty()) return demangled;
                }
            } else {
                // 32-bit: the COL holds a direct TypeDescriptor pointer at +0x0C
                if (auto td = read<uint32_t>(*m_process, col + 0x0C)) {
                    const std::string name = read_cstr(*m_process, *td + 0x08); // TypeDescriptor.name (32-bit layout)
                    if (auto demangled = demangle_msvc(name); !demangled.empty()) return demangled;
                }
            }
        }
    }

    // --- Itanium (GCC/Clang): the pointer before the vtable is the std::type_info; its +ptr field is the name ---
    if (auto ti_ptr = read<uint64_t>(*m_process, vtable_ptr - m_process->pointer_size())) {
        const uintptr_t ti = static_cast<uintptr_t>(*ti_ptr);
        if (module_of(ti, modules)) {
            uint64_t name_ptr = 0;
            if (m_process->read_raw(ti + m_process->pointer_size(), &name_ptr, m_process->pointer_size()) &&
                user_address(name_ptr)) {
                const std::string name = read_cstr(*m_process, static_cast<uintptr_t>(name_ptr));
                if (!name.empty() && (std::isdigit(static_cast<unsigned char>(name[0])) || name[0] == 'N')) {
                    const std::string demangled = demangle_itanium(name);
                    if (!demangled.empty() && demangled != name) return demangled;
                }
            }
        }
    }
    return std::nullopt;
}

StructLayout StructureDissector::dissect(uintptr_t address, size_t size, std::vector<hal::ModuleInfo> modules) const {
    if (modules.empty() && m_process->is_attached()) modules = m_process->get_modules();
    const size_t ptr_size = m_process->pointer_size();

    StructLayout layout;
    layout.address = address;
    layout.size = size;

    std::vector<uint8_t> buf(size);
    std::vector<bool> ok(size, false);
    if (!m_process->read_raw(address, buf.data(), size)) {
        for (size_t i = 0; i < size; ++i) ok[i] = m_process->read_raw(address + i, &buf[i], 1);
    } else {
        std::fill(ok.begin(), ok.end(), true);
    }
    auto readable = [&](size_t off, size_t n) {
        if (off + n > size) return false;
        for (size_t i = 0; i < n; ++i) if (!ok[off + i]) return false;
        return true;
    };

    for (size_t off = 0; off < size; ) {
        StructField f;
        f.offset = off;
        std::ostringstream name;
        name << "field_" << std::hex << off;
        f.name = name.str();

        if (!readable(off, 1)) { f.size = 1; f.type = "uint8_t"; f.value = "??"; f.note = "unreadable"; layout.fields.push_back(f); ++off; continue; }

        // An 8-byte (pointer-size) slot at an aligned offset: a pointer, vtable, or 64-bit number
        if (ptr_size == 8 && off % 8 == 0 && readable(off, 8)) {
            uint64_t word = 0;
            std::memcpy(&word, &buf[off], 8);
            if (user_address(word) && m_process->read_raw(static_cast<uintptr_t>(word), &word, 1)) {
                std::memcpy(&word, &buf[off], 8); // restore (the probe read clobbered it)
                const uintptr_t target = static_cast<uintptr_t>(word);
                f.size = 8;

                // The first pointer that is a vtable names the class and gives the vtable count
                if (off == 0) {
                    if (auto cls = class_from_vtable(target, modules)) {
                        layout.class_name = *cls;
                        f.name = "vtable";
                        f.type = "void**";
                        f.note = "vtable of " + *cls;
                        layout.vtable_functions = vtable_function_count(target, modules);
                        if (layout.vtable_functions) f.note += " (" + std::to_string(layout.vtable_functions) + " funcs)";
                        f.value = utils::format_address(target);
                        layout.fields.push_back(f);
                        off += 8;
                        continue;
                    }
                    if (size_t n = vtable_function_count(target, modules); n >= 2) {
                        f.name = "vtable";
                        f.type = "void**";
                        f.note = "vtable (" + std::to_string(n) + " funcs)";
                        layout.vtable_functions = n;
                        f.value = utils::format_address(target);
                        layout.fields.push_back(f);
                        off += 8;
                        continue;
                    }
                }

                // A pointer to a C string?
                uint8_t probe[8] = {0};
                if (m_process->read_raw(target, probe, sizeof probe) && printable_run(probe, 4)) {
                    const std::string text = read_cstr(*m_process, target, 48);
                    if (text.size() >= 4) {
                        f.type = "char*";
                        f.value = utils::format_address(target);
                        f.note = "\"" + (text.size() > 32 ? text.substr(0, 32) + "..." : text) + "\"";
                        layout.fields.push_back(f);
                        off += 8;
                        continue;
                    }
                }

                // A pointer to another object with a vtable -> its class name
                if (auto inner_vptr = read<uint64_t>(*m_process, target)) {
                    if (auto cls = class_from_vtable(static_cast<uintptr_t>(*inner_vptr), modules)) {
                        f.type = *cls + "*";
                        f.value = utils::format_address(target);
                        f.note = "points to a " + *cls;
                        layout.fields.push_back(f);
                        off += 8;
                        continue;
                    }
                }

                f.type = "void*";
                f.value = utils::format_address(target);
                const std::string where = module_offset(target, modules);
                f.note = where.empty() ? "-> " + utils::format_address(target) : "-> " + where;
                layout.fields.push_back(f);
                off += 8;
                continue;
            }
            // Not a pointer: a 64-bit integer, but only when the low 4 bytes don't already read as a clean
            // value on their own (a float, a small int, text or zero) -- otherwise this is two 4-byte fields.
            uint32_t low = 0;
            std::memcpy(&low, &buf[off], 4);
            float low_f = 0;
            std::memcpy(&low_f, &low, 4);
            const bool low_is_float = std::isnormal(low_f) && std::fabs(low_f) >= 1e-4f && std::fabs(low_f) <= 1e7f;
            const bool low_is_small_int = static_cast<int64_t>(static_cast<int32_t>(low)) >= -100000000 &&
                                          static_cast<int64_t>(static_cast<int32_t>(low)) <= 100000000;
            const bool low_clean = low == 0 || low_is_float || low_is_small_int || printable_run(&buf[off], 4);
            int64_t sval = 0;
            std::memcpy(&sval, &buf[off], 8);
            if (!low_clean && sval != 0 && (word >> 32) != 0 && std::llabs(sval) < 100000000000000LL) {
                f.size = 8;
                f.type = "int64_t";
                f.value = std::to_string(sval);
                layout.fields.push_back(f);
                off += 8;
                continue;
            }
        }
        if (ptr_size == 4 && off % 4 == 0 && readable(off, 4)) {
            uint32_t word = 0;
            std::memcpy(&word, &buf[off], 4);
            uint8_t b = 0;
            if (user_address(word) && m_process->read_raw(word, &b, 1)) {
                f.size = 4;
                if (off == 0) {
                    if (auto cls = class_from_vtable(word, modules)) {
                        layout.class_name = *cls;
                        f.name = "vtable"; f.type = "void**"; f.note = "vtable of " + *cls;
                        layout.vtable_functions = vtable_function_count(word, modules);
                        f.value = utils::format_address(word);
                        layout.fields.push_back(f); off += 4; continue;
                    }
                }
                f.type = "void*"; f.value = utils::format_address(word);
                const std::string where = module_offset(word, modules);
                f.note = where.empty() ? "-> " + utils::format_address(word) : "-> " + where;
                layout.fields.push_back(f); off += 4; continue;
            }
        }

        // Four printable bytes in a row: inline text (char[])
        if (readable(off, 4) && printable_run(&buf[off], 4)) {
            size_t len = 0;
            while (off + len < size && readable(off + len, 1) && buf[off + len] >= 0x20 && buf[off + len] <= 0x7E) ++len;
            f.size = len;
            f.type = "char[" + std::to_string(len) + "]";
            f.value = "\"" + std::string(buf.begin() + off, buf.begin() + off + len) + "\"";
            layout.fields.push_back(f);
            off += len;
            continue;
        }

        // A 4-byte number: float if it looks like one, else int
        if (readable(off, 4)) {
            uint32_t word = 0;
            std::memcpy(&word, &buf[off], 4);
            float fl = 0;
            std::memcpy(&fl, &word, 4);
            f.size = 4;
            if (std::isnormal(fl) && std::fabs(fl) >= 1e-4f && std::fabs(fl) <= 1e7f) {
                f.type = "float";
                std::ostringstream v; v << fl;
                f.value = v.str();
            } else {
                f.type = "int32_t";
                f.value = std::to_string(static_cast<int32_t>(word));
            }
            layout.fields.push_back(f);
            off += 4;
            continue;
        }

        f.size = 1; f.type = "uint8_t"; f.value = std::to_string(buf[off]);
        layout.fields.push_back(f);
        ++off;
    }
    return layout;
}

std::string StructLayout::to_cpp() const {
    std::ostringstream out;
    const std::string name = class_name.empty() ? "DissectedObject" : class_name;
    // a class name with :: can't be a struct tag; keep only the last part for the tag
    std::string tag = name;
    if (const size_t sep = tag.rfind("::"); sep != std::string::npos) tag = tag.substr(sep + 2);

    out << "// " << utils::format_address(address) << ", " << size << " bytes";
    if (!class_name.empty()) out << " - RTTI class " << class_name;
    out << "\n";
    out << "struct " << tag << " {\n";
    size_t expected = 0;
    for (const auto& f : fields) {
        if (f.offset > expected) out << "    uint8_t _pad_" << std::hex << expected << std::dec << "[" << (f.offset - expected) << "];\n";
        out << "    " << f.type << " " << f.name << ";";
        out << "  // +0x" << std::hex << f.offset << std::dec << " = " << f.value;
        if (!f.note.empty()) out << "  " << f.note;
        out << "\n";
        expected = f.offset + f.size;
    }
    out << "};\n";
    return out.str();
}

} // namespace nce::view
