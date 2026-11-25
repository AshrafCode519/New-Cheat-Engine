#include "debugger/elf_analyzer.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <unordered_set>

namespace nce::debugger {

namespace {

// Standard ELF constants (cross-platform, no <elf.h> dependency)
constexpr uint32_t kPtLoad    = 1;
constexpr uint32_t kPtDynamic = 2;

constexpr uint32_t kPfExec  = 1;
constexpr uint32_t kPfWrite = 2;
constexpr uint32_t kPfRead  = 4;

constexpr uint32_t kShtSymtab = 2;
constexpr uint32_t kShtStrtab = 3;
constexpr uint32_t kShtDynsym = 11;

constexpr uint64_t kShfWrite     = 0x1;
constexpr uint64_t kShfAlloc     = 0x2;
constexpr uint64_t kShfExecInstr = 0x4;

constexpr int64_t kDtNull    = 0;
constexpr int64_t kDtNeeded  = 1;
constexpr int64_t kDtHash    = 4;
constexpr int64_t kDtStrtab  = 5;
constexpr int64_t kDtSymtab  = 6;
constexpr int64_t kDtStrsz   = 10;
constexpr int64_t kDtSyment  = 11;
constexpr int64_t kDtGnuHash = 0x6ffffef5;

constexpr uint16_t kShnUndef = 0;
constexpr uint8_t kStbLocal  = 0;
constexpr uint8_t kStbGlobal = 1;
constexpr uint8_t kStbWeak   = 2;

uint16_t rd16(const uint8_t* p) {
    uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

uint32_t rd32(const uint8_t* p) {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

uint64_t rd64(const uint8_t* p) {
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

std::string elf_type_to_str(uint16_t t) {
    switch (t) {
        case 1: return "ET_REL";
        case 2: return "ET_EXEC";
        case 3: return "ET_DYN";
        case 4: return "ET_CORE";
        default: return "ET_UNKNOWN";
    }
}

std::string elf_machine_to_str(uint16_t m) {
    switch (m) {
        case 3:   return "x86 (32-bit)";
        case 40:  return "ARM";
        case 62:  return "x86_64 (64-bit)";
        case 183: return "AArch64";
        case 243: return "RISC-V";
        default:  return "Machine(" + std::to_string(m) + ")";
    }
}

std::string read_cstr_from_buf(const std::vector<uint8_t>& buf, size_t offset) {
    if (offset >= buf.size()) return {};
    size_t end = offset;
    const size_t limit = std::min(buf.size(), offset + 512);
    while (end < limit && buf[end] != 0) ++end;
    return std::string(reinterpret_cast<const char*>(buf.data() + offset), end - offset);
}

using ReadRangeFn = std::function<bool(uint64_t addr_or_off, size_t len, std::vector<uint8_t>& out, bool is_vaddr)>;

void append_symbol_unique(
    std::vector<ELFSymbol>& out,
    std::unordered_set<std::string>& seen,
    ELFSymbol sym)
{
    if (sym.name.empty()) return;
    std::string key = sym.name + "@" + std::to_string(sym.va);
    if (seen.insert(key).second) {
        out.push_back(std::move(sym));
    }
}

void parse_symbol_table_bytes(
    const std::vector<uint8_t>& sym_bytes,
    const std::vector<uint8_t>& str_bytes,
    bool is_64bit,
    uintptr_t load_bias,
    bool force_export_flag,
    std::vector<ELFSymbol>& out,
    std::unordered_set<std::string>& seen)
{
    const size_t entsize = is_64bit ? 24 : 16;
    const size_t count = sym_bytes.size() / entsize;
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* e = sym_bytes.data() + i * entsize;
        uint32_t st_name = rd32(e);
        uint8_t st_info = 0;
        uint16_t st_shndx = 0;
        uint64_t st_value = 0;
        uint64_t st_size = 0;

        if (is_64bit) {
            st_info  = e[4];
            st_shndx = rd16(e + 6);
            st_value = rd64(e + 8);
            st_size  = rd64(e + 16);
        } else {
            st_value = rd32(e + 4);
            st_size  = rd32(e + 8);
            st_info  = e[12];
            st_shndx = rd16(e + 14);
        }

        if (st_name == 0 || st_name >= str_bytes.size()) continue;
        std::string name = read_cstr_from_buf(str_bytes, st_name);
        if (name.empty()) continue;

        const uint8_t binding = static_cast<uint8_t>(st_info >> 4);
        const uint8_t type = static_cast<uint8_t>(st_info & 0x0F);

        ELFSymbol sym;
        sym.name = std::move(name);
        sym.section_index = st_shndx;
        sym.binding = binding;
        sym.type = type;
        sym.value = st_value;
        sym.size = st_size;
        sym.is_exported = (st_shndx != kShnUndef) &&
                          (binding == kStbGlobal || binding == kStbWeak) &&
                          (force_export_flag || st_value != 0);
        if (st_shndx != kShnUndef && st_value != 0) {
            sym.va = load_bias + static_cast<uintptr_t>(st_value);
        }
        if (sym.is_exported || (st_shndx != kShnUndef && binding == kStbLocal && st_value != 0)) {
            append_symbol_unique(out, seen, std::move(sym));
        }
    }
}

uint64_t vaddr_to_offset(const ELFInfo& info, uint64_t vaddr) {
    for (const auto& seg : info.segments) {
        if (seg.type != kPtLoad) continue;
        if (vaddr >= seg.virtual_address && vaddr < seg.virtual_address + seg.file_size) {
            return seg.offset + (vaddr - seg.virtual_address);
        }
    }
    return vaddr;
}

uint32_t probe_dynsym_count_from_hashes(
    const ReadRangeFn& reader,
    uint64_t hash_addr,
    uint64_t gnu_hash_addr,
    bool is_64bit,
    uintptr_t load_bias,
    uintptr_t module_base)
{
    auto norm_ptr = [&](uint64_t p) -> uint64_t {
        if (p == 0) return 0;
        if (module_base != 0 && p < module_base) return load_bias + p;
        return p;
    };

    if (hash_addr != 0) {
        std::vector<uint8_t> hdr;
        if (reader(norm_ptr(hash_addr), 8, hdr, true) && hdr.size() == 8) {
            uint32_t nchain = rd32(hdr.data() + 4);
            if (nchain > 0 && nchain < 1000000) return nchain;
        }
    }

    if (gnu_hash_addr != 0) {
        std::vector<uint8_t> hdr;
        uint64_t gh = norm_ptr(gnu_hash_addr);
        if (reader(gh, 16, hdr, true) && hdr.size() == 16) {
            uint32_t nbuckets   = rd32(hdr.data() + 0);
            uint32_t symoffset  = rd32(hdr.data() + 4);
            uint32_t bloom_size = rd32(hdr.data() + 8);
            if (nbuckets == 0 || nbuckets > 500000 || bloom_size > 500000) return 0;

            size_t bloom_bytes = static_cast<size_t>(bloom_size) * (is_64bit ? 8u : 4u);
            uint64_t buckets_addr = gh + 16 + bloom_bytes;
            std::vector<uint8_t> buckets;
            if (!reader(buckets_addr, static_cast<size_t>(nbuckets) * 4u, buckets, true)) return 0;

            uint32_t max_sym = 0;
            for (uint32_t i = 0; i < nbuckets; ++i) {
                uint32_t b = rd32(buckets.data() + i * 4u);
                if (b > max_sym) max_sym = b;
            }
            if (max_sym < symoffset) return symoffset;

            uint64_t chain_addr = buckets_addr + static_cast<uint64_t>(nbuckets) * 4u
                                + static_cast<uint64_t>(max_sym - symoffset) * 4u;
            uint32_t idx = max_sym;
            for (uint32_t step = 0; step < 65536; ++step) {
                std::vector<uint8_t> word;
                if (!reader(chain_addr + static_cast<uint64_t>(step) * 4u, 4, word, true) || word.size() < 4) {
                    break;
                }
                uint32_t val = rd32(word.data());
                ++idx;
                if (val & 1u) break;
            }
            return idx;
        }
    }
    return 0;
}

struct DwarfCursor {
    const uint8_t* data{nullptr};
    size_t size{0};
    size_t pos{0};

    [[nodiscard]] bool at_end() const noexcept { return pos >= size; }
    [[nodiscard]] bool has(size_t n) const noexcept { return pos <= size && n <= size - pos; }

    uint8_t read_u8(bool& ok) noexcept {
        if (!has(1)) { ok = false; return 0; }
        return data[pos++];
    }

    uint16_t read_u16(bool& ok) noexcept {
        if (!has(2)) { ok = false; return 0; }
        const uint16_t v = rd16(data + pos);
        pos += 2;
        return v;
    }

    uint32_t read_u32(bool& ok) noexcept {
        if (!has(4)) { ok = false; return 0; }
        const uint32_t v = rd32(data + pos);
        pos += 4;
        return v;
    }

    uint64_t read_u64(bool& ok) noexcept {
        if (!has(8)) { ok = false; return 0; }
        const uint64_t v = rd64(data + pos);
        pos += 8;
        return v;
    }

    uint64_t read_uint(size_t width, bool& ok) noexcept {
        if (!has(width)) { ok = false; return 0; }
        uint64_t v = 0;
        for (size_t i = 0; i < width && i < 8; ++i) {
            v |= static_cast<uint64_t>(data[pos + i]) << (i * 8u);
        }
        pos += width;
        return v;
    }

    uint64_t read_uleb128(bool& ok) noexcept {
        uint64_t result = 0;
        unsigned shift = 0;
        while (pos < size) {
            const uint8_t byte = data[pos++];
            if (shift < 64) {
                result |= static_cast<uint64_t>(byte & 0x7Fu) << shift;
            }
            if ((byte & 0x80u) == 0) return result;
            shift += 7;
            if (shift >= 70) { ok = false; return 0; }
        }
        ok = false;
        return 0;
    }

    int64_t read_sleb128(bool& ok) noexcept {
        uint64_t result = 0;
        unsigned shift = 0;
        uint8_t byte = 0;
        while (pos < size) {
            byte = data[pos++];
            if (shift < 64) {
                result |= static_cast<uint64_t>(byte & 0x7Fu) << shift;
            }
            shift += 7;
            if ((byte & 0x80u) == 0) {
                if (shift < 64 && (byte & 0x40u) != 0) {
                    result |= (~uint64_t{0}) << shift;
                }
                return static_cast<int64_t>(result);
            }
            if (shift >= 70) { ok = false; return 0; }
        }
        ok = false;
        return 0;
    }

    std::string read_cstr(bool& ok) {
        if (pos >= size) { ok = false; return {}; }
        const size_t start = pos;
        while (pos < size && data[pos] != 0) ++pos;
        if (pos >= size) { ok = false; return {}; }
        const size_t len = pos - start;
        ++pos; // consume NUL
        return std::string(reinterpret_cast<const char*>(data + start), len);
    }

    bool skip(size_t n) noexcept {
        if (!has(n)) return false;
        pos += n;
        return true;
    }
};

struct DwarfAttrSpec {
    uint64_t name{0};
    uint64_t form{0};
    int64_t implicit_const{0};
};

struct DwarfAbbrev {
    uint64_t code{0};
    uint64_t tag{0};
    bool has_children{false};
    std::vector<DwarfAttrSpec> attrs;
};

std::string read_str_at_offset(const std::vector<uint8_t>& strtab, uint64_t off) {
    if (off >= strtab.size()) return {};
    const size_t start = static_cast<size_t>(off);
    size_t end = start;
    while (end < strtab.size() && strtab[end] != 0) ++end;
    return std::string(reinterpret_cast<const char*>(strtab.data() + start), end - start);
}

std::vector<DwarfAbbrev> parse_dwarf_abbrev_table(const std::vector<uint8_t>& abbrev_sec, uint64_t offset) {
    std::vector<DwarfAbbrev> table;
    if (offset >= abbrev_sec.size()) return table;
    DwarfCursor cur{abbrev_sec.data(), abbrev_sec.size(), static_cast<size_t>(offset)};
    bool ok = true;
    while (ok && !cur.at_end()) {
        const uint64_t code = cur.read_uleb128(ok);
        if (!ok || code == 0) break;
        DwarfAbbrev entry;
        entry.code = code;
        entry.tag = cur.read_uleb128(ok);
        entry.has_children = (cur.read_u8(ok) != 0);
        if (!ok) break;
        while (ok && !cur.at_end()) {
            const uint64_t attr_name = cur.read_uleb128(ok);
            const uint64_t attr_form = cur.read_uleb128(ok);
            if (!ok) break;
            if (attr_name == 0 && attr_form == 0) break;
            int64_t impl_const = 0;
            if (attr_form == 0x21u) { // DW_FORM_implicit_const
                impl_const = cur.read_sleb128(ok);
                if (!ok) break;
            }
            entry.attrs.push_back({attr_name, attr_form, impl_const});
        }
        table.push_back(std::move(entry));
    }
    std::sort(table.begin(), table.end(), [](const DwarfAbbrev& a, const DwarfAbbrev& b) {
        return a.code < b.code;
    });
    return table;
}

const DwarfAbbrev* find_abbrev(const std::vector<DwarfAbbrev>& table, uint64_t code) {
    auto it = std::lower_bound(table.begin(), table.end(), code, [](const DwarfAbbrev& e, uint64_t c) {
        return e.code < c;
    });
    if (it != table.end() && it->code == code) return &(*it);
    return nullptr;
}

struct DwarfAttrValue {
    std::string str;
    uint64_t uint_val{0};
    bool has_str{false};
    bool has_uint{false};
    bool is_addr_form{false};
};

bool read_dwarf_attr_value(
    DwarfCursor& cur,
    uint64_t form,
    int64_t implicit_const,
    uint8_t addr_size,
    uint8_t offset_size,
    uint16_t cu_version,
    const std::vector<uint8_t>& debug_str,
    const std::vector<uint8_t>& debug_line_str,
    const std::vector<uint8_t>& debug_str_offsets,
    uint64_t cu_str_offsets_base,
    bool capture_value,
    DwarfAttrValue& out,
    int depth = 0)
{
    if (depth > 8) return false;
    bool ok = true;
    auto resolve_strx = [&](uint64_t idx) {
        if (!capture_value || debug_str_offsets.empty()) return;
        const size_t entry_off = static_cast<size_t>(cu_str_offsets_base + idx * offset_size);
        if (entry_off + offset_size > debug_str_offsets.size()) return;
        uint64_t str_off = 0;
        for (size_t i = 0; i < offset_size; ++i) {
            str_off |= static_cast<uint64_t>(debug_str_offsets[entry_off + i]) << (i * 8u);
        }
        out.str = read_str_at_offset(debug_str, str_off);
        out.has_str = !out.str.empty();
    };

    switch (form) {
        case 0x01u: // DW_FORM_addr
            out.uint_val = cur.read_uint(addr_size, ok);
            out.has_uint = ok;
            out.is_addr_form = true;
            return ok;
        case 0x03u: { // DW_FORM_block2
            const uint16_t len = cur.read_u16(ok);
            return ok && cur.skip(len);
        }
        case 0x04u: { // DW_FORM_block4
            const uint32_t len = cur.read_u32(ok);
            return ok && cur.skip(len);
        }
        case 0x05u: // DW_FORM_data2
            out.uint_val = cur.read_u16(ok);
            out.has_uint = ok;
            return ok;
        case 0x06u: // DW_FORM_data4
            out.uint_val = cur.read_u32(ok);
            out.has_uint = ok;
            return ok;
        case 0x07u: // DW_FORM_data8
            out.uint_val = cur.read_u64(ok);
            out.has_uint = ok;
            return ok;
        case 0x08u: { // DW_FORM_string
            std::string s = cur.read_cstr(ok);
            if (ok && capture_value) {
                out.str = std::move(s);
                out.has_str = true;
            }
            return ok;
        }
        case 0x09u:   // DW_FORM_block
        case 0x18u: { // DW_FORM_exprloc
            const uint64_t len = cur.read_uleb128(ok);
            return ok && cur.skip(static_cast<size_t>(len));
        }
        case 0x0Au: { // DW_FORM_block1
            const uint8_t len = cur.read_u8(ok);
            return ok && cur.skip(len);
        }
        case 0x0Bu: // DW_FORM_data1
        case 0x0Cu: // DW_FORM_flag
            out.uint_val = cur.read_u8(ok);
            out.has_uint = ok;
            return ok;
        case 0x0Du: // DW_FORM_sdata
            out.uint_val = static_cast<uint64_t>(cur.read_sleb128(ok));
            out.has_uint = ok;
            return ok;
        case 0x0Eu: { // DW_FORM_strp
            const uint64_t str_off = cur.read_uint(offset_size, ok);
            if (ok && capture_value) {
                out.str = read_str_at_offset(debug_str, str_off);
                out.has_str = true;
            }
            return ok;
        }
        case 0x0Fu: // DW_FORM_udata
            out.uint_val = cur.read_uleb128(ok);
            out.has_uint = ok;
            return ok;
        case 0x10u: { // DW_FORM_ref_addr
            const size_t sz = (cu_version == 2) ? addr_size : offset_size;
            return cur.skip(sz);
        }
        case 0x11u: return cur.skip(1); // DW_FORM_ref1
        case 0x12u: return cur.skip(2); // DW_FORM_ref2
        case 0x13u: return cur.skip(4); // DW_FORM_ref4
        case 0x14u: return cur.skip(8); // DW_FORM_ref8
        case 0x15u: { (void)cur.read_uleb128(ok); return ok; } // DW_FORM_ref_udata
        case 0x16u: { // DW_FORM_indirect
            const uint64_t actual = cur.read_uleb128(ok);
            if (!ok || actual == 0) return false;
            return read_dwarf_attr_value(
                cur, actual, implicit_const, addr_size, offset_size, cu_version,
                debug_str, debug_line_str, debug_str_offsets, cu_str_offsets_base,
                capture_value, out, depth + 1);
        }
        case 0x17u: // DW_FORM_sec_offset
            out.uint_val = cur.read_uint(offset_size, ok);
            out.has_uint = ok;
            return ok;
        case 0x19u: // DW_FORM_flag_present
            out.uint_val = 1;
            out.has_uint = true;
            return true;
        case 0x1Au: { // DW_FORM_strx
            const uint64_t idx = cur.read_uleb128(ok);
            if (ok) resolve_strx(idx);
            return ok;
        }
        case 0x1Bu: // DW_FORM_addrx
            (void)cur.read_uleb128(ok);
            return ok;
        case 0x1Cu: return cur.skip(4);           // DW_FORM_ref_sup4
        case 0x1Du: return cur.skip(offset_size); // DW_FORM_strp_sup
        case 0x1Eu: return cur.skip(16);          // DW_FORM_data16
        case 0x1Fu: { // DW_FORM_line_strp
            const uint64_t str_off = cur.read_uint(offset_size, ok);
            if (ok && capture_value) {
                out.str = read_str_at_offset(debug_line_str, str_off);
                out.has_str = true;
            }
            return ok;
        }
        case 0x20u: return cur.skip(8); // DW_FORM_ref_sig8
        case 0x21u: // DW_FORM_implicit_const
            out.uint_val = static_cast<uint64_t>(implicit_const);
            out.has_uint = true;
            return true;
        case 0x22u: // DW_FORM_loclistx
        case 0x23u: // DW_FORM_rnglistx
            (void)cur.read_uleb128(ok);
            return ok;
        case 0x24u: return cur.skip(8); // DW_FORM_ref_sup8
        case 0x25u: // DW_FORM_strx1
        case 0x26u: // DW_FORM_strx2
        case 0x27u: // DW_FORM_strx3
        case 0x28u: { // DW_FORM_strx4
            const uint64_t idx = cur.read_uint(static_cast<size_t>(form - 0x24u), ok);
            if (ok) resolve_strx(idx);
            return ok;
        }
        case 0x29u: // DW_FORM_addrx1
        case 0x2Au: // DW_FORM_addrx2
        case 0x2Bu: // DW_FORM_addrx3
        case 0x2Cu: // DW_FORM_addrx4
            return cur.skip(static_cast<size_t>(form - 0x28u));
        default:
            return false;
    }
}

void parse_dwarf_symbols(
    ELFInfo& info,
    const ReadRangeFn& reader,
    uintptr_t load_bias,
    bool prefer_file_offsets,
    std::unordered_set<std::string>& seen_symbols)
{
    constexpr size_t kMaxDwarfSection = 64u * 1024u * 1024u;
    auto find_sec_by_name = [&](const std::string& name) -> const ELFSection* {
        for (const auto& s : info.sections) {
            if (s.name == name) return &s;
        }
        return nullptr;
    };

    auto read_debug_sec = [&](const std::string& name) -> std::vector<uint8_t> {
        const auto* sec = find_sec_by_name(name);
        if (!sec || sec->size == 0 || sec->size > kMaxDwarfSection) return {};
        std::vector<uint8_t> buf;
        if (sec->file_offset != 0 && reader(sec->file_offset, static_cast<size_t>(sec->size), buf, false) &&
            buf.size() == sec->size) {
            return buf;
        }
        if (!prefer_file_offsets && sec->virtual_address != 0 &&
            reader(load_bias + sec->virtual_address, static_cast<size_t>(sec->size), buf, true) &&
            buf.size() == sec->size) {
            return buf;
        }
        return {};
    };

    const auto debug_info = read_debug_sec(".debug_info");
    const auto debug_abbrev = read_debug_sec(".debug_abbrev");
    if (debug_info.empty() || debug_abbrev.empty()) return;

    info.has_dwarf = true;
    const auto debug_str = read_debug_sec(".debug_str");
    const auto debug_line_str = read_debug_sec(".debug_line_str");
    const auto debug_str_offsets = read_debug_sec(".debug_str_offsets");

    size_t cu_offset = 0;
    while (cu_offset + 4 <= debug_info.size()) {
        DwarfCursor hdr{debug_info.data(), debug_info.size(), cu_offset};
        bool ok = true;
        uint64_t unit_len = hdr.read_u32(ok);
        if (!ok || unit_len == 0) break;
        uint8_t offset_size = 4;
        if (unit_len == 0xFFFFFFFFu) {
            offset_size = 8;
            unit_len = hdr.read_u64(ok);
            if (!ok) break;
        } else if (unit_len >= 0xFFFFFF00u) {
            break;
        }

        const size_t cu_end = hdr.pos + static_cast<size_t>(unit_len);
        if (cu_end > debug_info.size() || cu_end <= hdr.pos) break;

        const uint16_t version = hdr.read_u16(ok);
        if (!ok || version < 2 || version > 5) {
            cu_offset = cu_end;
            continue;
        }

        uint8_t addr_size = info.is_64bit ? 8 : 4;
        uint64_t abbrev_off = 0;
        if (version >= 5) {
            (void)hdr.read_u8(ok); // unit_type
            addr_size = hdr.read_u8(ok);
            abbrev_off = hdr.read_uint(offset_size, ok);
        } else {
            abbrev_off = hdr.read_uint(offset_size, ok);
            addr_size = hdr.read_u8(ok);
        }
        if (!ok || (addr_size != 4 && addr_size != 8)) {
            cu_offset = cu_end;
            continue;
        }

        const auto abbrevs = parse_dwarf_abbrev_table(debug_abbrev, abbrev_off);
        if (abbrevs.empty()) {
            cu_offset = cu_end;
            continue;
        }

        DwarfCursor cur{debug_info.data(), cu_end, hdr.pos};
        uint64_t cu_str_offsets_base = 0;
        bool cu_ok = true;
        while (cu_ok && !cur.at_end()) {
            const uint64_t abbrev_code = cur.read_uleb128(cu_ok);
            if (!cu_ok) break;
            if (abbrev_code == 0) continue;

            const auto* abbrev = find_abbrev(abbrevs, abbrev_code);
            if (!abbrev) break;

            const bool is_cu = (abbrev->tag == 0x11u);         // DW_TAG_compile_unit
            const bool is_subprogram = (abbrev->tag == 0x2Eu); // DW_TAG_subprogram

            std::string fn_name;
            std::string fn_linkage;
            uint64_t low_pc = 0;
            uint64_t high_pc = 0;
            bool has_low_pc = false;
            bool has_high_pc = false;
            bool high_pc_is_addr = false;
            bool is_declaration = false;

            for (const auto& attr : abbrev->attrs) {
                const bool want = is_cu || is_subprogram;
                DwarfAttrValue val;
                if (!read_dwarf_attr_value(
                        cur, attr.form, attr.implicit_const, addr_size, offset_size, version,
                        debug_str, debug_line_str, debug_str_offsets, cu_str_offsets_base,
                        want, val)) {
                    cu_ok = false;
                    break;
                }
                if (!want) continue;

                if (is_cu && attr.name == 0x72u && val.has_uint) { // DW_AT_str_offsets_base
                    cu_str_offsets_base = val.uint_val;
                } else if (is_subprogram) {
                    if (attr.name == 0x03u && val.has_str) { // DW_AT_name
                        fn_name = std::move(val.str);
                    } else if ((attr.name == 0x6Eu || attr.name == 0x2007u) && val.has_str) { // DW_AT_linkage_name
                        fn_linkage = std::move(val.str);
                    } else if (attr.name == 0x11u && val.has_uint) { // DW_AT_low_pc
                        low_pc = val.uint_val;
                        has_low_pc = true;
                    } else if (attr.name == 0x12u && val.has_uint) { // DW_AT_high_pc
                        high_pc = val.uint_val;
                        has_high_pc = true;
                        high_pc_is_addr = val.is_addr_form;
                    } else if (attr.name == 0x3Cu && val.has_uint && val.uint_val != 0) { // DW_AT_declaration
                        is_declaration = true;
                    }
                }
            }

            if (cu_ok && is_subprogram && !is_declaration && has_low_pc && low_pc != 0) {
                std::string chosen = !fn_name.empty() ? std::move(fn_name) : std::move(fn_linkage);
                if (!chosen.empty()) {
                    ++info.dwarf_function_count;
                    if (seen_symbols.insert(chosen).second) {
                        ELFSymbol sym;
                        sym.name = std::move(chosen);
                        sym.type = 2;    // STT_FUNC
                        sym.binding = 0; // STB_LOCAL
                        sym.value = low_pc;
                        sym.va = load_bias + static_cast<uintptr_t>(low_pc);
                        if (has_high_pc) {
                            sym.size = high_pc_is_addr
                                ? (high_pc > low_pc ? high_pc - low_pc : 0)
                                : high_pc;
                        }
                        sym.is_exported = false;
                        for (size_t idx = 0; idx < info.sections.size(); ++idx) {
                            const auto& s = info.sections[idx];
                            const uintptr_t cmp_addr = s.is_alloc ? sym.va : static_cast<uintptr_t>(low_pc);
                            if (s.virtual_address != 0 && s.size > 0 &&
                                cmp_addr >= s.virtual_address &&
                                cmp_addr < s.virtual_address + s.size) {
                                sym.section_index = static_cast<uint16_t>(idx);
                                break;
                            }
                        }
                        info.symbols.push_back(std::move(sym));
                    }
                }
            }
        }

        cu_offset = cu_end;
    }
}

std::optional<ELFInfo> parse_elf_core(
    const ReadRangeFn& reader,
    uintptr_t module_base,
    bool prefer_file_offsets)
{
    std::vector<uint8_t> ehdr;
    if (!reader(0, 64, ehdr, false) || ehdr.size() < 52) {
        return std::nullopt;
    }

    if (ehdr[0] != 0x7F || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') {
        return std::nullopt;
    }

    const uint8_t ei_class = ehdr[4];
    const uint8_t ei_data  = ehdr[5];
    if ((ei_class != 1 && ei_class != 2) || ei_data != 1) {
        return std::nullopt;
    }

    ELFInfo info;
    info.is_valid = true;
    info.is_64bit = (ei_class == 2);
    if (info.is_64bit && ehdr.size() < 64) return std::nullopt;

    info.type = rd16(ehdr.data() + 16);
    info.machine = rd16(ehdr.data() + 18);
    info.is_shared_object = (info.type == 3);
    info.type_name = elf_type_to_str(info.type);
    info.machine_name = elf_machine_to_str(info.machine);

    uint64_t e_entry = 0;
    uint64_t e_phoff = 0;
    uint64_t e_shoff = 0;
    uint16_t e_phentsize = 0;
    uint16_t e_phnum = 0;
    uint16_t e_shentsize = 0;
    uint16_t e_shnum = 0;
    uint16_t e_shstrndx = 0;

    if (info.is_64bit) {
        e_entry     = rd64(ehdr.data() + 24);
        e_phoff     = rd64(ehdr.data() + 32);
        e_shoff     = rd64(ehdr.data() + 40);
        e_phentsize = rd16(ehdr.data() + 54);
        e_phnum     = rd16(ehdr.data() + 56);
        e_shentsize = rd16(ehdr.data() + 58);
        e_shnum     = rd16(ehdr.data() + 60);
        e_shstrndx  = rd16(ehdr.data() + 62);
    } else {
        e_entry     = rd32(ehdr.data() + 24);
        e_phoff     = rd32(ehdr.data() + 28);
        e_shoff     = rd32(ehdr.data() + 32);
        e_phentsize = rd16(ehdr.data() + 42);
        e_phnum     = rd16(ehdr.data() + 44);
        e_shentsize = rd16(ehdr.data() + 46);
        e_shnum     = rd16(ehdr.data() + 48);
        e_shstrndx  = rd16(ehdr.data() + 50);
    }

    uintptr_t min_load_vaddr = UINTPTR_MAX;
    uintptr_t max_load_end   = 0;
    uint64_t dyn_vaddr       = 0;
    uint64_t dyn_offset      = 0;
    uint64_t dyn_size        = 0;

    // 1. Parse Program Headers
    if (e_phoff != 0 && e_phnum > 0 && e_phnum <= 256 && e_phentsize >= (info.is_64bit ? 56 : 32)) {
        std::vector<uint8_t> phdrs;
        const size_t total_ph_bytes = static_cast<size_t>(e_phnum) * e_phentsize;
        if (reader(e_phoff, total_ph_bytes, phdrs, false) && phdrs.size() >= total_ph_bytes) {
            for (uint16_t i = 0; i < e_phnum; ++i) {
                const uint8_t* p = phdrs.data() + static_cast<size_t>(i) * e_phentsize;
                ELFSegment seg;
                if (info.is_64bit) {
                    seg.type             = rd32(p + 0);
                    seg.flags            = rd32(p + 4);
                    seg.offset           = rd64(p + 8);
                    seg.virtual_address  = static_cast<uintptr_t>(rd64(p + 16));
                    seg.physical_address = static_cast<uintptr_t>(rd64(p + 24));
                    seg.file_size        = rd64(p + 32);
                    seg.memory_size      = rd64(p + 40);
                } else {
                    seg.type             = rd32(p + 0);
                    seg.offset           = rd32(p + 4);
                    seg.virtual_address  = static_cast<uintptr_t>(rd32(p + 8));
                    seg.physical_address = static_cast<uintptr_t>(rd32(p + 12));
                    seg.file_size        = rd32(p + 16);
                    seg.memory_size      = rd32(p + 20);
                    seg.flags            = rd32(p + 24);
                }
                seg.is_executable = (seg.flags & kPfExec) != 0;
                seg.is_writable   = (seg.flags & kPfWrite) != 0;
                seg.is_readable   = (seg.flags & kPfRead) != 0;

                if (seg.type == kPtLoad && seg.memory_size > 0) {
                    if (seg.virtual_address < min_load_vaddr) min_load_vaddr = seg.virtual_address;
                    const uintptr_t seg_end = seg.virtual_address + static_cast<uintptr_t>(seg.memory_size);
                    if (seg_end > max_load_end) max_load_end = seg_end;
                } else if (seg.type == kPtDynamic) {
                    dyn_vaddr  = seg.virtual_address;
                    dyn_offset = seg.offset;
                    dyn_size   = std::max(seg.file_size, seg.memory_size);
                }

                info.segments.push_back(std::move(seg));
            }
        }
    }

    if (min_load_vaddr == UINTPTR_MAX) min_load_vaddr = 0;

    uintptr_t load_bias = 0;
    if (module_base != 0) {
        if (module_base >= min_load_vaddr) {
            load_bias = module_base - min_load_vaddr;
        } else {
            load_bias = module_base;
        }
        info.image_base = module_base;
    } else {
        info.image_base = min_load_vaddr;
    }

    info.entry_point = e_entry ? (load_bias + static_cast<uintptr_t>(e_entry)) : 0;
    if (max_load_end > min_load_vaddr) {
        info.image_size = static_cast<size_t>(max_load_end - min_load_vaddr);
    }

    std::unordered_set<std::string> seen_symbols;

    // 2. Parse Section Headers (available in file buffers and preloaded section images)
    if (e_shoff != 0 && e_shnum > 0 && e_shnum <= 4096 && e_shentsize >= (info.is_64bit ? 64 : 40)) {
        std::vector<uint8_t> shdrs;
        const size_t total_sh_bytes = static_cast<size_t>(e_shnum) * e_shentsize;
        bool sh_read_ok = false;
        if (prefer_file_offsets) {
            sh_read_ok = reader(e_shoff, total_sh_bytes, shdrs, false);
        } else {
            // Try direct offset from module_base (in case tests map full image linearly)
            sh_read_ok = reader(e_shoff, total_sh_bytes, shdrs, false);
        }

        if (sh_read_ok && shdrs.size() >= total_sh_bytes) {
            for (uint16_t i = 0; i < e_shnum; ++i) {
                const uint8_t* s = shdrs.data() + static_cast<size_t>(i) * e_shentsize;
                ELFSection sec;
                uint32_t sh_name_off = rd32(s + 0);
                sec.type = rd32(s + 4);
                if (info.is_64bit) {
                    sec.flags           = rd64(s + 8);
                    sec.virtual_address = static_cast<uintptr_t>(rd64(s + 16));
                    sec.file_offset     = rd64(s + 24);
                    sec.size            = rd64(s + 32);
                    sec.link            = rd32(s + 40);
                    sec.entry_size      = rd64(s + 56);
                } else {
                    sec.flags           = rd32(s + 8);
                    sec.virtual_address = static_cast<uintptr_t>(rd32(s + 12));
                    sec.file_offset     = rd32(s + 16);
                    sec.size            = rd32(s + 20);
                    sec.link            = rd32(s + 24);
                    sec.entry_size      = rd32(s + 36);
                }
                sec.is_writable   = (sec.flags & kShfWrite) != 0;
                sec.is_alloc      = (sec.flags & kShfAlloc) != 0;
                sec.is_executable = (sec.flags & kShfExecInstr) != 0;
                sec.is_readable   = sec.is_alloc;
                if (sec.is_alloc && load_bias != 0) {
                    sec.virtual_address += load_bias;
                }
                sec.name = std::to_string(sh_name_off); // placeholder until shstrtab read
                info.sections.push_back(std::move(sec));
            }

            // Resolve section names from .shstrtab
            if (e_shstrndx < info.sections.size()) {
                const auto& shstr = info.sections[e_shstrndx];
                std::vector<uint8_t> shstr_bytes;
                if (shstr.size > 0 && shstr.size <= 4 * 1024 * 1024 &&
                    reader(shstr.file_offset, static_cast<size_t>(shstr.size), shstr_bytes, false)) {
                    for (auto& sec : info.sections) {
                        uint32_t off = static_cast<uint32_t>(std::stoul(sec.name));
                        sec.name = read_cstr_from_buf(shstr_bytes, off);
                    }
                } else {
                    for (auto& sec : info.sections) sec.name.clear();
                }
            } else {
                for (auto& sec : info.sections) sec.name.clear();
            }

            // Extract SHT_DYNSYM and SHT_SYMTAB symbols cleanly
            for (const auto& sec : info.sections) {
                if (sec.type != kShtDynsym && sec.type != kShtSymtab) continue;
                if (sec.link >= info.sections.size() || sec.size == 0 || sec.size > 32 * 1024 * 1024) continue;
                const auto& str_sec = info.sections[sec.link];
                if (str_sec.type != kShtStrtab || str_sec.size == 0 || str_sec.size > 32 * 1024 * 1024) continue;

                std::vector<uint8_t> sym_bytes, str_bytes;
                bool ok1 = prefer_file_offsets
                    ? reader(sec.file_offset, static_cast<size_t>(sec.size), sym_bytes, false)
                    : (sec.is_alloc && sec.virtual_address != 0
                        ? reader(sec.virtual_address, static_cast<size_t>(sec.size), sym_bytes, true)
                        : reader(sec.file_offset, static_cast<size_t>(sec.size), sym_bytes, false));
                bool ok2 = prefer_file_offsets
                    ? reader(str_sec.file_offset, static_cast<size_t>(str_sec.size), str_bytes, false)
                    : (str_sec.is_alloc && str_sec.virtual_address != 0
                        ? reader(str_sec.virtual_address, static_cast<size_t>(str_sec.size), str_bytes, true)
                        : reader(str_sec.file_offset, static_cast<size_t>(str_sec.size), str_bytes, false));

                if (ok1 && ok2) {
                    parse_symbol_table_bytes(
                        sym_bytes, str_bytes, info.is_64bit, load_bias,
                        sec.type == kShtDynsym, info.symbols, seen_symbols);
                }
            }
        }
    }

    // 3. Parse PT_DYNAMIC (critical for stripped live process images without section headers)
    if (dyn_size > 0 && dyn_size <= 1024 * 1024) {
        std::vector<uint8_t> dyn_bytes;
        const uint64_t read_at = prefer_file_offsets ? dyn_offset : (load_bias + dyn_vaddr);
        if (reader(read_at, static_cast<size_t>(dyn_size), dyn_bytes, !prefer_file_offsets)) {
            const size_t ent = info.is_64bit ? 16 : 8;
            uint64_t strtab_ptr = 0;
            uint64_t symtab_ptr = 0;
            uint64_t strsz      = 0;
            uint64_t hash_ptr   = 0;
            uint64_t gnuhash_ptr= 0;
            std::vector<uint64_t> needed_offsets;

            for (size_t off = 0; off + ent <= dyn_bytes.size(); off += ent) {
                int64_t tag = info.is_64bit
                    ? static_cast<int64_t>(rd64(dyn_bytes.data() + off))
                    : static_cast<int64_t>(static_cast<int32_t>(rd32(dyn_bytes.data() + off)));
                uint64_t val = info.is_64bit
                    ? rd64(dyn_bytes.data() + off + 8)
                    : rd32(dyn_bytes.data() + off + 4);
                if (tag == kDtNull) break;
                switch (tag) {
                    case kDtNeeded:  needed_offsets.push_back(val); break;
                    case kDtHash:    hash_ptr = val; break;
                    case kDtStrtab:  strtab_ptr = val; break;
                    case kDtSymtab:  symtab_ptr = val; break;
                    case kDtStrsz:   strsz = val; break;
                    case kDtGnuHash: gnuhash_ptr = val; break;
                    default: break;
                }
            }

            auto resolve_dyn_addr = [&](uint64_t p) -> uint64_t {
                if (prefer_file_offsets) return vaddr_to_offset(info, p);
                if (module_base != 0 && p < module_base) return load_bias + p;
                return p;
            };

            if (strtab_ptr != 0 && strsz > 0 && strsz <= 16 * 1024 * 1024) {
                std::vector<uint8_t> dynstr_bytes;
                if (reader(resolve_dyn_addr(strtab_ptr), static_cast<size_t>(strsz), dynstr_bytes, !prefer_file_offsets)) {
                    for (uint64_t noff : needed_offsets) {
                        std::string lib = read_cstr_from_buf(dynstr_bytes, static_cast<size_t>(noff));
                        if (!lib.empty()) info.needed_libraries.push_back(std::move(lib));
                    }

                    if (symtab_ptr != 0) {
                        uint32_t sym_count = 0;
                        if (prefer_file_offsets) {
                            // If section headers didn't yield symbols, compute via hash tables
                            uint64_t hoff = hash_ptr ? vaddr_to_offset(info, hash_ptr) : 0;
                            uint64_t ghoff = gnuhash_ptr ? vaddr_to_offset(info, gnuhash_ptr) : 0;
                            if (hoff) {
                                std::vector<uint8_t> hh;
                                if (reader(hoff, 8, hh, false) && hh.size() == 8) sym_count = rd32(hh.data() + 4);
                            } else if (ghoff) {
                                // Use gnu_hash via file offset reader
                                sym_count = probe_dynsym_count_from_hashes(
                                    [&](uint64_t a, size_t l, std::vector<uint8_t>& out, bool) {
                                        return reader(a, l, out, false);
                                    },
                                    0, ghoff, info.is_64bit, 0, 0);
                            }
                        } else {
                            sym_count = probe_dynsym_count_from_hashes(
                                reader, hash_ptr, gnuhash_ptr, info.is_64bit, load_bias, module_base);
                        }

                        if (sym_count == 0 && strtab_ptr > symtab_ptr) {
                            const size_t entsz = info.is_64bit ? 24 : 16;
                            uint64_t diff = strtab_ptr - symtab_ptr;
                            if (diff <= 4 * 1024 * 1024) {
                                sym_count = static_cast<uint32_t>(diff / entsz);
                            }
                        }

                        if (sym_count > 0 && sym_count <= 250000) {
                            const size_t symsz = static_cast<size_t>(sym_count) * (info.is_64bit ? 24u : 16u);
                            std::vector<uint8_t> dynsym_bytes;
                            if (reader(resolve_dyn_addr(symtab_ptr), symsz, dynsym_bytes, !prefer_file_offsets)) {
                                parse_symbol_table_bytes(
                                    dynsym_bytes, dynstr_bytes, info.is_64bit, load_bias,
                                    true, info.symbols, seen_symbols);
                            }
                        }
                    }
                }
            }
        }
    }

    parse_dwarf_symbols(info, reader, load_bias, prefer_file_offsets, seen_symbols);

    return info;
}

} // namespace

bool ELFAnalyzer::is_elf_magic(hal::IProcess& proc, uintptr_t module_base) {
    if (module_base == 0) return false;
    uint8_t magic[4]{};
    if (!proc.read_raw(module_base, magic, 4)) return false;
    return magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

std::optional<ELFInfo> ELFAnalyzer::analyze(hal::IProcess& proc, uintptr_t module_base) {
    if (!proc.is_attached() || module_base == 0) return std::nullopt;
    ReadRangeFn reader = [&](uint64_t addr_or_off, size_t len, std::vector<uint8_t>& out, bool is_vaddr) -> bool {
        out.resize(len);
        uintptr_t target = is_vaddr
            ? static_cast<uintptr_t>(addr_or_off)
            : (module_base + static_cast<uintptr_t>(addr_or_off));
        if (!is_vaddr && addr_or_off == 0) target = module_base;
        if (!proc.read_raw(target, out.data(), len)) {
            out.clear();
            return false;
        }
        return true;
    };
    return parse_elf_core(reader, module_base, false);
}

std::optional<ELFInfo> ELFAnalyzer::analyze_bytes(const std::vector<uint8_t>& elf_bytes, uintptr_t base_va) {
    if (elf_bytes.size() < 52) return std::nullopt;
    ReadRangeFn reader = [&](uint64_t off, size_t len, std::vector<uint8_t>& out, bool) -> bool {
        if (off >= elf_bytes.size() || len > elf_bytes.size() - static_cast<size_t>(off)) {
            out.clear();
            return false;
        }
        out.assign(
            elf_bytes.begin() + static_cast<std::ptrdiff_t>(off),
            elf_bytes.begin() + static_cast<std::ptrdiff_t>(off + len));
        return true;
    };
    return parse_elf_core(reader, base_va, true);
}

const ELFSection* ELFAnalyzer::find_section(const ELFInfo& info, const std::string& name) {
    for (const auto& s : info.sections) {
        if (s.name == name) return &s;
    }
    return nullptr;
}

const ELFSection* ELFAnalyzer::find_section_at(const ELFInfo& info, uintptr_t address) {
    for (const auto& s : info.sections) {
        if (s.virtual_address != 0 && s.size > 0 &&
            address >= s.virtual_address && address < s.virtual_address + s.size) {
            return &s;
        }
    }
    return nullptr;
}

const ELFSymbol* ELFAnalyzer::find_symbol_by_name(const ELFInfo& info, const std::string& name) {
    for (const auto& sym : info.symbols) {
        if (sym.name == name) return &sym;
    }
    return nullptr;
}

const ELFSymbol* ELFAnalyzer::find_symbol_by_address(const ELFInfo& info, uintptr_t address) {
    const ELFSymbol* best = nullptr;
    for (const auto& sym : info.symbols) {
        if (sym.va == 0) continue;
        if (sym.va == address) return &sym;
        if (sym.size > 0 && address >= sym.va && address < sym.va + sym.size) {
            if (!best || sym.va > best->va) best = &sym;
        }
    }
    return best;
}

} // namespace nce::debugger
