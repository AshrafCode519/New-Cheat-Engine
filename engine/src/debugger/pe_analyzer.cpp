#include "../../include/debugger/pe_analyzer.hpp"
#include <cstring>
#include <algorithm>

namespace nce::debugger {

namespace {

std::string read_null_term_string(hal::IProcess& proc, uintptr_t address, size_t max_len = 256) {
    std::vector<char> buf(max_len, '\0');
    if (!proc.read_raw(address, buf.data(), max_len - 1)) {
        return "";
    }
    buf[max_len - 1] = '\0';
    return std::string(buf.data());
}

} // anonymous namespace

bool PEAnalyzer::is_pe_magic(const hal::IProcess& proc, uintptr_t module_base) {
    if (!proc.is_attached() || module_base == 0) return false;
    uint8_t dos[64]{};
    if (!proc.read_raw(module_base, dos, sizeof(dos))) return false;
    uint16_t mz = 0;
    std::memcpy(&mz, &dos[0], 2);
    if (mz != 0x5A4D) return false;
    int32_t lfanew = 0;
    std::memcpy(&lfanew, &dos[0x3C], 4);
    if (lfanew < 64 || lfanew > 0x1000) return false;
    uint32_t nt_sig = 0;
    if (!proc.read_raw(module_base + static_cast<uintptr_t>(lfanew), &nt_sig, 4)) return false;
    return nt_sig == 0x00004550u;
}

std::optional<PEInfo> PEAnalyzer::analyze(hal::IProcess& proc, uintptr_t module_base) {
    if (!proc.is_attached() || module_base == 0) {
        return std::nullopt;
    }

    // 1. Read DOS header
    uint8_t dos_header[64]{};
    if (!proc.read_raw(module_base, dos_header, sizeof(dos_header))) {
        return std::nullopt;
    }

    uint16_t e_magic = 0;
    std::memcpy(&e_magic, &dos_header[0], 2);
    if (e_magic != 0x5A4D) { // 'MZ'
        return std::nullopt;
    }

    int32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, &dos_header[0x3C], 4);
    if (e_lfanew < 64 || e_lfanew > 0x1000) {
        return std::nullopt;
    }

    // 2. Read PE signature and File Header
    const uintptr_t nt_header_addr = module_base + static_cast<uintptr_t>(e_lfanew);
    uint8_t nt_buf[4 + 20 + 240]{}; // Sig + FileHeader + OptionalHeader (large enough for 32 & 64)
    if (!proc.read_raw(nt_header_addr, nt_buf, sizeof(nt_buf))) {
        return std::nullopt;
    }

    uint32_t pe_sig = 0;
    std::memcpy(&pe_sig, &nt_buf[0], 4);
    if (pe_sig != 0x00004550) { // 'PE\0\0'
        return std::nullopt;
    }

    PEInfo info;
    info.is_valid = true;

    // File Header (at +4)
    uint16_t machine = 0;
    std::memcpy(&machine, &nt_buf[4], 2);
    uint16_t num_sections = 0;
    std::memcpy(&num_sections, &nt_buf[6], 2);
    uint16_t size_opt_header = 0;
    std::memcpy(&size_opt_header, &nt_buf[20], 2);

    // Optional Header (at +24)
    const size_t opt_offset = 24;
    uint16_t opt_magic = 0;
    std::memcpy(&opt_magic, &nt_buf[opt_offset], 2);

    info.is_64bit = (opt_magic == 0x020B);

    uint32_t entry_rva = 0;
    std::memcpy(&entry_rva, &nt_buf[opt_offset + 16], 4);
    info.entry_point = module_base + entry_rva;

    uint32_t image_size_u32 = 0;
    uint16_t subsystem_id = 0;
    uint32_t export_dir_rva = 0;
    uint32_t export_dir_size = 0;
    uint32_t import_dir_rva = 0;
    uint32_t import_dir_size = 0;

    if (info.is_64bit) {
        uint64_t img_base64 = 0;
        std::memcpy(&img_base64, &nt_buf[opt_offset + 24], 8);
        info.image_base = module_base != 0 ? module_base : img_base64;

        std::memcpy(&image_size_u32, &nt_buf[opt_offset + 56], 4);
        std::memcpy(&subsystem_id, &nt_buf[opt_offset + 68], 2);

        // Data directories: export at +112, import at +120
        std::memcpy(&export_dir_rva, &nt_buf[opt_offset + 112], 4);
        std::memcpy(&export_dir_size, &nt_buf[opt_offset + 116], 4);
        std::memcpy(&import_dir_rva, &nt_buf[opt_offset + 120], 4);
        std::memcpy(&import_dir_size, &nt_buf[opt_offset + 124], 4);
    } else {
        uint32_t img_base32 = 0;
        std::memcpy(&img_base32, &nt_buf[opt_offset + 28], 4);
        info.image_base = module_base != 0 ? module_base : img_base32;

        std::memcpy(&image_size_u32, &nt_buf[opt_offset + 56], 4);
        std::memcpy(&subsystem_id, &nt_buf[opt_offset + 68], 2);

        // Data directories: export at +96, import at +104
        std::memcpy(&export_dir_rva, &nt_buf[opt_offset + 96], 4);
        std::memcpy(&export_dir_size, &nt_buf[opt_offset + 100], 4);
        std::memcpy(&import_dir_rva, &nt_buf[opt_offset + 104], 4);
        std::memcpy(&import_dir_size, &nt_buf[opt_offset + 108], 4);
    }

    info.image_size = image_size_u32;
    switch (subsystem_id) {
        case 1: info.subsystem = "Native"; break;
        case 2: info.subsystem = "Windows GUI"; break;
        case 3: info.subsystem = "Windows Console (CUI)"; break;
        case 7: info.subsystem = "POSIX CUI"; break;
        default: info.subsystem = "Unknown (" + std::to_string(subsystem_id) + ")"; break;
    }

    // 3. Read Section Headers
    const uintptr_t sections_start = nt_header_addr + 4 + 20 + size_opt_header;
    const size_t max_sec_to_read = std::min<size_t>(num_sections, 64);
    for (size_t i = 0; i < max_sec_to_read; ++i) {
        uint8_t sec_buf[40]{};
        if (!proc.read_raw(sections_start + i * 40, sec_buf, 40)) break;

        PESection sec;
        char name_raw[9]{};
        std::memcpy(name_raw, &sec_buf[0], 8);
        sec.name = name_raw;

        std::memcpy(&sec.virtual_size, &sec_buf[8], 4);
        std::memcpy(&sec.virtual_address, &sec_buf[12], 4);
        std::memcpy(&sec.raw_size, &sec_buf[16], 4);
        std::memcpy(&sec.characteristics, &sec_buf[36], 4);

        sec.is_executable = (sec.characteristics & 0x20000000) != 0;
        sec.is_readable   = (sec.characteristics & 0x40000000) != 0;
        sec.is_writable   = (sec.characteristics & 0x80000000) != 0;

        info.sections.push_back(std::move(sec));
    }

    // 4. Parse Exports (if present)
    if (export_dir_rva != 0 && export_dir_size > 0) {
        const uintptr_t exp_dir_addr = module_base + export_dir_rva;
        uint8_t exp_dir_buf[40]{};
        if (proc.read_raw(exp_dir_addr, exp_dir_buf, sizeof(exp_dir_buf))) {
            uint32_t num_funcs = 0, num_names = 0;
            uint32_t rva_funcs = 0, rva_names = 0, rva_ordinals = 0;
            uint32_t base_ord = 0;

            std::memcpy(&base_ord, &exp_dir_buf[16], 4);
            std::memcpy(&num_funcs, &exp_dir_buf[20], 4);
            std::memcpy(&num_names, &exp_dir_buf[24], 4);
            std::memcpy(&rva_funcs, &exp_dir_buf[28], 4);
            std::memcpy(&rva_names, &exp_dir_buf[32], 4);
            std::memcpy(&rva_ordinals, &exp_dir_buf[36], 4);

            const size_t parse_count = std::min<size_t>(num_names, 16384);
            if (parse_count > 0 && rva_names != 0 && rva_ordinals != 0 && rva_funcs != 0) {
                std::vector<uint32_t> name_rvas(parse_count);
                std::vector<uint16_t> ordinals(parse_count);

                proc.read_raw(module_base + rva_names, name_rvas.data(), parse_count * sizeof(uint32_t));
                proc.read_raw(module_base + rva_ordinals, ordinals.data(), parse_count * sizeof(uint16_t));

                for (size_t i = 0; i < parse_count; ++i) {
                    if (name_rvas[i] == 0) continue;
                    std::string func_name = read_null_term_string(proc, module_base + name_rvas[i]);
                    if (func_name.empty()) continue;

                    uint16_t ord = ordinals[i];
                    uint32_t func_rva = 0;
                    if (proc.read_raw(module_base + rva_funcs + ord * sizeof(uint32_t), &func_rva, sizeof(func_rva))) {
                        PEExport exp;
                        exp.name = std::move(func_name);
                        exp.ordinal = static_cast<uint16_t>(base_ord + ord);
                        exp.rva = func_rva;
                        exp.va = module_base + func_rva;

                        // Check if forwarded
                        if (func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size) {
                            exp.is_forwarded = true;
                            exp.forwarder_name = read_null_term_string(proc, module_base + func_rva);
                        }

                        info.exports.push_back(std::move(exp));
                    }
                }
            }
        }
    }

    // 5. Parse Imports (if present)
    if (import_dir_rva != 0 && import_dir_size > 0) {
        uintptr_t cur_desc_addr = module_base + import_dir_rva;
        for (size_t mod_idx = 0; mod_idx < 64; ++mod_idx, cur_desc_addr += 20) {
            uint8_t desc_buf[20]{};
            if (!proc.read_raw(cur_desc_addr, desc_buf, 20)) break;

            uint32_t orig_first_thunk = 0, name_rva = 0, first_thunk = 0;
            std::memcpy(&orig_first_thunk, &desc_buf[0], 4);
            std::memcpy(&name_rva, &desc_buf[12], 4);
            std::memcpy(&first_thunk, &desc_buf[16], 4);

            if (name_rva == 0 && first_thunk == 0) break; // End of import descriptors

            std::string mod_name = read_null_term_string(proc, module_base + name_rva);
            if (mod_name.empty()) continue;

            PEImportModule import_mod;
            import_mod.module_name = std::move(mod_name);

            uint32_t thunk_rva = (orig_first_thunk != 0) ? orig_first_thunk : first_thunk;
            uintptr_t cur_thunk = module_base + thunk_rva;
            uintptr_t cur_iat = module_base + first_thunk;

            for (size_t fn_idx = 0; fn_idx < 256; ++fn_idx) {
                if (info.is_64bit) {
                    uint64_t entry_val = 0;
                    if (!proc.read_raw(cur_thunk, &entry_val, 8) || entry_val == 0) break;

                    PEImportFunction fn;
                    fn.iat_rva = static_cast<uint32_t>(first_thunk + fn_idx * 8);
                    fn.iat_va = cur_iat;

                    if (entry_val & 0x8000000000000000ULL) {
                        fn.ordinal = static_cast<uint16_t>(entry_val & 0xFFFF);
                        fn.name = "Ordinal#" + std::to_string(fn.ordinal);
                    } else {
                        // Pointer to IMAGE_IMPORT_BY_NAME (+2 for hint)
                        uintptr_t ibn_addr = module_base + static_cast<uintptr_t>(entry_val & 0x7FFFFFFF);
                        fn.name = read_null_term_string(proc, ibn_addr + 2);
                    }

                    import_mod.functions.push_back(std::move(fn));
                    cur_thunk += 8;
                    cur_iat += 8;
                } else {
                    uint32_t entry_val = 0;
                    if (!proc.read_raw(cur_thunk, &entry_val, 4) || entry_val == 0) break;

                    PEImportFunction fn;
                    fn.iat_rva = static_cast<uint32_t>(first_thunk + fn_idx * 4);
                    fn.iat_va = cur_iat;

                    if (entry_val & 0x80000000) {
                        fn.ordinal = static_cast<uint16_t>(entry_val & 0xFFFF);
                        fn.name = "Ordinal#" + std::to_string(fn.ordinal);
                    } else {
                        uintptr_t ibn_addr = module_base + static_cast<uintptr_t>(entry_val & 0x7FFFFFFF);
                        fn.name = read_null_term_string(proc, ibn_addr + 2);
                    }

                    import_mod.functions.push_back(std::move(fn));
                    cur_thunk += 4;
                    cur_iat += 4;
                }
            }

            info.imports.push_back(std::move(import_mod));
        }
    }

    return info;
}

std::optional<PEInfo> PEAnalyzer::analyze_bytes(const std::vector<uint8_t>& pe_bytes, uintptr_t base_va) {
    if (pe_bytes.size() < 64) return std::nullopt;

    uint16_t e_magic = 0;
    std::memcpy(&e_magic, pe_bytes.data(), 2);
    if (e_magic != 0x5A4D) return std::nullopt;

    int32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, pe_bytes.data() + 0x3C, 4);
    if (e_lfanew < 64 || static_cast<size_t>(e_lfanew + 24) > pe_bytes.size()) return std::nullopt;

    const size_t nt_off = static_cast<size_t>(e_lfanew);
    uint32_t pe_sig = 0;
    std::memcpy(&pe_sig, pe_bytes.data() + nt_off, 4);
    if (pe_sig != 0x00004550) return std::nullopt;

    PEInfo info;
    info.is_valid = true;

    uint16_t num_sections = 0;
    std::memcpy(&num_sections, pe_bytes.data() + nt_off + 6, 2);
    uint16_t size_opt_header = 0;
    std::memcpy(&size_opt_header, pe_bytes.data() + nt_off + 20, 2);

    const size_t opt_offset = nt_off + 24;
    if (opt_offset + 2 > pe_bytes.size()) return std::nullopt;

    uint16_t opt_magic = 0;
    std::memcpy(&opt_magic, pe_bytes.data() + opt_offset, 2);
    info.is_64bit = (opt_magic == 0x020B);

    if (info.is_64bit && opt_offset + 32 <= pe_bytes.size()) {
        uint64_t img_base64 = 0;
        std::memcpy(&img_base64, pe_bytes.data() + opt_offset + 24, 8);
        info.image_base = (base_va != 0) ? base_va : img_base64;
    } else if (!info.is_64bit && opt_offset + 32 <= pe_bytes.size()) {
        uint32_t img_base32 = 0;
        std::memcpy(&img_base32, pe_bytes.data() + opt_offset + 28, 4);
        info.image_base = (base_va != 0) ? base_va : img_base32;
    }

    // Read sections
    const size_t sec_start = opt_offset + size_opt_header;
    for (size_t i = 0; i < num_sections; ++i) {
        const size_t sec_off = sec_start + i * 40;
        if (sec_off + 40 > pe_bytes.size()) break;

        PESection sec;
        char name_raw[9]{};
        std::memcpy(name_raw, pe_bytes.data() + sec_off, 8);
        sec.name = name_raw;

        std::memcpy(&sec.virtual_size, pe_bytes.data() + sec_off + 8, 4);
        std::memcpy(&sec.virtual_address, pe_bytes.data() + sec_off + 12, 4);
        std::memcpy(&sec.raw_size, pe_bytes.data() + sec_off + 16, 4);
        std::memcpy(&sec.characteristics, pe_bytes.data() + sec_off + 36, 4);

        sec.is_executable = (sec.characteristics & 0x20000000) != 0;
        sec.is_readable   = (sec.characteristics & 0x40000000) != 0;
        sec.is_writable   = (sec.characteristics & 0x80000000) != 0;

        info.sections.push_back(std::move(sec));
    }

    return info;
}

const PESection* PEAnalyzer::find_section(const PEInfo& info, uintptr_t address) {
    if (!info.is_valid) return nullptr;
    const uintptr_t rva = (address >= info.image_base) ? (address - info.image_base) : address;

    for (const auto& sec : info.sections) {
        const size_t sz = sec.virtual_size != 0 ? sec.virtual_size : sec.raw_size;
        if (rva >= sec.virtual_address && rva < sec.virtual_address + sz) {
            return &sec;
        }
    }
    return nullptr;
}

const PEExport* PEAnalyzer::find_export_by_name(const PEInfo& info, const std::string& name) {
    for (const auto& exp : info.exports) {
        if (exp.name == name) return &exp;
    }
    return nullptr;
}

const PEExport* PEAnalyzer::find_export_by_address(const PEInfo& info, uintptr_t address) {
    for (const auto& exp : info.exports) {
        if (exp.va == address) return &exp;
    }
    return nullptr;
}

} // namespace nce::debugger
