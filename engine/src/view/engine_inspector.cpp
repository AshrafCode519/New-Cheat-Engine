#include "view/engine_inspector.hpp"
#include "debugger/elf_analyzer.hpp"
#include "debugger/pe_analyzer.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

namespace nce::view {

namespace {

bool icontains(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(
        hay.begin(), hay.end(),
        needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != hay.end();
}

std::string to_lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

uint16_t rd16(const uint8_t* p) { uint16_t v = 0; std::memcpy(&v, p, 2); return v; }
uint32_t rd32(const uint8_t* p) { uint32_t v = 0; std::memcpy(&v, p, 4); return v; }
int32_t  rdi32(const uint8_t* p) { int32_t v = 0; std::memcpy(&v, p, 4); return v; }

std::string read_cstr(const std::vector<uint8_t>& buf, uint32_t offset, uint32_t max_len = 512) {
    if (offset >= buf.size()) return {};
    const size_t end_cap = std::min<size_t>(buf.size(), static_cast<size_t>(offset) + max_len);
    size_t end = offset;
    while (end < end_cap && buf[end] != 0) ++end;
    return std::string(reinterpret_cast<const char*>(buf.data() + offset), end - offset);
}

void collect_module_exports(
    hal::IProcess& proc,
    uintptr_t base,
    const std::vector<std::string>& wanted,
    std::map<std::string, uintptr_t>& out)
{
    if (base == 0) return;
    if (debugger::ELFAnalyzer::is_elf_magic(proc, base)) {
        if (auto elf = debugger::ELFAnalyzer::analyze(proc, base)) {
            for (const auto& name : wanted) {
                if (auto* sym = debugger::ELFAnalyzer::find_symbol_by_name(*elf, name)) {
                    out[name] = sym->va;
                }
            }
        }
    } else if (auto pe = debugger::PEAnalyzer::analyze(proc, base)) {
        for (const auto& name : wanted) {
            if (auto* exp = debugger::PEAnalyzer::find_export_by_name(*pe, name)) {
                out[name] = exp->va;
            }
        }
    }
}

bool read_ptr(hal::IProcess& proc, uintptr_t addr, uintptr_t& out) {
    uint64_t v = 0;
    const size_t psz = proc.pointer_size() == 4 ? 4 : 8;
    if (!proc.read_raw(addr, &v, psz)) return false;
    out = static_cast<uintptr_t>(v);
    return true;
}

std::string decode_fname_entry_bytes(const uint8_t* bytes, uint16_t len, bool is_wide) {
    if (!bytes || len == 0 || len > 512) return {};
    if (!is_wide) {
        std::string s;
        s.reserve(len);
        for (uint16_t i = 0; i < len; ++i) {
            const uint8_t ch = bytes[i];
            if (ch == 0) break;
            s.push_back((ch >= 0x20 && ch < 0x7F) ? static_cast<char>(ch) : '?');
        }
        return s;
    }
    std::string s;
    s.reserve(len);
    for (uint16_t i = 0; i < len; ++i) {
        uint16_t wc = rd16(bytes + static_cast<size_t>(i) * 2u);
        if (wc == 0) break;
        s.push_back((wc >= 0x20 && wc < 0x7F) ? static_cast<char>(wc & 0x7F) : '?');
    }
    return s;
}

} // namespace

EngineDetection EngineInspector::detect(hal::IProcess& proc) {
    EngineDetection det;
    if (!proc.is_attached()) {
        det.details = "Not attached to target process.";
        return det;
    }

    auto modules = proc.get_modules();
    const hal::ModuleInfo* il2cpp_mod = nullptr;
    const hal::ModuleInfo* mono_mod   = nullptr;
    const hal::ModuleInfo* unity_mod  = nullptr;
    const hal::ModuleInfo* main_mod   = nullptr;

    for (const auto& mod : modules) {
        if (!main_mod) main_mod = &mod;
        const std::string lower = to_lower_copy(mod.name);
        if (lower == "gameassembly.dll" || lower == "gameassembly.so" || lower == "libil2cpp.so") {
            il2cpp_mod = &mod;
        } else if (lower.find("mono") != std::string::npos &&
                   (lower.find("bdwgc") != std::string::npos || lower.find("libmono") != std::string::npos || lower == "mono.dll")) {
            mono_mod = &mod;
        } else if (lower == "unityplayer.dll" || lower == "unityplayer.so") {
            unity_mod = &mod;
        }
    }

    if (il2cpp_mod) {
        det.kind = GameEngineKind::UnityIL2CPP;
        det.engine_name = "Unity (IL2CPP)";
        det.runtime_module = il2cpp_mod->name;
        det.runtime_base = il2cpp_mod->base_address;
        collect_module_exports(proc, il2cpp_mod->base_address, {
            "il2cpp_init",
            "il2cpp_domain_get",
            "il2cpp_domain_get_assemblies",
            "il2cpp_assembly_get_image",
            "il2cpp_image_get_class_count",
            "il2cpp_image_get_class",
            "il2cpp_class_from_name",
            "il2cpp_class_get_name",
            "il2cpp_class_get_namespace",
            "il2cpp_class_get_fields",
            "il2cpp_field_get_name",
            "il2cpp_field_get_offset"
        }, det.api_exports);
        std::ostringstream ss;
        ss << "Detected " << il2cpp_mod->name << " (" << det.api_exports.size() << " IL2CPP APIs resolved)";
        if (unity_mod) ss << "; player: " << unity_mod->name;
        det.details = ss.str();
        return det;
    }

    if (mono_mod) {
        det.kind = GameEngineKind::UnityMono;
        det.engine_name = "Unity (Mono)";
        det.runtime_module = mono_mod->name;
        det.runtime_base = mono_mod->base_address;
        collect_module_exports(proc, mono_mod->base_address, {
            "mono_get_root_domain",
            "mono_thread_attach",
            "mono_assembly_foreach",
            "mono_assembly_get_image",
            "mono_class_from_name",
            "mono_class_get_fields",
            "mono_field_get_name",
            "mono_field_get_offset",
            "mono_class_get_method_from_name"
        }, det.api_exports);
        std::ostringstream ss;
        ss << "Detected " << mono_mod->name << " (" << det.api_exports.size() << " Mono APIs resolved)";
        if (unity_mod) ss << "; player: " << unity_mod->name;
        det.details = ss.str();
        return det;
    }

    if (unity_mod) {
        det.kind = GameEngineKind::UnityMono;
        det.engine_name = "Unity";
        det.runtime_module = unity_mod->name;
        det.runtime_base = unity_mod->base_address;
        det.details = "Detected UnityPlayer runtime (" + unity_mod->name + ").";
        return det;
    }

    // Check modules for Unreal symbols/exports (GUObjectArray, GNames, NamePoolData)
    const std::vector<std::string> unreal_syms = {
        "GUObjectArray", "GNames", "NamePoolData",
        "?GUObjectArray@@3VFUObjectArray@@A",
        "?NamePoolData@@3VFNamePool@@A"
    };
    for (const auto& mod : modules) {
        std::map<std::string, uintptr_t> found;
        collect_module_exports(proc, mod.base_address, unreal_syms, found);
        if (!found.empty() || to_lower_copy(mod.name).find("unrealeditor") != std::string::npos ||
            to_lower_copy(mod.name).find("-win64-shipping") != std::string::npos) {
            det.kind = GameEngineKind::UnrealEngine;
            det.engine_name = "Unreal Engine";
            det.runtime_module = mod.name;
            det.runtime_base = mod.base_address;
            det.api_exports = std::move(found);
            for (const auto& [k, v] : det.api_exports) {
                if (k.find("GNames") != std::string::npos || k.find("NamePool") != std::string::npos) {
                    det.gnames_hint = v;
                } else if (k.find("GUObjectArray") != std::string::npos) {
                    det.gobjects_hint = v;
                }
            }
            det.details = "Detected Unreal Engine module " + mod.name;
            return det;
        }
    }

    if (main_mod) {
        det.runtime_module = main_mod->name;
        det.runtime_base = main_mod->base_address;
    }
    det.details = "No Unity or Unreal runtime module detected cleanly.";
    return det;
}

UnityMetadataReport EngineInspector::parse_unity_metadata_bytes(
    const std::vector<uint8_t>& bytes,
    const std::string& filter,
    size_t max_types)
{
    UnityMetadataReport report;
    if (bytes.size() < 0xAC) {
        report.error = "Metadata buffer too small (< 0xAC bytes).";
        return report;
    }

    report.sanity = rd32(bytes.data() + 0x00);
    report.version = rdi32(bytes.data() + 0x04);
    if (report.sanity != 0xFAB11BAF) {
        report.error = "Invalid IL2CPP global-metadata sanity magic (expected 0xFAB11BAF).";
        return report;
    }

    const uint32_t string_off = rd32(bytes.data() + 0x18);
    const uint32_t string_sz  = rd32(bytes.data() + 0x1C);
    const uint32_t fields_off = rd32(bytes.data() + 0x60);
    const uint32_t fields_sz  = rd32(bytes.data() + 0x64);
    const uint32_t types_off  = rd32(bytes.data() + 0xA0);
    const uint32_t types_sz   = rd32(bytes.data() + 0xA4);

    auto range_ok = [&](uint32_t off, uint32_t sz) {
        return static_cast<uint64_t>(off) + static_cast<uint64_t>(sz) <= bytes.size();
    };

    if (!range_ok(string_off, string_sz) || string_sz == 0) {
        report.error = "Invalid string table offset/size in metadata header.";
        return report;
    }
    if (!range_ok(types_off, types_sz)) {
        report.error = "Invalid typeDefinitions offset/size in metadata header.";
        return report;
    }
    if (!range_ok(fields_off, fields_sz)) {
        report.error = "Invalid fields offset/size in metadata header.";
        return report;
    }

    // Il2CppFieldDefinition is 12 bytes across IL2CPP v24-v31: { int32 nameIndex; int32 typeIndex; int32 token; }
    constexpr size_t kFieldStride = 12;
    report.total_fields = fields_sz / kFieldStride;

    // Candidate Il2CppTypeDefinition strides & fieldStart/field_count offsets by version:
    // - v29+: 88 bytes, fieldStart @ +0x24, field_count @ +0x44
    // - v27-v28: 88 or 92 bytes, fieldStart @ +0x28, field_count @ +0x48 (or +0x24/+0x44)
    // - v24: 100 or 104 bytes, fieldStart @ +0x2C, field_count @ +0x4C
    struct LayoutCandidate {
        size_t stride;
        size_t field_start_off;
        size_t field_count_off;
        size_t flags_off;
        size_t token_off;
    };

    std::vector<LayoutCandidate> candidates;
    if (report.version >= 29) {
        candidates.push_back({88, 0x24, 0x44, 0x3C, 0x38});
        candidates.push_back({84, 0x24, 0x44, 0x3C, 0x38});
        candidates.push_back({92, 0x28, 0x48, 0x40, 0x3C});
    } else if (report.version >= 27) {
        candidates.push_back({88, 0x28, 0x48, 0x40, 0x3C});
        candidates.push_back({92, 0x28, 0x48, 0x40, 0x3C});
        candidates.push_back({88, 0x24, 0x44, 0x3C, 0x38});
    } else {
        candidates.push_back({104, 0x2C, 0x4C, 0x44, 0x40});
        candidates.push_back({100, 0x2C, 0x4C, 0x44, 0x40});
        candidates.push_back({88, 0x24, 0x44, 0x3C, 0x38});
    }

    LayoutCandidate chosen = candidates.front();
    bool found_layout = false;
    for (const auto& cand : candidates) {
        if (cand.stride == 0 || (types_sz % cand.stride) != 0) continue;
        const size_t ntypes = types_sz / cand.stride;
        if (ntypes == 0) {
            chosen = cand;
            found_layout = true;
            break;
        }
        bool plausible = true;
        const size_t check_n = std::min<size_t>(ntypes, 32);
        for (size_t i = 0; i < check_n; ++i) {
            const uint8_t* td = bytes.data() + types_off + i * cand.stride;
            const uint32_t nidx = rd32(td + 0);
            const uint32_t nsidx = rd32(td + 4);
            const int32_t fstart = rdi32(td + cand.field_start_off);
            const uint16_t fcnt = rd16(td + cand.field_count_off);
            if (nidx >= string_sz || nsidx >= string_sz) {
                plausible = false;
                break;
            }
            if (fcnt > 0 && (fstart < 0 || static_cast<size_t>(fstart) + fcnt > report.total_fields)) {
                plausible = false;
                break;
            }
        }
        if (plausible) {
            chosen = cand;
            found_layout = true;
            break;
        }
    }

    if (!found_layout && types_sz > 0) {
        report.error = "Unsupported or misaligned Il2CppTypeDefinition stride for metadata version " +
                       std::to_string(report.version) + ".";
        return report;
    }

    report.valid = true;
    report.total_types = chosen.stride ? (types_sz / chosen.stride) : 0;

    for (size_t i = 0; i < report.total_types; ++i) {
        const uint8_t* td = bytes.data() + types_off + i * chosen.stride;
        const uint32_t name_idx = rd32(td + 0);
        const uint32_t ns_idx   = rd32(td + 4);
        if (name_idx >= string_sz || ns_idx >= string_sz) continue;

        std::string cls_name = read_cstr(bytes, string_off + name_idx);
        std::string cls_ns   = read_cstr(bytes, string_off + ns_idx);
        if (cls_name.empty()) continue;

        std::string full_name = cls_ns.empty() ? cls_name : (cls_ns + "." + cls_name);
        if (!icontains(full_name, filter)) continue;

        UnityTypeInfo info;
        info.name        = std::move(cls_name);
        info.namespaze   = std::move(cls_ns);
        info.field_start = rdi32(td + chosen.field_start_off);
        info.field_count = rd16(td + chosen.field_count_off);
        info.token       = rdi32(td + chosen.token_off);
        info.flags       = rd32(td + chosen.flags_off);

        if (info.field_count > 0 && info.field_start >= 0 &&
            static_cast<size_t>(info.field_start) + info.field_count <= report.total_fields) {
            const uint16_t cap_fields = std::min<uint16_t>(info.field_count, 512);
            info.fields.reserve(cap_fields);
            for (uint16_t f = 0; f < cap_fields; ++f) {
                const uint8_t* fd = bytes.data() + fields_off +
                                    (static_cast<size_t>(info.field_start) + f) * kFieldStride;
                const uint32_t fn_idx = rd32(fd + 0);
                if (fn_idx >= string_sz) continue;
                UnityFieldInfo field;
                field.name       = read_cstr(bytes, string_off + fn_idx);
                field.type_index = rdi32(fd + 4);
                field.token      = rdi32(fd + 8);
                info.fields.push_back(std::move(field));
            }
        }

        report.types.push_back(std::move(info));
        if (report.types.size() >= max_types) break;
    }

    return report;
}

UnityMetadataReport EngineInspector::parse_unity_metadata_file(
    const std::string& file_path,
    const std::string& filter,
    size_t max_types)
{
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        UnityMetadataReport r;
        r.error = "Unable to open metadata file: " + file_path;
        return r;
    }
    const auto sz = file.tellg();
    if (sz <= 0 || sz > 256 * 1024 * 1024) {
        UnityMetadataReport r;
        r.error = "Metadata file empty or exceeds 256 MB limit.";
        return r;
    }
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (!file.read(reinterpret_cast<char*>(buf.data()), sz)) {
        UnityMetadataReport r;
        r.error = "Failed reading metadata file bytes.";
        return r;
    }
    return parse_unity_metadata_bytes(buf, filter, max_types);
}

std::string EngineInspector::read_unreal_fname(
    hal::IProcess& proc,
    uintptr_t fname_pool_addr,
    uint32_t name_index,
    const UnrealOffsets& offsets)
{
    if (!proc.is_attached() || fname_pool_addr == 0) return {};

    // FName ComparisonIndex: upper 16 bits = BlockIndex, lower 16 bits = Offset (in FNameEntry stride units)
    const uint32_t block_idx = name_index >> 16;
    const uint32_t entry_off = (name_index & 0xFFFFu) * offsets.fname_stride;
    if (block_idx >= 8192) return {};

    uintptr_t block_ptr = 0;
    const size_t ptr_size = (proc.pointer_size() == 4) ? 4 : 8;
    if (!read_ptr(proc, fname_pool_addr + offsets.fname_pool_blocks_offset + block_idx * ptr_size, block_ptr) ||
        block_ptr == 0) {
        return {};
    }

    const uintptr_t entry_addr = block_ptr + entry_off;
    uint16_t header = 0;
    if (!proc.read_raw(entry_addr, &header, sizeof(header))) return {};

    const bool is_wide = (header & offsets.fname_wide_mask) != 0;
    const uint16_t len = static_cast<uint16_t>(header >> offsets.fname_len_shift);
    if (len == 0 || len > 256) return {};

    const size_t byte_len = static_cast<size_t>(len) * (is_wide ? 2u : 1u);
    std::vector<uint8_t> raw(byte_len);
    if (!proc.read_raw(entry_addr + 2, raw.data(), byte_len)) return {};

    return decode_fname_entry_bytes(raw.data(), len, is_wide);
}

std::vector<UnrealNameEntry> EngineInspector::scan_unreal_names(
    hal::IProcess& proc,
    uintptr_t fname_pool_addr,
    const UnrealOffsets& offsets,
    uint32_t max_blocks,
    size_t max_names)
{
    std::vector<UnrealNameEntry> out;
    if (!proc.is_attached() || fname_pool_addr == 0) return out;

    uint32_t current_block = 0;
    uint32_t current_cursor = 0;
    uint8_t pool_hdr[8]{};
    if (!proc.read_raw(fname_pool_addr + offsets.fname_pool_header_offset, pool_hdr, sizeof(pool_hdr))) {
        return out;
    }
    current_block = rd32(pool_hdr);
    current_cursor = rd32(pool_hdr + 4);

    const uint32_t blocks_to_read = std::min<uint32_t>(current_block + 1, std::min<uint32_t>(max_blocks, 512));
    const size_t ptr_size = (proc.pointer_size() == 4) ? 4 : 8;
    constexpr uint32_t kBlockSize = 65536u * 2u; // FNameEntry block capacity (64k strides * 2 bytes = 128 KB)

    for (uint32_t b = 0; b < blocks_to_read && out.size() < max_names; ++b) {
        uintptr_t block_ptr = 0;
        if (!read_ptr(proc, fname_pool_addr + offsets.fname_pool_blocks_offset + b * ptr_size, block_ptr) ||
            block_ptr == 0) {
            continue;
        }

        const uint32_t block_limit = (b == current_block)
            ? std::min<uint32_t>(current_cursor, kBlockSize)
            : kBlockSize;
        if (block_limit < 4) continue;

        std::vector<uint8_t> block_buf(block_limit);
        if (!proc.read_raw(block_ptr, block_buf.data(), block_limit)) continue;

        uint32_t offset = 0;
        while (offset + 2 <= block_buf.size() && out.size() < max_names) {
            const uint16_t header = rd16(block_buf.data() + offset);
            const bool is_wide = (header & offsets.fname_wide_mask) != 0;
            const uint16_t len = static_cast<uint16_t>(header >> offsets.fname_len_shift);
            if (len == 0) break;

            const size_t byte_len = static_cast<size_t>(len) * (is_wide ? 2u : 1u);
            if (offset + 2 + byte_len > block_buf.size()) break;

            std::string name = decode_fname_entry_bytes(block_buf.data() + offset + 2, len, is_wide);
            if (!name.empty()) {
                const uint32_t idx = (b << 16) | (offset / offsets.fname_stride);
                out.push_back({idx, block_ptr + offset, std::move(name)});
            }

            const size_t raw_advance = 2u + byte_len;
            const size_t aligned = ((raw_advance + offsets.fname_stride - 1u) / offsets.fname_stride) * offsets.fname_stride;
            offset += static_cast<uint32_t>(aligned);
        }
    }

    return out;
}

std::vector<UnrealObjectInfo> EngineInspector::dump_unreal_objects(
    hal::IProcess& proc,
    uintptr_t guobject_array_addr,
    uintptr_t fname_pool_addr,
    const UnrealOffsets& offsets,
    const std::string& filter,
    size_t max_objects)
{
    std::vector<UnrealObjectInfo> out;
    if (!proc.is_attached() || guobject_array_addr == 0) return out;

    uintptr_t chunks_ptr = 0;
    if (!read_ptr(proc, guobject_array_addr + offsets.obj_array_chunks_offset, chunks_ptr) || chunks_ptr == 0) {
        return out;
    }

    uint32_t num_elements = 0;
    uint32_t num_chunks = 0;
    if (!proc.read_raw(guobject_array_addr + offsets.obj_array_num_elements_offset, &num_elements, sizeof(num_elements)) ||
        !proc.read_raw(guobject_array_addr + offsets.obj_array_num_chunks_offset, &num_chunks, sizeof(num_chunks))) {
        return out;
    }

    if (num_elements == 0 || num_chunks == 0 || num_chunks > 2048) return out;

    const size_t ptr_size = (proc.pointer_size() == 4) ? 4 : 8;
    const size_t elements_per_chunk = offsets.obj_elements_per_chunk ? offsets.obj_elements_per_chunk : 65536;

    for (uint32_t c = 0; c < num_chunks && out.size() < max_objects; ++c) {
        uintptr_t chunk_addr = 0;
        if (!read_ptr(proc, chunks_ptr + c * ptr_size, chunk_addr) || chunk_addr == 0) continue;

        const uint32_t start_idx = c * static_cast<uint32_t>(elements_per_chunk);
        if (start_idx >= num_elements) break;

        const uint32_t count_in_chunk = std::min<uint32_t>(
            static_cast<uint32_t>(elements_per_chunk),
            num_elements - start_idx);
        // Cap chunk read reasonably if filtering huge lists
        const uint32_t iter_count = std::min<uint32_t>(count_in_chunk, static_cast<uint32_t>(std::max<size_t>(max_objects * 4, 4096)));

        for (uint32_t i = 0; i < iter_count && out.size() < max_objects; ++i) {
            const uintptr_t item_addr = chunk_addr + static_cast<size_t>(i) * offsets.uobject_item_stride;
            uintptr_t obj_ptr = 0;
            if (!read_ptr(proc, item_addr, obj_ptr) || obj_ptr == 0) continue;

            UnrealObjectInfo info;
            info.index = start_idx + i;
            info.address = obj_ptr;

            uint32_t name_idx = 0;
            proc.read_raw(obj_ptr + offsets.uobject_name_offset, &name_idx, sizeof(name_idx));
            read_ptr(proc, obj_ptr + offsets.uobject_class_offset, info.class_address);
            read_ptr(proc, obj_ptr + offsets.uobject_outer_offset, info.outer_address);
            info.name_index = name_idx;

            if (fname_pool_addr != 0) {
                info.name = read_unreal_fname(proc, fname_pool_addr, name_idx, offsets);
                if (info.class_address != 0) {
                    uint32_t cls_name_idx = 0;
                    if (proc.read_raw(info.class_address + offsets.uobject_name_offset, &cls_name_idx, sizeof(cls_name_idx))) {
                        info.class_name = read_unreal_fname(proc, fname_pool_addr, cls_name_idx, offsets);
                    }
                }
            }

            if (!filter.empty()) {
                if (!icontains(info.name, filter) && !icontains(info.class_name, filter)) {
                    continue;
                }
            }

            out.push_back(std::move(info));
        }
    }

    return out;
}

UnityMetadataReport EngineInspector::parse_unity_metadata_memory(
    hal::IProcess& proc,
    uintptr_t metadata_addr,
    const std::string& filter,
    size_t max_types)
{
    UnityMetadataReport report;
    if (!proc.is_attached()) {
        report.error = "Not attached to target process.";
        return report;
    }

    uintptr_t found_addr = metadata_addr;
    uint32_t needed_size = 0;

    auto validate_header_at = [&](uintptr_t addr, uint32_t& out_size) -> bool {
        uint8_t hdr[0xB0]{};
        if (!proc.read_raw(addr, hdr, sizeof(hdr))) return false;
        const uint32_t sanity = rd32(hdr + 0x00);
        const int32_t ver     = rdi32(hdr + 0x04);
        if (sanity != 0xFAB11BAF || ver < 16 || ver > 40) return false;
        const uint32_t str_end   = rd32(hdr + 0x18) + rd32(hdr + 0x1C);
        const uint32_t fld_end   = rd32(hdr + 0x60) + rd32(hdr + 0x64);
        const uint32_t typ_end   = rd32(hdr + 0xA0) + rd32(hdr + 0xA4);
        const uint32_t max_end   = std::max({str_end, fld_end, typ_end, 0x100u});
        if (max_end == 0 || max_end > 128 * 1024 * 1024) return false;
        out_size = max_end;
        return true;
    };

    if (found_addr != 0) {
        if (!validate_header_at(found_addr, needed_size)) {
            report.error = "No valid IL2CPP global-metadata header at specified address.";
            return report;
        }
    } else {
        // Scan readable committed regions for aligned 0xFAB11BAF header magic
        constexpr uint32_t kMagic = 0xFAB11BAF;
        constexpr uint32_t kMask = hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess | hal::FilterFlags::ExcludeGuardPages;
        for (const auto& reg : proc.query_regions(kMask)) {
            if (!reg.is_readable || reg.size < 0xB0 || reg.size > 256 * 1024 * 1024) continue;
            std::vector<uint8_t> buf(reg.size);
            if (!proc.read_raw(reg.base_address, buf.data(), buf.size())) continue;
            for (size_t off = 0; off + 0xB0 <= buf.size(); off += 4) {
                if (rd32(buf.data() + off) == kMagic) {
                    uint32_t sz = 0;
                    if (validate_header_at(reg.base_address + off, sz)) {
                        found_addr = reg.base_address + off;
                        needed_size = sz;
                        break;
                    }
                }
            }
            if (found_addr != 0) break;
        }
    }

    if (found_addr == 0 || needed_size == 0) {
        report.error = "Could not locate IL2CPP global-metadata.dat (0xFAB11BAF) in process RAM.";
        return report;
    }

    std::vector<uint8_t> mem(needed_size);
    if (!proc.read_raw(found_addr, mem.data(), needed_size)) {
        report.error = "Failed to read mapped global-metadata buffer from process RAM.";
        return report;
    }
    return parse_unity_metadata_bytes(mem, filter, max_types);
}

StructLayout EngineInspector::dissect_unity_object(
    hal::IProcess& proc,
    uintptr_t obj_addr,
    const Il2CppClassOffsets& offsets)
{
    StructLayout layout;
    layout.address = obj_addr;
    if (!proc.is_attached() || obj_addr == 0) return layout;

    auto read_remote_cstr = [&](uintptr_t ptr) -> std::string {
        if (ptr == 0) return {};
        char buf[128]{};
        if (!proc.read_raw(ptr, buf, sizeof(buf) - 1)) return {};
        buf[sizeof(buf) - 1] = '\0';
        return std::string(buf);
    };

    uintptr_t klass_ptr = 0;
    if (!read_ptr(proc, obj_addr, klass_ptr) || klass_ptr == 0) return layout;

    uintptr_t name_ptr = 0, ns_ptr = 0;
    read_ptr(proc, klass_ptr + offsets.class_name_ptr_offset, name_ptr);
    read_ptr(proc, klass_ptr + offsets.class_ns_ptr_offset, ns_ptr);
    const std::string cname = read_remote_cstr(name_ptr);
    const std::string cns   = read_remote_cstr(ns_ptr);
    layout.class_name = cns.empty() ? cname : (cns + "." + cname);

    uintptr_t fields_ptr = 0;
    uint16_t field_count = 0;
    if (!read_ptr(proc, klass_ptr + offsets.class_fields_ptr_offset, fields_ptr) ||
        !proc.read_raw(klass_ptr + offsets.class_field_count_offset, &field_count, sizeof(field_count)) ||
        fields_ptr == 0) {
        return layout;
    }

    const uint16_t cap = std::min<uint16_t>(field_count, 256);
    size_t max_end = 16;
    for (uint16_t i = 0; i < cap; ++i) {
        const uintptr_t finfo = fields_ptr + static_cast<size_t>(i) * offsets.field_info_stride;
        uintptr_t fn_ptr = 0;
        int32_t f_off = -1;
        uint32_t f_tok = 0;
        if (!read_ptr(proc, finfo + offsets.field_name_ptr_offset, fn_ptr)) break;
        proc.read_raw(finfo + offsets.field_offset_offset, &f_off, sizeof(f_off));
        proc.read_raw(finfo + offsets.field_token_offset, &f_tok, sizeof(f_tok));

        std::string fname = read_remote_cstr(fn_ptr);
        if (fname.empty() || f_off < 0 || f_off > 0x10000) continue;

        StructField sf;
        sf.offset = static_cast<size_t>(f_off);
        sf.size   = 4;
        sf.name   = std::move(fname);
        sf.type   = "int32_t";

        uint32_t iv = 0;
        if (proc.read_raw(obj_addr + sf.offset, &iv, sizeof(iv))) {
            float fv = 0.0f;
            std::memcpy(&fv, &iv, 4);
            std::ostringstream vs;
            vs << static_cast<int32_t>(iv);
            if (fv > -1e6f && fv < 1e6f && fv != 0.0f && (iv & 0x7FFFFFFF) > 0x38000000) {
                vs << " (float: " << fv << ")";
            }
            sf.value = vs.str();
        }
        std::ostringstream note;
        note << "IL2CPP token 0x" << std::hex << std::uppercase << f_tok;
        sf.note = note.str();
        max_end = std::max(max_end, sf.offset + sf.size);
        layout.fields.push_back(std::move(sf));
    }
    std::sort(layout.fields.begin(), layout.fields.end(),
              [](const StructField& a, const StructField& b) { return a.offset < b.offset; });
    layout.size = max_end;
    return layout;
}

UnrealGlobalsResult EngineInspector::find_unreal_globals(hal::IProcess& proc, uintptr_t scan_module_base) {
    UnrealGlobalsResult res;
    if (!proc.is_attached()) return res;

    // 1. Try export-based detection first
    auto det = detect(proc);
    if (det.gnames_hint != 0) {
        res.fname_pool_va = det.gnames_hint;
        res.found_names = true;
    }
    if (det.gobjects_hint != 0) {
        res.guobject_array_va = det.gobjects_hint;
        res.found_objects = true;
    }
    if (!det.runtime_module.empty()) res.source_module = det.runtime_module;

    auto validate_fname_pool = [&](uintptr_t cand) -> bool {
        if (cand == 0) return false;
        uint8_t hdr[8]{};
        if (!proc.read_raw(cand + 0x08, hdr, sizeof(hdr))) return false;
        const uint32_t cur_blk = rd32(hdr);
        const uint32_t cur_off = rd32(hdr + 4);
        if (cur_blk > 512 || cur_off > 0x40000) return false;
        return read_unreal_fname(proc, cand, 0) == "None";
    };

    auto validate_uobj_array = [&](uintptr_t cand, uintptr_t fn_pool) -> bool {
        if (cand == 0) return false;
        UnrealOffsets def;
        uintptr_t chunks_ptr = 0;
        uint32_t num_elems = 0, num_chunks = 0;
        if (!read_ptr(proc, cand + def.obj_array_chunks_offset, chunks_ptr) || chunks_ptr == 0) return false;
        if (!proc.read_raw(cand + def.obj_array_num_elements_offset, &num_elems, 4)) return false;
        if (!proc.read_raw(cand + def.obj_array_num_chunks_offset, &num_chunks, 4)) return false;
        if (num_elems == 0 || num_elems > 5000000 || num_chunks == 0 || num_chunks > 2048) return false;
        uintptr_t chunk0 = 0, obj0 = 0;
        if (!read_ptr(proc, chunks_ptr, chunk0) || chunk0 == 0) return false;
        if (!read_ptr(proc, chunk0, obj0) || obj0 == 0) return false;
        if (fn_pool != 0) {
            uint32_t nidx = 0;
            if (!proc.read_raw(obj0 + def.uobject_name_offset, &nidx, 4)) return false;
            return !read_unreal_fname(proc, fn_pool, nidx, def).empty();
        }
        return true;
    };

    auto validate_uworld = [&](uintptr_t uw_cand) -> bool {
        if (uw_cand == 0 || uw_cand == res.fname_pool_va || uw_cand == res.guobject_array_va) return false;
        UnrealOffsets def;
        uintptr_t level_ptr = 0;
        if (!read_ptr(proc, uw_cand + def.uworld_level_offset, level_ptr) || level_ptr == 0) return false;
        uintptr_t actors_data = 0;
        int32_t actor_count = 0;
        if (!read_ptr(proc, level_ptr + def.ulevel_actors_offset, actors_data) ||
            !proc.read_raw(level_ptr + def.ulevel_actors_offset + def.tarray_count_offset, &actor_count, 4)) {
            return false;
        }
        if (actors_data == 0 || actor_count <= 0 || actor_count > 200000) return false;
        uintptr_t actor0 = 0;
        if (!read_ptr(proc, actors_data, actor0) || actor0 == 0) return false;
        if (res.fname_pool_va != 0) {
            uint32_t nidx = 0;
            if (!proc.read_raw(actor0 + def.uobject_name_offset, &nidx, 4)) return false;
            return !read_unreal_fname(proc, res.fname_pool_va, nidx, def).empty();
        }
        return true;
    };

    for (const auto& [k, v] : det.api_exports) {
        if (k.find("GWorld") != std::string::npos && v != 0) {
            uintptr_t deref = 0;
            if (read_ptr(proc, v, deref) && validate_uworld(deref)) {
                res.gworld_va = deref;
                res.found_world = true;
                break;
            }
            if (validate_uworld(v)) {
                res.gworld_va = v;
                res.found_world = true;
                break;
            }
        }
    }
    if (res.found_names && res.found_objects && res.found_world) return res;

    // 2. Scan executable regions (or specified module) for x64 RIP-relative LEA/MOV operands:
    // Matches REX.W/R (0x48..0x4F) + opcode (0x8D LEA or 0x8B MOV) + ModRM (mod=00, rm=101 -> (modrm & 0xC7) == 0x05)
    std::vector<uintptr_t> candidates;
    constexpr uint32_t kExecMask = hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess |
                                   hal::FilterFlags::ExcludeGuardPages | hal::FilterFlags::ExecutableOnly;
    for (const auto& reg : proc.query_regions(kExecMask)) {
        if (scan_module_base != 0) {
            // Restrict to reasonable range near target module if specified
            if (reg.base_address < scan_module_base || reg.base_address > scan_module_base + 0x20000000ULL) {
                continue;
            }
        }
        if (reg.size < 7 || reg.size > 64 * 1024 * 1024) continue;
        std::vector<uint8_t> code(reg.size);
        if (!proc.read_raw(reg.base_address, code.data(), code.size())) continue;

        for (size_t i = 0; i + 7 <= code.size(); ++i) {
            const uint8_t b0 = code[i];
            const uint8_t b1 = code[i + 1];
            const uint8_t b2 = code[i + 2];
            if ((b0 >= 0x40 && b0 <= 0x4F) && (b1 == 0x8D || b1 == 0x8B) && ((b2 & 0xC7) == 0x05)) {
                int32_t disp = 0;
                std::memcpy(&disp, code.data() + i + 3, 4);
                const uintptr_t target = reg.base_address + i + 7 + static_cast<intptr_t>(disp);
                candidates.push_back(target);
            }
        }
    }

    if (!res.found_names) {
        for (uintptr_t c : candidates) {
            if (validate_fname_pool(c)) {
                res.fname_pool_va = c;
                res.found_names = true;
                break;
            }
        }
    }

    if (!res.found_objects) {
        for (uintptr_t c : candidates) {
            if (c != res.fname_pool_va && validate_uobj_array(c, res.fname_pool_va)) {
                res.guobject_array_va = c;
                res.found_objects = true;
                break;
            }
        }
    }

    // 3. Auto-detect GWorld (either UWorld** pointer global or direct UWorld* via PersistentLevel -> Actors)
    if (!res.found_world) {
        for (uintptr_t c : candidates) {
            uintptr_t deref = 0;
            if (read_ptr(proc, c, deref) && validate_uworld(deref)) {
                res.gworld_va = deref;
                res.found_world = true;
                break;
            }
            if (validate_uworld(c)) {
                res.gworld_va = c;
                res.found_world = true;
                break;
            }
        }
    }

    return res;
}

StructLayout EngineInspector::dissect_unreal_object(
    hal::IProcess& proc,
    uintptr_t uobject_addr,
    uintptr_t fname_pool_addr,
    const UnrealOffsets& offsets)
{
    StructLayout layout;
    layout.address = uobject_addr;
    if (!proc.is_attached() || uobject_addr == 0) return layout;

    uintptr_t cur_struct = 0;
    if (!read_ptr(proc, uobject_addr + offsets.uobject_class_offset, cur_struct) || cur_struct == 0) {
        return layout;
    }

    if (fname_pool_addr != 0) {
        uint32_t cls_nidx = 0;
        if (proc.read_raw(cur_struct + offsets.uobject_name_offset, &cls_nidx, sizeof(cls_nidx))) {
            layout.class_name = read_unreal_fname(proc, fname_pool_addr, cls_nidx, offsets);
        }
    }

    size_t max_end = 0x28;
    for (int depth = 0; depth < 16 && cur_struct != 0; ++depth) {
        uintptr_t ffield_ptr = 0;
        read_ptr(proc, cur_struct + offsets.ustruct_child_props_offset, ffield_ptr);

        for (int guard = 0; guard < 256 && ffield_ptr != 0; ++guard) {
            uint32_t fname_idx = 0;
            int32_t prop_off = -1;
            int32_t elem_sz = 0;
            proc.read_raw(ffield_ptr + offsets.ffield_name_offset, &fname_idx, sizeof(fname_idx));
            proc.read_raw(ffield_ptr + offsets.ffield_offset_internal, &prop_off, sizeof(prop_off));
            proc.read_raw(ffield_ptr + offsets.ffield_elem_size_offset, &elem_sz, sizeof(elem_sz));

            std::string ftype_name = "uint32_t";
            uintptr_t fcls_ptr = 0;
            if (fname_pool_addr != 0 &&
                read_ptr(proc, ffield_ptr + offsets.ffield_class_offset, fcls_ptr) && fcls_ptr != 0) {
                uint32_t fcls_nidx = 0;
                if (proc.read_raw(fcls_ptr + offsets.ffield_class_name_offset, &fcls_nidx, sizeof(fcls_nidx))) {
                    std::string fc = read_unreal_fname(proc, fname_pool_addr, fcls_nidx, offsets);
                    if (fc.find("Float") != std::string::npos) ftype_name = "float";
                    else if (fc.find("Double") != std::string::npos) ftype_name = "double";
                    else if (fc.find("Bool") != std::string::npos) ftype_name = "bool";
                    else if (fc.find("Object") != std::string::npos) ftype_name = "UObject*";
                    else if (fc.find("Int64") != std::string::npos) ftype_name = "int64_t";
                    else if (fc.find("Int") != std::string::npos) ftype_name = "int32_t";
                    else if (!fc.empty()) ftype_name = fc;
                }
            }

            std::string pname = fname_pool_addr
                ? read_unreal_fname(proc, fname_pool_addr, fname_idx, offsets)
                : "";
            if (!pname.empty() && prop_off >= 0 && prop_off < 0x10000) {
                StructField sf;
                sf.offset = static_cast<size_t>(prop_off);
                sf.size   = (elem_sz > 0 && elem_sz <= 8) ? static_cast<size_t>(elem_sz) : 4;
                sf.type   = ftype_name;
                sf.name   = std::move(pname);

                if (sf.type == "float" && sf.size >= 4) {
                    float v = 0;
                    if (proc.read_raw(uobject_addr + sf.offset, &v, 4)) sf.value = std::to_string(v);
                } else if (sf.type == "double" && sf.size >= 8) {
                    double v = 0;
                    if (proc.read_raw(uobject_addr + sf.offset, &v, 8)) sf.value = std::to_string(v);
                } else if (sf.type == "UObject*") {
                    uintptr_t p = 0;
                    if (read_ptr(proc, uobject_addr + sf.offset, p)) {
                        std::ostringstream ss; ss << "0x" << std::hex << std::uppercase << p;
                        sf.value = ss.str();
                        sf.child_pointer = p;
                    }
                } else {
                    int32_t v = 0;
                    if (proc.read_raw(uobject_addr + sf.offset, &v, 4)) sf.value = std::to_string(v);
                }

                max_end = std::max(max_end, sf.offset + sf.size);
                layout.fields.push_back(std::move(sf));
            }

            uintptr_t next_ff = 0;
            if (!read_ptr(proc, ffield_ptr + offsets.ffield_next_offset, next_ff) || next_ff == ffield_ptr) {
                break;
            }
            ffield_ptr = next_ff;
        }

        uintptr_t super_ptr = 0;
        if (!read_ptr(proc, cur_struct + offsets.ustruct_super_offset, super_ptr) || super_ptr == cur_struct) {
            break;
        }
        cur_struct = super_ptr;
    }

    std::sort(layout.fields.begin(), layout.fields.end(),
              [](const StructField& a, const StructField& b) { return a.offset < b.offset; });
    layout.size = max_end;
    return layout;
}

std::vector<UnrealActorInfo> EngineInspector::dump_unreal_actors(
    hal::IProcess& proc,
    uintptr_t uworld_addr,
    uintptr_t fname_pool_addr,
    const UnrealOffsets& offsets,
    size_t max_actors)
{
    std::vector<UnrealActorInfo> out;
    if (!proc.is_attached() || uworld_addr == 0) return out;

    uintptr_t level_ptr = 0;
    if (!read_ptr(proc, uworld_addr + offsets.uworld_level_offset, level_ptr) || level_ptr == 0) {
        return out;
    }

    uintptr_t actors_data = 0;
    int32_t actor_count = 0;
    if (!read_ptr(proc, level_ptr + offsets.ulevel_actors_offset, actors_data) ||
        !proc.read_raw(level_ptr + offsets.ulevel_actors_offset + offsets.tarray_count_offset, &actor_count, sizeof(actor_count)) ||
        actors_data == 0 || actor_count <= 0) {
        return out;
    }

    const size_t ptr_size = (proc.pointer_size() == 4) ? 4 : 8;
    const uint32_t cap = static_cast<uint32_t>(std::min<size_t>(static_cast<size_t>(actor_count), max_actors));

    for (uint32_t i = 0; i < cap; ++i) {
        uintptr_t actor_ptr = 0;
        if (!read_ptr(proc, actors_data + i * ptr_size, actor_ptr) || actor_ptr == 0) continue;

        UnrealActorInfo info;
        info.index = i;
        info.address = actor_ptr;

        if (fname_pool_addr != 0) {
            uint32_t nidx = 0;
            if (proc.read_raw(actor_ptr + offsets.uobject_name_offset, &nidx, sizeof(nidx))) {
                info.name = read_unreal_fname(proc, fname_pool_addr, nidx, offsets);
            }
            uintptr_t cls_ptr = 0;
            if (read_ptr(proc, actor_ptr + offsets.uobject_class_offset, cls_ptr) && cls_ptr != 0) {
                uint32_t cls_nidx = 0;
                if (proc.read_raw(cls_ptr + offsets.uobject_name_offset, &cls_nidx, sizeof(cls_nidx))) {
                    info.class_name = read_unreal_fname(proc, fname_pool_addr, cls_nidx, offsets);
                }
            }
        }

        uintptr_t root_comp = 0;
        if (read_ptr(proc, actor_ptr + offsets.actor_root_comp_offset, root_comp) && root_comp != 0) {
            if (offsets.lwc_double_coords) {
                double xyz[3]{};
                if (proc.read_raw(root_comp + offsets.scene_comp_location_offset, xyz, sizeof(xyz))) {
                    info.has_location = true;
                    info.x = xyz[0]; info.y = xyz[1]; info.z = xyz[2];
                }
            } else {
                float xyz[3]{};
                if (proc.read_raw(root_comp + offsets.scene_comp_location_offset, xyz, sizeof(xyz))) {
                    info.has_location = true;
                    info.x = xyz[0]; info.y = xyz[1]; info.z = xyz[2];
                }
            }
        }

        out.push_back(std::move(info));
    }

    return out;
}

UnrealCalibrationResult EngineInspector::calibrate_unreal_offsets(
    hal::IProcess& proc,
    uintptr_t world_or_actor_addr,
    uintptr_t fname_pool_addr,
    const UnrealOffsets& seed)
{
    UnrealCalibrationResult res;
    res.offsets = seed;
    if (!proc.is_attached() || world_or_actor_addr == 0 || fname_pool_addr == 0) return res;

    uintptr_t actor_addr = 0;

    // 1. Check if sample object looks like a UWorld (has PersistentLevel)
    auto world_lay = dissect_unreal_object(proc, world_or_actor_addr, fname_pool_addr, res.offsets);
    uintptr_t level_ptr = 0;
    for (const auto& f : world_lay.fields) {
        if (f.name == "PersistentLevel" && f.child_pointer != 0) {
            res.offsets.uworld_level_offset = f.offset;
            level_ptr = f.child_pointer;
            std::ostringstream ss;
            ss << "UWorld::PersistentLevel calibrated at +0x" << std::hex << f.offset;
            res.notes.push_back(ss.str());
            break;
        }
    }
    if (level_ptr == 0 && read_ptr(proc, world_or_actor_addr + res.offsets.uworld_level_offset, level_ptr) && level_ptr != 0) {
        auto lvl_lay = dissect_unreal_object(proc, level_ptr, fname_pool_addr, res.offsets);
        if (lvl_lay.class_name.find("Level") == std::string::npos) level_ptr = 0;
    }

    // 2. Locate ULevel::Actors TArray and grab Actor[0]
    if (level_ptr != 0) {
        static constexpr size_t kLevelCand[] = {0x98, 0xA0, 0xA8, 0x88, 0x90, 0xB0};
        for (size_t off : kLevelCand) {
            uintptr_t arr_data = 0;
            int32_t arr_cnt = 0;
            uintptr_t a0 = 0;
            if (read_ptr(proc, level_ptr + off, arr_data) && arr_data != 0 &&
                proc.read_raw(level_ptr + off + res.offsets.tarray_count_offset, &arr_cnt, 4) &&
                arr_cnt > 0 && arr_cnt < 200000 &&
                read_ptr(proc, arr_data, a0) && a0 != 0) {
                uint32_t nidx = 0;
                if (proc.read_raw(a0 + res.offsets.uobject_name_offset, &nidx, 4) &&
                    !read_unreal_fname(proc, fname_pool_addr, nidx, res.offsets).empty()) {
                    res.offsets.ulevel_actors_offset = off;
                    actor_addr = a0;
                    std::ostringstream ss;
                    ss << "ULevel::Actors calibrated at +0x" << std::hex << off;
                    res.notes.push_back(ss.str());
                    break;
                }
            }
        }
    }

    if (actor_addr == 0) actor_addr = world_or_actor_addr;

    // 3. Dissect sample AActor to find RootComponent offset
    auto actor_lay = dissect_unreal_object(proc, actor_addr, fname_pool_addr, res.offsets);
    uintptr_t root_comp = 0;
    for (const auto& f : actor_lay.fields) {
        if (f.name == "RootComponent") {
            res.offsets.actor_root_comp_offset = f.offset;
            root_comp = f.child_pointer;
            std::ostringstream ss;
            ss << "AActor::RootComponent calibrated at +0x" << std::hex << f.offset;
            res.notes.push_back(ss.str());
            break;
        }
    }
    if (root_comp == 0) {
        read_ptr(proc, actor_addr + res.offsets.actor_root_comp_offset, root_comp);
    }

    // 4. Dissect USceneComponent to find RelativeLocation offset + UE5 LWC double detection
    if (root_comp != 0) {
        auto root_lay = dissect_unreal_object(proc, root_comp, fname_pool_addr, res.offsets);
        for (const auto& f : root_lay.fields) {
            if (f.name == "RelativeLocation") {
                res.offsets.scene_comp_location_offset = f.offset;
                const bool is_lwc = (f.size >= 24) || (f.type.find("Double") != std::string::npos) ||
                                    (f.type == "double");
                res.offsets.lwc_double_coords = is_lwc;
                std::ostringstream ss;
                ss << "USceneComponent::RelativeLocation at +0x" << std::hex << f.offset
                   << (is_lwc ? " (UE5 LWC Double3 24B)" : " (Float3 12B)");
                res.notes.push_back(ss.str());
                break;
            }
        }
    }

    res.ok = !res.notes.empty();
    return res;
}

} // namespace nce::view
