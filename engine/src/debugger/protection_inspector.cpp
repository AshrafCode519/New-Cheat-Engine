#include "../../include/debugger/protection_inspector.hpp"
#include "../../include/debugger/elf_analyzer.hpp"
#include "../../include/debugger/pe_analyzer.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <unordered_set>

namespace nce::debugger {

namespace {

std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool read_ptr_val(const hal::IProcess& proc, uintptr_t addr, uintptr_t& out) {
    out = 0;
    if (proc.pointer_size() == 4) {
        uint32_t v32 = 0;
        if (!proc.read_raw(addr, &v32, 4)) return false;
        out = v32;
        return true;
    }
    return proc.read_raw(addr, &out, sizeof(out));
}

bool address_in_modules(uintptr_t addr, const std::vector<hal::ModuleInfo>& mods) {
    if (addr == 0) return true;
    for (const auto& m : mods) {
        if (addr >= m.base_address && addr < m.base_address + m.size) return true;
    }
    return false;
}

} // namespace

ProtectionReport ProtectionInspector::inspect(hal::IProcess& process) {
    ProtectionReport rep;
    if (!process.is_attached()) {
        rep.summary = "Not attached to any process.";
        return rep;
    }

    static const std::unordered_set<std::string> kAntiDebugApis = {
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "ntsetinformationthread",
        "ntquerysysteminformation",
        "addvectoredexceptionhandler",
        "setunhandledexceptionfilter",
        "outputdebugstringa",
        "outputdebugstringw",
        "ptrace",
    };

    static const std::unordered_set<std::string> kTimingApis = {
        "queryperformancecounter",
        "gettickcount",
        "gettickcount64",
        "timegettime",
        "clock_gettime",
    };

    const auto modules = process.get_modules();
    for (const auto& mod : modules) {
        if (PEAnalyzer::is_pe_magic(process, mod.base_address)) {
            auto pe = PEAnalyzer::analyze(process, mod.base_address);
            if (!pe || !pe->is_valid) continue;

            for (const auto& imp_mod : pe->imports) {
                for (const auto& fn : imp_mod.functions) {
                    const std::string lf = lower_copy(fn.name);
                    if (kAntiDebugApis.count(lf)) {
                        rep.has_anti_debug_apis = true;
                        rep.findings.push_back({
                            "Anti-Debug",
                            "High",
                            fn.iat_va,
                            mod.name,
                            "Imports anti-debug API '" + imp_mod.module_name + "!" + fn.name + "'",
                            "Expect IsDebuggerPresent/PEB checks; prefer hardware watches or clean VEH attach."
                        });
                    } else if (kTimingApis.count(lf)) {
                        rep.has_timing_checks = true;
                        rep.findings.push_back({
                            "Timing Check",
                            "Info",
                            fn.iat_va,
                            mod.name,
                            "Uses timing API '" + imp_mod.module_name + "!" + fn.name + "'",
                            "Speedhack targets these APIs cleanly; anti-cheat may compare delta against RDTSC."
                        });
                    }

                    // Live IAT Hook check: verify IAT target address resolves inside a known loaded module
                    if (fn.iat_va != 0) {
                        uintptr_t target = 0;
                        if (read_ptr_val(process, fn.iat_va, target) && target != 0 &&
                            !address_in_modules(target, modules)) {
                            rep.has_iat_hooks = true;
                            rep.findings.push_back({
                                "IAT Hook",
                                "High",
                                fn.iat_va,
                                mod.name,
                                "IAT slot for '" + fn.name + "' points outside known modules",
                                "Likely hooked/trampolined import (anti-cheat or overlay hook)."
                            });
                        }
                    }
                }
            }

            for (const auto& sec : pe->sections) {
                if (sec.is_executable && sec.is_writable) {
                    rep.has_rwx_caves = true;
                    rep.findings.push_back({
                        "RWX Cave",
                        "Medium",
                        mod.base_address + sec.virtual_address,
                        mod.name,
                        "PE section '" + sec.name + "' has RWX permissions (packed or self-modifying code)",
                        "Section may unpack at runtime; anchor signatures after entry initialization."
                    });
                }
            }
        } else if (ELFAnalyzer::is_elf_magic(process, mod.base_address)) {
            auto elf = ELFAnalyzer::analyze(process, mod.base_address);
            if (!elf || !elf->is_valid) continue;
            for (const auto& sym : elf->symbols) {
                const std::string ls = lower_copy(sym.name);
                if (kAntiDebugApis.count(ls)) {
                    rep.has_anti_debug_apis = true;
                    rep.findings.push_back({
                        "Anti-Debug",
                        "High",
                        sym.va,
                        mod.name,
                        "References anti-debug symbol '" + sym.name + "'",
                        "Target checks ptrace/debugger status."
                    });
                }
            }
            for (const auto& seg : elf->segments) {
                if (seg.is_executable && seg.is_writable) {
                    rep.has_rwx_caves = true;
                    rep.findings.push_back({
                        "RWX Cave",
                        "Medium",
                        seg.virtual_address,
                        mod.name,
                        "ELF PT_LOAD segment is RWX",
                        "Possible JIT/packer runtime segment."
                    });
                }
            }
        }
    }

    // Check unbacked private RWX memory allocations (JIT / hidden anti-cheat shellcode / hooks)
    const auto regions = process.query_regions(
        hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess | hal::FilterFlags::ExcludeGuardPages);
    size_t private_rwx_count = 0;
    for (const auto& r : regions) {
        if (r.is_executable && r.is_writable && r.type == hal::MemoryType::Private) {
            ++private_rwx_count;
            if (private_rwx_count <= 8) {
                rep.has_rwx_caves = true;
                rep.findings.push_back({
                    "RWX Cave",
                    "Medium",
                    r.base_address,
                    "(private)",
                    "Unbacked Private RWX memory region",
                    "May hold injected hooks, JIT code (Mono/V8), or anti-cheat shellcode."
                });
            }
        }
    }

    int score = 0;
    if (rep.has_anti_debug_apis) score += 40;
    if (rep.has_iat_hooks)       score += 35;
    if (rep.has_rwx_caves)       score += 20;
    if (rep.has_timing_checks)   score += 10;
    rep.risk_score = std::min(100, score);

    std::ostringstream ss;
    ss << "Protection Risk: " << rep.risk_score << "/100 (" << rep.findings.size() << " findings"
       << (rep.has_anti_debug_apis ? ", anti-debug APIs" : "")
       << (rep.has_iat_hooks ? ", IAT hooks" : "")
       << (rep.has_rwx_caves ? ", RWX caves" : "")
       << ")";
    rep.summary = ss.str();
    return rep;
}

} // namespace nce::debugger
