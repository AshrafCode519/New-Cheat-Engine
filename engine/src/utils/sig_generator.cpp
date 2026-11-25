#include "../../include/utils/sig_generator.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/debugger/disassembler.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace nce::utils {

namespace {

// Counts occurrences of an AOB pattern in a memory buffer
size_t count_pattern_matches(
    const uint8_t* data, size_t data_size,
    const std::vector<uint8_t>& pattern_bytes,
    const std::vector<bool>& mask
) {
    if (data_size < pattern_bytes.size() || pattern_bytes.empty()) return 0;
    size_t matches = 0;
    const size_t limit = data_size - pattern_bytes.size();

    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_bytes.size(); ++j) {
            if (mask[j] && data[i + j] != pattern_bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            ++matches;
            if (matches > 1) return matches; // Early exit once we know it's not unique
        }
    }
    return matches;
}

} // anonymous namespace

std::vector<SignatureGenerator::ReadableSlice> SignatureGenerator::read_module_slices(
    const hal::IProcess& process,
    const hal::ModuleInfo& mod
) {
    std::vector<ReadableSlice> slices;
    if (!process.is_attached() || mod.base_address == 0 || mod.size == 0 || mod.size > 256u * 1024u * 1024u) {
        return slices;
    }

    const uintptr_t mod_begin = mod.base_address;
    const uintptr_t mod_end = mod.base_address + mod.size;
    constexpr uint32_t kFilter =
        hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess | hal::FilterFlags::ExcludeGuardPages;

    const auto regions = process.query_regions(kFilter);
    auto append_range = [&](uintptr_t r_begin, uintptr_t r_end) {
        if (r_end <= r_begin) return;
        const size_t total = static_cast<size_t>(r_end - r_begin);
        ReadableSlice slice;
        slice.base_address = r_begin;
        slice.bytes.resize(total);
        if (process.read_raw(r_begin, slice.bytes.data(), total)) {
            slices.push_back(std::move(slice));
            return;
        }
        // Fallback: read page-by-page across partial gaps so one unreadable page doesn't discard the region
        constexpr size_t kPage = 4096;
        ReadableSlice cur;
        for (size_t off = 0; off < total; off += kPage) {
            const size_t chunk = std::min(kPage, total - off);
            uint8_t page_buf[kPage]{};
            if (process.read_raw(r_begin + off, page_buf, chunk)) {
                if (cur.bytes.empty()) cur.base_address = r_begin + off;
                cur.bytes.insert(cur.bytes.end(), page_buf, page_buf + chunk);
            } else if (!cur.bytes.empty()) {
                slices.push_back(std::move(cur));
                cur = {};
            }
        }
        if (!cur.bytes.empty()) slices.push_back(std::move(cur));
    };

    for (const auto& reg : regions) {
        if (!reg.is_readable || !reg.is_committed || reg.is_guard || reg.size == 0) continue;
        const uintptr_t lo = std::max(mod_begin, reg.base_address);
        const uintptr_t hi = std::min(mod_end, reg.end_address());
        if (lo < hi) {
            // Coalesce adjacent readable slices so patterns spanning section boundaries still match
            if (!slices.empty() && slices.back().base_address + slices.back().bytes.size() == lo) {
                const size_t prev_sz = slices.back().bytes.size();
                const size_t add_sz = static_cast<size_t>(hi - lo);
                slices.back().bytes.resize(prev_sz + add_sz);
                if (!process.read_raw(lo, slices.back().bytes.data() + prev_sz, add_sz)) {
                    slices.back().bytes.resize(prev_sz);
                    append_range(lo, hi);
                }
            } else {
                append_range(lo, hi);
            }
        }
    }

    if (slices.empty()) {
        append_range(mod_begin, mod_end);
    }
    return slices;
}

std::optional<SignatureGenerator::GeneratedSig> SignatureGenerator::generate(
    const hal::IProcess& process,
    uintptr_t address,
    size_t max_bytes
) {
    if (!process.is_attached() || address == 0) return std::nullopt;

    // Find the module containing `address`
    const auto modules = process.get_modules();
    const hal::ModuleInfo* host_module = nullptr;
    for (const auto& m : modules) {
        if (address >= m.base_address && address < m.base_address + m.size) {
            host_module = &m;
            break;
        }
    }

    // Read instructions at `address`
    std::vector<uint8_t> code_buffer(max_bytes + 32, 0);
    if (!process.read_raw(address, code_buffer.data(), code_buffer.size())) {
        return std::nullopt;
    }

    auto instructions = debugger::Disassembler::disassemble_range(
        code_buffer.data(), code_buffer.size(), address, 16
    );

    if (instructions.empty()) return std::nullopt;

    std::vector<ReadableSlice> module_slices;
    if (host_module) {
        module_slices = read_module_slices(process, *host_module);
    }

    std::vector<uint8_t> pattern_bytes;
    std::vector<bool> pattern_mask;

    GeneratedSig best_sig;

    for (const auto& inst : instructions) {
        if (pattern_bytes.size() >= max_bytes) break;

        // Inspect instruction to mask relative displacements
        bool has_rel32 = false;
        // Check for calls, jumps, or rip-relative memory references
        if (inst.mnemonic == "call" || inst.mnemonic == "jmp" ||
            inst.mnemonic.rfind("j", 0) == 0 || // conditional jumps (je, jne, jg, etc.)
            inst.operands.find("[rip") != std::string::npos) {
            if (inst.bytes.size() >= 5) {
                has_rel32 = true;
            }
        }

        for (size_t b = 0; b < inst.bytes.size(); ++b) {
            if (pattern_bytes.size() >= max_bytes) break;

            pattern_bytes.push_back(inst.bytes[b]);

            // If instruction has rel32, mask the last 4 bytes as wildcards
            if (has_rel32 && b >= inst.bytes.size() - 4) {
                pattern_mask.push_back(false); // wildcard '?'
            } else {
                pattern_mask.push_back(true);  // exact byte
            }
        }

        // Test uniqueness across all readable slices of the host module
        size_t matches = 0;
        for (const auto& slice : module_slices) {
            matches += count_pattern_matches(
                slice.bytes.data(), slice.bytes.size(), pattern_bytes, pattern_mask
            );
            if (matches > 1) break;
        }

        // Format pattern string
        std::ostringstream ss;
        size_t wildcards = 0;
        for (size_t i = 0; i < pattern_bytes.size(); ++i) {
            if (i > 0) ss << " ";
            if (!pattern_mask[i]) {
                ss << "?";
                ++wildcards;
            } else {
                ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(pattern_bytes[i]);
            }
        }

        best_sig.pattern = ss.str();
        best_sig.length = pattern_bytes.size();
        best_sig.wildcard_count = wildcards;
        best_sig.module_matches = matches;
        best_sig.is_unique = (matches == 1);

        if (best_sig.is_unique) {
            return best_sig;
        }
    }

    return best_sig;
}

} // namespace nce::utils
