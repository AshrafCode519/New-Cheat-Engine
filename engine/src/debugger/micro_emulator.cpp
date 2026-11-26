#include "../../include/debugger/micro_emulator.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>

namespace nce::debugger {

namespace {

std::string trim_str(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string lower_str(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

class SandboxMemory {
public:
    explicit SandboxMemory(const hal::IProcess* proc) : m_proc(proc) {}

    void apply_patch(uintptr_t addr, const std::vector<uint8_t>& bytes) {
        for (size_t i = 0; i < bytes.size(); ++i) {
            m_dirty[addr + i] = bytes[i];
        }
    }

    bool read_raw(uintptr_t addr, void* out, size_t len) const {
        if (len == 0) return true;
        auto* dst = static_cast<uint8_t*>(out);
        bool all_dirty = true;
        for (size_t i = 0; i < len; ++i) {
            if (m_dirty.find(addr + i) == m_dirty.end()) {
                all_dirty = false;
                break;
            }
        }
        if (all_dirty) {
            for (size_t i = 0; i < len; ++i) dst[i] = m_dirty.at(addr + i);
            return true;
        }
        std::vector<uint8_t> base(len, 0);
        bool proc_ok = (m_proc && m_proc->is_attached() && m_proc->read_raw(addr, base.data(), len));
        for (size_t i = 0; i < len; ++i) {
            auto it = m_dirty.find(addr + i);
            if (it != m_dirty.end()) {
                dst[i] = it->second;
            } else if (proc_ok) {
                dst[i] = base[i];
            } else {
                // Allow partial dirty reads if at least start of buffer was synthetic stack/cave
                return false;
            }
        }
        return true;
    }

    void write_raw(uintptr_t addr, const void* data, size_t len, std::vector<EmuMemoryAccess>& log) {
        const auto* src = static_cast<const uint8_t*>(data);
        uint64_t prev_val = 0;
        if (len <= 8) (void)read_raw(addr, &prev_val, len);
        uint64_t new_val = 0;
        if (len <= 8 && len > 0) std::memcpy(&new_val, src, len);
        for (size_t i = 0; i < len; ++i) {
            m_dirty[addr + i] = src[i];
        }
        if (len > 0 && len <= 8) {
            log.push_back({addr, len, new_val, prev_val, true});
        }
    }

    bool read_val(uintptr_t addr, size_t sz, uint64_t& out, std::vector<EmuMemoryAccess>& log, bool record = true) const {
        out = 0;
        if (sz == 0 || sz > 8) return false;
        if (!read_raw(addr, &out, sz)) return false;
        if (record) log.push_back({addr, sz, out, out, false});
        return true;
    }

private:
    const hal::IProcess* m_proc{nullptr};
    std::unordered_map<uintptr_t, uint8_t> m_dirty;
};

struct RegSlot {
    uint64_t Registers::* ptr;
    size_t width_bytes;
    bool high8{false};
};

std::optional<RegSlot> lookup_reg(const std::string& raw) {
    const std::string r = lower_str(trim_str(raw));
    static const std::pair<const char*, RegSlot> kTable[] = {
        {"rax", {&Registers::rax, 8}}, {"rcx", {&Registers::rcx, 8}}, {"rdx", {&Registers::rdx, 8}}, {"rbx", {&Registers::rbx, 8}},
        {"rsp", {&Registers::rsp, 8}}, {"rbp", {&Registers::rbp, 8}}, {"rsi", {&Registers::rsi, 8}}, {"rdi", {&Registers::rdi, 8}},
        {"rip", {&Registers::rip, 8}}, {"r8",  {&Registers::r8,  8}}, {"r9",  {&Registers::r9,  8}}, {"r10", {&Registers::r10, 8}},
        {"r11", {&Registers::r11, 8}}, {"r12", {&Registers::r12, 8}}, {"r13", {&Registers::r13, 8}}, {"r14", {&Registers::r14, 8}},
        {"r15", {&Registers::r15, 8}},
        {"eax", {&Registers::rax, 4}}, {"ecx", {&Registers::rcx, 4}}, {"edx", {&Registers::rdx, 4}}, {"ebx", {&Registers::rbx, 4}},
        {"esp", {&Registers::rsp, 4}}, {"ebp", {&Registers::rbp, 4}}, {"esi", {&Registers::rsi, 4}}, {"edi", {&Registers::rdi, 4}},
        {"eip", {&Registers::rip, 4}}, {"r8d", {&Registers::r8,  4}}, {"r9d", {&Registers::r9,  4}}, {"r10d",{&Registers::r10, 4}},
        {"r11d",{&Registers::r11, 4}}, {"r12d",{&Registers::r12, 4}}, {"r13d",{&Registers::r13, 4}}, {"r14d",{&Registers::r14, 4}},
        {"r15d",{&Registers::r15, 4}},
        {"ax",  {&Registers::rax, 2}}, {"cx",  {&Registers::rcx, 2}}, {"dx",  {&Registers::rdx, 2}}, {"bx",  {&Registers::rbx, 2}},
        {"sp",  {&Registers::rsp, 2}}, {"bp",  {&Registers::rbp, 2}}, {"si",  {&Registers::rsi, 2}}, {"di",  {&Registers::rdi, 2}},
        {"al",  {&Registers::rax, 1}}, {"cl",  {&Registers::rcx, 1}}, {"dl",  {&Registers::rdx, 1}}, {"bl",  {&Registers::rbx, 1}},
        {"spl", {&Registers::rsp, 1}}, {"bpl", {&Registers::rbp, 1}}, {"sil", {&Registers::rsi, 1}}, {"dil", {&Registers::rdi, 1}},
        {"ah",  {&Registers::rax, 1, true}}, {"ch", {&Registers::rcx, 1, true}},
        {"dh",  {&Registers::rdx, 1, true}}, {"bh", {&Registers::rbx, 1, true}},
    };
    for (const auto& [name, slot] : kTable) {
        if (r == name) return slot;
    }
    return std::nullopt;
}

int parse_xmm_index(const std::string& raw) {
    const std::string s = lower_str(trim_str(raw));
    if (s.rfind("xmm", 0) == 0 && s.size() >= 4) {
        int idx = std::atoi(s.c_str() + 3);
        if (idx >= 0 && idx < 8) return idx;
    }
    return -1;
}

uint64_t read_reg(const Registers& regs, const RegSlot& s) {
    const uint64_t v = regs.*(s.ptr);
    if (s.high8) return (v >> 8) & 0xFFULL;
    if (s.width_bytes == 1) return v & 0xFFULL;
    if (s.width_bytes == 2) return v & 0xFFFFULL;
    if (s.width_bytes == 4) return v & 0xFFFFFFFFULL;
    return v;
}

void write_reg(Registers& regs, const RegSlot& s, uint64_t val, bool is_64bit) {
    uint64_t& dst = regs.*(s.ptr);
    if (s.high8) {
        dst = (dst & ~0xFF00ULL) | ((val & 0xFFULL) << 8);
    } else if (s.width_bytes == 1) {
        dst = (dst & ~0xFFULL) | (val & 0xFFULL);
    } else if (s.width_bytes == 2) {
        dst = (dst & ~0xFFFFULL) | (val & 0xFFFFULL);
    } else if (s.width_bytes == 4) {
        dst = val & 0xFFFFFFFFULL; // x86-64 zero-extends 32-bit GPR writes (and on x86 upper 32 stays 0)
    } else {
        dst = is_64bit ? val : (val & 0xFFFFFFFFULL);
    }
}

bool parse_imm(const std::string& raw, uint64_t& out) {
    std::string s = trim_str(raw);
    if (s.empty()) return false;
    bool neg = false;
    if (s[0] == '-') { neg = true; s = trim_str(s.substr(1)); }
    else if (s[0] == '+') { s = trim_str(s.substr(1)); }
    if (s.empty() || !std::isdigit(static_cast<unsigned char>(s[0]))) return false;
    char* endp = nullptr;
    uint64_t val = std::strtoull(s.c_str(), &endp, 0);
    if (!endp || *endp != '\0') return false;
    out = neg ? static_cast<uint64_t>(-static_cast<int64_t>(val)) : val;
    return true;
}

size_t infer_mem_size(const std::string& op, size_t default_sz) {
    const std::string l = lower_str(op);
    if (l.find("byte ptr") != std::string::npos) return 1;
    if (l.find("word ptr") != std::string::npos && l.find("dword") == std::string::npos && l.find("qword") == std::string::npos) return 2;
    if (l.find("dword ptr") != std::string::npos) return 4;
    if (l.find("qword ptr") != std::string::npos) return 8;
    return default_sz;
}

bool eval_mem_ea(const std::string& op, const DecodedInstruction& insn, const Registers& regs, bool is_64bit, uintptr_t& out_ea) {
    const size_t lb = op.find('[');
    const size_t rb = op.rfind(']');
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb) return false;
    std::string inner = lower_str(trim_str(op.substr(lb + 1, rb - lb - 1)));
    const uint64_t next_rip = insn.address + insn.length;
    if (inner.rfind("rip", 0) == 0 && insn.branch_target != 0 &&
        lower_str(insn.mnemonic).rfind("call", 0) != 0 && lower_str(insn.mnemonic) != "jmp") {
        out_ea = insn.branch_target;
        return true;
    }

    // Tokenize +/- terms like: rbx + rcx*4 + 0x10 or ebp - 0x8 or rip + 0x0
    int64_t acc = 0;
    size_t i = 0;
    int sign = 1;
    while (i < inner.size()) {
        while (i < inner.size() && std::isspace(static_cast<unsigned char>(inner[i]))) ++i;
        if (i >= inner.size()) break;
        if (inner[i] == '+') { sign = 1; ++i; continue; }
        if (inner[i] == '-') { sign = -1; ++i; continue; }

        size_t j = i;
        while (j < inner.size() && inner[j] != '+' && inner[j] != '-') ++j;
        std::string term = trim_str(inner.substr(i, j - i));
        i = j;

        const size_t star = term.find('*');
        if (star != std::string::npos) {
            std::string lhs = trim_str(term.substr(0, star));
            std::string rhs = trim_str(term.substr(star + 1));
            uint64_t scale = 1;
            if (!parse_imm(rhs, scale)) {
                if (parse_imm(lhs, scale)) std::swap(lhs, rhs);
                else return false;
            }
            auto rs = lookup_reg(lhs);
            if (!rs) return false;
            const uint64_t rv = (rs->ptr == &Registers::rip) ? next_rip : read_reg(regs, *rs);
            acc += sign * static_cast<int64_t>(rv * scale);
        } else if (auto rs = lookup_reg(term)) {
            const uint64_t rv = (rs->ptr == &Registers::rip) ? next_rip : read_reg(regs, *rs);
            acc += sign * static_cast<int64_t>(rv);
        } else {
            uint64_t imm = 0;
            if (!parse_imm(term, imm)) return false;
            acc += sign * static_cast<int64_t>(imm);
        }
    }

    out_ea = is_64bit ? static_cast<uintptr_t>(acc) : static_cast<uintptr_t>(static_cast<uint32_t>(acc));
    return true;
}

std::vector<std::string> split_ops(const std::string& ops) {
    std::vector<std::string> out;
    int depth = 0;
    size_t start = 0;
    for (size_t i = 0; i < ops.size(); ++i) {
        if (ops[i] == '[') ++depth;
        else if (ops[i] == ']' && depth > 0) --depth;
        else if (ops[i] == ',' && depth == 0) {
            out.push_back(trim_str(ops.substr(start, i - start)));
            start = i + 1;
        }
    }
    const std::string tail = trim_str(ops.substr(start));
    if (!tail.empty()) out.push_back(tail);
    return out;
}

constexpr uint64_t kCF = 1ULL << 0;
constexpr uint64_t kZF = 1ULL << 6;
constexpr uint64_t kSF = 1ULL << 7;
constexpr uint64_t kOF = 1ULL << 11;

uint64_t width_mask(size_t w) {
    if (w == 1) return 0xFFULL;
    if (w == 2) return 0xFFFFULL;
    if (w == 4) return 0xFFFFFFFFULL;
    return ~0ULL;
}

void update_flags_logic(Registers& r, uint64_t res, size_t w) {
    const uint64_t m = width_mask(w);
    const uint64_t sign_bit = 1ULL << (w * 8 - 1);
    res &= m;
    r.eflags &= ~(kCF | kZF | kSF | kOF);
    if (res == 0) r.eflags |= kZF;
    if (res & sign_bit) r.eflags |= kSF;
}

void update_flags_add(Registers& r, uint64_t a, uint64_t b, size_t w) {
    const uint64_t m = width_mask(w);
    const uint64_t sign_bit = 1ULL << (w * 8 - 1);
    a &= m; b &= m;
    const uint64_t res = (a + b) & m;
    r.eflags &= ~(kCF | kZF | kSF | kOF);
    if (res == 0) r.eflags |= kZF;
    if (res & sign_bit) r.eflags |= kSF;
    if (res < a) r.eflags |= kCF;
    if (~(a ^ b) & (a ^ res) & sign_bit) r.eflags |= kOF;
}

void update_flags_sub(Registers& r, uint64_t a, uint64_t b, size_t w) {
    const uint64_t m = width_mask(w);
    const uint64_t sign_bit = 1ULL << (w * 8 - 1);
    a &= m; b &= m;
    const uint64_t res = (a - b) & m;
    r.eflags &= ~(kCF | kZF | kSF | kOF);
    if (res == 0) r.eflags |= kZF;
    if (res & sign_bit) r.eflags |= kSF;
    if (a < b) r.eflags |= kCF;
    if ((a ^ b) & (a ^ res) & sign_bit) r.eflags |= kOF;
}

bool check_jcc(const std::string& m, uint64_t ef) {
    const bool cf = (ef & kCF) != 0;
    const bool zf = (ef & kZF) != 0;
    const bool sf = (ef & kSF) != 0;
    const bool of = (ef & kOF) != 0;
    if (m == "je" || m == "jz" || m == "sete") return zf;
    if (m == "jne" || m == "jnz" || m == "setne") return !zf;
    if (m == "jl" || m == "jnge" || m == "setl") return sf != of;
    if (m == "jle" || m == "jng" || m == "setle") return zf || (sf != of);
    if (m == "jg" || m == "jnle" || m == "setg") return !zf && (sf == of);
    if (m == "jge" || m == "jnl" || m == "setge") return sf == of;
    if (m == "jb" || m == "jnae" || m == "jc" || m == "setb") return cf;
    if (m == "jbe" || m == "jna" || m == "setbe") return cf || zf;
    if (m == "ja" || m == "jnbe" || m == "seta") return !cf && !zf;
    if (m == "jae" || m == "jnb" || m == "jnc" || m == "setae") return !cf;
    if (m == "js" || m == "sets") return sf;
    if (m == "jns" || m == "setns") return !sf;
    return false;
}

std::string canonical_gpr(const std::string& raw) {
    if (auto s = lookup_reg(raw)) {
        if (s->ptr == &Registers::rax) return "rax";
        if (s->ptr == &Registers::rbx) return "rbx";
        if (s->ptr == &Registers::rcx) return "rcx";
        if (s->ptr == &Registers::rdx) return "rdx";
        if (s->ptr == &Registers::rsi) return "rsi";
        if (s->ptr == &Registers::rdi) return "rdi";
        if (s->ptr == &Registers::rbp) return "rbp";
        if (s->ptr == &Registers::rsp) return "rsp";
        if (s->ptr == &Registers::r8) return "r8";
        if (s->ptr == &Registers::r9) return "r9";
        if (s->ptr == &Registers::r10) return "r10";
        if (s->ptr == &Registers::r11) return "r11";
        if (s->ptr == &Registers::r12) return "r12";
        if (s->ptr == &Registers::r13) return "r13";
        if (s->ptr == &Registers::r14) return "r14";
        if (s->ptr == &Registers::r15) return "r15";
    }
    const int xi = parse_xmm_index(raw);
    if (xi >= 0) return "xmm" + std::to_string(xi);
    return "";
}

void extract_regs_in_expr(const std::string& expr, std::set<std::string>& out) {
    std::string tok;
    for (size_t i = 0; i <= expr.size(); ++i) {
        if (i < expr.size() && std::isalnum(static_cast<unsigned char>(expr[i]))) {
            tok.push_back(expr[i]);
        } else {
            if (!tok.empty()) {
                const std::string c = canonical_gpr(tok);
                if (!c.empty()) out.insert(c);
                tok.clear();
            }
        }
    }
}

} // namespace

EmulationResult MicroEmulator::emulate(
    const hal::IProcess* process,
    uintptr_t entry_rip,
    const Registers& initial_regs,
    size_t max_steps,
    bool is_64bit,
    const std::vector<MemWritePatch>& overlay_patches
) {
    EmulationResult res;
    res.final_regs = initial_regs;
    if (entry_rip == 0) {
        res.fault_reason = "Zero entry instruction pointer";
        return res;
    }

    SandboxMemory mem(process);

    const size_t ptr_sz = is_64bit ? 8 : 4;
    constexpr uintptr_t kSentinelRet64 = 0xDEADBEEF00000001ULL;
    constexpr uint32_t  kSentinelRet32 = 0xDEADBEEFu;
    const uintptr_t sentinel = is_64bit ? kSentinelRet64 : static_cast<uintptr_t>(kSentinelRet32);

    // Provide a safe clean sandbox stack automatically if caller left RSP == 0
    if (res.final_regs.rsp == 0) {
        res.final_regs.rsp = is_64bit ? 0x00007FFE00001000ULL : 0x007E1000ULL;
        std::vector<uint8_t> stack_zero(512, 0);
        mem.apply_patch(res.final_regs.rsp - 256, stack_zero);
    }
    // Seed sentinel return address before caller patches so custom overlay patches win
    std::vector<uint8_t> ret_bytes(ptr_sz, 0);
    std::memcpy(ret_bytes.data(), &sentinel, ptr_sz);
    mem.apply_patch(res.final_regs.rsp, ret_bytes);

    for (const auto& p : overlay_patches) {
        mem.apply_patch(p.address, p.bytes);
    }

    std::array<uint64_t, 8> xmm_bits{};
    res.final_regs.rip = entry_rip;

    for (size_t step = 0; step < max_steps; ++step) {
        const uintptr_t rip = res.final_regs.rip;
        if (rip == sentinel) {
            res.completed = true;
            res.returned_cleanly = true;
            break;
        }

        uint8_t code[16]{};
        if (!mem.read_raw(rip, code, sizeof(code))) {
            // Try decoding shorter tail if close to page boundary
            size_t got = 0;
            while (got < sizeof(code) && mem.read_raw(rip + got, code + got, 1)) ++got;
            if (got == 0) {
                res.fault_reason = "Unmapped instruction fetch";
                break;
            }
        }

        const auto insn = Disassembler::decode(code, sizeof(code), rip, is_64bit);
        if (insn.length == 0 || insn.mnemonic == "db" || insn.mnemonic == "unknown") {
            res.fault_reason = "Unsupported instruction at RIP";
            break;
        }

        const std::string mnem = lower_str(insn.mnemonic);
        const auto ops = split_ops(insn.operands);
        uintptr_t next_rip = rip + insn.length;

        auto read_operand = [&](const std::string& op, size_t width_hint, uint64_t& val, size_t& out_w) -> bool {
            if (auto rs = lookup_reg(op)) {
                out_w = rs->width_bytes;
                val = read_reg(res.final_regs, *rs);
                return true;
            }
            uint64_t imm = 0;
            if (parse_imm(op, imm)) {
                out_w = width_hint;
                val = imm & width_mask(out_w);
                return true;
            }
            uintptr_t ea = 0;
            if (eval_mem_ea(op, insn, res.final_regs, is_64bit, ea)) {
                out_w = infer_mem_size(op, width_hint);
                return mem.read_val(ea, out_w, val, res.accesses, true);
            }
            return false;
        };

        auto write_operand = [&](const std::string& op, uint64_t val, size_t width_hint) -> bool {
            if (auto rs = lookup_reg(op)) {
                write_reg(res.final_regs, *rs, val, is_64bit);
                return true;
            }
            uintptr_t ea = 0;
            if (eval_mem_ea(op, insn, res.final_regs, is_64bit, ea)) {
                const size_t sz = infer_mem_size(op, width_hint);
                mem.write_raw(ea, &val, sz, res.accesses);
                return true;
            }
            return false;
        };

        auto operand_width = [&](const std::string& op, size_t def_sz) -> size_t {
            if (auto rs = lookup_reg(op)) return rs->width_bytes;
            return infer_mem_size(op, def_sz);
        };

        bool ok = true;
        if (mnem == "nop" || mnem == "endbr64" || mnem == "endbr32" || mnem == "pause") {
            // No-op
        } else if (mnem == "int3" || mnem == "hlt") {
            res.completed = true;
            res.fault_reason = (mnem == "int3") ? "Hit INT 3" : "Halted";
            res.trace.push_back({rip, insn.mnemonic + (insn.operands.empty() ? "" : " " + insn.operands), res.final_regs.rax, res.final_regs.rsp});
            ++res.steps_executed;
            break;
        } else if (mnem == "ret" || mnem == "retn") {
            uint64_t target = 0;
            if (!mem.read_val(res.final_regs.rsp, ptr_sz, target, res.accesses, true)) {
                res.fault_reason = "Stack read fault on RET";
                break;
            }
            uint64_t pop_imm = 0;
            if (!ops.empty()) parse_imm(ops[0], pop_imm);
            res.final_regs.rsp += ptr_sz + pop_imm;
            next_rip = static_cast<uintptr_t>(target);
            res.steps_executed++;
            res.trace.push_back({rip, insn.mnemonic, res.final_regs.rax, res.final_regs.rsp});
            res.final_regs.rip = next_rip;
            if (next_rip == sentinel) {
                res.completed = true;
                res.returned_cleanly = true;
                break;
            }
            continue;
        } else if (mnem == "call") {
            const bool is_indirect = (!ops.empty() && (ops[0].find('[') != std::string::npos || lookup_reg(ops[0]).has_value()));
            const uintptr_t target = (!is_indirect) ? insn.branch_target : 0;
            if (target == 0) {
                uint64_t ind = 0;
                size_t w = ptr_sz;
                if (ops.empty() || !read_operand(ops[0], ptr_sz, ind, w) || ind == 0) {
                    res.fault_reason = "Unresolved indirect call";
                    break;
                }
                res.final_regs.rsp -= ptr_sz;
                uint64_t ra = next_rip;
                mem.write_raw(res.final_regs.rsp, &ra, ptr_sz, res.accesses);
                next_rip = static_cast<uintptr_t>(ind);
            } else {
                res.final_regs.rsp -= ptr_sz;
                uint64_t ra = next_rip;
                mem.write_raw(res.final_regs.rsp, &ra, ptr_sz, res.accesses);
                next_rip = target;
            }
        } else if (mnem == "jmp") {
            const bool is_indirect = (!ops.empty() && (ops[0].find('[') != std::string::npos || lookup_reg(ops[0]).has_value()));
            if (!is_indirect && insn.branch_target != 0) {
                next_rip = insn.branch_target;
            } else if (!ops.empty()) {
                uint64_t target = 0;
                size_t w = ptr_sz;
                if (!read_operand(ops[0], ptr_sz, target, w) || target == 0) {
                    res.fault_reason = "Unresolved indirect jmp";
                    break;
                }
                next_rip = static_cast<uintptr_t>(target);
            }
        } else if (!mnem.empty() && mnem[0] == 'j' && insn.branch_target != 0) {
            if (check_jcc(mnem, res.final_regs.eflags)) next_rip = insn.branch_target;
        } else if (mnem == "push" && ops.size() == 1) {
            uint64_t val = 0;
            size_t w = ptr_sz;
            ok = read_operand(ops[0], ptr_sz, val, w);
            if (ok) {
                res.final_regs.rsp -= ptr_sz;
                mem.write_raw(res.final_regs.rsp, &val, ptr_sz, res.accesses);
            }
        } else if (mnem == "pop" && ops.size() == 1) {
            uint64_t val = 0;
            ok = mem.read_val(res.final_regs.rsp, ptr_sz, val, res.accesses, true);
            if (ok) {
                res.final_regs.rsp += ptr_sz;
                ok = write_operand(ops[0], val, ptr_sz);
            }
        } else if (mnem == "lea" && ops.size() == 2) {
            uintptr_t ea = 0;
            ok = eval_mem_ea(ops[1], insn, res.final_regs, is_64bit, ea) &&
                 write_operand(ops[0], ea, ptr_sz);
        } else if (mnem == "mov" && ops.size() == 2) {
            const size_t w = operand_width(ops[0], operand_width(ops[1], ptr_sz));
            uint64_t rhs = 0;
            size_t rw = w;
            ok = read_operand(ops[1], w, rhs, rw) && write_operand(ops[0], rhs, w);
        } else if ((mnem == "movzx" || mnem == "movsx" || mnem == "movsxd") && ops.size() == 2) {
            const size_t dw = operand_width(ops[0], ptr_sz);
            const size_t sw = operand_width(ops[1], 1);
            uint64_t rhs = 0;
            size_t rw = sw;
            ok = read_operand(ops[1], sw, rhs, rw);
            if (ok && (mnem == "movsx" || mnem == "movsxd")) {
                const uint64_t sign_bit = 1ULL << (rw * 8 - 1);
                if (rhs & sign_bit) rhs |= ~width_mask(rw);
            }
            if (ok) ok = write_operand(ops[0], rhs, dw);
        } else if (mnem == "xchg" && ops.size() == 2) {
            const size_t w = operand_width(ops[0], ptr_sz);
            uint64_t a = 0, b = 0;
            size_t aw = w, bw = w;
            ok = read_operand(ops[0], w, a, aw) && read_operand(ops[1], w, b, bw) &&
                 write_operand(ops[0], b, w) && write_operand(ops[1], a, w);
        } else if ((mnem == "add" || mnem == "sub" || mnem == "and" || mnem == "or" || mnem == "xor" ||
                    mnem == "shl" || mnem == "sal" || mnem == "shr" || mnem == "sar" ||
                    mnem == "cmp" || mnem == "test") && ops.size() == 2) {
            const size_t w = operand_width(ops[0], operand_width(ops[1], ptr_sz));
            uint64_t a = 0, b = 0;
            size_t aw = w, bw = w;
            ok = read_operand(ops[0], w, a, aw) && read_operand(ops[1], w, b, bw);
            if (ok) {
                uint64_t outv = a;
                if (mnem == "add") {
                    outv = (a + b) & width_mask(w);
                    update_flags_add(res.final_regs, a, b, w);
                } else if (mnem == "sub" || mnem == "cmp") {
                    outv = (a - b) & width_mask(w);
                    update_flags_sub(res.final_regs, a, b, w);
                } else if (mnem == "and" || mnem == "test") {
                    outv = (a & b) & width_mask(w);
                    update_flags_logic(res.final_regs, outv, w);
                } else if (mnem == "or") {
                    outv = (a | b) & width_mask(w);
                    update_flags_logic(res.final_regs, outv, w);
                } else if (mnem == "xor") {
                    outv = (a ^ b) & width_mask(w);
                    update_flags_logic(res.final_regs, outv, w);
                } else if (mnem == "shl" || mnem == "sal") {
                    const uint64_t shift = b & (w == 8 ? 63u : 31u);
                    outv = (a << shift) & width_mask(w);
                    update_flags_logic(res.final_regs, outv, w);
                } else if (mnem == "shr") {
                    const uint64_t shift = b & (w == 8 ? 63u : 31u);
                    outv = (a & width_mask(w)) >> shift;
                    update_flags_logic(res.final_regs, outv, w);
                } else if (mnem == "sar") {
                    const uint64_t shift = b & (w == 8 ? 63u : 31u);
                    int64_t s = static_cast<int64_t>(a & width_mask(w));
                    if (w < 8 && (s & (1LL << (w * 8 - 1)))) s |= ~static_cast<int64_t>(width_mask(w));
                    outv = static_cast<uint64_t>(s >> shift) & width_mask(w);
                    update_flags_logic(res.final_regs, outv, w);
                }
                if (mnem != "cmp" && mnem != "test") ok = write_operand(ops[0], outv, w);
            }
        } else if ((mnem == "inc" || mnem == "dec" || mnem == "neg" || mnem == "not") && ops.size() == 1) {
            const size_t w = operand_width(ops[0], ptr_sz);
            uint64_t a = 0;
            size_t aw = w;
            ok = read_operand(ops[0], w, a, aw);
            if (ok) {
                uint64_t outv = a;
                if (mnem == "inc") {
                    outv = (a + 1) & width_mask(w);
                    update_flags_add(res.final_regs, a, 1, w);
                } else if (mnem == "dec") {
                    outv = (a - 1) & width_mask(w);
                    update_flags_sub(res.final_regs, a, 1, w);
                } else if (mnem == "neg") {
                    outv = (0ULL - a) & width_mask(w);
                    update_flags_sub(res.final_regs, 0, a, w);
                } else {
                    outv = (~a) & width_mask(w);
                }
                ok = write_operand(ops[0], outv, w);
            }
        } else if (mnem == "imul" && ops.size() >= 2) {
            const size_t w = operand_width(ops[0], ptr_sz);
            uint64_t a = 0, b = 0;
            size_t aw = w, bw = w;
            ok = read_operand(ops.size() == 3 ? ops[1] : ops[0], w, a, aw) &&
                 read_operand(ops.back(), w, b, bw);
            if (ok) {
                const int64_t sa = static_cast<int64_t>(a);
                const int64_t sb = static_cast<int64_t>(b);
                ok = write_operand(ops[0], static_cast<uint64_t>(sa * sb) & width_mask(w), w);
            }
        } else if (mnem.rfind("cmov", 0) == 0 && ops.size() == 2) {
            const std::string jequiv = "j" + mnem.substr(4);
            if (check_jcc(jequiv, res.final_regs.eflags)) {
                const size_t w = operand_width(ops[0], ptr_sz);
                uint64_t rhs = 0;
                size_t rw = w;
                ok = read_operand(ops[1], w, rhs, rw) && write_operand(ops[0], rhs, w);
            }
        } else if ((mnem == "movss" || mnem == "addss" || mnem == "subss" || mnem == "mulss" || mnem == "divss" ||
                    mnem == "movsd" || mnem == "addsd" || mnem == "subsd" || mnem == "mulsd" || mnem == "divsd" ||
                    mnem == "xorps" || mnem == "xorpd") && ops.size() == 2) {
            const bool is_double = (mnem.back() == 'd');
            const size_t flt_sz = is_double ? 8 : 4;
            const int dx = parse_xmm_index(ops[0]);
            const int sx = parse_xmm_index(ops[1]);
            auto to_dbl = [&](uint64_t bits) -> double {
                if (is_double) {
                    double d = 0.0;
                    std::memcpy(&d, &bits, 8);
                    return d;
                }
                uint32_t u32 = static_cast<uint32_t>(bits & 0xFFFFFFFFULL);
                float f = 0.0f;
                std::memcpy(&f, &u32, 4);
                return static_cast<double>(f);
            };
            auto from_dbl = [&](double d) -> uint64_t {
                uint64_t out_b = 0;
                if (is_double) {
                    std::memcpy(&out_b, &d, 8);
                } else {
                    float f = static_cast<float>(d);
                    std::memcpy(&out_b, &f, 4);
                }
                return out_b;
            };
            if (mnem == "movss" || mnem == "movsd") {
                if (dx >= 0 && sx >= 0) xmm_bits[static_cast<size_t>(dx)] = xmm_bits[static_cast<size_t>(sx)];
                else if (dx >= 0) {
                    uintptr_t ea = 0; uint64_t v = 0;
                    ok = eval_mem_ea(ops[1], insn, res.final_regs, is_64bit, ea) && mem.read_val(ea, flt_sz, v, res.accesses);
                    if (ok) xmm_bits[static_cast<size_t>(dx)] = v;
                } else if (sx >= 0) {
                    uintptr_t ea = 0;
                    ok = eval_mem_ea(ops[0], insn, res.final_regs, is_64bit, ea);
                    if (ok) {
                        uint64_t v = xmm_bits[static_cast<size_t>(sx)];
                        mem.write_raw(ea, &v, flt_sz, res.accesses);
                    }
                } else ok = false;
            } else if ((mnem == "xorps" || mnem == "xorpd") && dx >= 0 && sx >= 0) {
                xmm_bits[static_cast<size_t>(dx)] ^= xmm_bits[static_cast<size_t>(sx)];
            } else if (dx >= 0) {
                uint64_t rhs_b = 0;
                if (sx >= 0) rhs_b = xmm_bits[static_cast<size_t>(sx)];
                else {
                    uintptr_t ea = 0;
                    ok = eval_mem_ea(ops[1], insn, res.final_regs, is_64bit, ea) && mem.read_val(ea, flt_sz, rhs_b, res.accesses);
                }
                if (ok) {
                    const double a = to_dbl(xmm_bits[static_cast<size_t>(dx)]);
                    const double b = to_dbl(rhs_b);
                    double r = a;
                    if (mnem.rfind("add", 0) == 0) r = a + b;
                    else if (mnem.rfind("sub", 0) == 0) r = a - b;
                    else if (mnem.rfind("mul", 0) == 0) r = a * b;
                    else if (mnem.rfind("div", 0) == 0) {
                        if (b == 0.0) { ok = false; res.fault_reason = "Floating-point divide by zero"; }
                        else r = a / b;
                    }
                    if (ok) xmm_bits[static_cast<size_t>(dx)] = from_dbl(r);
                }
            } else {
                ok = false;
            }
        } else {
            res.fault_reason = "Unsupported instruction '" + insn.mnemonic + "'";
            break;
        }

        if (!ok) {
            if (res.fault_reason.empty()) res.fault_reason = "Execution fault on '" + insn.mnemonic + "'";
            break;
        }

        res.trace.push_back({
            rip,
            insn.mnemonic + (insn.operands.empty() ? "" : " " + insn.operands),
            res.final_regs.rax,
            res.final_regs.rsp
        });
        ++res.steps_executed;
        res.final_regs.rip = next_rip;

        if (step + 1 == max_steps) {
            res.completed = true;
        }
    }

    for (size_t i = 0; i < 8; ++i) {
        double d = 0.0;
        std::memcpy(&d, &xmm_bits[i], sizeof(double));
        if (!std::isfinite(d) || (xmm_bits[i] >> 32) == 0) {
            uint32_t u32 = static_cast<uint32_t>(xmm_bits[i] & 0xFFFFFFFFULL);
            float f = 0.0f;
            std::memcpy(&f, &u32, sizeof(float));
            res.xmm_f64[i] = std::isfinite(f) ? static_cast<double>(f) : d;
        } else {
            res.xmm_f64[i] = d;
        }
    }
    return res;
}

EmulationResult MicroEmulator::dry_run_hook(
    const hal::IProcess& process,
    uintptr_t target_address,
    const std::vector<uint8_t>& cave_code,
    uintptr_t cave_address,
    const Registers& initial_regs,
    size_t max_steps
) {
    EmulationResult res;
    if (!process.is_attached() || target_address == 0 || cave_code.empty() || cave_address == 0) {
        res.fault_reason = "Invalid dry_run_hook arguments";
        return res;
    }

    const bool is_64 = (process.pointer_size() != 4);
    std::vector<MemWritePatch> patches;
    patches.push_back({cave_address, cave_code});

    std::vector<uint8_t> detour_bytes;
    const int64_t diff = static_cast<int64_t>(cave_address) - static_cast<int64_t>(target_address + 5);
    if (diff >= -0x7FFF0000LL && diff <= 0x7FFF0000LL) {
        detour_bytes.resize(5);
        detour_bytes[0] = 0xE9;
        const int32_t rel = static_cast<int32_t>(diff);
        std::memcpy(&detour_bytes[1], &rel, 4);
    } else if (is_64) {
        detour_bytes = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
        detour_bytes.resize(14);
        std::memcpy(&detour_bytes[6], &cave_address, 8);
    } else {
        detour_bytes.resize(6);
        detour_bytes[0] = 0x68;
        const uint32_t dst32 = static_cast<uint32_t>(cave_address);
        std::memcpy(&detour_bytes[1], &dst32, 4);
        detour_bytes[5] = 0xC3;
    }
    patches.push_back({target_address, std::move(detour_bytes)});

    return emulate(&process, target_address, initial_regs, max_steps, is_64, patches);
}

std::vector<TaintStep> MicroEmulator::backward_taint(
    const ControlFlowGraph& cfg,
    uintptr_t sink_address,
    const std::string& target_reg
) {
    std::vector<DecodedInstruction> flat;
    bool found_sink = false;
    for (const auto& b : cfg.blocks) {
        for (const auto& insn : b.instructions) {
            flat.push_back(insn);
            if (insn.address == sink_address) {
                found_sink = true;
                break;
            }
        }
        if (found_sink) break;
    }
    if (flat.empty()) return {};

    std::set<std::string> tainted;
    const std::string seed = canonical_gpr(target_reg);
    if (seed.empty()) return {};
    tainted.insert(seed);

    std::vector<TaintStep> rev;
    for (size_t idx = flat.size(); idx-- > 0;) {
        const auto& insn = flat[idx];
        const std::string m = lower_str(insn.mnemonic);
        const auto ops = split_ops(insn.operands);
        if (ops.empty()) continue;

        const std::string dst_reg = canonical_gpr(ops[0]);
        if (dst_reg.empty() || tainted.find(dst_reg) == tainted.end()) continue;

        TaintStep step;
        step.address = insn.address;
        step.instruction = insn.mnemonic + (insn.operands.empty() ? "" : " " + insn.operands);
        step.tainted_regs.assign(tainted.begin(), tainted.end());

        if ((m == "xor" || m == "sub") && ops.size() == 2 && canonical_gpr(ops[1]) == dst_reg) {
            step.origin_note = dst_reg + " cleared to 0 (" + m + ")";
            tainted.erase(dst_reg);
        } else if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "lea" ||
                   m == "movss" || m == "movsd") {
            tainted.erase(dst_reg);
            if (ops.size() >= 2) {
                std::set<std::string> src_regs;
                extract_regs_in_expr(ops[1], src_regs);
                for (const auto& r : src_regs) tainted.insert(r);
                if (src_regs.empty()) {
                    step.origin_note = dst_reg + " loaded from constant/global " + ops[1];
                } else {
                    step.origin_note = dst_reg + " <- " + ops[1];
                }
            }
        } else if (ops.size() >= 2) {
            std::set<std::string> src_regs;
            for (size_t oi = 1; oi < ops.size(); ++oi) extract_regs_in_expr(ops[oi], src_regs);
            for (const auto& r : src_regs) tainted.insert(r);
            step.origin_note = dst_reg + " mutated via " + m;
        } else {
            step.origin_note = dst_reg + " modified by " + m;
        }

        rev.push_back(std::move(step));
        if (tainted.empty()) break;
    }

    std::reverse(rev.begin(), rev.end());
    return rev;
}

} // namespace nce::debugger
