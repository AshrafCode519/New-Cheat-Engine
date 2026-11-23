#include "../../include/assembler/x86_assembler.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <sstream>

namespace nce::assembler {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return {};
    return s.substr(a, s.find_last_not_of(" \t") - a + 1);
}

std::vector<std::string> split_commas(const std::string& s) {
    std::vector<std::string> out;
    int depth = 0;
    std::string cur;
    for (char c : s) {
        if (c == '[') ++depth;
        else if (c == ']') --depth;
        if (c == ',' && depth == 0) {
            out.push_back(trim(cur));
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!trim(cur).empty()) out.push_back(trim(cur));
    return out;
}

// A register's number (0-15) and width in bits. The number is the architectural encoding (rax=0 .. rdi=7,
// r8=8 .. r15=15); REX.B/R/X carry its 4th bit.
struct Reg {
    int num{0};
    int bits{0};     // 8, 16, 32, 64
    bool high8{false}; // ah/ch/dh/bh
};

const std::array<const char*, 16> k64 = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
const std::array<const char*, 16> k32 = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                         "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
const std::array<const char*, 16> k16 = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                                         "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
const std::array<const char*, 16> k8 = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                                        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
const std::array<const char*, 4> k8h = {"ah", "ch", "dh", "bh"};

std::optional<Reg> parse_reg(const std::string& token) {
    const std::string t = lower(trim(token));
    for (int i = 0; i < 16; ++i) {
        if (t == k64[i]) return Reg{i, 64, false};
        if (t == k32[i]) return Reg{i, 32, false};
        if (t == k16[i]) return Reg{i, 16, false};
        if (t == k8[i]) return Reg{i, 8, false};
    }
    for (int i = 0; i < 4; ++i) {
        if (t == k8h[i]) return Reg{i + 4, 8, true};
    }
    return std::nullopt;
}

// Parses a number: 0x.. / decimal / -decimal, into a 64-bit signed value
std::optional<int64_t> parse_number(const std::string& token) {
    std::string t = trim(token);
    if (t.empty()) return std::nullopt;
    bool neg = false;
    if (t[0] == '+') t.erase(0, 1);
    else if (t[0] == '-') { neg = true; t.erase(0, 1); }
    int base = 10;
    if (t.size() > 2 && (t.compare(0, 2, "0x") == 0 || t.compare(0, 2, "0X") == 0)) {
        base = 16;
        t = t.substr(2);
    }
    if (t.empty()) return std::nullopt;
    uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(t.data(), t.data() + t.size(), value, base);
    if (ec != std::errc() || ptr != t.data() + t.size()) return std::nullopt;
    return neg ? -static_cast<int64_t>(value) : static_cast<int64_t>(value);
}

// A memory operand: [base + index*scale + disp]. Any part may be absent.
struct Mem {
    std::optional<Reg> base;
    std::optional<Reg> index;
    int scale{1};
    int64_t disp{0};
    bool rip_relative{false};
    int width{0}; // byte/word/dword/qword ptr, 0 if unstated
};

std::optional<Mem> parse_mem(const std::string& token, std::string& error) {
    std::string t = lower(trim(token));
    Mem mem;
    // size prefix
    const std::pair<const char*, int> sizes[] = {{"byte", 8}, {"word", 16}, {"dword", 32}, {"qword", 64}};
    for (const auto& [word, bits] : sizes) {
        if (t.compare(0, std::strlen(word), word) == 0) {
            mem.width = bits;
            t = trim(t.substr(std::strlen(word)));
            if (t.compare(0, 3, "ptr") == 0) t = trim(t.substr(3));
            break;
        }
    }
    if (t.empty() || t.front() != '[' || t.back() != ']') return std::nullopt;
    t = t.substr(1, t.size() - 2);

    // Split on + and - into signed terms
    std::vector<std::pair<char, std::string>> terms;
    std::string cur;
    char sign = '+';
    for (char c : t) {
        if (c == '+' || c == '-') {
            if (!trim(cur).empty()) terms.emplace_back(sign, trim(cur));
            cur.clear();
            sign = c;
        } else {
            cur += c;
        }
    }
    if (!trim(cur).empty()) terms.emplace_back(sign, trim(cur));

    for (const auto& [s, term] : terms) {
        if (term.find('*') != std::string::npos) { // index*scale
            const size_t star = term.find('*');
            const std::string a = trim(term.substr(0, star));
            const std::string b = trim(term.substr(star + 1));
            auto reg = parse_reg(a);
            auto scale = parse_number(b);
            if (!reg && (reg = parse_reg(b))) scale = parse_number(a); // scale*index
            if (!reg || !scale || (*scale != 1 && *scale != 2 && *scale != 4 && *scale != 8)) {
                error = "bad scaled index in " + token;
                return std::nullopt;
            }
            mem.index = reg;
            mem.scale = static_cast<int>(*scale);
        } else if (lower(term) == "rip") {
            mem.rip_relative = true;
        } else if (auto reg = parse_reg(term)) {
            if (!mem.base) mem.base = reg;
            else if (!mem.index) mem.index = reg;
            else { error = "too many registers in " + token; return std::nullopt; }
        } else if (auto num = parse_number(term)) {
            mem.disp += (s == '-') ? -*num : *num;
        } else {
            error = "can't read '" + term + "' in " + token;
            return std::nullopt;
        }
    }
    return mem;
}

struct Operand {
    enum class Kind { Reg, Mem, Imm } kind;
    Reg reg;
    Mem mem;
    int64_t imm{0};
};

std::optional<Operand> parse_operand(const std::string& token, std::string& error) {
    if (auto r = parse_reg(token)) return Operand{Operand::Kind::Reg, *r, {}, 0};
    if (token.find('[') != std::string::npos) {
        auto m = parse_mem(token, error);
        if (!m) return std::nullopt;
        return Operand{Operand::Kind::Mem, {}, *m, 0};
    }
    if (auto n = parse_number(token)) return Operand{Operand::Kind::Imm, {}, {}, *n};
    error = "can't read operand '" + token + "'";
    return std::nullopt;
}

void put_le(std::vector<uint8_t>& out, uint64_t value, int bytes) {
    for (int i = 0; i < bytes; ++i) out.push_back(static_cast<uint8_t>(value >> (8 * i)));
}

bool fits_i8(int64_t v) { return v >= -128 && v <= 127; }
bool fits_i32(int64_t v) { return v >= INT32_MIN && v <= INT32_MAX; }

// Builder for one instruction: holds the chosen prefixes, opcode, ModRM/SIB and trailing bytes.
struct Insn {
    bool x64;
    bool rex_w{false}, rex_r{false}, rex_x{false}, rex_b{false};
    bool need_rex{false};   // a byte register spl/bpl/sil/dil/r8b.. forces a REX even when 0
    bool op16{false};       // 16-bit operand-size prefix
    std::vector<uint8_t> opcode;
    bool has_modrm{false};
    uint8_t modrm{0};
    bool has_sib{false};
    uint8_t sib{0};
    std::vector<uint8_t> disp;
    std::vector<uint8_t> imm;
    std::optional<size_t> rel32_at; // offset into the final bytes of a rel32 to patch

    // reg field of ModRM (an opcode extension /digit or a register)
    void set_reg(int r) {
        modrm = (modrm & 0xC7) | ((r & 7) << 3);
        if (r >= 8) rex_r = true;
    }
    // ModRM for a register operand (mod=11)
    void rm_reg(const Reg& r) {
        has_modrm = true;
        modrm = (modrm & 0x38) | 0xC0 | (r.num & 7);
        if (r.num >= 8) rex_b = true;
        if (r.bits == 8 && !r.high8 && r.num >= 4 && r.num <= 7) need_rex = true; // spl/bpl/sil/dil
    }
    void rm_mem(const Mem& m, bool x64);

    std::vector<uint8_t> bytes() {
        std::vector<uint8_t> out;
        if (op16) out.push_back(0x66);
        const bool rex = rex_w || rex_r || rex_x || rex_b || need_rex;
        if (rex) {
            out.push_back(0x40 | (rex_w << 3) | (rex_r << 2) | (rex_x << 1) | rex_b);
        }
        out.insert(out.end(), opcode.begin(), opcode.end());
        if (has_modrm) out.push_back(modrm);
        if (has_sib) out.push_back(sib);
        const size_t disp_at = out.size();
        out.insert(out.end(), disp.begin(), disp.end());
        if (rel32_at) rel32_at = disp_at; // rel32 is carried in `disp`
        out.insert(out.end(), imm.begin(), imm.end());
        return out;
    }
};

void Insn::rm_mem(const Mem& m, bool is64) {
    has_modrm = true;
    if (m.rip_relative) {           // [rip + disp32]
        modrm = (modrm & 0x38) | 0x05;
        put_le(disp, static_cast<uint64_t>(m.disp), 4);
        return;
    }
    const bool have_base = m.base.has_value();
    const bool have_index = m.index.has_value();

    if (!have_base && !have_index) { // [disp32] -> in 64-bit this needs a SIB with no base
        if (is64) {
            modrm = (modrm & 0x38) | 0x04;
            has_sib = true;
            sib = (0 << 6) | (4 << 3) | 5; // scale=0, index=none, base=none
            put_le(disp, static_cast<uint64_t>(m.disp), 4);
        } else {
            modrm = (modrm & 0x38) | 0x05;
            put_le(disp, static_cast<uint64_t>(m.disp), 4);
        }
        return;
    }

    // Decide the displacement form
    int mod;
    const bool base_is_bp = have_base && (m.base->num & 7) == 5; // rbp/r13 can't be mod=00
    if (m.disp == 0 && !base_is_bp) mod = 0;
    else if (fits_i8(m.disp)) mod = 1;
    else mod = 2;

    const bool need_sib = have_index || (have_base && (m.base->num & 7) == 4); // rsp/r12 base forces SIB
    if (!need_sib) {
        modrm = (modrm & 0x38) | (mod << 6) | (m.base->num & 7);
        if (m.base->num >= 8) rex_b = true;
    } else {
        modrm = (modrm & 0x38) | (mod << 6) | 4; // rm=100 -> SIB
        has_sib = true;
        int scale_bits = m.scale == 1 ? 0 : m.scale == 2 ? 1 : m.scale == 4 ? 2 : 3;
        int index = have_index ? (m.index->num & 7) : 4; // 4 = no index
        int base = have_base ? (m.base->num & 7) : 5;    // 5 + mod=00 = no base
        sib = (scale_bits << 6) | (index << 3) | base;
        if (have_index && m.index->num >= 8) rex_x = true;
        if (have_base && m.base->num >= 8) rex_b = true;
        if (!have_base) { mod = 0; modrm = (modrm & 0x3F) | 0x00; } // disp32, no base
    }
    if (mod == 1) put_le(disp, static_cast<uint64_t>(m.disp), 1);
    else if (mod == 2 || (need_sib && !have_base)) put_le(disp, static_cast<uint64_t>(m.disp), 4);
}

// Sets operand-size bits (REX.W / 0x66) from a register width
void apply_width(Insn& in, int bits) {
    if (bits == 64) in.rex_w = true;
    else if (bits == 16) in.op16 = true;
}

} // anonymous namespace

std::optional<X86Assembler::Encoded> X86Assembler::encode(const std::string& instruction, uintptr_t address,
                                                          std::string& error) {
    const std::string line = trim(instruction);
    const size_t sp = line.find_first_of(" \t");
    const std::string mnem = lower(sp == std::string::npos ? line : line.substr(0, sp));
    const std::string rest = sp == std::string::npos ? "" : trim(line.substr(sp));
    const std::vector<std::string> ops = split_commas(rest);

    Insn in;
    in.x64 = m_x64;
    auto done = [&](std::optional<size_t> rel = std::nullopt) -> std::optional<Encoded> {
        Encoded e;
        e.bytes = in.bytes();
        if (rel) e.rel32_offset = in.rel32_at;
        return e;
    };

    // --- no operands ---
    if (ops.empty()) {
        if (mnem == "nop") return Encoded{{0x90}, std::nullopt, false, 0};
        if (mnem == "ret") return Encoded{{0xC3}, std::nullopt, false, 0};
        if (mnem == "int3") return Encoded{{0xCC}, std::nullopt, false, 0};
        if (mnem == "pushfq" || mnem == "pushf") return Encoded{{0x9C}, std::nullopt, false, 0};
        if (mnem == "popfq" || mnem == "popf") return Encoded{{0x9D}, std::nullopt, false, 0};
        if (mnem == "cpuid") return Encoded{{0x0F, 0xA2}, std::nullopt, false, 0};
        error = "unknown instruction '" + mnem + "'";
        return std::nullopt;
    }

    // --- push / pop reg ---
    if ((mnem == "push" || mnem == "pop") && ops.size() == 1) {
        if (auto r = parse_reg(ops[0]); r && (r->bits == 64 || r->bits == 16)) {
            if (r->bits == 16) in.op16 = true;
            if (r->num >= 8) in.rex_b = true;
            in.opcode = {static_cast<uint8_t>((mnem == "push" ? 0x50 : 0x58) + (r->num & 7))};
            return done();
        }
        if (mnem == "push") {
            if (auto n = parse_number(ops[0])) {
                if (fits_i8(*n)) { in.opcode = {0x6A}; put_le(in.imm, static_cast<uint64_t>(*n), 1); }
                else { in.opcode = {0x68}; put_le(in.imm, static_cast<uint64_t>(*n), 4); }
                return done();
            }
        }
        error = mnem + " supports a 64-bit register (or a push immediate)";
        return std::nullopt;
    }

    // --- jmp / call / jcc rel32 ---
    static const std::vector<std::pair<std::string, uint8_t>> jcc = {
        {"jmp", 0xE9}, {"call", 0xE8}, {"je", 0x84}, {"jz", 0x84}, {"jne", 0x85}, {"jnz", 0x85},
        {"jg", 0x8F}, {"jge", 0x8D}, {"jl", 0x8C}, {"jle", 0x8E}, {"ja", 0x87}, {"jae", 0x83},
        {"jb", 0x82}, {"jbe", 0x86}, {"js", 0x88}, {"jns", 0x89}};
    // jmp/call to a register or memory is indirect (FF /4, FF /2), handled further down, not a rel32
    const bool indirect_target = (mnem == "jmp" || mnem == "call") && ops.size() == 1 &&
                                 (parse_reg(ops[0]).has_value() || ops[0].find('[') != std::string::npos);
    if (ops.size() == 1 && !indirect_target) {
        for (const auto& [name, op] : jcc) {
            if (mnem != name) continue;
            const bool two_byte = (name != "jmp" && name != "call");
            if (two_byte) in.opcode = {0x0F, op};
            else in.opcode = {op};
            size_t rel_pos;
            Encoded e;
            auto target = parse_number(ops[0]);
            if (target) { // absolute target: rel = target - (addr + len)
                const size_t len = in.opcode.size() + 4;
                const int64_t rel = static_cast<int64_t>(*target) - static_cast<int64_t>(address + len);
                if (m_x64 && !fits_i32(rel)) { error = name + " target is more than 2GB away"; return std::nullopt; }
                e.bytes = in.opcode;
                rel_pos = e.bytes.size();
                put_le(e.bytes, static_cast<uint64_t>(rel), 4);
                e.rel32_offset = rel_pos;
                e.rel_is_absolute = true;
                e.rel_target = static_cast<uintptr_t>(*target);
                return e;
            }
            // a label: leave a zero rel32 for the caller to patch
            e.bytes = in.opcode;
            e.rel32_offset = e.bytes.size();
            put_le(e.bytes, 0, 4);
            return e;
        }
    }

    // --- the ALU / mov family: two operands ---
    if (ops.size() == 2) {
        std::string err;
        auto dst = parse_operand(ops[0], err);
        auto src = parse_operand(ops[1], err);
        if (!dst || !src) { error = err; return std::nullopt; }

        // width of the operation: from a register operand, else from a sized memory operand
        int width = 0;
        for (const auto* o : {&*dst, &*src}) {
            if (o->kind == Operand::Kind::Reg) width = o->reg.bits;
        }
        if (width == 0) {
            if (dst->kind == Operand::Kind::Mem && dst->mem.width) width = dst->mem.width;
            else if (src->kind == Operand::Kind::Mem && src->mem.width) width = src->mem.width;
        }
        if (width == 0) { error = "the operand size is unclear; add byte/word/dword/qword ptr"; return std::nullopt; }
        apply_width(in, width);
        const bool byte = width == 8;

        // ALU ops that share the /digit + opcode layout
        struct Alu { const char* name; uint8_t rm_r; uint8_t digit; uint8_t ax_imm; };
        static const Alu alus[] = {
            {"add", 0x00, 0, 0x04}, {"or", 0x08, 1, 0x0C}, {"adc", 0x10, 2, 0x14}, {"sbb", 0x18, 3, 0x1C},
            {"and", 0x20, 4, 0x24}, {"sub", 0x28, 5, 0x2C}, {"xor", 0x30, 6, 0x34}, {"cmp", 0x38, 7, 0x3C}};

        // mov
        if (mnem == "mov") {
            if (src->kind == Operand::Kind::Imm && dst->kind == Operand::Kind::Reg) {
                const Reg& r = dst->reg;
                if (r.bits == 64 && !fits_i32(src->imm)) { // mov r64, imm64 (B8 +rq, imm64)
                    if (r.num >= 8) in.rex_b = true;
                    in.rex_w = true;
                    in.opcode = {static_cast<uint8_t>(0xB8 + (r.num & 7))};
                    auto b = in.bytes();
                    put_le(b, static_cast<uint64_t>(src->imm), 8);
                    Encoded e; e.bytes = b; return e;
                }
                if (r.bits == 64) { // mov r64, imm32 -> C7 /0 (sign-extended), shorter than B8+imm64
                    in.opcode = {0xC7};
                    in.rm_reg(r);
                    in.set_reg(0);
                    put_le(in.imm, static_cast<uint64_t>(src->imm), 4);
                    return done();
                }
                // mov r32/r16/r8, imm via B8/B0 +rd
                if (r.num >= 8) in.rex_b = true;
                if (byte) {
                    if (r.bits == 8 && !r.high8 && r.num >= 4 && r.num <= 7) in.need_rex = true;
                    in.opcode = {static_cast<uint8_t>(0xB0 + (r.num & 7))};
                    put_le(in.imm, static_cast<uint64_t>(src->imm), 1);
                } else {
                    in.opcode = {static_cast<uint8_t>(0xB8 + (r.num & 7))};
                    put_le(in.imm, static_cast<uint64_t>(src->imm), width == 16 ? 2 : 4);
                }
                return done();
            }
            if (src->kind == Operand::Kind::Imm && dst->kind == Operand::Kind::Mem) { // mov [mem], imm (C6/C7 /0)
                in.opcode = {static_cast<uint8_t>(byte ? 0xC6 : 0xC7)};
                in.rm_mem(dst->mem, m_x64);
                in.set_reg(0);
                put_le(in.imm, static_cast<uint64_t>(src->imm), byte ? 1 : width == 16 ? 2 : 4);
                return done();
            }
            // mov r/m, r (88/89) or mov r, r/m (8A/8B)
            if (src->kind == Operand::Kind::Reg && dst->kind != Operand::Kind::Imm) {
                in.opcode = {static_cast<uint8_t>(byte ? 0x88 : 0x89)};
                in.set_reg(src->reg.num);
                if (byte && !src->reg.high8 && src->reg.num >= 4 && src->reg.num <= 7) in.need_rex = true;
                if (dst->kind == Operand::Kind::Reg) in.rm_reg(dst->reg); else in.rm_mem(dst->mem, m_x64);
                return done();
            }
            if (dst->kind == Operand::Kind::Reg && src->kind == Operand::Kind::Mem) {
                in.opcode = {static_cast<uint8_t>(byte ? 0x8A : 0x8B)};
                in.set_reg(dst->reg.num);
                in.rm_mem(src->mem, m_x64);
                return done();
            }
            error = "unsupported mov form";
            return std::nullopt;
        }

        if (mnem == "lea") {
            if (dst->kind != Operand::Kind::Reg || src->kind != Operand::Kind::Mem) {
                error = "lea needs a register and a memory operand";
                return std::nullopt;
            }
            in.rex_w = dst->reg.bits == 64;
            in.op16 = dst->reg.bits == 16;
            in.opcode = {0x8D};
            in.set_reg(dst->reg.num);
            in.rm_mem(src->mem, m_x64);
            return done();
        }

        for (const auto& a : alus) {
            if (mnem != a.name) continue;
            if (src->kind == Operand::Kind::Imm) {
                const bool imm8 = fits_i8(src->imm) && !byte;
                in.opcode = {static_cast<uint8_t>(byte ? 0x80 : imm8 ? 0x83 : 0x81)};
                if (dst->kind == Operand::Kind::Reg) in.rm_reg(dst->reg); else in.rm_mem(dst->mem, m_x64);
                in.set_reg(a.digit);
                put_le(in.imm, static_cast<uint64_t>(src->imm), byte ? 1 : imm8 ? 1 : width == 16 ? 2 : 4);
                return done();
            }
            if (src->kind == Operand::Kind::Reg) { // op r/m, r
                in.opcode = {static_cast<uint8_t>(a.rm_r + (byte ? 0 : 1))};
                in.set_reg(src->reg.num);
                if (byte && !src->reg.high8 && src->reg.num >= 4 && src->reg.num <= 7) in.need_rex = true;
                if (dst->kind == Operand::Kind::Reg) in.rm_reg(dst->reg); else in.rm_mem(dst->mem, m_x64);
                return done();
            }
            if (dst->kind == Operand::Kind::Reg && src->kind == Operand::Kind::Mem) { // op r, r/m
                in.opcode = {static_cast<uint8_t>(a.rm_r + (byte ? 2 : 3))};
                in.set_reg(dst->reg.num);
                in.rm_mem(src->mem, m_x64);
                return done();
            }
        }

        if (mnem == "test") {
            if (src->kind == Operand::Kind::Reg) {
                in.opcode = {static_cast<uint8_t>(byte ? 0x84 : 0x85)};
                in.set_reg(src->reg.num);
                if (dst->kind == Operand::Kind::Reg) in.rm_reg(dst->reg); else in.rm_mem(dst->mem, m_x64);
                return done();
            }
            if (src->kind == Operand::Kind::Imm) {
                in.opcode = {static_cast<uint8_t>(byte ? 0xF6 : 0xF7)};
                if (dst->kind == Operand::Kind::Reg) in.rm_reg(dst->reg); else in.rm_mem(dst->mem, m_x64);
                in.set_reg(0);
                put_le(in.imm, static_cast<uint64_t>(src->imm), byte ? 1 : width == 16 ? 2 : 4);
                return done();
            }
        }

        error = "unsupported instruction '" + mnem + "' with these operands";
        return std::nullopt;
    }

    // --- inc / dec / neg / not / mul / div: one r/m operand ---
    if (ops.size() == 1) {
        std::string err;
        auto dst = parse_operand(ops[0], err);
        if (!dst) { error = err; return std::nullopt; }
        int width = dst->kind == Operand::Kind::Reg ? dst->reg.bits : dst->mem.width;
        if (width == 0) { error = "the operand size is unclear; add byte/word/dword/qword ptr"; return std::nullopt; }
        apply_width(in, width);
        const bool byte = width == 8;

        struct Unary { const char* name; uint8_t opcode; uint8_t digit; };
        static const Unary unaries[] = {{"inc", 0xFE, 0}, {"dec", 0xFE, 1}, {"not", 0xF6, 2}, {"neg", 0xF6, 3},
                                        {"mul", 0xF6, 4}, {"imul", 0xF6, 5}, {"div", 0xF6, 6}, {"idiv", 0xF6, 7}};
        for (const auto& u : unaries) {
            if (mnem != u.name) continue;
            in.opcode = {static_cast<uint8_t>(u.opcode + (byte ? 0 : 1))};
            if (dst->kind == Operand::Kind::Reg) in.rm_reg(dst->reg); else in.rm_mem(dst->mem, m_x64);
            in.set_reg(u.digit);
            return done();
        }
        // call/jmp through a register or memory (indirect): FF /2, FF /4
        if (mnem == "call" || mnem == "jmp") {
            in.opcode = {0xFF};
            if (dst->kind == Operand::Kind::Reg) in.rm_reg(dst->reg); else in.rm_mem(dst->mem, m_x64);
            in.set_reg(mnem == "call" ? 2 : 4);
            in.rex_w = false; // default 64-bit operand size for these, no REX.W needed
            return done();
        }
    }

    error = "unknown or unsupported instruction '" + mnem + "'";
    return std::nullopt;
}

} // namespace nce::assembler
