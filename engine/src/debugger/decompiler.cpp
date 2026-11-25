#include "../../include/debugger/decompiler.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace nce::debugger {

namespace {

std::string trim_copy(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string hex_str(uint64_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << v;
    return ss.str();
}

// Canonicalizes register aliases (eax/ax/al -> rax, etc.) so 32/64-bit writes stay coherent
std::string canonical_reg(const std::string& r_in) {
    const std::string r = lower_copy(trim_copy(r_in));
    static const std::unordered_map<std::string, const char*> kAliases = {
        {"rax","rax"},{"eax","rax"},{"ax","rax"},{"al","rax"},{"ah","rax"},
        {"rbx","rbx"},{"ebx","rbx"},{"bx","rbx"},{"bl","rbx"},{"bh","rbx"},
        {"rcx","rcx"},{"ecx","rcx"},{"cx","rcx"},{"cl","rcx"},{"ch","rcx"},
        {"rdx","rdx"},{"edx","rdx"},{"dx","rdx"},{"dl","rdx"},{"dh","rdx"},
        {"rsi","rsi"},{"esi","rsi"},{"si","rsi"},{"sil","rsi"},
        {"rdi","rdi"},{"edi","rdi"},{"di","rdi"},{"dil","rdi"},
        {"rbp","rbp"},{"ebp","rbp"},{"bp","rbp"},{"bpl","rbp"},
        {"rsp","rsp"},{"esp","rsp"},{"sp","rsp"},{"spl","rsp"},
        {"r8","r8"},{"r8d","r8"},{"r8w","r8"},{"r8b","r8"},
        {"r9","r9"},{"r9d","r9"},{"r9w","r9"},{"r9b","r9"},
        {"r10","r10"},{"r10d","r10"},{"r10w","r10"},{"r10b","r10"},
        {"r11","r11"},{"r11d","r11"},{"r11w","r11"},{"r11b","r11"},
        {"r12","r12"},{"r12d","r12"},{"r12w","r12"},{"r12b","r12"},
        {"r13","r13"},{"r13d","r13"},{"r13w","r13"},{"r13b","r13"},
        {"r14","r14"},{"r14d","r14"},{"r14w","r14"},{"r14b","r14"},
        {"r15","r15"},{"r15d","r15"},{"r15w","r15"},{"r15b","r15"},
    };
    auto it = kAliases.find(r);
    if (it != kAliases.end()) return it->second;
    if (r.rfind("xmm", 0) == 0) return r;
    return {};
}

std::string mem_c_type(const std::string& prefix_hint) {
    const std::string p = lower_copy(prefix_hint);
    if (p.find("byte ptr") != std::string::npos) return "uint8_t";
    if (p.find("word ptr") != std::string::npos && p.find("dword") == std::string::npos &&
        p.find("qword") == std::string::npos && p.find("xmmword") == std::string::npos) return "uint16_t";
    if (p.find("dword ptr") != std::string::npos) return "int32_t";
    if (p.find("qword ptr") != std::string::npos) return "int64_t";
    if (p.find("xmmword ptr") != std::string::npos) return "__m128";
    return "int64_t";
}

bool parse_signed_number(const std::string& s_in, int64_t& out) {
    std::string s = trim_copy(s_in);
    if (s.empty()) return false;
    bool neg = false;
    if (s.front() == '-') { neg = true; s = trim_copy(s.substr(1)); }
    else if (s.front() == '+') { s = trim_copy(s.substr(1)); }
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
        base = 16;
    }
    if (s.empty()) return false;
    uint64_t v = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
    if (ec != std::errc() || ptr != s.data() + s.size()) return false;
    out = neg ? -static_cast<int64_t>(v) : static_cast<int64_t>(v);
    return true;
}

std::pair<std::string, std::string> split_two_operands(const std::string& ops) {
    int depth = 0;
    for (size_t i = 0; i < ops.size(); ++i) {
        if (ops[i] == '[') ++depth;
        else if (ops[i] == ']' && depth > 0) --depth;
        else if (ops[i] == ',' && depth == 0) {
            return {trim_copy(ops.substr(0, i)), trim_copy(ops.substr(i + 1))};
        }
    }
    return {trim_copy(ops), ""};
}

std::string sanitize_ident(std::string raw) {
    if (raw.empty()) return "sym";
    for (char& c : raw) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') c = '_';
    }
    if (std::isdigit(static_cast<unsigned char>(raw.front()))) raw = "_" + raw;
    return raw;
}

struct LiftState {
    explicit LiftState(const DecompileOptions& o) : opts(o) {}
    const DecompileOptions& opts;
    std::set<std::string> local_decls;
    std::set<std::string> params_used;
    std::unordered_map<std::string, std::string> reg_expr; // canonical reg -> current C expr
    std::string last_cmp_lhs;
    std::string last_cmp_rhs;
    bool last_cmp_is_test{false};

    std::string reg_var(const std::string& r) {
        const std::string c = canonical_reg(r);
        if (c.empty()) return trim_copy(r);
        const bool is_param = opts.sysv_abi
            ? (c == "rdi" || c == "rsi" || c == "rdx" || c == "rcx" || c == "r8" || c == "r9")
            : (c == "rcx" || c == "rdx" || c == "r8" || c == "r9");
        if (is_param) {
            params_used.insert(c);
        } else if (c != "rsp" && c != "rbp") {
            const std::string ty = (c.rfind("xmm", 0) == 0) ? "double" : "int64_t";
            local_decls.insert(ty + " " + c + ";");
        }
        return c;
    }

    std::string format_mem_expr(const std::string& operand, const DecodedInstruction& insn, bool for_lea) {
        const size_t lb = operand.find('[');
        const size_t rb = operand.rfind(']');
        if (lb == std::string::npos || rb == std::string::npos || rb <= lb) return operand;
        const std::string prefix = operand.substr(0, lb);
        std::string inner = trim_copy(operand.substr(lb + 1, rb - lb - 1));
        const std::string lower_inner = lower_copy(inner);

        if (lower_inner.rfind("rip", 0) == 0 && insn.branch_target != 0) {
            std::string sym_expr;
            if (opts.symbol_resolver) {
                std::string s = opts.symbol_resolver(insn.branch_target);
                if (!s.empty()) sym_expr = sanitize_ident(s);
            }
            if (sym_expr.empty()) sym_expr = "g_" + hex_str(insn.branch_target);
            if (for_lea) return "&" + sym_expr;
            return "*(" + mem_c_type(prefix) + "*)&" + sym_expr;
        }

        // Parse base +/- disp or simple scaled index
        int64_t disp = 0;
        std::string base_part = inner;
        const size_t plus = inner.find('+');
        const size_t minus = inner.find('-');
        if (plus != std::string::npos && inner.find('*') == std::string::npos) {
            int64_t val = 0;
            if (parse_signed_number(inner.substr(plus + 1), val)) {
                disp = val;
                base_part = trim_copy(inner.substr(0, plus));
            }
        } else if (minus != std::string::npos && inner.find('*') == std::string::npos) {
            int64_t val = 0;
            if (parse_signed_number(inner.substr(minus + 1), val)) {
                disp = -val;
                base_part = trim_copy(inner.substr(0, minus));
            }
        }

        const std::string base_c = canonical_reg(base_part);
        if (base_c == "rbp" && disp < 0) {
            const std::string var = "var_" + hex_str(static_cast<uint64_t>(-disp)).substr(2);
            local_decls.insert(mem_c_type(prefix) + " " + var + " = 0;");
            return for_lea ? ("&" + var) : var;
        }
        if (base_c == "rsp" && disp >= 0) {
            const std::string var = "stack_" + hex_str(static_cast<uint64_t>(disp)).substr(2);
            local_decls.insert(mem_c_type(prefix) + " " + var + " = 0;");
            return for_lea ? ("&" + var) : var;
        }

        if (!opts.struct_fields.empty() && !base_c.empty()) {
            const std::string expected_base = opts.struct_base_reg.empty()
                ? (opts.sysv_abi ? "rdi" : "rcx")
                : canonical_reg(opts.struct_base_reg);
            if (base_c == expected_base) {
                auto fit = opts.struct_fields.find(disp);
                if (fit != opts.struct_fields.end()) {
                    const std::string field = sanitize_ident(fit->second.second);
                    const std::string expr = reg_var(base_c) + "->" + field;
                    return for_lea ? ("&(" + expr + ")") : expr;
                }
            }
        }

        std::string addr_expr = base_part;
        if (!base_c.empty()) {
            addr_expr = read_rval(base_c);
            if (disp > 0) addr_expr += " + " + hex_str(static_cast<uint64_t>(disp));
            else if (disp < 0) addr_expr += " - " + hex_str(static_cast<uint64_t>(-disp));
        } else {
            // General expression (SIB, index*scale, etc.)
            for (const char* r : {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"}) {
                if (lower_inner.find(r) != std::string::npos) reg_var(r);
            }
            addr_expr = inner;
        }

        if (for_lea) return "(" + addr_expr + ")";
        return "*(" + mem_c_type(prefix) + "*)(" + addr_expr + ")";
    }

    std::string read_rval(const std::string& op_in, const DecodedInstruction* insn = nullptr) {
        const std::string op = trim_copy(op_in);
        if (op.find('[') != std::string::npos && insn) {
            return format_mem_expr(op, *insn, false);
        }
        const std::string c = canonical_reg(op);
        if (!c.empty()) {
            reg_var(c);
            auto it = reg_expr.find(c);
            if (it != reg_expr.end() && !it->second.empty()) return it->second;
            return c;
        }
        return op;
    }

    std::string condition_from_jcc(const std::string& mnem_in) const {
        std::string cc = lower_copy(mnem_in);
        if (!cc.empty() && cc[0] == 'j') cc = cc.substr(1);
        if (last_cmp_lhs.empty()) return "flag_" + cc;

        if (last_cmp_is_test && last_cmp_lhs == last_cmp_rhs) {
            if (cc == "e" || cc == "z") return last_cmp_lhs + " == 0";
            if (cc == "ne" || cc == "nz") return last_cmp_lhs + " != 0";
            if (cc == "s") return "(int64_t)" + last_cmp_lhs + " < 0";
            if (cc == "ns") return "(int64_t)" + last_cmp_lhs + " >= 0";
        }
        const std::string rhs = last_cmp_is_test ? ("(" + last_cmp_lhs + " & " + last_cmp_rhs + ") != 0") : last_cmp_rhs;
        if (last_cmp_is_test) {
            if (cc == "e" || cc == "z") return "(" + last_cmp_lhs + " & " + last_cmp_rhs + ") == 0";
            if (cc == "ne" || cc == "nz") return rhs;
        }
        auto rel = [&](const char* op) { return last_cmp_lhs + " " + op + " " + last_cmp_rhs; };
        if (cc == "e" || cc == "z") return rel("==");
        if (cc == "ne" || cc == "nz") return rel("!=");
        if (cc == "l" || cc == "nge" || cc == "b" || cc == "c" || cc == "nae") return rel("<");
        if (cc == "le" || cc == "ng" || cc == "be" || cc == "na") return rel("<=");
        if (cc == "g" || cc == "nle" || cc == "a" || cc == "nbe") return rel(">");
        if (cc == "ge" || cc == "nl" || cc == "ae" || cc == "nb" || cc == "nc") return rel(">=");
        if (cc == "p" || cc == "pe") return "is_unordered(" + last_cmp_lhs + ", " + last_cmp_rhs + ")";
        return last_cmp_lhs + " /* " + cc + " */ " + last_cmp_rhs;
    }

    std::string lift_instruction(const DecodedInstruction& insn, bool& is_branch_or_ret) {
        is_branch_or_ret = false;
        std::string mnem = lower_copy(insn.mnemonic);
        const bool is_lock = mnem.rfind("lock ", 0) == 0;
        if (is_lock) mnem = trim_copy(mnem.substr(5));

        const auto [dst_raw, src_raw] = split_two_operands(insn.operands);

        auto fmt_comment = [&](std::string stmt) {
            if (opts.include_address_comments && !stmt.empty()) {
                stmt += " // " + hex_str(insn.address);
            }
            return stmt;
        };

        if (mnem == "nop" || mnem == "int3") return {};
        if (mnem == "ret" || mnem == "retn") {
            is_branch_or_ret = true;
            if (reg_expr.count("rax")) return fmt_comment("return " + reg_expr["rax"] + ";");
            return fmt_comment("return rax;");
        }
        if (mnem == "jmp" || (mnem.size() >= 2 && mnem[0] == 'j')) {
            is_branch_or_ret = true;
            return {};
        }

        if (mnem == "call") {
            std::string target = dst_raw;
            if (insn.branch_target != 0) {
                if (opts.symbol_resolver) {
                    const std::string sym = opts.symbol_resolver(insn.branch_target);
                    if (!sym.empty()) target = sym;
                }
                if (target == dst_raw) target = "sub_" + hex_str(insn.branch_target).substr(2);
            }
            reg_var("rax");
            std::vector<std::string> args;
            const std::vector<const char*> abi_regs = opts.sysv_abi
                ? std::vector<const char*>{"rdi", "rsi", "rdx", "rcx"}
                : std::vector<const char*>{"rcx", "rdx", "r8", "r9"};
            for (const char* r : abi_regs) {
                auto it = reg_expr.find(r);
                if (it != reg_expr.end()) args.push_back(it->second);
            }
            std::ostringstream call_ss;
            call_ss << "rax = " << sanitize_ident(target) << "(";
            for (size_t i = 0; i < args.size(); ++i) {
                if (i > 0) call_ss << ", ";
                call_ss << args[i];
            }
            call_ss << ");";
            reg_expr.erase("rax");
            return fmt_comment(call_ss.str());
        }

        if (mnem == "push" || mnem == "pop") {
            if (!dst_raw.empty()) reg_var(dst_raw);
            return fmt_comment("/* " + mnem + " " + dst_raw + " */");
        }

        if (mnem == "cmp" || mnem == "test" || mnem == "ucomiss" || mnem == "ucomisd" ||
            mnem == "comiss" || mnem == "comisd") {
            last_cmp_lhs = read_rval(dst_raw, &insn);
            last_cmp_rhs = read_rval(src_raw, &insn);
            last_cmp_is_test = (mnem == "test");
            return {};
        }

        if (mnem == "lea" && !dst_raw.empty() && !src_raw.empty()) {
            const std::string d_var = reg_var(dst_raw);
            const std::string rhs = format_mem_expr(src_raw, insn, true);
            reg_expr[d_var] = rhs;
            return fmt_comment(d_var + " = " + rhs + ";");
        }

        if (mnem == "xor" && canonical_reg(dst_raw) == canonical_reg(src_raw) && !canonical_reg(dst_raw).empty()) {
            const std::string d_var = reg_var(dst_raw);
            reg_expr[d_var] = "0";
            return fmt_comment(d_var + " = 0;");
        }

        if ((mnem == "pxor" || mnem == "xorps" || mnem == "xorpd") &&
            canonical_reg(dst_raw) == canonical_reg(src_raw) && !dst_raw.empty()) {
            const std::string d_var = reg_var(dst_raw);
            reg_expr[d_var] = "0.0";
            return fmt_comment(d_var + " = 0.0;");
        }

        auto assign_reg_or_mem = [&](const std::string& lhs_raw, const std::string& rhs) -> std::string {
            if (lhs_raw.find('[') != std::string::npos) {
                const std::string lhs = format_mem_expr(lhs_raw, insn, false);
                return fmt_comment(lhs + " = " + rhs + ";");
            }
            const std::string d_var = reg_var(lhs_raw);
            reg_expr[d_var] = d_var;
            return fmt_comment(d_var + " = " + rhs + ";");
        };

        if (mnem == "mov" || mnem == "movzx" || mnem == "movsx" || mnem == "movsxd" ||
            mnem == "movss" || mnem == "movsd" || mnem == "movaps" || mnem == "movups" ||
            mnem == "movapd" || mnem == "movupd" || mnem == "movdqu" || mnem == "movdqa" ||
            mnem == "movd" || mnem == "movq") {
            const std::string rhs = read_rval(src_raw, &insn);
            if (dst_raw.find('[') == std::string::npos) {
                const std::string d_var = reg_var(dst_raw);
                reg_expr[d_var] = (rhs != d_var && rhs.size() < 48) ? rhs : d_var;
                return fmt_comment(d_var + " = " + rhs + ";");
            }
            return assign_reg_or_mem(dst_raw, rhs);
        }

        if (mnem == "cvtss2sd" || mnem == "cvtsd2ss" || mnem == "cvtsi2ss" || mnem == "cvtsi2sd" ||
            mnem == "cvttss2si" || mnem == "cvttsd2si") {
            const std::string cast = (mnem == "cvtss2sd" || mnem == "cvtsi2sd") ? "(double)"
                                   : (mnem == "cvtsd2ss" || mnem == "cvtsi2ss") ? "(float)" : "(int64_t)";
            const std::string rhs = cast + read_rval(src_raw, &insn);
            const std::string d_var = reg_var(dst_raw);
            reg_expr[d_var] = d_var;
            return fmt_comment(d_var + " = " + rhs + ";");
        }

        // Binary arithmetic / bitwise / SSE scalar ops
        static const std::unordered_map<std::string, const char*> kBinOps = {
            {"add","+="},{"addss","+="},{"addsd","+="},{"addps","+="},{"addpd","+="},
            {"sub","-="},{"subss","-="},{"subsd","-="},{"subps","-="},{"subpd","-="},
            {"imul","*="},{"mulss","*="},{"mulsd","*="},{"mulps","*="},{"mulpd","*="},
            {"divss","/="},{"divsd","/="},{"divps","/="},{"divpd","/="},
            {"and","&="},{"andps","&="},{"andpd","&="},
            {"or","|="},{"orps","|="},{"orpd","|="},
            {"xor","^="},{"pxor","^="},{"xorps","^="},{"xorpd","^="},
            {"shl","<<="},{"sal","<<="},{"shr",">>="},{"sar",">>="}
        };
        if (auto it = kBinOps.find(mnem); it != kBinOps.end() && !src_raw.empty()) {
            const std::string rhs = read_rval(src_raw, &insn);
            const std::string lhs = (dst_raw.find('[') != std::string::npos)
                ? format_mem_expr(dst_raw, insn, false)
                : reg_var(dst_raw);
            if (dst_raw.find('[') == std::string::npos) reg_expr.erase(lhs);
            return fmt_comment((is_lock ? "atomic_fetch_op(" + lhs + " " + it->second + " " + rhs + ");"
                                        : lhs + " " + it->second + " " + rhs + ";"));
        }

        if (mnem == "minss" || mnem == "minsd" || mnem == "maxss" || mnem == "maxsd") {
            const std::string fn = (mnem.rfind("min", 0) == 0) ? "std::min" : "std::max";
            const std::string d_var = reg_var(dst_raw);
            const std::string rhs = read_rval(src_raw, &insn);
            reg_expr.erase(d_var);
            return fmt_comment(d_var + " = " + fn + "(" + d_var + ", " + rhs + ");");
        }

        if (mnem == "xadd" || mnem == "cmpxchg") {
            const std::string lhs = (dst_raw.find('[') != std::string::npos)
                ? format_mem_expr(dst_raw, insn, false) : reg_var(dst_raw);
            const std::string rhs = read_rval(src_raw, &insn);
            if (mnem == "xadd") {
                return fmt_comment((is_lock ? "atomic_exchange_add(&(" + lhs + "), " + rhs + ");"
                                            : rhs + " = exchange_add(&(" + lhs + "), " + rhs + ");"));
            }
            return fmt_comment((is_lock ? "atomic_cmpxchg(&(" + lhs + "), rax, " + rhs + ");"
                                        : "cmpxchg(&(" + lhs + "), rax, " + rhs + ");"));
        }

        if (mnem == "inc" || mnem == "dec" || mnem == "neg" || mnem == "not") {
            const std::string lhs = (dst_raw.find('[') != std::string::npos)
                ? format_mem_expr(dst_raw, insn, false) : reg_var(dst_raw);
            if (dst_raw.find('[') == std::string::npos) reg_expr.erase(lhs);
            if (mnem == "inc") return fmt_comment((is_lock ? "atomic_inc(&(" + lhs + "));" : "++" + lhs + ";"));
            if (mnem == "dec") return fmt_comment((is_lock ? "atomic_dec(&(" + lhs + "));" : "--" + lhs + ";"));
            const char* op = (mnem == "neg") ? "-" : "~";
            return fmt_comment(lhs + " = " + op + lhs + ";");
        }

        if (mnem.rfind("cmov", 0) == 0 && !src_raw.empty()) {
            const std::string cc = condition_from_jcc("j" + mnem.substr(4));
            const std::string d_var = reg_var(dst_raw);
            const std::string rhs = read_rval(src_raw, &insn);
            reg_expr.erase(d_var);
            return fmt_comment("if (" + cc + ") " + d_var + " = " + rhs + ";");
        }

        return fmt_comment("/* " + insn.format() + " */");
    }
};

} // namespace

DecompileOptions DecompileOptions::from_struct(const view::StructLayout& layout, std::string base_reg) {
    DecompileOptions opts;
    opts.struct_base_reg = std::move(base_reg);
    for (const auto& f : layout.fields) {
        opts.struct_fields[static_cast<int64_t>(f.offset)] = {f.type, f.name};
    }
    return opts;
}

DecompiledFunction PseudoCDecompiler::decompile(const ControlFlowGraph& cfg, const DecompileOptions& options) {
    DecompiledFunction out;
    out.entry_address = cfg.entry_address;
    if (options.symbol_resolver && cfg.entry_address != 0) {
        out.name = options.symbol_resolver(cfg.entry_address);
    }
    if (out.name.empty()) {
        out.name = "sub_" + hex_str(cfg.entry_address).substr(2);
    }
    out.name = sanitize_ident(out.name);

    if (cfg.blocks.empty()) {
        out.signature = "void " + out.name + "(void)";
        out.code = out.signature + "\n{\n    // No instructions decoded.\n}\n";
        return out;
    }

    // Build outgoing edge adjacency per block
    struct EdgeOut { size_t to; CFGEdge::Kind kind; };
    std::vector<std::vector<EdgeOut>> adj(cfg.blocks.size());
    std::vector<bool> has_back_edge(cfg.blocks.size(), false);
    for (const auto& e : cfg.edges) {
        if (e.from_block < adj.size() && e.to_block < adj.size()) {
            adj[e.from_block].push_back({e.to_block, e.kind});
            if (e.to_block <= e.from_block) has_back_edge[e.to_block] = true;
        }
    }

    LiftState state{options};
    struct LiftedBlockInfo {
        DecompiledBlock block;
        std::string term_cond;
        std::optional<size_t> true_blk;
        std::optional<size_t> false_blk;
        std::optional<size_t> uncond_blk;
        bool ends_with_ret{false};
    };
    std::vector<LiftedBlockInfo> lifted(cfg.blocks.size());

    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        const auto& b = cfg.blocks[i];
        lifted[i].block.block_id = b.id;
        lifted[i].block.start_address = b.start_address;
        // Clear register expression folding across non-sequential block boundaries
        if (i > 0) {
            state.reg_expr.clear();
            state.last_cmp_lhs.clear();
            state.last_cmp_rhs.clear();
        }
        for (const auto& insn : b.instructions) {
            bool is_term = false;
            const std::string stmt = state.lift_instruction(insn, is_term);
            if (!stmt.empty()) lifted[i].block.statements.push_back(stmt);
            if (is_term) {
                const std::string m = lower_copy(insn.mnemonic);
                if (m == "ret" || m == "retn") {
                    lifted[i].ends_with_ret = true;
                } else if (m != "jmp" && m.size() >= 2 && m[0] == 'j') {
                    lifted[i].term_cond = state.condition_from_jcc(m);
                }
            }
        }
        for (const auto& eo : adj[i]) {
            if (eo.kind == CFGEdge::Kind::TrueBranch) lifted[i].true_blk = eo.to;
            else if (eo.kind == CFGEdge::Kind::FalseBranch) lifted[i].false_blk = eo.to;
            else lifted[i].uncond_blk = eo.to;
        }
        out.blocks.push_back(lifted[i].block);
    }

    // Build function signature from observed ABI parameter registers
    std::ostringstream sig;
    sig << "int64_t " << out.name << "(";
    const std::vector<const char*> abi_order = options.sysv_abi
        ? std::vector<const char*>{"rdi","rsi","rdx","rcx","r8","r9"}
        : std::vector<const char*>{"rcx","rdx","r8","r9"};
    bool first_p = true;
    for (const char* r : abi_order) {
        if (state.params_used.count(r)) {
            if (!first_p) sig << ", ";
            if (!options.struct_fields.empty() && r == abi_order[0]) {
                sig << "void* " << r;
            } else {
                sig << "int64_t " << r;
            }
            first_p = false;
        }
    }
    if (first_p) sig << "void";
    sig << ")";
    out.signature = sig.str();

    out.locals.assign(state.local_decls.begin(), state.local_decls.end());

    // Render structured Pseudo-C with simple loop/if detection + goto fallback for irreducible edges
    std::ostringstream body;
    body << out.signature << " {\n";
    for (const auto& decl : out.locals) {
        body << "    " << decl << "\n";
    }
    if (!out.locals.empty()) body << "\n";

    std::vector<bool> emitted(lifted.size(), false);
    auto emit_indent = [&](int lvl) {
        for (int k = 0; k < lvl; ++k) body << "    ";
    };

    std::function<void(size_t, int)> emit_block = [&](size_t idx, int indent) {
        if (idx >= lifted.size() || emitted[idx]) return;
        emitted[idx] = true;
        const auto& lb = lifted[idx];
        const bool loop_hdr = has_back_edge[idx];

        if (idx > 0 && !loop_hdr) {
            body << "block_" << hex_str(lb.block.start_address).substr(2) << ":\n";
        }
        if (loop_hdr) {
            emit_indent(indent);
            body << "while (true) { // loop @" << hex_str(lb.block.start_address) << "\n";
            ++indent;
        }

        for (const auto& st : lb.block.statements) {
            emit_indent(indent);
            body << st << "\n";
        }

        if (!lb.ends_with_ret) {
            if (lb.true_blk && lb.false_blk) {
                const size_t t_idx = *lb.true_blk;
                const size_t f_idx = *lb.false_blk;
                const std::string cond = lb.term_cond.empty() ? "cond" : lb.term_cond;
                if (loop_hdr && t_idx == idx) {
                    emit_indent(indent);
                    body << "if (!(" << cond << ")) break;\n";
                    if (!emitted[f_idx]) emit_block(f_idx, indent - 1);
                } else {
                    emit_indent(indent);
                    body << "if (" << cond << ") {\n";
                    if (!emitted[t_idx] && t_idx > idx) {
                        emit_block(t_idx, indent + 1);
                    } else {
                        emit_indent(indent + 1);
                        body << "goto block_" << hex_str(lifted[t_idx].block.start_address).substr(2) << ";\n";
                    }
                    emit_indent(indent);
                    body << "}";
                    if (!emitted[f_idx] && f_idx == idx + 1) {
                        body << " else {\n";
                        emit_block(f_idx, indent + 1);
                        emit_indent(indent);
                        body << "}\n";
                    } else {
                        body << "\n";
                        if (!emitted[f_idx]) emit_block(f_idx, indent);
                        else {
                            emit_indent(indent);
                            body << "goto block_" << hex_str(lifted[f_idx].block.start_address).substr(2) << ";\n";
                        }
                    }
                }
            } else if (lb.uncond_blk) {
                const size_t nxt = *lb.uncond_blk;
                if (nxt != idx + 1 || emitted[nxt]) {
                    emit_indent(indent);
                    if (loop_hdr && nxt == idx) {
                        body << "continue;\n";
                    } else {
                        body << "goto block_" << hex_str(lifted[nxt].block.start_address).substr(2) << ";\n";
                    }
                }
            }
        }

        if (loop_hdr) {
            --indent;
            emit_indent(indent);
            body << "}\n";
        }
    };

    for (size_t i = 0; i < lifted.size(); ++i) {
        if (!emitted[i]) emit_block(i, 1);
    }

    body << "}\n";
    out.code = body.str();
    return out;
}

} // namespace nce::debugger
