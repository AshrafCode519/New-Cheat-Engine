#include "../../include/debugger/condition_eval.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <vector>

namespace nce::debugger {

namespace {

enum class TokKind {
    End,
    Number,
    Ident,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Plus,
    Minus,
    Amp,
    Pipe,
    Caret,
    Bang,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr
};

struct Token {
    TokKind kind{TokKind::End};
    std::string text;
    uint64_t number{0};
};

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool tokenize(const std::string& input, std::vector<Token>& out, std::string& err) {
    out.clear();
    size_t i = 0;
    while (i < input.size()) {
        if (std::isspace(static_cast<unsigned char>(input[i]))) {
            ++i;
            continue;
        }
        const char c = input[i];
        const char next = (i + 1 < input.size()) ? input[i + 1] : '\0';

        if (c == '&' && next == '&') { out.push_back({TokKind::AndAnd, "&&", 0}); i += 2; continue; }
        if (c == '|' && next == '|') { out.push_back({TokKind::OrOr, "||", 0}); i += 2; continue; }
        if (c == '=' && next == '=') { out.push_back({TokKind::EqEq, "==", 0}); i += 2; continue; }
        if (c == '!' && next == '=') { out.push_back({TokKind::NotEq, "!=", 0}); i += 2; continue; }
        if (c == '<' && next == '=') { out.push_back({TokKind::Le, "<=", 0}); i += 2; continue; }
        if (c == '>' && next == '=') { out.push_back({TokKind::Ge, ">=", 0}); i += 2; continue; }

        switch (c) {
            case '(': out.push_back({TokKind::LParen, "(", 0}); ++i; continue;
            case ')': out.push_back({TokKind::RParen, ")", 0}); ++i; continue;
            case '[': out.push_back({TokKind::LBracket, "[", 0}); ++i; continue;
            case ']': out.push_back({TokKind::RBracket, "]", 0}); ++i; continue;
            case '+': out.push_back({TokKind::Plus, "+", 0}); ++i; continue;
            case '-': out.push_back({TokKind::Minus, "-", 0}); ++i; continue;
            case '&': out.push_back({TokKind::Amp, "&", 0}); ++i; continue;
            case '|': out.push_back({TokKind::Pipe, "|", 0}); ++i; continue;
            case '^': out.push_back({TokKind::Caret, "^", 0}); ++i; continue;
            case '!': out.push_back({TokKind::Bang, "!", 0}); ++i; continue;
            case '<': out.push_back({TokKind::Lt, "<", 0}); ++i; continue;
            case '>': out.push_back({TokKind::Gt, ">", 0}); ++i; continue;
            default: break;
        }

        if (std::isdigit(static_cast<unsigned char>(c))) {
            size_t j = i;
            int base = 10;
            if (c == '0' && (next == 'x' || next == 'X')) {
                base = 16;
                j += 2;
                while (j < input.size() && std::isxdigit(static_cast<unsigned char>(input[j]))) ++j;
                if (j == i + 2) {
                    err = "Invalid hex literal at position " + std::to_string(i);
                    return false;
                }
                uint64_t val = 0;
                auto [p, ec] = std::from_chars(input.data() + i + 2, input.data() + j, val, 16);
                if (ec != std::errc() || p != input.data() + j) {
                    err = "Hex number overflow or invalid digits: " + input.substr(i, j - i);
                    return false;
                }
                out.push_back({TokKind::Number, input.substr(i, j - i), val});
                i = j;
                continue;
            }
            while (j < input.size() && std::isdigit(static_cast<unsigned char>(input[j]))) ++j;
            uint64_t val = 0;
            auto [p, ec] = std::from_chars(input.data() + i, input.data() + j, val, base);
            if (ec != std::errc() || p != input.data() + j) {
                err = "Invalid integer literal: " + input.substr(i, j - i);
                return false;
            }
            out.push_back({TokKind::Number, input.substr(i, j - i), val});
            i = j;
            continue;
        }

        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t j = i;
            while (j < input.size() && (std::isalnum(static_cast<unsigned char>(input[j])) || input[j] == '_')) ++j;
            out.push_back({TokKind::Ident, lower(input.substr(i, j - i)), 0});
            i = j;
            continue;
        }

        err = std::string("Unexpected character '") + c + "' at position " + std::to_string(i);
        return false;
    }
    out.push_back({TokKind::End, "", 0});
    return true;
}

struct Val {
    uint64_t v{0};
    int width_bits{64}; // 8, 16, 32, or 64 (for literal: 64)
    bool is_literal{false};
};

uint64_t mask_for(int bits) {
    if (bits >= 64) return ~uint64_t{0};
    return (uint64_t{1} << bits) - 1;
}

int64_t sign_extend(uint64_t v, int bits) {
    if (bits == 8) return static_cast<int8_t>(v);
    if (bits == 16) return static_cast<int16_t>(v);
    if (bits == 32) return static_cast<int32_t>(v);
    return static_cast<int64_t>(v);
}

std::optional<Val> lookup_ident(const std::string& name, const Registers& r, size_t hit_count) {
    if (name == "hit" || name == "hits" || name == "hitcount") {
        return Val{static_cast<uint64_t>(hit_count), 64, false};
    }
    if (name == "eflags" || name == "efl") return Val{r.eflags, 64, false};
    if (name == "rip") return Val{r.rip, 64, false};
    if (name == "eip") return Val{r.rip & 0xFFFFFFFFULL, 32, false};

    static const std::pair<const char*, uint64_t Registers::*> k64[] = {
        {"rax", &Registers::rax}, {"rbx", &Registers::rbx}, {"rcx", &Registers::rcx}, {"rdx", &Registers::rdx},
        {"rsi", &Registers::rsi}, {"rdi", &Registers::rdi}, {"rbp", &Registers::rbp}, {"rsp", &Registers::rsp},
        {"r8", &Registers::r8},   {"r9", &Registers::r9},   {"r10", &Registers::r10}, {"r11", &Registers::r11},
        {"r12", &Registers::r12}, {"r13", &Registers::r13}, {"r14", &Registers::r14}, {"r15", &Registers::r15},
    };
    for (const auto& [reg, m] : k64) {
        if (name == reg) return Val{r.*m, 64, false};
    }

    static const std::pair<const char*, uint64_t Registers::*> k32[] = {
        {"eax", &Registers::rax}, {"ebx", &Registers::rbx}, {"ecx", &Registers::rcx}, {"edx", &Registers::rdx},
        {"esi", &Registers::rsi}, {"edi", &Registers::rdi}, {"ebp", &Registers::rbp}, {"esp", &Registers::rsp},
        {"r8d", &Registers::r8},  {"r9d", &Registers::r9},  {"r10d", &Registers::r10}, {"r11d", &Registers::r11},
        {"r12d", &Registers::r12}, {"r13d", &Registers::r13}, {"r14d", &Registers::r14}, {"r15d", &Registers::r15},
    };
    for (const auto& [reg, m] : k32) {
        if (name == reg) return Val{(r.*m) & 0xFFFFFFFFULL, 32, false};
    }

    static const std::pair<const char*, uint64_t Registers::*> k16[] = {
        {"ax", &Registers::rax}, {"bx", &Registers::rbx}, {"cx", &Registers::rcx}, {"dx", &Registers::rdx},
        {"si", &Registers::rsi}, {"di", &Registers::rdi}, {"bp", &Registers::rbp}, {"sp", &Registers::rsp},
    };
    for (const auto& [reg, m] : k16) {
        if (name == reg) return Val{(r.*m) & 0xFFFFULL, 16, false};
    }

    static const std::pair<const char*, uint64_t Registers::*> k8[] = {
        {"al", &Registers::rax}, {"bl", &Registers::rbx}, {"cl", &Registers::rcx}, {"dl", &Registers::rdx},
        {"sil", &Registers::rsi}, {"dil", &Registers::rdi}, {"bpl", &Registers::rbp}, {"spl", &Registers::rsp},
    };
    for (const auto& [reg, m] : k8) {
        if (name == reg) return Val{(r.*m) & 0xFFULL, 8, false};
    }

    return std::nullopt;
}

class Parser {
public:
    Parser(const std::vector<Token>& toks, const Registers& regs, const hal::IProcess* proc, size_t hit_count, bool dry_run)
        : m_toks(toks), m_regs(regs), m_proc(proc), m_hit(hit_count), m_dry_run(dry_run) {}

    bool parse(Val& out, std::string& err) {
        if (!parse_or(out, err)) return false;
        if (cur().kind != TokKind::End) {
            err = "Unexpected token '" + cur().text + "'";
            return false;
        }
        return true;
    }

private:
    const Token& cur() const { return m_toks[m_pos]; }
    const Token& advance() {
        const Token& t = m_toks[m_pos];
        if (m_pos + 1 < m_toks.size()) ++m_pos;
        return t;
    }

    bool parse_or(Val& out, std::string& err) {
        if (!parse_and(out, err)) return false;
        while (cur().kind == TokKind::OrOr) {
            advance();
            Val rhs;
            if (!parse_and(rhs, err)) return false;
            out = Val{(out.v != 0 || rhs.v != 0) ? 1ULL : 0ULL, 64, true};
        }
        return true;
    }

    bool parse_and(Val& out, std::string& err) {
        if (!parse_cmp(out, err)) return false;
        while (cur().kind == TokKind::AndAnd) {
            advance();
            Val rhs;
            if (!parse_cmp(rhs, err)) return false;
            out = Val{(out.v != 0 && rhs.v != 0) ? 1ULL : 0ULL, 64, true};
        }
        return true;
    }

    bool parse_cmp(Val& out, std::string& err) {
        if (!parse_bit(out, err)) return false;
        TokKind k = cur().kind;
        if (k == TokKind::EqEq || k == TokKind::NotEq ||
            k == TokKind::Lt || k == TokKind::Le ||
            k == TokKind::Gt || k == TokKind::Ge) {
            advance();
            Val rhs;
            if (!parse_bit(rhs, err)) return false;

            // Compare using the narrower explicit register/deref bit-width when one side is a literal
            int cmp_bits = 64;
            if (!out.is_literal && rhs.is_literal) cmp_bits = out.width_bits;
            else if (out.is_literal && !rhs.is_literal) cmp_bits = rhs.width_bits;
            else if (!out.is_literal && !rhs.is_literal) cmp_bits = std::min(out.width_bits, rhs.width_bits);

            const uint64_t mask = mask_for(cmp_bits);
            const uint64_t lv = out.v & mask;
            const uint64_t rv = rhs.v & mask;
            const int64_t ls = sign_extend(lv, cmp_bits);
            const int64_t rs = sign_extend(rv, cmp_bits);

            bool res = false;
            switch (k) {
                case TokKind::EqEq:  res = (lv == rv); break;
                case TokKind::NotEq: res = (lv != rv); break;
                case TokKind::Lt:    res = (ls < rs); break;
                case TokKind::Le:    res = (ls <= rs); break;
                case TokKind::Gt:    res = (ls > rs); break;
                case TokKind::Ge:    res = (ls >= rs); break;
                default: break;
            }
            out = Val{res ? 1ULL : 0ULL, 64, true};
        }
        return true;
    }

    bool parse_bit(Val& out, std::string& err) {
        if (!parse_add(out, err)) return false;
        while (cur().kind == TokKind::Amp || cur().kind == TokKind::Pipe || cur().kind == TokKind::Caret) {
            TokKind op = advance().kind;
            Val rhs;
            if (!parse_add(rhs, err)) return false;
            uint64_t v = 0;
            if (op == TokKind::Amp) v = out.v & rhs.v;
            else if (op == TokKind::Pipe) v = out.v | rhs.v;
            else v = out.v ^ rhs.v;
            out = Val{v, 64, out.is_literal && rhs.is_literal};
        }
        return true;
    }

    bool parse_add(Val& out, std::string& err) {
        if (!parse_unary(out, err)) return false;
        while (cur().kind == TokKind::Plus || cur().kind == TokKind::Minus) {
            TokKind op = advance().kind;
            Val rhs;
            if (!parse_unary(rhs, err)) return false;
            uint64_t v = (op == TokKind::Plus) ? (out.v + rhs.v) : (out.v - rhs.v);
            out = Val{v, 64, out.is_literal && rhs.is_literal};
        }
        return true;
    }

    bool parse_unary(Val& out, std::string& err) {
        if (cur().kind == TokKind::Bang) {
            advance();
            if (!parse_unary(out, err)) return false;
            out = Val{out.v == 0 ? 1ULL : 0ULL, 64, true};
            return true;
        }
        if (cur().kind == TokKind::Minus) {
            advance();
            if (!parse_unary(out, err)) return false;
            out = Val{static_cast<uint64_t>(-static_cast<int64_t>(out.v)), out.width_bits, out.is_literal};
            return true;
        }
        if (cur().kind == TokKind::Plus) {
            advance();
            return parse_unary(out, err);
        }
        return parse_primary(out, err);
    }

    bool parse_deref(int width_bits, Val& out, std::string& err) {
        advance(); // consume '['
        Val addr;
        if (!parse_or(addr, err)) return false;
        if (cur().kind != TokKind::RBracket) {
            err = "Expected ']' after memory address expression";
            return false;
        }
        advance(); // consume ']'

        if (m_dry_run || !m_proc) {
            out = Val{0, width_bits, false};
            return true;
        }

        uint64_t read_val = 0;
        const size_t nbytes = static_cast<size_t>(width_bits / 8);
        if (!m_proc->read_raw(static_cast<uintptr_t>(addr.v), &read_val, nbytes)) {
            err = "Failed to read " + std::to_string(nbytes) + " bytes at memory address";
            return false;
        }
        read_val &= mask_for(width_bits);
        out = Val{read_val, width_bits, false};
        return true;
    }

    bool parse_primary(Val& out, std::string& err) {
        if (cur().kind == TokKind::LParen) {
            advance();
            if (!parse_or(out, err)) return false;
            if (cur().kind != TokKind::RParen) {
                err = "Expected ')'";
                return false;
            }
            advance();
            return true;
        }

        if (cur().kind == TokKind::LBracket) {
            return parse_deref(64, out, err);
        }

        if (cur().kind == TokKind::Number) {
            uint64_t num = advance().number;
            out = Val{num, 64, true};
            return true;
        }

        if (cur().kind == TokKind::Ident) {
            std::string name = advance().text;

            // Sized memory dereference prefix: byte/word/dword/qword [ptr]? [...]
            int width_bits = 0;
            if (name == "byte") width_bits = 8;
            else if (name == "word") width_bits = 16;
            else if (name == "dword" || name == "int") width_bits = 32;
            else if (name == "qword") width_bits = 64;

            if (width_bits != 0) {
                if (cur().kind == TokKind::Ident && cur().text == "ptr") advance();
                if (cur().kind != TokKind::LBracket) {
                    err = "Expected '[' after size specifier '" + name + "'";
                    return false;
                }
                return parse_deref(width_bits, out, err);
            }

            auto reg = lookup_ident(name, m_regs, m_hit);
            if (!reg) {
                err = "Unknown identifier or register '" + name + "'";
                return false;
            }
            out = *reg;
            return true;
        }

        err = "Expected expression, got '" + (cur().text.empty() ? "end of input" : cur().text) + "'";
        return false;
    }

    const std::vector<Token>& m_toks;
    const Registers& m_regs;
    const hal::IProcess* m_proc;
    size_t m_hit{0};
    bool m_dry_run{false};
    size_t m_pos{0};
};

} // anonymous namespace

std::optional<std::string> ConditionEvaluator::validate(const std::string& expression) {
    if (expression.empty()) return std::nullopt;
    std::vector<Token> toks;
    std::string err;
    if (!tokenize(expression, toks, err)) return err;
    Registers dummy{};
    Parser p(toks, dummy, nullptr, 0, /*dry_run=*/true);
    Val out;
    if (!p.parse(out, err)) return err;
    return std::nullopt;
}

ConditionEvaluator::Result ConditionEvaluator::evaluate(
    const std::string& expression,
    const Registers& regs,
    const hal::IProcess* process,
    size_t hit_count
) {
    Result res;
    if (expression.empty()) {
        res.ok = true;
        res.matched = true;
        res.value = 1;
        return res;
    }

    std::vector<Token> toks;
    if (!tokenize(expression, toks, res.error)) {
        return res;
    }

    Parser p(toks, regs, process, hit_count, /*dry_run=*/false);
    Val out;
    if (!p.parse(out, res.error)) {
        return res;
    }

    res.ok = true;
    res.value = out.v;
    res.matched = (out.v != 0);
    return res;
}

} // namespace nce::debugger
