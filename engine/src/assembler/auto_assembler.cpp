#include "../../include/assembler/auto_assembler.hpp"
#include "../../include/debugger/disassembler.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/utils/sig_generator.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace nce::assembler {

namespace {

std::string trim(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t\r");
    if (a == std::string::npos) return {};
    return s.substr(a, s.find_last_not_of(" \t\r") - a + 1);
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string strip_comment(const std::string& line) {
    bool quote = false;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '"') quote = !quote;
        else if (!quote && line[i] == ';') return line.substr(0, i);
        else if (!quote && line[i] == '/' && i + 1 < line.size() && line[i + 1] == '/') return line.substr(0, i);
    }
    return line;
}

// Extracts {$lua} ... {$asm} blocks cleanly, returning non-Lua assembly lines and extracted Lua scripts.
struct ExtractedBody {
    std::vector<std::string> asm_lines;
    std::vector<std::string> lua_blocks;
};

ExtractedBody parse_body_and_lua(const std::string& body) {
    ExtractedBody res;
    std::istringstream in(body);
    std::string line;
    bool in_lua = false;
    std::ostringstream cur_lua;

    while (std::getline(in, line)) {
        const std::string t = lower(trim(line));
        if (!in_lua && t == "{$lua}") {
            in_lua = true;
            cur_lua.str("");
            cur_lua.clear();
            continue;
        }
        if (in_lua && t == "{$asm}") {
            in_lua = false;
            res.lua_blocks.push_back(cur_lua.str());
            continue;
        }
        if (in_lua) {
            cur_lua << line << "\n";
        } else {
            const std::string clean = trim(strip_comment(line));
            if (!clean.empty()) res.asm_lines.push_back(clean);
        }
    }
    if (in_lua && !cur_lua.str().empty()) {
        res.lua_blocks.push_back(cur_lua.str());
    }
    return res;
}

std::vector<std::string> split_args(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool quote = false;
    for (char c : s) {
        if (c == '"') quote = !quote;
        if (c == ',' && !quote) { out.push_back(trim(cur)); cur.clear(); }
        else cur += c;
    }
    out.push_back(trim(cur));
    return out;
}

std::vector<std::string> split_data_tokens(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool quote = false;
    for (char c : s) {
        if (c == '"') quote = !quote;
        if (!quote && (c == ' ' || c == '\t' || c == ',')) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// Parses decimal (#100, 100, -10) or hex ($1000, 0x1000) integers
std::optional<int64_t> parse_int(const std::string& token) {
    std::string t = trim(token);
    if (t.empty()) return std::nullopt;
    bool neg = false;
    int base = 10;
    if (t[0] == '#') {
        t.erase(0, 1);
        if (!t.empty() && t[0] == '$') { base = 16; t.erase(0, 1); }
    } else if (t[0] == '$') {
        base = 16;
        t.erase(0, 1);
    }
    if (!t.empty() && t[0] == '+') t.erase(0, 1);
    else if (!t.empty() && t[0] == '-') { neg = true; t.erase(0, 1); }
    if (base == 10 && t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        base = 16;
        t = t.substr(2);
    }
    if (t.empty()) return std::nullopt;
    uint64_t v = 0;
    const auto [p, ec] = std::from_chars(t.data(), t.data() + t.size(), v, base);
    if (ec != std::errc() || p != t.data() + t.size()) return std::nullopt;
    return neg ? -static_cast<int64_t>(v) : static_cast<int64_t>(v);
}

bool is_identifier_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

std::optional<uintptr_t> scan_range(const hal::IProcess& process, uintptr_t base, size_t size,
                                    const scanner::AOBPattern& pattern) {
    const size_t plen = pattern.bytes.size();
    if (plen == 0 || size < plen) return std::nullopt;
    constexpr size_t chunk = 1 << 20;
    std::vector<uint8_t> buf;
    for (uintptr_t start = base; start + plen <= base + size; ) {
        const size_t want = std::min(chunk, static_cast<size_t>(base + size - start));
        buf.resize(want);
        if (!process.read_raw(start, buf.data(), want)) { start += chunk - (plen - 1); continue; }
        for (size_t i = 0; i + plen <= want; ++i) {
            bool hit = true;
            for (size_t j = 0; j < plen; ++j) {
                if (pattern.mask[j] && buf[i + j] != pattern.bytes[j]) { hit = false; break; }
            }
            if (hit) return start + i;
        }
        if (want < chunk) break;
        start += chunk - (plen - 1);
    }
    return std::nullopt;
}

} // anonymous namespace

struct AutoAssembler::Assembly {
    std::vector<std::string> lines;
    std::map<std::string, uintptr_t> labels;
    std::map<std::string, size_t> cave_sizes;
    std::map<std::string, std::string> defines;
    uintptr_t address{0};
    bool have_address{false};
};

AutoAssembler::AutoAssembler(std::shared_ptr<hal::IProcess> process)
    : m_process(std::move(process)), m_encoder(m_process->pointer_size() == 8) {}

void AutoAssembler::set_symbol(const std::string& name, uintptr_t address) { m_symbols[name] = address; }
void AutoAssembler::clear_symbol(const std::string& name) { m_symbols.erase(name); }

std::optional<uintptr_t> AutoAssembler::symbol(const std::string& name) const {
    const auto it = m_symbols.find(name);
    return it == m_symbols.end() ? std::nullopt : std::optional<uintptr_t>(it->second);
}

AutoAssembler::Sections AutoAssembler::split_sections(const std::string& script) {
    Sections s;
    enum { None, Enable, Disable } where = None;
    std::istringstream in(script);
    std::string line;
    while (std::getline(in, line)) {
        const std::string tag = lower(trim(strip_comment(line)));
        if (tag == "[enable]") { where = Enable; s.had_markers = true; continue; }
        if (tag == "[disable]") { where = Disable; s.had_markers = true; continue; }
        if (where == Enable) s.enable += line + "\n";
        else if (where == Disable) s.disable += line + "\n";
        else s.enable += line + "\n";
    }
    return s;
}

std::string AutoAssembler::apply_defines(const Assembly& a, const std::string& line) const {
    if (a.defines.empty()) return line;
    std::string out;
    out.reserve(line.size());
    bool in_quote = false;
    size_t i = 0;
    while (i < line.size()) {
        char c = line[i];
        if (c == '"') {
            in_quote = !in_quote;
            out += c;
            ++i;
            continue;
        }
        if (!in_quote && (std::isalpha(static_cast<unsigned char>(c)) || c == '_')) {
            size_t j = i;
            while (j < line.size() && is_identifier_char(line[j])) ++j;
            std::string word = line.substr(i, j - i);
            auto it = a.defines.find(word);
            if (it != a.defines.end()) {
                out += it->second;
            } else {
                out += word;
            }
            i = j;
        } else {
            out += c;
            ++i;
        }
    }
    return out;
}

std::optional<uintptr_t> AutoAssembler::resolve(const std::string& expression) const {
    std::string e = trim(expression);
    if (e.empty()) return std::nullopt;
    int64_t total = 0;
    size_t i = 0;
    int sign = 1;
    auto modules = m_process->is_attached() ? m_process->get_modules() : std::vector<hal::ModuleInfo>{};
    while (i < e.size()) {
        while (i < e.size() && (e[i] == ' ' || e[i] == '\t')) ++i;
        if (i < e.size() && (e[i] == '+' || e[i] == '-')) { sign = e[i] == '-' ? -1 : 1; ++i; continue; }

        std::string term;
        if (i < e.size() && e[i] == '"') {
            const size_t end = e.find('"', i + 1);
            if (end == std::string::npos) return std::nullopt;
            term = e.substr(i + 1, end - i - 1);
            i = end + 1;
            uintptr_t base = 0;
            const std::string want = lower(term);
            for (const auto& m : modules) {
                if (lower(m.name) == want) { base = m.base_address; break; }
            }
            if (base == 0) return std::nullopt;
            total += sign * static_cast<int64_t>(base);
            sign = 1;
            continue;
        }
        size_t j = i;
        while (j < e.size() && (is_identifier_char(e[j]) || e[j] == '.' || e[j] == '$' || e[j] == '#')) ++j;
        term = e.substr(i, j - i);
        i = j;
        if (term.empty()) return std::nullopt;

        if (auto num = parse_int(term)) {
            total += sign * *num;
        } else if (auto sym = symbol(term)) {
            total += sign * static_cast<int64_t>(*sym);
        } else {
            uintptr_t base = 0;
            const std::string want = lower(term);
            for (const auto& m : modules) {
                if (lower(m.name) == want) { base = m.base_address; break; }
            }
            if (base == 0) return std::nullopt;
            total += sign * static_cast<int64_t>(base);
        }
        sign = 1;
    }
    return static_cast<uintptr_t>(total);
}

std::string AutoAssembler::substitute_symbols(const Assembly& a, const std::string& operands) const {
    std::string out;
    size_t i = 0;
    while (i < operands.size()) {
        char c = operands[i];
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t j = i;
            while (j < operands.size() && is_identifier_char(operands[j])) ++j;
            size_t k = j;
            while (k < operands.size() && (operands[k] == '+' || operands[k] == '-' ||
                                           is_identifier_char(operands[k]) || operands[k] == 'x' || operands[k] == '$')) {
                ++k;
            }
            const std::string word = operands.substr(i, j - i);
            const std::string full = operands.substr(i, k - i);

            std::optional<uintptr_t> addr;
            if (const auto it = a.labels.find(word); it != a.labels.end() && k == j) addr = it->second;
            if (!addr) {
                const size_t op_pos = full.find_first_of("+-");
                if (op_pos != std::string::npos) {
                    const std::string head = full.substr(0, op_pos);
                    if (const auto it = a.labels.find(head); it != a.labels.end()) {
                        const std::string tail = full.substr(op_pos);
                        if (auto n = parse_int(tail)) { addr = it->second + *n; i = k; out += utils::format_address(*addr); continue; }
                    }
                }
            }
            if (!addr && k == j) addr = resolve(word);
            if (addr) { out += utils::format_address(*addr); i = j; }
            else { out += word; i = j; }
        } else {
            out += c;
            ++i;
        }
    }
    return out;
}

bool AutoAssembler::first_pass(Assembly& a, std::string& error) {
    for (const std::string& raw_line : a.lines) {
        const std::string low_raw = lower(raw_line);
        const std::string line = (low_raw.rfind("define(", 0) == 0) ? raw_line : apply_defines(a, raw_line);

        if (apply_directive(a, line, /*first=*/true, error)) {
            if (!error.empty()) return false;
            continue;
        }
        if (line.back() == ':') {
            const std::string target = trim(line.substr(0, line.size() - 1));
            if (const auto it = a.labels.find(target); it != a.labels.end()) { a.address = it->second; a.have_address = true; }
            else if (auto addr = resolve(target)) { a.address = *addr; a.have_address = true; }
            else { a.labels[target] = a.address; }
            continue;
        }
        if (!a.have_address) { error = "no address yet: start with a label/alloc or an address like \"game.exe\"+0x10"; return false; }

        const size_t space = line.find_first_of(" \t");
        const std::string mnem = lower(line.substr(0, space));
        const std::string operands = space == std::string::npos ? "" : line.substr(space + 1);

        if (mnem == "db") {
            a.address += split_data_tokens(operands).size();
            continue;
        }
        if (mnem == "dw") {
            a.address += split_data_tokens(operands).size() * 2;
            continue;
        }
        if (mnem == "dd" || mnem == "df" || mnem == "float") {
            a.address += split_data_tokens(operands).size() * 4;
            continue;
        }
        if (mnem == "dq" || mnem == "double") {
            a.address += split_data_tokens(operands).size() * 8;
            continue;
        }

        const std::string resolved = line.substr(0, space) + (operands.empty() ? "" : " " + substitute_symbols(a, operands));
        std::string enc_err;
        auto encoded = m_encoder.encode(resolved, a.address, enc_err);
        if (!encoded) {
            const std::string dummy = line.substr(0, space) + " 0x140000000";
            encoded = m_encoder.encode(dummy, a.address, enc_err);
            if (!encoded) { error = "line '" + line + "': " + enc_err; return false; }
        }
        a.address += encoded->bytes.size();
    }
    return true;
}

bool AutoAssembler::emit_pass(Assembly& a, ScriptEffect& effect, std::string& error) {
    a.address = 0;
    a.have_address = false;
    for (const std::string& raw_line : a.lines) {
        const std::string low_raw = lower(raw_line);
        const std::string line = (low_raw.rfind("define(", 0) == 0) ? raw_line : apply_defines(a, raw_line);

        std::string dir_err;
        if (apply_directive(a, line, /*first=*/false, dir_err)) {
            if (!dir_err.empty()) { error = dir_err; return false; }
            // Check if readmem emitted bytes that need recording
            if (lower(line).rfind("readmem(", 0) == 0) {
                const size_t open = line.find('(');
                const size_t close = line.rfind(')');
                auto args = split_args(line.substr(open + 1, close - open - 1));
                auto src = resolve(args[0]);
                if (!src) {
                    if (auto it = a.labels.find(args[0]); it != a.labels.end()) src = it->second;
                }
                auto sz = parse_int(args[1]);
                if (!src || !sz || *sz <= 0) { error = "readmem: invalid address or size"; return false; }
                std::vector<uint8_t> bytes(static_cast<size_t>(*sz));
                if (!m_process->read_raw(*src, bytes.data(), bytes.size())) {
                    error = "readmem: cannot read source memory";
                    return false;
                }
                std::vector<uint8_t> original(bytes.size());
                if (!m_process->read_raw(a.address, original.data(), bytes.size()) ||
                    !m_process->write_raw(a.address, bytes.data(), bytes.size())) {
                    error = "readmem: cannot patch target at " + utils::format_address(a.address);
                    return false;
                }
                effect.patches.push_back({a.address, std::move(original), std::move(bytes)});
                a.address += static_cast<size_t>(*sz);
            }
            continue;
        }
        if (line.back() == ':') {
            const std::string target = trim(line.substr(0, line.size() - 1));
            if (const auto it = a.labels.find(target); it != a.labels.end()) { a.address = it->second; a.have_address = true; }
            else if (auto addr = resolve(target)) { a.address = *addr; a.have_address = true; }
            continue;
        }
        const size_t space = line.find_first_of(" \t");
        const std::string mnem = lower(line.substr(0, space));
        const std::string operands = space == std::string::npos ? "" : line.substr(space + 1);

        std::vector<uint8_t> bytes;
        if (mnem == "db") {
            for (const std::string& token : split_data_tokens(operands)) {
                std::string hex_tok = token;
                if (!hex_tok.empty() && hex_tok[0] != '#' && hex_tok[0] != '$' &&
                    !(hex_tok.size() > 2 && hex_tok[0] == '0' && (hex_tok[1] == 'x' || hex_tok[1] == 'X'))) {
                    hex_tok = "0x" + hex_tok;
                }
                auto v = parse_int(hex_tok);
                if (!v || *v < 0 || *v > 0xFF) { error = "db: '" + token + "' is not a byte"; return false; }
                bytes.push_back(static_cast<uint8_t>(*v));
            }
        } else if (mnem == "dw") {
            for (const std::string& token : split_data_tokens(operands)) {
                auto v = parse_int(token);
                if (!v) { error = "dw: invalid word '" + token + "'"; return false; }
                uint16_t w = static_cast<uint16_t>(*v);
                bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&w), reinterpret_cast<const uint8_t*>(&w) + 2);
            }
        } else if (mnem == "dd") {
            for (const std::string& token : split_data_tokens(operands)) {
                auto v = parse_int(token);
                if (!v) {
                    auto sym_addr = resolve(token);
                    if (!sym_addr) {
                        if (auto it = a.labels.find(token); it != a.labels.end()) sym_addr = it->second;
                    }
                    if (!sym_addr) { error = "dd: invalid dword '" + token + "'"; return false; }
                    v = static_cast<int64_t>(*sym_addr);
                }
                uint32_t d = static_cast<uint32_t>(*v);
                bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&d), reinterpret_cast<const uint8_t*>(&d) + 4);
            }
        } else if (mnem == "dq") {
            for (const std::string& token : split_data_tokens(operands)) {
                uint64_t q = 0;
                if (auto v = parse_int(token)) {
                    q = static_cast<uint64_t>(*v);
                } else if (auto it = a.labels.find(token); it != a.labels.end()) {
                    q = it->second;
                } else if (auto addr = resolve(token)) {
                    q = *addr;
                } else {
                    error = "dq: unresolved qword/symbol '" + token + "'";
                    return false;
                }
                bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&q), reinterpret_cast<const uint8_t*>(&q) + 8);
            }
        } else if (mnem == "df" || mnem == "float") {
            for (const std::string& token : split_data_tokens(operands)) {
                try {
                    std::string clean = (!token.empty() && token[0] == '#') ? token.substr(1) : token;
                    float f = std::stof(clean);
                    bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&f), reinterpret_cast<const uint8_t*>(&f) + 4);
                } catch (...) {
                    error = "float: invalid float '" + token + "'";
                    return false;
                }
            }
        } else if (mnem == "double") {
            for (const std::string& token : split_data_tokens(operands)) {
                try {
                    std::string clean = (!token.empty() && token[0] == '#') ? token.substr(1) : token;
                    double d = std::stod(clean);
                    bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&d), reinterpret_cast<const uint8_t*>(&d) + 8);
                } catch (...) {
                    error = "double: invalid double '" + token + "'";
                    return false;
                }
            }
        } else {
            const std::string resolved = line.substr(0, space) + (operands.empty() ? "" : " " + substitute_symbols(a, operands));
            std::string enc_err;
            auto encoded = m_encoder.encode(resolved, a.address, enc_err);
            if (!encoded) { error = "line '" + line + "': " + enc_err; return false; }
            bytes = encoded->bytes;
        }

        std::vector<uint8_t> original(bytes.size());
        if (!m_process->read_raw(a.address, original.data(), bytes.size())) {
            error = "can't read the bytes at " + utils::format_address(a.address) + " to patch them";
            return false;
        }
        if (!m_process->write_raw(a.address, bytes.data(), bytes.size())) {
            error = "can't write to " + utils::format_address(a.address) + " (no write access?)";
            return false;
        }
        if (!effect.patches.empty()) {
            auto& last = effect.patches.back();
            if (last.address + last.written.size() == a.address) {
                last.original.insert(last.original.end(), original.begin(), original.end());
                last.written.insert(last.written.end(), bytes.begin(), bytes.end());
                a.address += bytes.size();
                continue;
            }
        }
        effect.patches.push_back({a.address, std::move(original), bytes});
        a.address += bytes.size();
    }
    return true;
}

bool AutoAssembler::apply_directive(Assembly& a, const std::string& line, bool first, std::string& error) {
    const std::string low = lower(line);
    auto args_of = [&](size_t open) {
        const size_t close = line.rfind(')');
        if (close == std::string::npos || close <= open) return std::vector<std::string>{};
        return split_args(line.substr(open + 1, close - open - 1));
    };

    if (low.rfind("define(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "define(name, value) needs two arguments"; return true; }
        a.defines[args[0]] = args[1];
        return true;
    }
    if (low.rfind("alloc(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "alloc(name, size [, nearAddress]) needs a name and a size"; return true; }
        if (first) {
            auto size = parse_int(args[1]);
            if (!size || *size <= 0) { error = "alloc: '" + args[1] + "' is not a size"; return true; }
            uintptr_t near = 0;
            if (args.size() >= 3) {
                if (auto n = resolve(args[2])) near = *n;
                else if (auto it = a.labels.find(args[2]); it != a.labels.end()) near = it->second;
            }
            const uintptr_t cave = m_process->allocate_memory(static_cast<size_t>(*size), 0x40 /* RWX */, near);
            if (cave == 0) { error = "alloc: the target refused " + args[1] + " bytes"; return true; }
            a.labels[args[0]] = cave;
            a.cave_sizes[args[0]] = static_cast<size_t>(*size);
        }
        return true;
    }
    if (low.rfind("globalalloc(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "globalalloc(name, size [, nearAddress]) needs a name and size"; return true; }
        if (first) {
            if (auto it = m_global_allocs.find(args[0]); it != m_global_allocs.end() && it->second.address != 0) {
                a.labels[args[0]] = it->second.address;
            } else {
                auto size = parse_int(args[1]);
                if (!size || *size <= 0) { error = "globalalloc: invalid size '" + args[1] + "'"; return true; }
                uintptr_t near = 0;
                if (args.size() >= 3) { if (auto n = resolve(args[2])) near = *n; }
                const uintptr_t cave = m_process->allocate_memory(static_cast<size_t>(*size), 0x40, near);
                if (cave == 0) { error = "globalalloc: allocation failed for " + args[0]; return true; }
                a.labels[args[0]] = cave;
                m_symbols[args[0]] = cave;
                m_global_allocs[args[0]] = {cave, static_cast<size_t>(*size)};
            }
        }
        return true;
    }
    if (low.rfind("label(", 0) == 0) {
        return true;
    }
    if (low.rfind("registersymbol(", 0) == 0 || low.rfind("unregistersymbol(", 0) == 0) {
        return true;
    }
    if (low.rfind("aobscanmodule(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 3) { error = "aobscanmodule(name, module, AA BB ?? ..) needs three parts"; return true; }
        if (first) {
            std::string pattern;
            for (size_t k = 2; k < args.size(); ++k) pattern += (k > 2 ? " " : "") + args[k];
            auto parsed = utils::parse_aob_pattern(pattern);
            if (!parsed) { error = "aobscanmodule: bad pattern '" + pattern + "'"; return true; }
            uintptr_t base = 0, size = 0;
            for (const auto& m : m_process->get_modules()) {
                if (lower(m.name) == lower(args[1])) { base = m.base_address; size = m.size; break; }
            }
            if (base == 0) { error = "aobscanmodule: module '" + args[1] + "' is not loaded"; return true; }
            auto found = scan_range(*m_process, base, size, *parsed);
            if (!found) { error = "aobscanmodule: pattern not found in " + args[1]; return true; }
            a.labels[args[0]] = *found;
        }
        return true;
    }
    if (low.rfind("aobscan(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "aobscan(name, AA BB ?? ..) needs a name and pattern"; return true; }
        if (first) {
            std::string pattern;
            for (size_t k = 1; k < args.size(); ++k) pattern += (k > 1 ? " " : "") + args[k];
            auto parsed = utils::parse_aob_pattern(pattern);
            if (!parsed) { error = "aobscan: bad pattern '" + pattern + "'"; return true; }
            std::optional<uintptr_t> found;
            for (const auto& reg : m_process->query_regions(hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess)) {
                found = scan_range(*m_process, reg.base_address, reg.size, *parsed);
                if (found) break;
            }
            if (!found) { error = "aobscan: pattern not found in target memory"; return true; }
            a.labels[args[0]] = *found;
        }
        return true;
    }
    if (low.rfind("aobscanregion(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 4) { error = "aobscanregion(name, start, end, pattern) needs 4 parts"; return true; }
        if (first) {
            auto start_addr = resolve(args[1]);
            auto end_addr   = resolve(args[2]);
            if (!start_addr || !end_addr || *end_addr <= *start_addr) {
                error = "aobscanregion: invalid address range";
                return true;
            }
            std::string pattern;
            for (size_t k = 3; k < args.size(); ++k) pattern += (k > 3 ? " " : "") + args[k];
            auto parsed = utils::parse_aob_pattern(pattern);
            if (!parsed) { error = "aobscanregion: bad pattern '" + pattern + "'"; return true; }
            auto found = scan_range(*m_process, *start_addr, static_cast<size_t>(*end_addr - *start_addr), *parsed);
            if (!found) { error = "aobscanregion: pattern not found in specified range"; return true; }
            a.labels[args[0]] = *found;
        }
        return true;
    }
    if (low.rfind("assert(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "assert(address, AA BB ..) needs an address and expected bytes"; return true; }
        if (first) {
            auto addr = resolve(args[0]);
            if (!addr) {
                if (auto it = a.labels.find(args[0]); it != a.labels.end()) addr = it->second;
            }
            if (!addr) { error = "assert: cannot resolve address '" + args[0] + "'"; return true; }
            std::string pattern;
            for (size_t k = 1; k < args.size(); ++k) pattern += (k > 1 ? " " : "") + args[k];
            auto parsed = utils::parse_aob_pattern(pattern);
            if (!parsed || parsed->bytes.empty()) { error = "assert: invalid byte pattern '" + pattern + "'"; return true; }
            std::vector<uint8_t> live(parsed->bytes.size());
            if (!m_process->read_raw(*addr, live.data(), live.size())) {
                error = "assert: cannot read bytes at " + utils::format_address(*addr);
                return true;
            }
            for (size_t i = 0; i < live.size(); ++i) {
                if (parsed->mask[i] && live[i] != parsed->bytes[i]) {
                    error = "assert failed at " + utils::format_address(*addr) + " (byte mismatch at +" + std::to_string(i) + ")";
                    return true;
                }
            }
        }
        return true;
    }
    if (low.rfind("fullaccess(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "fullaccess(address, size) needs 2 arguments"; return true; }
        if (first) {
            auto addr = resolve(args[0]);
            auto sz = parse_int(args[1]);
            if (!addr || !sz || *sz <= 0) { error = "fullaccess: invalid address or size"; return true; }
            uint8_t probe = 0;
            if (!m_process->read_raw(*addr, &probe, 1)) {
                error = "fullaccess: unreadable memory at " + utils::format_address(*addr);
                return true;
            }
        }
        return true;
    }
    if (low.rfind("readmem(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "readmem(address, size) needs 2 arguments"; return true; }
        if (first) {
            if (!a.have_address) { error = "readmem: no active target address yet"; return true; }
            auto sz = parse_int(args[1]);
            if (!sz || *sz <= 0) { error = "readmem: invalid size"; return true; }
            a.address += static_cast<size_t>(*sz);
        }
        return true;
    }
    if (low.rfind("dealloc(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (!first && !args.empty()) {
            if (auto it = m_global_allocs.find(args[0]); it != m_global_allocs.end()) {
                m_process->free_memory(it->second.address, it->second.size);
                m_global_allocs.erase(it);
                m_symbols.erase(args[0]);
            }
        }
        return true;
    }
    return false;
}

bool AutoAssembler::run(const std::string& body, ScriptEffect& effect, std::string& error, bool committing) {
    const ExtractedBody parsed = parse_body_and_lua(body);

    if (committing) {
        for (const auto& lua_code : parsed.lua_blocks) {
            if (!m_lua_runner) {
                error = "Script contains {$lua} block but no Lua runner is configured.";
                return false;
            }
            std::string lua_err;
            if (!m_lua_runner(lua_code, lua_err)) {
                error = "Lua block failed: " + lua_err;
                return false;
            }
        }
    }

    Assembly a;
    a.lines = parsed.asm_lines;
    if (a.lines.empty()) return true;

    if (!first_pass(a, error)) return false;

    for (const auto& [name, size] : a.cave_sizes) {
        effect.allocations.push_back({a.labels[name], size});
    }

    if (committing) {
        if (!emit_pass(a, effect, error)) {
            for (const auto& p : effect.patches) m_process->write_raw(p.address, p.original.data(), p.original.size());
            for (const auto& c : effect.allocations) m_process->free_memory(c.address, c.size);
            effect = {};
            return false;
        }
        for (const std::string& line : a.lines) {
            const std::string low = lower(line);
            if (low.rfind("registersymbol(", 0) == 0) {
                const size_t open = line.find('(');
                const size_t close = line.rfind(')');
                if (open != std::string::npos && close != std::string::npos && close > open) {
                    const std::string name = split_args(line.substr(open + 1, close - open - 1))[0];
                    if (const auto it = a.labels.find(name); it != a.labels.end()) {
                        m_symbols[name] = it->second;
                        effect.symbols.push_back(name);
                    }
                }
            }
        }
    }
    return true;
}

AssembleResult AutoAssembler::enable(const std::string& script) {
    AssembleResult result;
    if (!m_process->is_attached()) { result.message = "Attach to the game first."; return result; }
    const Sections s = split_sections(script);
    std::string error;
    if (!run(s.enable, result.effect, error, /*committing=*/true)) {
        result.message = error;
        return result;
    }
    result.ok = true;
    std::ostringstream note;
    note << "Script on: " << result.effect.patches.size() << " patch(es)";
    if (!result.effect.allocations.empty()) note << ", " << result.effect.allocations.size() << " cave(s)";
    result.message = note.str();
    return result;
}

AssembleResult AutoAssembler::disable(const std::string& script, const ScriptEffect& effect) {
    AssembleResult result;
    const Sections s = split_sections(script);

    if (!s.disable.empty() && m_process->is_attached()) {
        ScriptEffect disable_effect;
        std::string error;
        if (!run(s.disable, disable_effect, error, /*committing=*/true)) {
            result.message = "The [DISABLE] section failed: " + error;
        }
    }

    size_t restored = 0;
    if (m_process->is_attached()) {
        for (auto it = effect.patches.rbegin(); it != effect.patches.rend(); ++it) {
            if (m_process->write_raw(it->address, it->original.data(), it->original.size())) ++restored;
        }
    }
    for (const auto& c : effect.allocations) m_process->free_memory(c.address, c.size);
    for (const auto& name : effect.symbols) m_symbols.erase(name);

    result.ok = true;
    result.message = "Script off: restored " + std::to_string(restored) + " patch(es)";
    if (!effect.allocations.empty()) result.message += ", freed " + std::to_string(effect.allocations.size()) + " cave(s)";
    return result;
}

std::string AutoAssembler::generate_aob_hook_script(
    const hal::IProcess& proc,
    uintptr_t address,
    const std::string& label_name,
    size_t min_bytes)
{
    if (!proc.is_attached() || address == 0) return {};

    const std::string sym = label_name.empty() ? "INJECT" : label_name;
    uint8_t buf[64]{};
    if (!proc.read_raw(address, buf, sizeof(buf))) return {};

    std::vector<debugger::DecodedInstruction> stolen;
    size_t stolen_len = 0;
    while (stolen_len < min_bytes && stolen_len < sizeof(buf)) {
        auto insn = debugger::Disassembler::decode(buf + stolen_len, sizeof(buf) - stolen_len, address + stolen_len);
        if (insn.length == 0) break;
        stolen.push_back(insn);
        stolen_len += insn.length;
    }
    if (stolen_len < min_bytes || stolen.empty()) return {};

    std::string host_mod;
    uintptr_t mod_off = 0;
    for (const auto& m : proc.get_modules()) {
        if (address >= m.base_address && address < m.base_address + m.size) {
            host_mod = m.name;
            mod_off = address - m.base_address;
            break;
        }
    }

    std::optional<utils::SignatureGenerator::GeneratedSig> sig;
    if (!host_mod.empty()) {
        sig = utils::SignatureGenerator::generate(proc, address, 32);
    }

    auto fmt_bytes_hex = [](const uint8_t* p, size_t n) {
        std::ostringstream bs;
        bs << std::hex << std::uppercase;
        for (size_t i = 0; i < n; ++i) {
            if (i > 0) bs << ' ';
            bs << std::setw(2) << std::setfill('0') << static_cast<unsigned>(p[i]);
        }
        return bs.str();
    };

    std::ostringstream ss;
    ss << "// Auto-Generated AOB Code-Cave Hook (" << utils::format_address(address) << ")\n";
    ss << "[ENABLE]\n";
    if (sig && sig->is_unique && !host_mod.empty()) {
        ss << "aobscanmodule(" << sym << ", " << host_mod << ", " << sig->pattern << ")\n";
    } else if (!host_mod.empty()) {
        ss << "define(" << sym << ", \"" << host_mod << "\"+0x" << std::hex << std::uppercase << mod_off << std::dec << ")\n";
    } else {
        ss << "define(" << sym << ", " << utils::format_address(address) << ")\n";
    }
    ss << "alloc(newmem, 2048, " << sym << ")\n";
    ss << "label(code)\n";
    ss << "label(return)\n\n";
    ss << "newmem:\n";
    ss << "  // Place custom injection assembly here\n\n";
    ss << "code:\n";

    X86Assembler probe_enc;
    for (const auto& insn : stolen) {
        std::string asm_line = insn.mnemonic + (insn.operands.empty() ? "" : (" " + insn.operands));
        std::string err;
        const bool is_pc_rel = (insn.branch_target != 0);
        if (!is_pc_rel && probe_enc.encode(asm_line, 0x1000, err)) {
            ss << "  " << asm_line << "\n";
        } else {
            ss << "  db " << fmt_bytes_hex(insn.bytes.data(), insn.bytes.size())
               << " // " << asm_line << "\n";
        }
    }
    ss << "  jmp return\n\n";
    ss << sym << ":\n";
    ss << "  jmp newmem\n";
    for (size_t n = 5; n < stolen_len; ++n) {
        ss << "  nop\n";
    }
    ss << "return:\n";
    ss << "registersymbol(" << sym << ")\n\n";
    ss << "[DISABLE]\n";
    ss << sym << ":\n";
    ss << "  db " << fmt_bytes_hex(buf, stolen_len) << "\n";
    ss << "unregistersymbol(" << sym << ")\n";
    ss << "dealloc(newmem)\n";
    return ss.str();
}

} // namespace nce::assembler
