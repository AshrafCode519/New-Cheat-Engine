#include "../../include/assembler/auto_assembler.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
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

// Drops a // or ; comment that is not inside a quoted module name
std::string strip_comment(const std::string& line) {
    bool quote = false;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '"') quote = !quote;
        else if (!quote && line[i] == ';') return line.substr(0, i);
        else if (!quote && line[i] == '/' && i + 1 < line.size() && line[i + 1] == '/') return line.substr(0, i);
    }
    return line;
}

std::vector<std::string> lines_of(const std::string& body) {
    std::vector<std::string> out;
    std::istringstream in(body);
    std::string line;
    while (std::getline(in, line)) {
        const std::string clean = trim(strip_comment(line));
        if (!clean.empty()) out.push_back(clean);
    }
    return out;
}

// Splits "a,b,c" honouring quotes so a module name with a comma survives (rare, but correct)
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

// db takes bytes separated by spaces or commas: "db 90 90", "db 83,28,01"
std::vector<std::string> split_db(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == ',') { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::optional<int64_t> parse_int(const std::string& token) {
    std::string t = trim(token);
    if (t.empty()) return std::nullopt;
    bool neg = false;
    if (t[0] == '+') t.erase(0, 1);
    else if (t[0] == '-') { neg = true; t.erase(0, 1); }
    int base = 10;
    if (t.size() > 2 && (t[0] == '0') && (t[1] == 'x' || t[1] == 'X')) { base = 16; t = t.substr(2); }
    if (t.empty()) return std::nullopt;
    uint64_t v = 0;
    const auto [p, ec] = std::from_chars(t.data(), t.data() + t.size(), v, base);
    if (ec != std::errc() || p != t.data() + t.size()) return std::nullopt;
    return neg ? -static_cast<int64_t>(v) : static_cast<int64_t>(v);
}

bool is_identifier_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

// Finds the first place in [base, base+size) whose bytes match the masked pattern. Reads the range in 1 MB
// chunks that overlap by the pattern length, so a match on a chunk boundary is not missed.
std::optional<uintptr_t> scan_module(const hal::IProcess& process, uintptr_t base, size_t size,
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
        start += chunk - (plen - 1); // overlap so a boundary-straddling match is seen
    }
    return std::nullopt;
}

} // anonymous namespace

// One run's working state. The body is assembled twice: first to find where each label lands, then for real.
struct AutoAssembler::Assembly {
    std::vector<std::string> lines;
    std::map<std::string, uintptr_t> labels; // local labels + alloc caves (also copied to m_symbols on commit)
    std::map<std::string, size_t> cave_sizes;
    uintptr_t address{0}; // where the next instruction goes
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
        else s.enable += line + "\n"; // before any marker: part of enable
    }
    return s;
}

// Resolves a whole expression: a sum of terms, each a "quoted module"/bareword/symbol/number, + or -
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
        if (i < e.size() && e[i] == '"') { // "module.exe"
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
        while (j < e.size() && (is_identifier_char(e[j]) || e[j] == '.')) ++j; // module names have dots
        term = e.substr(i, j - i);
        i = j;
        if (term.empty()) return std::nullopt;

        if (auto num = parse_int(term)) {
            total += sign * *num;
        } else if (auto sym = symbol(term)) {
            total += sign * static_cast<int64_t>(*sym);
        } else {
            // a bareword that looks like a module name (game.exe)
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

// Replaces identifiers inside an operand string with their resolved hex address, leaving registers, numbers
// and the brackets alone. So "jmp mylabel" -> "jmp 0x...", "mov [myvalue], eax" -> "mov [0x...], eax".
std::string AutoAssembler::substitute_symbols(const Assembly& a, const std::string& operands) const {
    std::string out;
    size_t i = 0;
    while (i < operands.size()) {
        char c = operands[i];
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t j = i;
            while (j < operands.size() && is_identifier_char(operands[j])) ++j;
            // follow a trailing +0x.. / -0x.. so "label+8" resolves as one address
            size_t k = j;
            while (k < operands.size() && (operands[k] == '+' || operands[k] == '-' ||
                                           is_identifier_char(operands[k]) || operands[k] == 'x')) {
                ++k;
            }
            const std::string word = operands.substr(i, j - i);
            const std::string full = operands.substr(i, k - i);

            // a known label/cave/symbol (optionally with +offset) -> its address; else leave as-is (a register)
            std::optional<uintptr_t> addr;
            if (const auto it = a.labels.find(word); it != a.labels.end() && k == j) addr = it->second;
            if (!addr) {
                if (const auto it = a.labels.find(full.substr(0, full.find_first_of("+-"))); it != a.labels.end()) {
                    // label+offset: resolve the label, add the numeric tail
                    const std::string head = full.substr(0, full.find_first_of("+-"));
                    const std::string tail = full.substr(head.size());
                    if (auto n = parse_int(tail)) { addr = it->second + *n; i = k; out += utils::format_address(*addr); continue; }
                }
            }
            if (!addr && k == j) addr = resolve(word); // a global symbol or module name
            if (addr) { out += utils::format_address(*addr); i = j; }
            else { out += word; i = j; }
        } else {
            out += c;
            ++i;
        }
    }
    return out;
}

// First pass: run alloc/aobscan/registersymbol (so their addresses are known) and record where each label
// lands, advancing a model address by each instruction's length.
bool AutoAssembler::first_pass(Assembly& a, std::string& error) {
    for (const std::string& line : a.lines) {
        if (apply_directive(a, line, /*first=*/true, error)) {
            if (!error.empty()) return false;
            continue;
        }
        // an address target: a cave/aobscan name (`cave:`), a module expression (`"game.exe"+0x10:`),
        // or a new local label defined here (`return:`)
        if (line.back() == ':') {
            const std::string target = trim(line.substr(0, line.size() - 1));
            if (const auto it = a.labels.find(target); it != a.labels.end()) { a.address = it->second; a.have_address = true; }
            else if (auto addr = resolve(target)) { a.address = *addr; a.have_address = true; }
            else { a.labels[target] = a.address; } // a label at the current address
            continue;
        }
        if (!a.have_address) { error = "no address yet: start with a label/alloc or an address like \"game.exe\"+0x10"; return false; }

        // an instruction: its length advances the address (operands may still be unknown labels -> length is stable)
        const size_t space = line.find_first_of(" \t");
        const std::string mnem = line.substr(0, space);
        const std::string operands = space == std::string::npos ? "" : line.substr(space + 1);
        if (lower(mnem) == "db") {
            a.address += split_db(operands).size(); // one byte per value
            continue;
        }
        const std::string resolved = mnem + (operands.empty() ? "" : " " + substitute_symbols(a, operands));
        std::string enc_err;
        auto encoded = m_encoder.encode(resolved, a.address, enc_err);
        if (!encoded) {
            // a forward label still unknown: substitute a dummy same-size address so the length is right
            const std::string dummy = mnem + " 0x140000000";
            encoded = m_encoder.encode(dummy, a.address, enc_err);
            if (!encoded) { error = "line '" + line + "': " + enc_err; return false; }
        }
        a.address += encoded->bytes.size();
    }
    return true;
}

// Second pass: assemble for real, writing to the process. Records each patch's original bytes in `effect`.
bool AutoAssembler::emit_pass(Assembly& a, ScriptEffect& effect, std::string& error) {
    a.address = 0;
    a.have_address = false;
    for (const std::string& line : a.lines) {
        std::string ignore;
        if (apply_directive(a, line, /*first=*/false, ignore)) continue;
        if (line.back() == ':') {
            const std::string target = trim(line.substr(0, line.size() - 1));
            if (const auto it = a.labels.find(target); it != a.labels.end()) { a.address = it->second; a.have_address = true; }
            else if (auto addr = resolve(target)) { a.address = *addr; a.have_address = true; }
            continue;
        }
        const size_t space = line.find_first_of(" \t");
        const std::string mnem = line.substr(0, space);
        const std::string operands = space == std::string::npos ? "" : line.substr(space + 1);

        std::vector<uint8_t> bytes;
        if (lower(mnem) == "db") {
            for (const std::string& token : split_db(operands)) {
                auto v = token.size() > 2 && token[0] == '0' ? parse_int(token) : parse_int("0x" + token);
                if (!v || *v < 0 || *v > 0xFF) { error = "db: '" + token + "' is not a byte"; return false; }
                bytes.push_back(static_cast<uint8_t>(*v));
            }
        } else {
            const std::string resolved = mnem + (operands.empty() ? "" : " " + substitute_symbols(a, operands));
            std::string enc_err;
            auto encoded = m_encoder.encode(resolved, a.address, enc_err);
            if (!encoded) { error = "line '" + line + "': " + enc_err; return false; }
            bytes = encoded->bytes;
        }

        // Record what was there, then write
        std::vector<uint8_t> original(bytes.size());
        if (!m_process->read_raw(a.address, original.data(), bytes.size())) {
            error = "can't read the bytes at " + utils::format_address(a.address) + " to patch them";
            return false;
        }
        if (!m_process->write_raw(a.address, bytes.data(), bytes.size())) {
            error = "can't write to " + utils::format_address(a.address) + " (no write access?)";
            return false;
        }
        // Merge with the previous patch when this write begins right where it ended (one region, one undo)
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

// alloc / dealloc / label / aobscanmodule / registersymbol / unregistersymbol. Returns true if `line` was a
// directive (even one that failed: then `error` is set). On the first pass side effects happen; on the second
// the already-resolved labels are reused, but allocations and symbol registration are recorded in `effect`
// through the caller, so here they just resolve.
bool AutoAssembler::apply_directive(Assembly& a, const std::string& line, bool first, std::string& error) {
    const std::string low = lower(line);
    auto args_of = [&](size_t open) {
        const size_t close = line.rfind(')');
        return split_args(line.substr(open + 1, close - open - 1));
    };

    if (low.rfind("alloc(", 0) == 0) {
        auto args = args_of(line.find('('));
        if (args.size() < 2) { error = "alloc(name, size [, nearAddress]) needs a name and a size"; return true; }
        if (first) {
            auto size = parse_int(args[1]);
            if (!size || *size <= 0) { error = "alloc: '" + args[1] + "' is not a size"; return true; }
            uintptr_t near = 0;
            if (args.size() >= 3) { if (auto n = resolve(args[2])) near = *n; }
            const uintptr_t cave = m_process->allocate_memory(static_cast<size_t>(*size), 0x40 /* RWX */, near);
            if (cave == 0) { error = "alloc: the target refused " + args[1] + " bytes"; return true; }
            a.labels[args[0]] = cave;
            a.cave_sizes[args[0]] = static_cast<size_t>(*size);
        }
        return true;
    }
    if (low.rfind("label(", 0) == 0) {
        // declares a name; its address is set where `name:` appears. Nothing to do but note it exists.
        return true;
    }
    if (low.rfind("registersymbol(", 0) == 0 || low.rfind("unregistersymbol(", 0) == 0) {
        return true; // handled when committing (run())
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
            auto found = scan_module(*m_process, base, size, *parsed);
            if (!found) { error = "aobscanmodule: pattern not found in " + args[1]; return true; }
            a.labels[args[0]] = *found;
        }
        return true;
    }
    if (low.rfind("dealloc(", 0) == 0) return true; // caves are freed on disable, not mid-script
    return false;
}

// Runs one section. On any failure, rolls back every patch already made and frees every cave, so the target
// is never left half-changed. `committing` true = write to the process and keep symbols; used for enable.
bool AutoAssembler::run(const std::string& body, ScriptEffect& effect, std::string& error, bool committing) {
    Assembly a;
    a.lines = lines_of(body);
    if (a.lines.empty()) return true;

    if (!first_pass(a, error)) return false;

    // Caves allocated in the first pass belong to this run's effect, so disable can free them
    for (const auto& [name, size] : a.cave_sizes) {
        effect.allocations.push_back({a.labels[name], size});
    }

    if (committing) {
        if (!emit_pass(a, effect, error)) {
            // undo whatever landed
            for (const auto& p : effect.patches) m_process->write_raw(p.address, p.original.data(), p.original.size());
            for (const auto& c : effect.allocations) m_process->free_memory(c.address, c.size);
            effect = {};
            return false;
        }
        // commit this run's labels and any registersymbol into the global table
        for (const std::string& line : a.lines) {
            const std::string low = lower(line);
            if (low.rfind("registersymbol(", 0) == 0) {
                const size_t open = line.find('(');
                const std::string name = split_args(line.substr(open + 1, line.rfind(')') - open - 1))[0];
                if (const auto it = a.labels.find(name); it != a.labels.end()) {
                    m_symbols[name] = it->second;
                    effect.symbols.push_back(name);
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

    // If the script has a [DISABLE] section, run it first (it may write its own bytes)
    if (!s.disable.empty() && m_process->is_attached()) {
        ScriptEffect disable_effect;
        std::string error;
        if (!run(s.disable, disable_effect, error, /*committing=*/true)) {
            result.message = "The [DISABLE] section failed: " + error;
            // fall through and still restore the recorded bytes
        }
    }

    // Restore the original bytes (last write wins, so do it after the DISABLE section)
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

} // namespace nce::assembler
