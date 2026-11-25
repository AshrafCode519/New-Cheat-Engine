#include "../../include/table/cheat_table.hpp"
#include "../../include/hal/hotkeys.hpp"
#include "../../include/scanner/scan_results.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "../../include/utils/text_encoding.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

namespace nce::table {

namespace {

using json = nlohmann::ordered_json; // keeps keys in the order written

constexpr const char* FORMAT_NAME = "nce-table";
constexpr int FORMAT_VERSION = 1;

std::string to_hex(uint64_t value) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << value;
    return ss.str();
}

std::string to_signed_hex(int64_t value) {
    if (value < 0) {
        return "-" + to_hex(static_cast<uint64_t>(-value));
    }
    return to_hex(static_cast<uint64_t>(value));
}

template <typename T>
std::optional<T> from_hex(const std::string& text) {
    std::string_view digits(text);
    bool neg = false;
    if constexpr (std::is_signed_v<T>) {
        if (!digits.empty() && digits.front() == '-') {
            neg = true;
            digits.remove_prefix(1);
        }
    }
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) digits.remove_prefix(2);
    if (digits.empty()) return std::nullopt;
    uint64_t raw = 0;
    auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), raw, 16);
    if (ec != std::errc() || ptr != digits.data() + digits.size()) return std::nullopt;
    if constexpr (std::is_signed_v<T>) {
        if (neg) return static_cast<T>(-static_cast<int64_t>(raw));
        return static_cast<T>(raw);
    }
    return static_cast<T>(raw);
}

bool read_pointer(const hal::IProcess& process, uintptr_t address, uintptr_t& out) {
    if (process.pointer_size() == 4) {
        uint32_t value = 0;
        if (!process.read(address, value)) return false;
        out = value;
        return true;
    }
    return process.read(address, out);
}

size_t entry_size(const TableEntry& entry) {
    const size_t numeric = scanner::get_data_type_size(entry.type);
    const bool is_numeric = scanner::dispatch_numeric(entry.type, []<typename T>() {});
    return is_numeric ? numeric : entry.length;
}

// "module" (omitted for an absolute address), "offset" and "pointer" (omitted for a static address)
void write_path(json& item, const scanner::PointerPath& path) {
    if (!path.module_name.empty()) item["module"] = path.module_name;
    item["offset"] = to_hex(path.base_offset);
    if (!path.offsets.empty()) {
        json offsets = json::array();
        for (const auto o : path.offsets) offsets.push_back(to_signed_hex(o));
        item["pointer"] = offsets;
    }
}

std::optional<scanner::PointerPath> read_path(const json& item) {
    scanner::PointerPath path;
    path.module_name = item.value("module", "");
    auto offset = from_hex<uintptr_t>(item.value("offset", ""));
    if (!offset) return std::nullopt;
    path.base_offset = *offset;

    if (const auto pointer = item.find("pointer"); pointer != item.end()) {
        if (!pointer->is_array()) return std::nullopt;
        for (const auto& o : *pointer) {
            if (!o.is_string()) return std::nullopt;
            auto value = from_hex<int64_t>(o.get<std::string>());
            if (!value) return std::nullopt;
            path.offsets.push_back(*value);
        }
    }
    return path;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xF]);
    }
    return out;
}

std::optional<std::vector<uint8_t>> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        const char* first = hex.data() + i * 2;
        auto [ptr, ec] = std::from_chars(first, first + 2, bytes[i], 16);
        if (ec != std::errc() || ptr != first + 2) return std::nullopt;
    }
    return bytes;
}

bool same_path(const scanner::PointerPath& a, const scanner::PointerPath& b) {
    return a.module_name == b.module_name && a.base_offset == b.base_offset && a.offsets == b.offsets;
}

} // anonymous namespace

std::vector<scanner::PointerPath> find_permanent_paths(const TableEntry& entry, std::shared_ptr<hal::IProcess> process,
                                                       const std::vector<hal::ModuleInfo>& modules) {
    const uintptr_t address = entry.address(*process, modules);
    if (address == 0) return {};

    // The default search: many paths give reconcile many voters; ranking puts the likely ones first
    scanner::PointerScanner scanner(std::move(process));
    return scanner.scan(address).paths;
}

bool make_permanent(TableEntry& entry, const std::vector<scanner::PointerPath>& paths, const hal::IProcess& process,
                    const std::vector<hal::ModuleInfo>& modules, size_t max_alternatives) {
    if (paths.empty()) return false;

    // Remember the surroundings while the entry still points at the value
    entry.context.clear();
    const uintptr_t address = entry.address(process, modules);
    const size_t radius = TableEntry::CONTEXT_RADIUS;
    if (address > radius) {
        std::vector<uint8_t> window(2 * radius + entry_size(entry));
        if (process.read_raw(address - radius, window.data(), window.size())) entry.context = std::move(window);
    }

    entry.location = paths.front();
    const size_t kept = std::min(paths.size() - 1, max_alternatives);
    entry.alternatives.assign(paths.begin() + 1, paths.begin() + 1 + static_cast<std::ptrdiff_t>(kept));
    return true;
}

ReconcileResult reconcile(TableEntry& entry, const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules) {
    ReconcileResult result;
    if (entry.alternatives.empty()) return result;

    // Every path in rank order: the location first, then the alternatives
    std::vector<scanner::PointerPath> paths;
    paths.reserve(entry.alternatives.size() + 1);
    paths.push_back(entry.location);
    paths.insert(paths.end(), entry.alternatives.begin(), entry.alternatives.end());
    result.paths = paths.size();

    // The addresses the paths lead to now, in order of their best-ranked path, with their vote counts
    struct Candidate {
        uintptr_t address{0};
        size_t votes{0};
        size_t matches{0};      // remembered non-zero context words still there
        double nearness{0};     // the same words, each weighted by 1 / its distance from the value in words
        bool value_equal{false};
    };
    std::vector<uintptr_t> leads_to(paths.size(), 0);
    std::vector<Candidate> candidates;
    for (size_t i = 0; i < paths.size(); ++i) {
        leads_to[i] = paths[i].resolve(process, modules);
        if (leads_to[i] == 0) continue;
        ++result.resolved;
        auto it = std::find_if(candidates.begin(), candidates.end(), [&](const Candidate& c) { return c.address == leads_to[i]; });
        if (it == candidates.end()) candidates.push_back({leads_to[i], 1});
        else ++it->votes;
    }
    if (candidates.empty()) return result; // nothing resolves (other program, module not loaded): keep everything

    // Compare each candidate's surroundings with the remembered ones, word by word (zero words prove nothing)
    const size_t radius = TableEntry::CONTEXT_RADIUS;
    const size_t value_size = entry_size(entry);
    const bool has_context = entry.context.size() == 2 * radius + value_size;
    if (has_context) {
        for (size_t off = 0; off + 4 <= entry.context.size(); off += 4) {
            const bool overlaps_value = off + 4 > radius && off < radius + value_size;
            uint32_t saved = 0;
            std::memcpy(&saved, entry.context.data() + off, 4);
            if (!overlaps_value && saved != 0) ++result.context_words;
        }
        std::vector<uint8_t> window(entry.context.size());
        for (auto& c : candidates) {
            if (c.address <= radius || !process.read_raw(c.address - radius, window.data(), window.size())) continue;
            c.value_equal = std::memcmp(window.data() + radius, entry.context.data() + radius, value_size) == 0;
            for (size_t off = 0; off + 4 <= window.size(); off += 4) {
                const bool overlaps_value = off + 4 > radius && off < radius + value_size;
                uint32_t saved = 0;
                std::memcpy(&saved, entry.context.data() + off, 4);
                if (overlaps_value || saved == 0 || std::memcmp(window.data() + off, &saved, 4) != 0) continue;
                ++c.matches;
                // 1 for the words touching the value, 1/2 for the next ones, ...
                const size_t distance = off < radius ? (radius - off) / 4 : (off - (radius + value_size)) / 4 + 1;
                c.nearness += 1.0 / static_cast<double>(distance);
            }
        }
    }

    // Context first: near words, plus still holding the remembered value (as much as a direct neighbour)
    auto context_key = [](const Candidate& c) { return c.nearness + (c.value_equal ? 1.0 : 0.0); };
    double best_key = 0;
    for (const auto& c : candidates) best_key = std::max(best_key, context_key(c));

    // Candidates still in the running: about the best context match, or everyone if the context says nothing
    std::vector<size_t> pool;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (best_key == 0 || context_key(candidates[i]) >= 0.75 * best_key) pool.push_back(i);
    }

    // Among them, most votes wins; ties go to the better-ranked path (earlier candidate)
    size_t winner = pool.front();
    for (const size_t i : pool) {
        if (candidates[i].votes > candidates[winner].votes) winner = i;
    }
    size_t runner_up = 0;
    for (const size_t i : pool) {
        if (i != winner) runner_up = std::max(runner_up, candidates[i].votes);
    }

    const Candidate& chosen = candidates[winner];
    size_t most_votes = 0;
    for (const auto& c : candidates) most_votes = std::max(most_votes, c.votes);
    result.address = chosen.address;
    result.agreeing = chosen.votes;
    result.context_matches = chosen.matches;
    result.value_matches = chosen.value_equal;
    result.by_context = best_key > 0 && pool.size() == 1 && chosen.votes < most_votes;
    result.ambiguous = runner_up > 0 && runner_up * 2 >= chosen.votes;
    if (result.ambiguous) return result; // no clear choice: change nothing, the user decides

    std::vector<scanner::PointerPath> agreeing;
    agreeing.reserve(chosen.votes);
    for (size_t i = 0; i < paths.size(); ++i) {
        if (leads_to[i] == chosen.address) agreeing.push_back(std::move(paths[i]));
    }
    result.changed = agreeing.size() != result.paths || !same_path(agreeing.front(), entry.location);
    entry.location = std::move(agreeing.front());
    entry.alternatives.assign(std::make_move_iterator(agreeing.begin() + 1), std::make_move_iterator(agreeing.end()));
    return result;
}

uintptr_t TableEntry::address(const hal::IProcess& process, const std::vector<hal::ModuleInfo>& modules) const {
    if (!is_absolute()) return location.resolve(process, modules);

    uintptr_t current = location.base_offset;
    for (const auto offset : location.offsets) {
        uintptr_t value = 0;
        if (!read_pointer(process, current, value)) return 0;
        current = value + static_cast<uintptr_t>(offset);
    }
    return current;
}

std::string TableEntry::location_string() const {
    std::ostringstream ss;
    if (is_absolute()) {
        ss << utils::format_address(location.base_offset);
    } else {
        ss << location.module_name << "+" << to_hex(location.base_offset);
    }
    for (const auto offset : location.offsets) {
        ss << " -> " << to_hex(static_cast<uint64_t>(offset));
    }
    return ss.str();
}

TableEntry make_entry(uintptr_t address, scanner::DataType type, const std::vector<hal::ModuleInfo>& modules,
                      std::string description, size_t length) {
    TableEntry entry;
    entry.description = std::move(description);
    entry.type = type;
    entry.length = scanner::dispatch_numeric(type, []<typename T>() {}) ? 0 : length; // numbers know their size
    entry.location.base_offset = address;

    for (const auto& mod : modules) {
        if (address >= mod.base_address && address < mod.base_address + mod.size) {
            entry.location.module_name = mod.name;
            entry.location.base_offset = address - mod.base_address;
            break;
        }
    }
    return entry;
}

TableEntry make_entry(const scanner::PointerPath& path, scanner::DataType type, std::string description) {
    TableEntry entry;
    entry.description = std::move(description);
    entry.type = type;
    entry.location = path;
    return entry;
}

std::optional<scanner::ScanValue> read_entry(const TableEntry& entry, const hal::IProcess& process,
                                             const std::vector<hal::ModuleInfo>& modules) {
    const uintptr_t address = entry.address(process, modules);
    const size_t size = entry_size(entry);
    if (address == 0 || size == 0) return std::nullopt;

    std::vector<uint8_t> bytes(size);
    if (!process.read_raw(address, bytes.data(), size)) return std::nullopt;

    // Text entries stop at the first terminator, like the program reading them would
    if (entry.type == scanner::DataType::String) {
        const auto end = std::find(bytes.begin(), bytes.end(), uint8_t{0});
        return scanner::ScanValue::of(entry.type, std::string(bytes.begin(), end));
    }
    if (entry.type == scanner::DataType::String16) {
        size_t units = 0;
        while (units * 2 + 1 < bytes.size() && (bytes[units * 2] | bytes[units * 2 + 1]) != 0) ++units;
        bytes.resize(units * 2);
        return scanner::ScanValue::of(entry.type, std::move(bytes));
    }
    return scanner::value_from_bytes(entry.type, bytes.data(), bytes.size());
}

bool write_entry(const TableEntry& entry, const std::string& value_text, const hal::IProcess& process,
                 const std::vector<hal::ModuleInfo>& modules) {
    std::vector<uint8_t> bytes;

    if (auto value = utils::parse_scan_value(entry.type, value_text)) {
        bytes = scanner::value_to_bytes(*value);
    } else if (entry.type == scanner::DataType::String) {
        bytes.assign(value_text.begin(), value_text.end());
    } else if (entry.type == scanner::DataType::String16) {
        auto encoded = utils::utf8_to_utf16le(value_text);
        if (!encoded) return false;
        bytes = std::move(*encoded);
    } else {
        return false; // invalid number, or an aob entry
    }

    if (entry.type == scanner::DataType::String || entry.type == scanner::DataType::String16) {
        if (bytes.size() > entry.length) return false;
        // Terminate the shorter text so the old tail isn't read as part of it
        const size_t terminator = (entry.type == scanner::DataType::String16) ? 2 : 1;
        if (bytes.size() + terminator <= entry.length) bytes.resize(bytes.size() + terminator, 0);
    }

    const uintptr_t address = entry.address(process, modules);
    return address != 0 && process.write_raw(address, bytes.data(), bytes.size());
}

std::string Hotkey::to_string() const {
    switch (action) {
        case Action::ToggleFreeze: return keys + ": toggle freeze";
        case Action::Set: return keys + ": set to " + value;
        case Action::Add: return keys + ": add " + value;
    }
    return keys;
}

namespace {

const char* action_name(Hotkey::Action action) {
    switch (action) {
        case Hotkey::Action::ToggleFreeze: return "toggle";
        case Hotkey::Action::Set: return "set";
        case Hotkey::Action::Add: return "add";
    }
    return "toggle";
}

std::optional<Hotkey::Action> parse_action(const std::string& name) {
    if (name == "toggle") return Hotkey::Action::ToggleFreeze;
    if (name == "set") return Hotkey::Action::Set;
    if (name == "add") return Hotkey::Action::Add;
    return std::nullopt;
}

} // anonymous namespace

std::string to_json(const CheatTable& table) {
    json entries = json::array();
    for (const auto& e : table.entries) {
        json item = {
            {"description", e.description},
            {"type", utils::format_data_type(e.type)},
        };
        write_path(item, e.location);
        if (e.length > 0) item["length"] = e.length;
        if (e.frozen_value) item["freeze"] = *e.frozen_value;
        if (!e.group.empty()) item["group"] = e.group;
        if (!e.dropdown.empty()) item["dropdown"] = e.dropdown;
        if (!e.context.empty()) item["context"] = bytes_to_hex(e.context);
        if (!e.alternatives.empty()) {
            json alternatives = json::array();
            for (const auto& path : e.alternatives) {
                json alternative = json::object();
                write_path(alternative, path);
                alternatives.push_back(alternative);
            }
            item["alternatives"] = alternatives;
        }
        if (!e.hotkeys.empty()) {
            json hotkeys = json::array();
            for (const auto& h : e.hotkeys) {
                json hotkey = {{"keys", h.keys}, {"action", action_name(h.action)}};
                if (h.action != Hotkey::Action::ToggleFreeze) hotkey["value"] = h.value;
                hotkeys.push_back(hotkey);
            }
            item["hotkeys"] = hotkeys;
        }
        entries.push_back(item);
    }

    json doc = {
        {"format", FORMAT_NAME},
        {"version", FORMAT_VERSION},
        {"process", table.process_name},
        {"entries", entries},
    };
    if (!table.scripts.empty()) {
        json scripts = json::array();
        for (const auto& s : table.scripts) {
            scripts.push_back({{"name", s.name}, {"body", s.body}, {"enabled", s.enabled}});
        }
        doc["scripts"] = scripts;
    }
    if (!table.lua_script.empty()) {
        doc["lua_script"] = table.lua_script;
    }
    return doc.dump(2) + "\n";
}

std::optional<CheatTable> from_json(const std::string& text) {
    const json doc = json::parse(text, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) return std::nullopt;
    if (doc.value("format", "") != FORMAT_NAME || doc.value("version", 0) != FORMAT_VERSION) return std::nullopt;

    CheatTable table;
    table.process_name = doc.value("process", "");

    const auto entries = doc.find("entries");
    if (entries == doc.end() || !entries->is_array()) return std::nullopt;

    for (const auto& item : *entries) {
        if (!item.is_object()) return std::nullopt;

        TableEntry e;
        e.description = item.value("description", "");

        auto type = utils::parse_data_type(item.value("type", ""));
        if (!type) return std::nullopt;
        e.type = *type;

        auto location = read_path(item);
        if (!location) return std::nullopt;
        e.location = std::move(*location);

        if (const auto length = item.find("length"); length != item.end()) {
            if (!length->is_number_unsigned()) return std::nullopt;
            e.length = length->get<size_t>();
        }
        const bool is_numeric = scanner::dispatch_numeric(e.type, []<typename T>() {});
        if (is_numeric) e.length = 0;                // numbers know their size
        else if (e.length == 0) return std::nullopt; // text / aob entries need one

        if (const auto freeze = item.find("freeze"); freeze != item.end()) {
            if (!freeze->is_string()) return std::nullopt;
            e.frozen_value = freeze->get<std::string>();
        }

        if (const auto context = item.find("context"); context != item.end()) {
            auto bytes = context->is_string() ? hex_to_bytes(context->get<std::string>()) : std::nullopt;
            if (!bytes) return std::nullopt;
            e.context = std::move(*bytes);
        }

        if (const auto alternatives = item.find("alternatives"); alternatives != item.end()) {
            if (!alternatives->is_array()) return std::nullopt;
            for (const auto& alternative : *alternatives) {
                auto path = alternative.is_object() ? read_path(alternative) : std::nullopt;
                if (!path || path->module_name.empty()) return std::nullopt; // alternatives are pointer paths
                e.alternatives.push_back(std::move(*path));
            }
        }

        if (const auto hotkeys = item.find("hotkeys"); hotkeys != item.end()) {
            if (!hotkeys->is_array()) return std::nullopt;
            for (const auto& hotkey : *hotkeys) {
                if (!hotkey.is_object()) return std::nullopt;
                Hotkey h;
                h.keys = hal::normalize_hotkey(hotkey.value("keys", ""));
                const auto action = parse_action(hotkey.value("action", ""));
                if (h.keys.empty() || !action) return std::nullopt;
                h.action = *action;
                h.value = hotkey.value("value", "");
                e.hotkeys.push_back(std::move(h));
            }
        }
        e.group = item.value("group", "");
        if (const auto dd = item.find("dropdown"); dd != item.end()) {
            if (!dd->is_object()) return std::nullopt;
            for (const auto& [k, v] : dd->items()) {
                if (v.is_string()) e.dropdown[k] = v.get<std::string>();
            }
        }

        table.entries.push_back(std::move(e));
    }

    if (const auto scripts = doc.find("scripts"); scripts != doc.end()) {
        if (!scripts->is_array()) return std::nullopt;
        for (const auto& item : *scripts) {
            if (!item.is_object()) return std::nullopt;
            TableScript s;
            s.name = item.value("name", "");
            s.body = item.value("body", "");
            s.enabled = item.value("enabled", false);
            if (s.name.empty()) return std::nullopt;
            table.scripts.push_back(std::move(s));
        }
    }

    if (const auto lua_it = doc.find("lua_script"); lua_it != doc.end()) {
        if (!lua_it->is_string()) return std::nullopt;
        table.lua_script = lua_it->get<std::string>();
    }

    return table;
}

bool save_table(const std::string& path, const CheatTable& table) {
    std::ofstream out(path, std::ios::trunc | std::ios::binary);
    if (!out) return false;
    out << to_json(table);
    return static_cast<bool>(out);
}

std::optional<CheatTable> load_table(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream ss;
    ss << in.rdbuf();
    return from_json(ss.str());
}

} // namespace nce::table
