#include "../../include/hal/hotkeys.hpp"
#include <algorithm>
#include <cctype>

namespace nce::hal {

namespace {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool all_digits(const std::string& text) {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}

// The canonical name of a key (any case, a few aliases), or empty
std::string canonical_key(const std::string& name) {
    const std::string k = lower(name);
    if (k.size() == 1 && std::isalpha(static_cast<unsigned char>(k[0]))) return std::string(1, static_cast<char>(std::toupper(k[0])));
    if (k.size() == 1 && std::isdigit(static_cast<unsigned char>(k[0]))) return k;
    if (k.size() >= 2 && k[0] == 'f' && all_digits(k.substr(1))) {
        const int n = std::stoi(k.substr(1));
        if (n >= 1 && n <= 24) return "F" + std::to_string(n);
        return {};
    }
    for (const char* prefix : {"numpad", "num"}) {
        const std::string p = prefix;
        if (k.size() == p.size() + 1 && k.compare(0, p.size(), p) == 0) {
            const char c = k.back();
            if (std::isdigit(static_cast<unsigned char>(c))) return std::string("Num") + c;
            if (c == '+' || c == '-' || c == '*' || c == '/' || c == '.') return std::string("Num") + c;
        }
    }
    static const std::pair<const char*, const char*> names[] = {
        {"insert", "Insert"}, {"ins", "Insert"}, {"delete", "Delete"}, {"del", "Delete"}, {"home", "Home"},
        {"end", "End"}, {"pageup", "PageUp"}, {"pgup", "PageUp"}, {"pagedown", "PageDown"}, {"pgdn", "PageDown"},
        {"up", "Up"}, {"down", "Down"}, {"left", "Left"}, {"right", "Right"}, {"space", "Space"}, {"pause", "Pause"},
    };
    for (const auto& [alias, canonical] : names) {
        if (k == alias) return canonical;
    }
    return {};
}

// Keys a game or any program types with: taking them system-wide without a modifier breaks typing
bool needs_modifier(const std::string& key) {
    if (key.size() == 1) return true; // letters and digits
    return key == "Space" || key == "Up" || key == "Down" || key == "Left" || key == "Right";
}

} // anonymous namespace

std::optional<KeyCombo> parse_hotkey(const std::string& text, std::string* error) {
    auto fail = [&](std::string why) -> std::optional<KeyCombo> {
        if (error) *error = std::move(why);
        return std::nullopt;
    };

    KeyCombo combo;
    std::string rest; // no key name has a space: "Ctrl + F1" is "Ctrl+F1"
    for (const char c : text) {
        if (c != ' ' && c != '\t') rest += c;
    }
    // Modifiers are "name+" prefixes; what is left is the key (which may itself be "Num+")
    for (bool found = true; found;) {
        found = false;
        const std::string l = lower(rest);
        for (const auto& [name, flag] : {std::pair<const char*, bool*>{"ctrl+", &combo.ctrl}, {"control+", &combo.ctrl},
                                         {"alt+", &combo.alt}, {"shift+", &combo.shift}, {"win+", &combo.win}}) {
            const std::string n = name;
            if (l.size() > n.size() && l.compare(0, n.size(), n) == 0) {
                *flag = true;
                rest = rest.substr(n.size());
                found = true;
                break;
            }
        }
    }

    const std::string l = lower(rest);
    if (l.empty() || l == "ctrl" || l == "control" || l == "alt" || l == "shift" || l == "win") {
        return fail("'" + text + "' has no key: add one, as in Ctrl+F1.");
    }
    combo.key = canonical_key(rest);
    if (combo.key.empty()) {
        return fail("'" + rest + "' is not a key this program knows. Use F1-F24, A-Z, 0-9, Num0-Num9, Num+ Num- Num* Num/ "
                    "Num., Insert, Delete, Home, End, PageUp, PageDown, arrows, Space or Pause.");
    }
    if (needs_modifier(combo.key) && !combo.ctrl && !combo.alt && !combo.win) {
        return fail(combo.key + " alone would stop you typing it in every program while this one runs: add Ctrl or "
                    "Alt (as in Ctrl+" + combo.key + "), or use an F key or the numpad.");
    }
    return combo;
}

std::string format_hotkey(const KeyCombo& combo) {
    std::string text;
    if (combo.ctrl) text += "Ctrl+";
    if (combo.alt) text += "Alt+";
    if (combo.shift) text += "Shift+";
    if (combo.win) text += "Win+";
    return text + combo.key;
}

std::string normalize_hotkey(const std::string& text) {
    auto combo = parse_hotkey(text);
    return combo ? format_hotkey(*combo) : std::string();
}

} // namespace nce::hal
