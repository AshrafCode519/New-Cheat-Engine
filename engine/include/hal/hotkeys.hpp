#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nce::hal {

// A key with modifiers, as the user writes it: "F1", "Ctrl+F2", "Alt+Shift+Num5", "Ctrl+Num+"
struct KeyCombo {
    bool ctrl{false};
    bool alt{false};
    bool shift{false};
    bool win{false};
    // "F1".."F24", "A".."Z", "0".."9", "Num0".."Num9", "Num+", "Num-", "Num*", "Num/", "Num.", "Insert", "Delete",
    // "Home", "End", "PageUp", "PageDown", "Up", "Down", "Left", "Right", "Space", "Pause"
    std::string key;
};

// Parses a combo in any case, with its modifiers in any order. Letters, digits, Space and the arrows need
// Ctrl, Alt or Win: a system-wide hotkey takes its key away from every program, so a plain "W" would stop
// you typing W anywhere. On failure, `error` (if given) says why.
std::optional<KeyCombo> parse_hotkey(const std::string& text, std::string* error = nullptr);

// Canonical text: the modifiers in the order Ctrl+Alt+Shift+Win, then the key
std::string format_hotkey(const KeyCombo& combo);

// The canonical text of a combo, or empty if it doesn't parse
std::string normalize_hotkey(const std::string& text);

// System-wide hotkeys: they fire while another program (the game) is in front. They are waited for on a
// thread of their own, so the program needs no message loop (the CLI has none).
class IHotkeys {
public:
    using Handler = std::function<void(const std::string& combo)>; // called on the hotkey thread

    virtual ~IHotkeys() = default;

    // Called on every press with the canonical combo text
    virtual void on_press(Handler handler) = 0;

    // Registers these combos (canonical text), replacing the previous ones. Returns the ones that could not
    // be registered because another program (or another part of this one) already holds them.
    virtual std::vector<std::string> set(const std::vector<std::string>& combos) = 0;

    // Runs the handler as if a registered combo were pressed, without making any keyboard input (for
    // scripts and tests). False if the combo is not registered.
    virtual bool deliver(const std::string& combo) = 0;

    static std::unique_ptr<IHotkeys> create();
};

} // namespace nce::hal
