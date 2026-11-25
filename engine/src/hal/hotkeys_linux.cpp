#include "../../include/hal/hotkeys.hpp"

#ifndef _WIN32
#include <atomic>
#include <cctype>
#include <dlfcn.h>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <chrono>

namespace nce::hal {

namespace {

unsigned long key_name_to_xkeysym(const std::string& key) {
    if (key.size() == 1 && key[0] >= 'A' && key[0] <= 'Z') {
        return static_cast<unsigned long>(key[0]);
    }
    if (key.size() == 1 && key[0] >= '0' && key[0] <= '9') {
        return static_cast<unsigned long>(key[0]);
    }
    if (key.size() >= 2 && key[0] == 'F') {
        try {
            int fn = std::stoi(key.substr(1));
            if (fn >= 1 && fn <= 24) return 0xFFBEul + static_cast<unsigned long>(fn - 1);
        } catch (...) {}
    }
    if (key.rfind("Num", 0) == 0 && key.size() == 4) {
        char d = key[3];
        if (d >= '0' && d <= '9') return 0xFFB0ul + static_cast<unsigned long>(d - '0');
        if (d == '+') return 0xFFABul;
        if (d == '-') return 0xFFADul;
        if (d == '*') return 0xFFAAul;
        if (d == '/') return 0xFFAFul;
        if (d == '.') return 0xFFAEul;
    }
    static const std::unordered_map<std::string, unsigned long> special = {
        {"Space", 0x0020}, {"Insert", 0xFF63}, {"Delete", 0xFFFF},
        {"Home", 0xFF50},  {"End", 0xFF57},    {"PageUp", 0xFF55},
        {"PageDown", 0xFF56}, {"Left", 0xFF51}, {"Up", 0xFF52},
        {"Right", 0xFF53}, {"Down", 0xFF54},   {"Pause", 0xFF13},
    };
    auto it = special.find(key);
    return (it != special.end()) ? it->second : 0ul;
}

class LinuxHotkeys;

struct LinuxHotkeyRegistry {
    std::mutex mutex;
    std::map<std::string, LinuxHotkeys*> owners;
};

LinuxHotkeyRegistry& hotkey_registry() {
    static LinuxHotkeyRegistry reg;
    return reg;
}

class LinuxHotkeys final : public IHotkeys {
public:
    LinuxHotkeys() {
        m_worker = std::thread([this]() { poll_loop(); });
    }

    ~LinuxHotkeys() override {
        m_stop = true;
        if (m_worker.joinable()) m_worker.join();
        release_owned_combos();
    }

    void on_press(Handler handler) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_handler = std::move(handler);
    }

    std::vector<std::string> set(const std::vector<std::string>& combos) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        release_owned_combos();
        m_entries.clear();
        std::vector<std::string> failed;
        auto& reg = hotkey_registry();
        std::lock_guard<std::mutex> rlock(reg.mutex);
        for (const auto& text : combos) {
            auto parsed = parse_hotkey(text);
            if (!parsed) {
                failed.push_back(text);
                continue;
            }
            WatchEntry e;
            e.combo_text = format_hotkey(*parsed);
            e.parsed = *parsed;
            e.keysym = key_name_to_xkeysym(parsed->key);
            if (e.keysym == 0) {
                failed.push_back(text);
                continue;
            }
            auto it = reg.owners.find(e.combo_text);
            if (it != reg.owners.end() && it->second != this) {
                failed.push_back(text);
                continue;
            }
            reg.owners[e.combo_text] = this;
            m_entries.push_back(std::move(e));
        }
        return failed;
    }

    bool deliver(const std::string& combo) override {
        const std::string norm = normalize_hotkey(combo);
        Handler cb;
        bool registered = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& e : m_entries) {
                if (e.combo_text == norm || e.combo_text == combo) {
                    registered = true;
                    break;
                }
            }
            cb = m_handler;
        }
        if (!registered) return false;
        if (cb) cb(norm.empty() ? combo : norm);
        return true;
    }

private:
    void release_owned_combos() {
        auto& reg = hotkey_registry();
        std::lock_guard<std::mutex> rlock(reg.mutex);
        for (auto it = reg.owners.begin(); it != reg.owners.end();) {
            if (it->second == this) it = reg.owners.erase(it);
            else ++it;
        }
    }

    struct WatchEntry {
        std::string combo_text;
        KeyCombo parsed;
        unsigned long keysym{0};
        bool was_down{false};
    };

    void poll_loop() {
        void* x11 = dlopen("libX11.so.6", RTLD_LAZY);
        if (!x11) return;

        using OpenDisplayFn   = void*(*)(const char*);
        using CloseDisplayFn  = int(*)(void*);
        using QueryKeymapFn   = int(*)(void*, char[32]);
        using KeysymToCodeFn  = unsigned int(*)(void*, unsigned long);

        auto open_disp  = reinterpret_cast<OpenDisplayFn>(dlsym(x11, "XOpenDisplay"));
        auto close_disp = reinterpret_cast<CloseDisplayFn>(dlsym(x11, "XCloseDisplay"));
        auto query_map  = reinterpret_cast<QueryKeymapFn>(dlsym(x11, "XQueryKeymap"));
        auto sym_to_kc  = reinterpret_cast<KeysymToCodeFn>(dlsym(x11, "XKeysymToKeycode"));

        if (!open_disp || !close_disp || !query_map || !sym_to_kc) {
            dlclose(x11);
            return;
        }

        void* disp = open_disp(nullptr);
        if (!disp) {
            dlclose(x11);
            return;
        }

        auto is_kc_down = [](const char keys[32], unsigned int kc) {
            return kc != 0 && kc < 256 && ((keys[kc >> 3] & (1 << (kc & 7))) != 0);
        };

        const unsigned int kc_lctrl  = sym_to_kc(disp, 0xFFE3);
        const unsigned int kc_rctrl  = sym_to_kc(disp, 0xFFE4);
        const unsigned int kc_lshift = sym_to_kc(disp, 0xFFE1);
        const unsigned int kc_rshift = sym_to_kc(disp, 0xFFE2);
        const unsigned int kc_lalt   = sym_to_kc(disp, 0xFFE9);
        const unsigned int kc_ralt   = sym_to_kc(disp, 0xFFEA);
        const unsigned int kc_lsuper = sym_to_kc(disp, 0xFFEB);

        while (!m_stop) {
            char keymap[32]{};
            query_map(disp, keymap);

            const bool ctrl  = is_kc_down(keymap, kc_lctrl)  || is_kc_down(keymap, kc_rctrl);
            const bool shift = is_kc_down(keymap, kc_lshift) || is_kc_down(keymap, kc_rshift);
            const bool alt   = is_kc_down(keymap, kc_lalt)   || is_kc_down(keymap, kc_ralt);
            const bool win   = is_kc_down(keymap, kc_lsuper);

            std::vector<std::string> triggered;
            Handler cb;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                cb = m_handler;
                for (auto& e : m_entries) {
                    unsigned int kc = sym_to_kc(disp, e.keysym);
                    bool down = is_kc_down(keymap, kc) &&
                                (!e.parsed.ctrl  || ctrl) &&
                                (!e.parsed.alt   || alt) &&
                                (!e.parsed.shift || shift) &&
                                (!e.parsed.win   || win);
                    if (down && !e.was_down) {
                        triggered.push_back(e.combo_text);
                    }
                    e.was_down = down;
                }
            }

            if (cb) {
                for (const auto& t : triggered) cb(t);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }

        close_disp(disp);
        dlclose(x11);
    }

    std::atomic<bool> m_stop{false};
    std::thread m_worker;
    mutable std::mutex m_mutex;
    Handler m_handler;
    std::vector<WatchEntry> m_entries;
};

} // anonymous namespace

std::unique_ptr<IHotkeys> IHotkeys::create() {
    return std::make_unique<LinuxHotkeys>();
}

} // namespace nce::hal
#endif
