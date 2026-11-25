#include "../../include/hal/hotkeys.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <future>
#include <map>
#include <mutex>
#include <thread>

namespace nce::hal {

namespace {

UINT virtual_key(const std::string& key) {
    if (key.size() == 1 && key[0] >= 'A' && key[0] <= 'Z') return static_cast<UINT>(key[0]);
    if (key.size() == 1 && key[0] >= '0' && key[0] <= '9') return static_cast<UINT>(key[0]);
    if (key.size() >= 2 && key[0] == 'F') return VK_F1 + static_cast<UINT>(std::stoi(key.substr(1)) - 1);
    if (key.size() == 4 && key.compare(0, 3, "Num") == 0) {
        const char c = key[3];
        if (c >= '0' && c <= '9') return VK_NUMPAD0 + static_cast<UINT>(c - '0');
        switch (c) {
            case '+': return VK_ADD;
            case '-': return VK_SUBTRACT;
            case '*': return VK_MULTIPLY;
            case '/': return VK_DIVIDE;
            case '.': return VK_DECIMAL;
            default: return 0;
        }
    }
    static const std::map<std::string, UINT> named = {
        {"Insert", VK_INSERT}, {"Delete", VK_DELETE}, {"Home", VK_HOME}, {"End", VK_END}, {"PageUp", VK_PRIOR},
        {"PageDown", VK_NEXT}, {"Up", VK_UP}, {"Down", VK_DOWN}, {"Left", VK_LEFT}, {"Right", VK_RIGHT},
        {"Space", VK_SPACE}, {"Pause", VK_PAUSE},
    };
    const auto it = named.find(key);
    return it == named.end() ? 0 : it->second;
}

// RegisterHotKey without a window: WM_HOTKEY arrives in the message queue of the registering thread, so
// a thread of our own registers the keys and waits for them
class Win32Hotkeys final : public IHotkeys {
public:
    Win32Hotkeys() {
        std::promise<DWORD> started;
        auto thread_id = started.get_future();
        m_thread = std::thread([this, &started] { run(started); });
        m_thread_id = thread_id.get();
    }

    ~Win32Hotkeys() override {
        PostThreadMessageW(m_thread_id, WM_QUIT, 0, 0);
        m_thread.join();
    }

    void on_press(Handler handler) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_handler = std::move(handler);
    }

    std::vector<std::string> set(const std::vector<std::string>& combos) override {
        Request request{combos, {}};
        auto failed = request.failed.get_future();
        if (!PostThreadMessageW(m_thread_id, SET_MESSAGE, 0, reinterpret_cast<LPARAM>(&request))) return combos;
        return failed.get();
    }

    bool deliver(const std::string& combo) override {
        int id = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& [registered_id, registered] : m_registered) {
                if (registered == combo) id = registered_id;
            }
        }
        return id != 0 && PostThreadMessageW(m_thread_id, WM_HOTKEY, static_cast<WPARAM>(id), 0) != FALSE;
    }

private:
    struct Request {
        std::vector<std::string> combos;
        std::promise<std::vector<std::string>> failed;
    };
    static constexpr UINT SET_MESSAGE = WM_APP + 1;

    void run(std::promise<DWORD>& started) {
        MSG msg;
        PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE); // gives this thread its message queue
        started.set_value(GetCurrentThreadId());

        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            if (msg.message == WM_HOTKEY) {
                std::string combo;
                Handler handler;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const auto it = m_registered.find(static_cast<int>(msg.wParam));
                    if (it == m_registered.end()) continue;
                    combo = it->second;
                    handler = m_handler;
                }
                if (handler) handler(combo);
            } else if (msg.message == SET_MESSAGE) {
                auto* request = reinterpret_cast<Request*>(msg.lParam);
                request->failed.set_value(register_all(request->combos));
            }
        }
        register_all({});
    }

    // Runs on the hotkey thread: hotkeys belong to the thread that registered them
    std::vector<std::string> register_all(const std::vector<std::string>& combos) {
        std::map<int, std::string> previous;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            previous = m_registered;
        }
        for (const auto& [id, combo] : previous) UnregisterHotKey(nullptr, id);

        std::map<int, std::string> registered;
        std::vector<std::string> failed;
        int next_id = 1;
        for (const auto& combo : combos) {
            const auto parsed = parse_hotkey(combo);
            const UINT vk = parsed ? virtual_key(parsed->key) : 0;
            UINT modifiers = MOD_NOREPEAT;
            if (parsed && parsed->ctrl) modifiers |= MOD_CONTROL;
            if (parsed && parsed->alt) modifiers |= MOD_ALT;
            if (parsed && parsed->shift) modifiers |= MOD_SHIFT;
            if (parsed && parsed->win) modifiers |= MOD_WIN;
            if (vk != 0 && RegisterHotKey(nullptr, next_id, modifiers, vk)) {
                registered[next_id++] = combo;
            } else {
                failed.push_back(combo);
            }
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        m_registered = std::move(registered);
        return failed;
    }

    std::thread m_thread;
    DWORD m_thread_id{0};
    std::mutex m_mutex;
    Handler m_handler;
    std::map<int, std::string> m_registered; // hotkey id -> canonical combo
};

} // anonymous namespace

std::unique_ptr<IHotkeys> IHotkeys::create() {
    return std::make_unique<Win32Hotkeys>();
}

} // namespace nce::hal
#endif
