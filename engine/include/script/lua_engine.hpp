#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

struct lua_State;

namespace nce {
namespace hal { class IProcess; class IHotkeys; }
namespace debugger { struct Registers; }
namespace session { class Session; }

namespace script {

struct ScriptResult {
    bool success{false};
    std::string output;
    std::string error;
};

using PrintCallback = std::function<void(const std::string&)>;

class LuaEngine {
public:
    explicit LuaEngine(session::Session* session = nullptr);
    ~LuaEngine();

    LuaEngine(const LuaEngine&) = delete;
    LuaEngine& operator=(const LuaEngine&) = delete;
    LuaEngine(LuaEngine&&) = delete;
    LuaEngine& operator=(LuaEngine&&) = delete;

    void reset();
    void set_print_callback(PrintCallback cb);
    void set_session(session::Session* session);

    ScriptResult execute_string(const std::string& code);
    ScriptResult execute_file(const std::string& filepath);
    ScriptResult eval_expression(const std::string& expr);

    // Invoked when a software breakpoint hits. Exports RAX..R15/RIP/EFLAGS/THREADID, runs
    // global `debugger_onBreakpoint()` if defined, copies mutated registers back into `regs`,
    // and returns true if the script requested auto-continue (return 1/true).
    bool on_breakpoint_hit(uint32_t thread_id, uintptr_t rip, debugger::Registers& regs);

    // Hotkey & Timer control
    bool trigger_hotkey(const std::string& keys);
    void clear_timers();
    void clear_hotkeys();
    [[nodiscard]] size_t active_timer_count() const;
    [[nodiscard]] size_t active_hotkey_count() const;

    lua_State* get_state() const { return m_L; }
    session::Session* get_session() const { return m_session; }
    void append_output(const std::string& text);

private:
    friend struct LuaApi;

    struct TimerEntry {
        uint64_t id{0};
        int lua_ref{-1};
        std::atomic<bool> stop{false};
        std::thread worker;
    };

    void init_state();
    void register_nce_api();
    void sync_os_hotkeys_outside_lock(const std::vector<std::string>& combos);

    mutable std::recursive_mutex m_mutex;
    lua_State* m_L{nullptr};
    session::Session* m_session{nullptr};
    PrintCallback m_print_cb;
    std::ostringstream m_output_buffer;
    int m_eval_depth{0};

    std::unordered_map<uint64_t, std::shared_ptr<TimerEntry>> m_timers;
    std::vector<std::shared_ptr<TimerEntry>> m_retired_timers;
    uint64_t m_next_timer_id{1};

    std::unique_ptr<hal::IHotkeys> m_hotkeys;
    std::unordered_map<std::string, int> m_hotkey_refs;
};

} // namespace script
} // namespace nce
