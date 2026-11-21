#pragma once

#include "scan_session.hpp"
#include "../hal/hotkeys.hpp"
#include "../hal/process.hpp"
#include "../scanner/noise_map.hpp"
#include "../scanner/pointer_scanner.hpp"
#include "../scanner/value_tracker.hpp"
#include "../table/cheat_table.hpp"
#include "../view/memory_view.hpp"
#include <atomic>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace nce::session {

// The cheat table, shared with a thread that keeps frozen entries at their values and with the thread
// that waits for its hotkeys. Every access goes through this class, which holds the lock (with() for
// anything the operations below don't cover; change hotkeys only through add_hotkey / remove_hotkey).
class TableKeeper {
public:
    // hotkeys: where the table's hotkeys are registered (nullptr: none are; press() still works)
    TableKeeper(std::shared_ptr<hal::IProcess> process, std::unique_ptr<hal::IHotkeys> hotkeys);
    ~TableKeeper();
    TableKeeper(const TableKeeper&) = delete;
    TableKeeper& operator=(const TableKeeper&) = delete;

    // Runs fn(table, modules) under the lock
    template <typename Fn>
    decltype(auto) with(Fn&& fn) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return fn(m_table, std::as_const(m_modules));
    }

    struct AttachResult {
        bool attached{false};
        size_t unfrozen{0};     // absolute entries that belonged to the previous process
        std::string table_note; // what the table library did ("Opened the table of game.exe ..."), or empty
    };
    // Swaps the process under the lock, so the freeze thread never writes into the new process with the
    // old process' addresses: absolute entries are unfrozen. With the table library on, attaching to
    // another program saves the table and opens that program's (see set_library).
    AttachResult attach(uint32_t pid);
    void detach();

    struct ReconcileLine {
        size_t index{0};
        std::string description;
        table::ReconcileResult result;
    };
    // Permanent entries find their value in the current process (after a restart)
    std::vector<ReconcileLine> reconcile();

    Outcome add_result(const scanner::ScanResults& results, size_t index, std::string description);
    Outcome add_address(uintptr_t address, scanner::DataType type, std::string description);
    Outcome add_pointer(const scanner::PointerPath& path, scanner::DataType type, std::string description);
    Outcome set_value(size_t index, const std::string& value);
    Outcome freeze(size_t index, std::optional<std::string> value); // nullopt: keep its current value
    Outcome unfreeze(size_t index);
    size_t unfreeze_all();
    Outcome remove(size_t index);
    Outcome save(const std::string& path);
    Outcome load(const std::string& path);

    // Making an entry permanent takes a slow pointer scan, which runs without the lock: copy the entry,
    // scan (Session::find_permanent_paths), then apply. Fails if the entry changed meanwhile.
    [[nodiscard]] std::optional<table::TableEntry> entry(size_t index);
    Outcome make_permanent(size_t index, const table::TableEntry& scanned, const std::vector<scanner::PointerPath>& paths);

    [[nodiscard]] size_t size();
    [[nodiscard]] std::vector<hal::ModuleInfo> modules();
    void refresh_modules(); // the target loaded or unloaded modules since attach

    // Hotkeys: system-wide keys that act on entries while the game is in front (see table::Hotkey).
    // A combo can act on several entries. An entry has one action per combo: adding replaces it.
    Outcome add_hotkey(size_t index, const std::string& keys, table::Hotkey::Action action, const std::string& value);
    Outcome remove_hotkey(size_t index, const std::string& keys);
    // Runs what a combo is bound to, as pressing it does: "Health: frozen at 100; Mana: set to 999"
    Outcome press(const std::string& keys);
    // Told about every press of a bound combo (on the hotkey thread), e.g. to beep or show the result
    void on_hotkey(std::function<void(const std::string& combo, const Outcome& outcome)> listener);
    // Bound combos that another program already holds: they don't fire
    [[nodiscard]] std::vector<std::string> hotkeys_taken();

    // The table library: each program's table in <folder>/<program>.json. Attaching to a program opens its
    // table (a restart of the same program keeps the table as it is), and the table is saved there every
    // 2 s while it changes and when this object goes away. An empty folder turns it off: then the table
    // stays as it is whatever you attach to.
    void set_library(std::filesystem::path folder);
    [[nodiscard]] std::filesystem::path library();
    // Where the open table is kept ("" if the library is off or the table belongs to no program yet)
    [[nodiscard]] std::filesystem::path library_file();
    // Saves the open table to the library now, instead of at the next automatic save
    Outcome save_to_library();

private:
    void freeze_loop();
    Outcome apply_hotkey(table::TableEntry& entry, const table::Hotkey& hotkey); // with the lock held
    void rebind(); // registers the table's combos again; never with the lock held (see the .cpp)
    [[nodiscard]] std::filesystem::path library_file_locked(const std::string& program) const;
    std::string switch_table_locked(const std::string& program, bool& changed); // with both locks held
    Outcome autosave(bool force);
    [[nodiscard]] bool valid(size_t index) const { return index < m_table.entries.size(); }

    std::shared_ptr<hal::IProcess> m_process;
    std::mutex m_mutex;
    table::CheatTable m_table;
    std::vector<hal::ModuleInfo> m_modules;
    std::atomic<bool> m_running{true};
    std::thread m_freeze_thread;

    std::unique_ptr<hal::IHotkeys> m_hotkeys;
    std::mutex m_rebind_mutex;       // one rebind at a time, so the last table state wins
    std::vector<std::string> m_taken; // guarded by m_mutex
    std::mutex m_listener_mutex;
    std::function<void(const std::string&, const Outcome&)> m_listener;

    // Taken before m_mutex by everything that writes library files, so two writes never meet
    std::mutex m_save_mutex;
    std::filesystem::path m_library; // guarded by m_mutex
    std::string m_saved_text;        // the open table as last saved to the library (guarded by m_mutex)
};

// %APPDATA%\NewCheatEngine\tables on Windows (~/.config/new-cheat-engine/tables elsewhere)
std::filesystem::path default_library_folder();

// "found at 0x... (3 of 4 paths lead there; ...)", "close vote (...)", "none of its 4 paths resolve here ..."
std::string describe_reconcile(const table::ReconcileResult& result);

// Everything one attached target needs: the process, the scanner with its noise map, the current search,
// the cheat table and pointer paths. The CLI and the GUI are views on it.
class Session {
public:
    explicit Session(std::shared_ptr<hal::IProcess> process = hal::IProcess::create(),
                     std::unique_ptr<hal::IHotkeys> hotkeys = hal::IHotkeys::create());

    struct AttachReport {
        bool ok{false};
        bool read_only{false};  // writing and freezing won't work
        size_t unfrozen{0};     // absolute table entries that belonged to the previous process
        std::string table_note; // what the table library did, or empty
        std::vector<TableKeeper::ReconcileLine> reconciled;
    };
    // Attaches, starts a fresh search, drops the old noise map and re-finds permanent table entries.
    // Learning the noise of the new process is separate (learn_noise / set_noise), as it takes seconds.
    AttachReport attach(uint32_t pid);
    void detach();

    [[nodiscard]] bool attached() const { return m_process->is_attached(); }
    [[nodiscard]] bool exited() const { return m_process->get_pid() != 0 && !m_process->is_attached(); }
    // After the target exited: a new process of the same program, if one is running
    [[nodiscard]] std::optional<hal::ProcessInfo> find_restart() const;

    // Slow (samples for seconds): may run on a worker thread, then set_noise() applies it
    [[nodiscard]] std::shared_ptr<scanner::NoiseMap> learn_noise(const scanner::NoiseOptions& options = {},
                                                                 const std::atomic<bool>* stop = nullptr) const;
    void set_noise(std::shared_ptr<scanner::NoiseMap> noise); // nullptr: stop ignoring noise
    [[nodiscard]] std::string describe_noise() const;
    [[nodiscard]] const std::shared_ptr<scanner::NoiseMap>& noise() const { return m_noise; }

    // Reads the view again, with the target's modules and noise (keeps the last values when not attached)
    void refresh(view::MemoryView& view);

    [[nodiscard]] std::unique_ptr<scanner::ValueTracker> new_tracker(std::vector<scanner::DataType> types) const;
    [[nodiscard]] std::vector<scanner::PointerPath> find_permanent_paths(const table::TableEntry& entry);

    [[nodiscard]] hal::IProcess& process() { return *m_process; }
    [[nodiscard]] const std::shared_ptr<hal::IProcess>& process_ptr() const { return m_process; }
    [[nodiscard]] ScanSession& scans() { return m_scans; }
    [[nodiscard]] TableKeeper& table() { return *m_table; }
    [[nodiscard]] std::vector<scanner::PointerPath>& pointer_paths() { return m_pointer_paths; }

private:
    std::shared_ptr<hal::IProcess> m_process;
    std::shared_ptr<scanner::MemoryScanner> m_scanner;
    std::shared_ptr<scanner::NoiseMap> m_noise;
    ScanSession m_scans;
    std::unique_ptr<TableKeeper> m_table;
    std::vector<scanner::PointerPath> m_pointer_paths; // kept across attach: module-relative, meant for the next run
};

} // namespace nce::session
