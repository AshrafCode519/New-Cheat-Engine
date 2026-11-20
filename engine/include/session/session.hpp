#pragma once

#include "scan_session.hpp"
#include "../hal/process.hpp"
#include "../scanner/noise_map.hpp"
#include "../scanner/pointer_scanner.hpp"
#include "../scanner/value_tracker.hpp"
#include "../table/cheat_table.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace nce::session {

// The cheat table, shared with a thread that keeps frozen entries at their values. Every access goes
// through this class, which holds the lock (with() for anything the operations below don't cover).
class TableKeeper {
public:
    explicit TableKeeper(std::shared_ptr<hal::IProcess> process);
    ~TableKeeper();
    TableKeeper(const TableKeeper&) = delete;
    TableKeeper& operator=(const TableKeeper&) = delete;

    // Runs fn(table, modules) under the lock
    template <typename Fn>
    decltype(auto) with(Fn&& fn) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return fn(m_table, std::as_const(m_modules));
    }

    // Swaps the process under the lock, so the freeze thread never writes into the new process with the
    // old process' addresses: absolute entries are unfrozen first. Returns how many were unfrozen.
    size_t attach(uint32_t pid, bool& attached);
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

private:
    void freeze_loop();
    [[nodiscard]] bool valid(size_t index) const { return index < m_table.entries.size(); }

    std::shared_ptr<hal::IProcess> m_process;
    std::mutex m_mutex;
    table::CheatTable m_table;
    std::vector<hal::ModuleInfo> m_modules;
    std::atomic<bool> m_running{true};
    std::thread m_freeze_thread;
};

// "found at 0x... (3 of 4 paths lead there; ...)", "close vote (...)", "none of its 4 paths resolve here ..."
std::string describe_reconcile(const table::ReconcileResult& result);

// Everything one attached target needs: the process, the scanner with its noise map, the current search,
// the cheat table and pointer paths. The CLI and the GUI are views on it.
class Session {
public:
    explicit Session(std::shared_ptr<hal::IProcess> process = hal::IProcess::create());

    struct AttachReport {
        bool ok{false};
        bool read_only{false};  // writing and freezing won't work
        size_t unfrozen{0};     // absolute table entries that belonged to the previous process
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
