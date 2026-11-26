#pragma once

#include "scan_session.hpp"
#include "../hal/hotkeys.hpp"
#include "../hal/process.hpp"
#include "../hal/remote_process.hpp"
#include "../scanner/noise_map.hpp"
#include "../scanner/pointer_scanner.hpp"
#include "../scanner/value_tracker.hpp"
#include "../table/cheat_table.hpp"
#include "../view/memory_view.hpp"
#include "../assembler/auto_assembler.hpp"
#include "../debugger/access_watcher.hpp"
#include "../debugger/debug_coordinator.hpp"
#include "../debugger/hook_engine.hpp"
#include "../speedhack/speedhack.hpp"
#include "../view/memory_diff.hpp"
#include "../view/engine_inspector.hpp"
#include "../debugger/pe_analyzer.hpp"
#include "../debugger/elf_analyzer.hpp"
#include "../debugger/ultimap.hpp"
#include "../debugger/step_debugger.hpp"
#include "../debugger/decompiler.hpp"
#include "../debugger/causality_timeline.hpp"
#include "../debugger/micro_emulator.hpp"
#include "../debugger/protection_inspector.hpp"
#include "../debugger/pdb_reader.hpp"
#include "../hal/injector.hpp"
#include "../script/lua_engine.hpp"
#include "../script/plugin_manager.hpp"
#include <atomic>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
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

    struct ReconcileLine {
        size_t index{0};
        std::string description;
        table::ReconcileResult result;
    };
    // Permanent entries find their value in the current process (after a restart)
    std::vector<ReconcileLine> reconcile();

    struct AttachResult {
        bool attached{false};
        size_t unfrozen{0};     // absolute entries that belonged to the previous process
        std::string table_note; // what the table library did ("Opened the table of game.exe ..."), or empty
        std::string scripts_note; // which saved-on scripts were re-applied, and which failed
        std::vector<ReconcileLine> reconciled; // permanent entries, found before the freeze thread writes them
    };
    // Swaps the process under the lock, so the freeze thread never writes into the new process with the
    // old process' addresses: absolute entries are unfrozen. With the table library on, attaching to
    // another program saves the table and opens that program's (see set_library).
    AttachResult attach(uint32_t pid);
    void detach();


    Outcome add_result(const scanner::ScanResults& results, size_t index, std::string description);
    Outcome add_address(uintptr_t address, scanner::DataType type, std::string description);
    Outcome add_pointer(const scanner::PointerPath& path, scanner::DataType type, std::string description);
    Outcome set_value(size_t index, const std::string& value);
    Outcome freeze(size_t index, std::optional<std::string> value); // nullopt: keep its current value
    Outcome unfreeze(size_t index);
    size_t unfreeze_all();
    Outcome remove(size_t index);
    Outcome save(const std::string& path);
    // Replaces the table. With the library on, the open table is saved to it first, and while attached the
    // loaded table becomes the attached program's. Its permanent entries are reconciled before the freeze
    // thread can write through their old paths (what was found goes to `reconciled`).
    Outcome load(const std::string& path, std::vector<ReconcileLine>* reconciled = nullptr);

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
    // Tries the table's combos again (after another part of the program let go of some keys)
    void refresh_hotkeys() { rebind(); }

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

    // Auto-Assembler scripts saved in the table and turned on/off like entries (see table::TableScript).
    // Enabling runs the script's [ENABLE]; disabling runs [DISABLE] (or rolls back the recorded bytes).
    // Script names are unique. Scripts marked enabled are re-applied on attach, like freezes resume.
    Outcome add_script(const std::string& name, const std::string& body);
    Outcome set_script_body(size_t index, const std::string& body); // disables it first if it was on
    Outcome set_script_enabled(size_t index, bool on);
    Outcome remove_script(size_t index); // disables it first if it was on
    void set_process(std::shared_ptr<hal::IProcess> process);
    [[nodiscard]] std::optional<table::TableScript> script(size_t index);
    [[nodiscard]] size_t script_count();
    void set_lua_runner(assembler::AutoAssembler::LuaRunner runner);
    [[nodiscard]] std::string lua_script();
    void set_lua_script(std::string script);

private:
    void freeze_loop();
    Outcome apply_hotkey(table::TableEntry& entry, const table::Hotkey& hotkey); // with the lock held
    void rebind(); // registers the table's combos again; never with the lock held (see the .cpp)
    [[nodiscard]] std::filesystem::path library_file_locked(const std::string& program) const;
    std::string switch_table_locked(const std::string& program, bool& changed); // with both locks held
    std::vector<ReconcileLine> reconcile_locked();
    Outcome autosave(bool force);
    Outcome autosave_saving(bool force); // with m_save_mutex held
    Outcome set_script_enabled_locked(size_t index, bool on); // with m_mutex held
    std::string reapply_scripts_locked(); // on attach: re-enable the scripts marked enabled, report failures
    [[nodiscard]] bool valid(size_t index) const { return index < m_table.entries.size(); }
    [[nodiscard]] bool valid_script(size_t index) const { return index < m_table.scripts.size(); }

    std::shared_ptr<hal::IProcess> m_process;
    std::mutex m_mutex;
    table::CheatTable m_table;
    std::vector<hal::ModuleInfo> m_modules;
    std::atomic<bool> m_running{true};

    std::unique_ptr<hal::IHotkeys> m_hotkeys;
    std::mutex m_rebind_mutex;       // one rebind at a time, so the last table state wins
    std::vector<std::string> m_taken; // guarded by m_mutex
    std::mutex m_listener_mutex;
    std::function<void(const std::string&, const Outcome&)> m_listener;

    // Taken before m_mutex by everything that writes library files, so two writes never meet
    std::mutex m_save_mutex;
    std::filesystem::path m_library; // guarded by m_mutex
    std::string m_saved_text;        // the open table as last saved to the library (guarded by m_mutex)

    // Auto-Assembler scripts: the assembler (remade on attach) and what each running script changed, by name
    std::unique_ptr<assembler::AutoAssembler> m_assembler; // guarded by m_mutex
    std::map<std::string, assembler::ScriptEffect> m_active; // guarded by m_mutex
    assembler::AutoAssembler::LuaRunner m_lua_runner; // guarded by m_mutex

    std::thread m_freeze_thread; // last: it starts once every member above exists
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
        std::string scripts_note; // which saved-on Auto-Assembler scripts were re-applied, or empty
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

    // "Find what writes/accesses this address": hardware breakpoints (DR0-DR3) or stealth GuardPage watches,
    // supporting both local DebugCoordinator and remote NCE3 sessions.
    bool watch(uintptr_t address, size_t size, debugger::WatchKind kind);
    void stop_watch();
    void stop_watch_address(uintptr_t address);
    [[nodiscard]] bool watching() const;
    [[nodiscard]] uintptr_t watched_address() const;
    [[nodiscard]] std::vector<uintptr_t> watched_addresses() const;
    [[nodiscard]] std::vector<debugger::AccessHit> watch_hits() const;

    // Speedhack: dilates time inside the attached process (QPC and GetTickCount64)
    bool set_speed(double multiplier);
    bool enable_speedhack();
    bool disable_speedhack();
    [[nodiscard]] bool speedhack_installed() const;
    [[nodiscard]] bool speedhack_enabled() const;
    [[nodiscard]] double speedhack_speed() const;
    [[nodiscard]] speedhack::Speedhack* speedhack() { return m_speedhack.get(); }
    [[nodiscard]] const speedhack::Speedhack* speedhack() const { return m_speedhack.get(); }

    // Memory snapshot diffing
    bool diff_snapshot_a(uintptr_t address, size_t size);
    bool diff_snapshot_b();
    [[nodiscard]] view::DiffSummary diff_compare() const;
    [[nodiscard]] const view::MemoryDiff& memory_diff() const { return m_diff; }
    void diff_clear() { m_diff.clear(); }

    // PE & ELF Header / Module analysis
    [[nodiscard]] std::optional<debugger::PEInfo> analyze_module(const std::string& module_name);
    [[nodiscard]] std::optional<debugger::PEInfo> analyze_pe(uintptr_t base_address);
    [[nodiscard]] std::optional<debugger::ELFInfo> analyze_module_elf(const std::string& module_name);
    [[nodiscard]] std::optional<debugger::ELFInfo> analyze_elf(uintptr_t base_address);

    // Game Engine Inspectors (Unity Mono/IL2CPP & Unreal Engine GNames/GObjects)
    [[nodiscard]] view::EngineDetection detect_game_engine() const;
    [[nodiscard]] view::UnityMetadataReport inspect_unity_metadata(
        const std::string& file_path, const std::string& filter = "", size_t max_types = 512) const;
    [[nodiscard]] std::vector<view::UnrealNameEntry> scan_unreal_names(
        uintptr_t fname_pool_addr, const view::UnrealOffsets& offsets = {},
        uint32_t max_blocks = 8, size_t max_names = 2048) const;
    [[nodiscard]] std::vector<view::UnrealObjectInfo> dump_unreal_objects(
        uintptr_t guobject_array_addr, uintptr_t fname_pool_addr,
        const view::UnrealOffsets& offsets = {}, const std::string& filter = "",
        size_t max_objects = 1024) const;
    [[nodiscard]] view::UnityMetadataReport inspect_unity_metadata_memory(
        uintptr_t metadata_addr = 0, const std::string& filter = "", size_t max_types = 512) const;
    [[nodiscard]] view::StructLayout dissect_unity_object(
        uintptr_t obj_addr, const view::Il2CppClassOffsets& offsets = {}) const;
    [[nodiscard]] view::UnrealGlobalsResult find_unreal_globals(uintptr_t module_base = 0) const;
    [[nodiscard]] view::StructLayout dissect_unreal_object(
        uintptr_t uobject_addr, uintptr_t fname_pool_addr, const view::UnrealOffsets& offsets = {}) const;
    [[nodiscard]] std::vector<view::UnrealActorInfo> dump_unreal_actors(
        uintptr_t uworld_addr, uintptr_t fname_pool_addr,
        const view::UnrealOffsets& offsets = {}, size_t max_actors = 512) const;

    // Disassembler Control-Flow Graph (CFG) & Ultimap Code Execution Profiler
    [[nodiscard]] debugger::ControlFlowGraph build_cfg(
        uintptr_t entry_address, size_t max_insns = 256, size_t max_blocks = 48) const;
    [[nodiscard]] debugger::UltimapProfiler& ultimap() { return m_ultimap; }
    [[nodiscard]] const debugger::UltimapProfiler& ultimap() const { return m_ultimap; }

    // One-click AOB Code-Cave script generation
    [[nodiscard]] std::string generate_aob_hook_script(
        uintptr_t address, const std::string& label_name = "INJECT", size_t min_bytes = 5) const;

    // Cross-references (calls / jumps / RIP-rel references targeting `target_address`)
    [[nodiscard]] std::vector<debugger::CrossReference> find_references(
        uintptr_t target_address, uintptr_t module_base = 0, size_t max_results = 256) const;

    // Unreal Engine offset auto-calibration & binary PointerMap compare
    [[nodiscard]] view::UnrealCalibrationResult calibrate_unreal_offsets(
        uintptr_t world_or_actor_addr, uintptr_t fname_pool_addr, const view::UnrealOffsets& seed = {}) const;
    bool build_and_save_pointer_map(const std::string& path) const;
    [[nodiscard]] scanner::PointerScanResult scan_saved_pointer_map(
        const std::string& map_path, uintptr_t target_address, const scanner::PointerScanOptions& opts = {}) const;

    // Interactive step debugger (Win32 Debug API & VEH backends, conditional BPs & tracepoints)
    bool dbg_attach(debugger::DebugBackend backend = debugger::DebugBackend::Win32DebugAPI);
    void dbg_detach();
    bool dbg_set_bp(uintptr_t addr, const std::string& note = "", const std::string& condition = "", bool is_tracepoint = false);
    bool dbg_remove_bp(uintptr_t addr);
    bool dbg_resume();
    bool dbg_pause();
    bool dbg_step_into();
    bool dbg_step_over();
    bool dbg_step_out();
    [[nodiscard]] debugger::StepDebugger* step_debugger() { return m_debugger.get(); }
    [[nodiscard]] const debugger::StepDebugger* step_debugger() const { return m_debugger.get(); }
    [[nodiscard]] debugger::DebugCoordinator* debug_coordinator() { return m_debug_coordinator.get(); }

    // Hook Engine (live code caves, detours, inline payload hooks)
    [[nodiscard]] debugger::HookEngine* hook_engine() { return m_hook_engine.get(); }
    [[nodiscard]] const debugger::HookEngine* hook_engine() const { return m_hook_engine.get(); }
    std::optional<debugger::HookInfo> hook_detour(uintptr_t target, uintptr_t destination);
    std::optional<debugger::HookInfo> hook_payload(uintptr_t target, const std::vector<uint8_t>& payload);
    bool unhook(uintptr_t target);
    void unhook_all();
    [[nodiscard]] std::vector<debugger::HookInfo> active_hooks() const;

    // Threads & DLL injection utilities
    [[nodiscard]] std::vector<hal::ThreadInfo> list_threads() const;
    bool inject_dll(const std::string& dll_path, std::string& error_out);

    // Symbol lookup & Disassembly annotation (DbgHelp PDB when debugged + PE Exports fallback)
    [[nodiscard]] std::string resolve_symbol(uintptr_t address) const;
    void annotate_disassembly(std::vector<debugger::DecodedInstruction>& instructions) const;

    // Embedded Lua Scripting Engine
    script::ScriptResult run_lua(const std::string& code);
    script::ScriptResult run_lua_file(const std::string& filepath);
    script::ScriptResult eval_lua_expression(const std::string& expr);
    Outcome run_table_lua_script();
    void reset_lua();
    [[nodiscard]] script::LuaEngine* lua_engine() { return m_lua.get(); }
    [[nodiscard]] const script::LuaEngine* lua_engine() const { return m_lua.get(); }

    // Remote Target Server connectivity (nce_server / RemoteProcess)
    Outcome connect_remote(const std::string& host, uint16_t port, const std::string& auth_token = "");
    void disconnect_remote();
    [[nodiscard]] bool is_remote() const noexcept { return m_remote != nullptr; }
    [[nodiscard]] std::string remote_endpoint() const;
    [[nodiscard]] std::vector<hal::ProcessInfo> list_processes() const;

    // Pseudo-C Decompiler & Execution Causality Timeline
    [[nodiscard]] debugger::DecompiledFunction decompile_function(
        uintptr_t entry_address, uintptr_t struct_address = 0, size_t max_insns = 256) const;
    [[nodiscard]] debugger::CausalityTimeline& timeline() { return m_timeline; }
    [[nodiscard]] const debugger::CausalityTimeline& timeline() const { return m_timeline; }
    size_t capture_timeline_from_trace(uintptr_t watch_address = 0, size_t watch_bytes_len = 64);
    size_t capture_timeline_from_watch(uintptr_t watch_address = 0, size_t watch_bytes_len = 64);

    // Hybrid PE + ELF module inspection (including Wine/Proton mapped PE modules on Linux)
    struct HybridModuleInfo {
        std::string name;
        std::string path;
        uintptr_t base_address{0};
        size_t size{0};
        std::string format; // "PE", "ELF", or "Unknown"
        bool is_64bit{false};
        size_t export_or_symbol_count{0};
        bool has_dwarf{false};
    };
    [[nodiscard]] std::vector<HybridModuleInfo> inspect_hybrid_modules() const;
    [[nodiscard]] bool is_proton_or_wine() const;

    // NCE v3.0: Micro-Emulator, Taint Slicer, Stealth/Protection Inspector, Local PDB, SDK Dumper, Plugins
    [[nodiscard]] debugger::EmulationResult emulate_code(
        uintptr_t entry_rip,
        const debugger::Registers& regs = {},
        size_t max_steps = 64,
        const std::vector<debugger::MemWritePatch>& patches = {}) const;
    [[nodiscard]] debugger::EmulationResult dry_run_hook(
        uintptr_t target_address,
        const std::vector<uint8_t>& cave_code,
        uintptr_t cave_address,
        const debugger::Registers& regs = {},
        size_t max_steps = 64) const;
    [[nodiscard]] std::vector<debugger::TaintStep> trace_backward_taint(
        uintptr_t entry_address,
        uintptr_t sink_address,
        const std::string& reg_name) const;
    [[nodiscard]] debugger::ProtectionReport inspect_protections() const;

    bool load_pdb(const std::string& module_name_or_base, const std::string& pdb_path, std::string& out_msg);
    [[nodiscard]] std::vector<std::pair<std::string, debugger::PDBSymbol>> search_pdb_symbols(
        const std::string& query, size_t max_results = 64) const;

    [[nodiscard]] std::string dump_sdk_header(const std::string& filter = "", size_t max_classes = 256) const;
    [[nodiscard]] bool remote_encrypted() const noexcept;
    [[nodiscard]] std::optional<hal::RemoteDebugState> remote_debug_state() const;

    [[nodiscard]] script::PluginManager& plugins() { return *m_plugins; }
    [[nodiscard]] const script::PluginManager& plugins() const { return *m_plugins; }

    // AOB Self-Healing Table anchors & migration
    Outcome anchor_entry_signature(size_t index, uintptr_t code_address, int64_t struct_offset = 0);
    table::SignatureMigrationReport migrate_table_signatures();

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
    debugger::AccessWatcher m_watcher;
    std::shared_ptr<debugger::DebugCoordinator> m_debug_coordinator;
    std::unique_ptr<speedhack::Speedhack> m_speedhack;
    view::MemoryDiff m_diff;
    std::unique_ptr<debugger::StepDebugger> m_debugger;
    std::unique_ptr<debugger::HookEngine> m_hook_engine;
    std::unique_ptr<script::LuaEngine> m_lua;
    std::unique_ptr<script::PluginManager> m_plugins;
    mutable std::map<uintptr_t, debugger::PEInfo> m_pe_cache;
    mutable std::map<uintptr_t, debugger::ELFInfo> m_elf_cache;
    mutable std::map<uintptr_t, debugger::PDBReader> m_pdb_cache;
    mutable std::set<uintptr_t> m_pdb_probed;
    debugger::UltimapProfiler m_ultimap;
    debugger::CausalityTimeline m_timeline;
    std::shared_ptr<hal::RemoteProcess> m_remote;
    bool m_remote_watching{false};
    uintptr_t m_remote_watch_addr{0};
    bool m_remote_speed_on{false};
    double m_remote_speed{1.0};
    mutable std::mutex m_sym_mutex;
};

} // namespace nce::session
