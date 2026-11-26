#pragma once

#include "imgui.h"
#include "imgui_stdlib.h"

#include "session/session.hpp"
#include "view/structure_dissector.hpp"
#include "debugger/access_watcher.hpp"
#include "debugger/disassembler.hpp"
#include "debugger/micro_emulator.hpp"
#include "debugger/protection_inspector.hpp"
#include "debugger/pdb_reader.hpp"
#include "table/standalone_generator.hpp"
#include "view/vector_detector.hpp"
#include "utils/sig_generator.hpp"
#include "utils/hex_utils.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace nce::gui {

// Global hotkeys for smart track, so the user can answer without leaving the game.
enum HotkeyAction { HOTKEY_READY = 1, HOTKEY_DOWN, HOTKEY_UP, HOTKEY_CHANGED };
extern std::vector<int> g_hotkeys_pressed;

#ifdef _WIN32
extern void* g_hwnd_native; // HWND stored cleanly without pulling windows.h into tab headers
#else
extern void* g_sdl_win_native;
#endif

void beep(uint32_t frequency, uint32_t ms);
bool register_hotkeys();
void unregister_hotkeys();

inline const char* const kTypeNames[] = {
    "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "str", "wstr", "aob",
    "i16be", "i32be", "i64be", "f32be", "f64be"
};
inline constexpr int kDefaultType = 2; // i32

const std::vector<const char*>& next_labels();
inline const char* const kFloatModes[] = {"rounded", "truncated", "exact"}; // in FloatMatchMode order

using ApplyResult = std::function<void()>;

enum class Tab {
    Keep,
    PointerScanner,
    Memory,
    MemoryMap,
    Hotkeys,
    Scripts,
    Dissect,
    Watch,
    Disasm,
    Radar,
    Speedhack,
    Diff,
    PETools,
    EngineInspector,
    LuaScript
};

inline const char* const kHotkeyActions[] = {"Toggle freeze", "Set to", "Add"};

struct App {
    // Presses of the table's hotkeys arrive on the hotkey thread and are shown by the UI each frame.
    // Declared before the session, so they outlive its hotkey thread.
    std::mutex hotkey_mutex;
    std::vector<std::pair<std::string, session::Outcome>> hotkey_events;

    session::Session session;
    std::vector<hal::ProcessInfo> processes;
    std::string process_filter;
    int selected_process = -1;
    std::string attached_label;

    int type_index = kDefaultType;
    bool unknown_value = false;
    bool scan_xor_mode = false;
    std::string scan_xor_key = "auto";
    std::string first_value;
    int next_index = 0;
    std::string next_value1;
    std::string next_value2;
    int float_mode = 0;

    std::future<ApplyResult> job;
    std::string job_label;
    std::chrono::steady_clock::time_point job_start;
    std::string status = "Pick a process and attach.";
    bool status_timed = true;

    std::vector<std::string> edit_buffers;
    std::string table_note;
    int editing_row = -1;
    std::string table_path = "table.json";

    enum class TrackStage { Off, Quiet, Changing };
    std::unique_ptr<scanner::ValueTracker> tracker;
    TrackStage track_stage = TrackStage::Off;
    bool track_stop_requested = false;
    bool track_auto_type = true;
    std::vector<scanner::RankedCandidate> track_best;
    size_t track_events = 0;
    std::string track_summary;
    std::string track_value;
    std::chrono::steady_clock::time_point last_quiet;

    std::string ptr_target;
    int ptr_depth = 4;
    uint32_t ptr_offset = 0x800;
    bool ptr_allow_neg = false;
    uint32_t ptr_neg_offset = 0x100;
    std::string ptr_module;
    int ptr_add_type = kDefaultType;

    view::MemoryView memory;
    std::vector<uintptr_t> memory_back;
    std::vector<uintptr_t> memory_forward;
    std::string memory_input;
    std::chrono::steady_clock::time_point memory_refreshed;
    Tab select_tab = Tab::Keep;
    uintptr_t memory_selected_addr = 0;
    int inspector_type_idx = 0;
    std::string inspector_write_buf;
    std::string inspector_status;

    int hotkey_row = 0;
    std::string hotkey_keys;
    int hotkey_action = 0;
    std::string hotkey_value;
    bool hotkey_recording = false;
    std::string hotkey_note;
    bool memory_scroll = false;

    std::string script_name;
    std::string script_body = "[ENABLE]\n\n[DISABLE]\n";
    std::string script_note;
    int editing_script = -1;

    std::string dissect_input;
    int dissect_bytes = 128;
    std::optional<view::StructLayout> dissect_result;
    std::string dissect_note;
    bool dissect_pending = false;
    std::string dissect_compare_input;
    bool dissect_compare_diff_only = false;
    std::optional<view::StructComparison> dissect_compare_result;

    std::string watch_input;
    int watch_size_index = 2;
    std::string watch_note;
    int watch_selected_hit = -1;

    float speedhack_multiplier = 1.0f;
    std::string speedhack_note;

    std::string diff_addr_input;
    int diff_size_bytes = 128;
    view::DiffSummary diff_last_summary;
    std::string diff_status;

    std::string pe_module_input;
    std::optional<debugger::PEInfo> pe_current_info;
    std::optional<debugger::ELFInfo> elf_current_info;
    std::string pe_status;

    view::EngineDetection engine_detection;
    std::string unity_meta_path = "global-metadata.dat";
    std::string unity_filter;
    std::optional<view::UnityMetadataReport> unity_report;
    std::string unreal_gnames_input;
    std::string unreal_gobjects_input;
    std::string unreal_filter;
    std::string unreal_uworld_input;
    std::string unity_obj_input;
    std::vector<view::UnrealNameEntry> unreal_names;
    std::vector<view::UnrealObjectInfo> unreal_objects;
    std::vector<view::UnrealActorInfo> unreal_actors;
    std::optional<view::StructLayout> engine_dissected_obj;
    std::string engine_status;

    std::string disasm_input;
    int disasm_count = 15;
    int disasm_view_mode = 0; // 0: List, 1: CFG, 2: Ultimap, 3: Pseudo-C, 4: Causality, 5: Micro-Emu/Taint
    std::optional<debugger::ControlFlowGraph> disasm_cfg;
    std::string ultimap_module_filter;
    std::vector<debugger::UltimapFunction> ultimap_candidates;
    std::vector<debugger::DecodedInstruction> disasm_instructions;
    std::vector<uintptr_t> disasm_back;
    int disasm_selected_row = -1;
    std::string disasm_asm_input;
    std::string disasm_note;
    std::string dbg_status_note;
    int dbg_backend_index = 0;
    std::string bp_condition_input;
    bool bp_trace_mode = false;

    bool dissect_live_update = true;
    std::vector<uintptr_t> dissect_history;
    std::map<uintptr_t, view::StructLayout> dissect_children;
    std::set<uintptr_t> dissect_expanded;
    float cfg_zoom = 1.0f;
    float cfg_pan_x = 0.0f;
    float cfg_pan_y = 0.0f;
    bool radar_plot_actors = true;
    bool cmd_palette_open = false;
    std::string cmd_palette_filter;
    std::string ptr_map_path = "pointers.ncem";
    int trace_step_count = 15;
    uintptr_t disasm_xref_target = 0;
    std::vector<debugger::CrossReference> disasm_xrefs;
    std::string mem_map_filter;
    view::UnrealOffsets unreal_offsets;

    int plot_entry_index = -1;
    static constexpr size_t kPlotCapacity = 120;
    float plot_history[kPlotCapacity]{0};
    size_t plot_head = 0;
    size_t plot_count = 0;
    float plot_min = 0.0f;
    float plot_max = 100.0f;
    void push_plot(float val) {
        plot_history[plot_head] = val;
        plot_head = (plot_head + 1) % kPlotCapacity;
        if (plot_count < kPlotCapacity) ++plot_count;
        if (val < plot_min) plot_min = val - 1.0f;
        if (val > plot_max) plot_max = val + 1.0f;
    }

    bool track_pending = false;

    view::VectorDetector vector_detector;
    std::string radar_coord_addr;
    std::string radar_wp_name;
    std::string radar_note;
    int radar_format_idx = 0;
    float radar_zoom = 100.0f;
    std::vector<view::VectorCandidate> radar_candidates;
    std::vector<view::Vector3d> radar_trail;

    bool auto_reattach = true;
    std::chrono::steady_clock::time_point next_reattach_check;
    uint32_t restart_pid = 0;
    std::chrono::steady_clock::time_point restart_seen_at;

    std::string hook_target_input;
    std::string hook_payload_or_dest;
    bool hook_detour_mode = false;
    std::string hook_note;

    std::string lua_script = "-- New Cheat Engine Lua Script\nprint('Hello from Lua 5.4!')\n";
    std::string lua_console_output = "[*] Lua 5.4 ready. Type code or use the REPL bar below.\n";
    std::string lua_repl_input;
    struct LuaWatchItem {
        std::string expr;
        std::string value;
        bool ok{true};
    };
    std::string lua_watch_expr_input;
    std::vector<LuaWatchItem> lua_watches;
    std::chrono::steady_clock::time_point next_lua_watch_eval{};

    std::string remote_host = "127.0.0.1";
    int remote_port = 27055;
    std::string remote_token;
    std::string remote_error;

    std::string decomp_struct_addr;
    std::optional<debugger::DecompiledFunction> decomp_result;
    std::string timeline_watch_addr;

    std::vector<session::Session::HybridModuleInfo> hybrid_modules;
    int anchor_row = -1;
    std::string anchor_code_addr;
    int anchor_struct_offset = 0;
    std::string anchor_error;

    // NCE v3.0: Micro-Emulator, Backward Taint, Stealth/Protection, Local PDB, SDK Dumper & Workspace Theme
    std::string emu_addr_input;
    int emu_steps = 48;
    std::optional<debugger::EmulationResult> emu_result;
    std::string taint_entry_input;
    std::string taint_sink_input;
    std::string taint_reg_input = "rax";
    std::vector<debugger::TaintStep> taint_steps;

    std::optional<debugger::ProtectionReport> prot_report;
    std::string pdb_module_input;
    std::string pdb_path_input;
    std::string pdb_search_input;
    std::string pdb_status;
    std::vector<std::pair<std::string, debugger::PDBSymbol>> pdb_hits;

    std::string sdk_filter;
    std::string sdk_out_path = "SDK.hpp";
    std::string sdk_preview;

    bool workspace_dark_theme = true;
    float workspace_font_scale = 1.0f;
    float dpi_scale = 1.0f;
};

// Common helpers (app_common.cpp)
scanner::DataType type_at(int index);
int type_index_of(scanner::DataType type);
bool is_numeric(scanner::DataType type);
bool is_attached(const App& app);
scanner::FloatMatchMode float_mode(const App& app);
void show(App& app, const session::Outcome& outcome);
bool job_running(const App& app);
float em(float n);
long long elapsed_ms(std::chrono::steady_clock::time_point start);
void start_job(App& app, std::string label, std::function<ApplyResult()> work);
void poll_job(App& app);
void refresh_processes(App& app);
void learn_noise(App& app, const std::string& prefix = "");
std::string describe_reconciled(const std::vector<session::TableKeeper::ReconcileLine>& lines);
void make_entry_permanent(App& app, size_t index);
void attach(App& app, const hal::ProcessInfo& info, const std::string& note = "");
void tick_reattach(App& app);
void first_scan(App& app);
void next_scan(App& app);
void undo(App& app);
void add_result_to_table(App& app, size_t row);
void open_memory(App& app, uintptr_t address, bool remember = true);
void refresh_track(App& app);
void start_tracking(App& app);
void track_event(App& app, const scanner::Expectation& expected);
void stop_tracking(App& app);
void process_hotkeys(App& app);
void tick_tracking(App& app);
void show_table_hotkeys(App& app);

std::filesystem::path workspace_config_path();
void apply_workspace_theme(const App& app);
void load_workspace_config(App& app);
void save_workspace_config(const App& app);

// Tab & main view drawers (gui/src/tabs/*.cpp)
void draw_process_bar(App& app);
void draw_scan_controls(App& app);
void draw_tracking(App& app);
void draw_results(App& app);
void draw_cheat_table(App& app);
void draw_pointer_scanner(App& app);
void draw_memory(App& app);
void draw_hotkeys(App& app);
void draw_scripts(App& app);
void draw_dissect(App& app);
void draw_oscilloscope(App& app);
void draw_watch(App& app);
void draw_disasm(App& app);
void draw_radar(App& app);
void draw_speedhack(App& app);
void draw_diff(App& app);
void draw_pe_tools(App& app);
void draw_engine_inspector(App& app);
void draw_memory_map(App& app);
void draw_lua_studio(App& app);
void draw_ui(App& app);

} // namespace nce::gui
