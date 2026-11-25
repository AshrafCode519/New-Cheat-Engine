// New Cheat Engine - graphical front end (Dear ImGui on Win32 + Direct3D 11).
// Long operations (scans, pointer scans) run on a worker thread; their results are applied on the
// UI thread once they finish, and the scan controls are disabled meanwhile.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <d3d11.h>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "imgui_stdlib.h"

#include "session/session.hpp"
#include "view/structure_dissector.hpp"
#include "debugger/access_watcher.hpp"
#include "debugger/disassembler.hpp"
#include "table/standalone_generator.hpp"
#include "view/vector_detector.hpp"
#include "utils/sig_generator.hpp"
#include "utils/hex_utils.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
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

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

using namespace nce;

namespace {

// ---- Direct3D 11 setup (as in the Dear ImGui Win32 + DX11 example) ------------------------------

ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_device_context = nullptr;
IDXGISwapChain* g_swap_chain = nullptr;
ID3D11RenderTargetView* g_render_target = nullptr;
bool g_swap_chain_occluded = false;
UINT g_resize_width = 0;
UINT g_resize_height = 0;

void create_render_target() {
    ID3D11Texture2D* back_buffer = nullptr;
    g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
    g_device->CreateRenderTargetView(back_buffer, nullptr, &g_render_target);
    back_buffer->Release();
}

void cleanup_render_target() {
    if (g_render_target) {
        g_render_target->Release();
        g_render_target = nullptr;
    }
}

bool create_device(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL level;
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
                                                D3D11_SDK_VERSION, &sd, &g_swap_chain, &g_device, &level, &g_device_context);
    if (res == DXGI_ERROR_UNSUPPORTED) { // no GPU driver: fall back to the software rasterizer
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2,
                                            D3D11_SDK_VERSION, &sd, &g_swap_chain, &g_device, &level, &g_device_context);
    }
    if (res != S_OK) return false;

    create_render_target();
    return true;
}

void cleanup_device() {
    cleanup_render_target();
    if (g_swap_chain) { g_swap_chain->Release(); g_swap_chain = nullptr; }
    if (g_device_context) { g_device_context->Release(); g_device_context = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

// Global hotkeys for smart track, so the user can answer without leaving the game. Each action has a
// numpad key and a Ctrl+Shift+digit alternative (for keyboards without a numpad).
enum HotkeyAction { HOTKEY_READY = 1, HOTKEY_DOWN, HOTKEY_UP, HOTKEY_CHANGED };
HWND g_window = nullptr;
std::vector<int> g_hotkeys_pressed; // filled by window_proc, drained by the main loop (same thread)

bool register_hotkeys() {
    const UINT numpad[] = {VK_NUMPAD0, VK_SUBTRACT, VK_ADD, VK_MULTIPLY};
    bool ok = true;
    for (int action = HOTKEY_READY; action <= HOTKEY_CHANGED; ++action) {
        ok &= RegisterHotKey(g_window, action, MOD_NOREPEAT, numpad[action - 1]) != FALSE;
        ok &= RegisterHotKey(g_window, action + 10, MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT, '0' + action) != FALSE;
    }
    return ok;
}

void unregister_hotkeys() {
    for (int action = HOTKEY_READY; action <= HOTKEY_CHANGED; ++action) {
        UnregisterHotKey(g_window, action);
        UnregisterHotKey(g_window, action + 10);
    }
}

// Audible feedback: the game is in front, so the window can't show anything
void beep(DWORD frequency, DWORD ms) {
    std::thread([frequency, ms] { Beep(frequency, ms); }).detach();
}

LRESULT WINAPI window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam)) return true;

    switch (msg) {
        case WM_HOTKEY:
            g_hotkeys_pressed.push_back(static_cast<int>(wparam) % 10);
            return 0;
        case WM_SIZE:
            if (wparam == SIZE_MINIMIZED) return 0;
            g_resize_width = LOWORD(lparam);
            g_resize_height = HIWORD(lparam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wparam & 0xfff0) == SC_KEYMENU) return 0; // no ALT application menu
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

// ---- Application state ---------------------------------------------------------------------------

const char* const kTypeNames[] = {
    "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "str", "wstr", "aob",
    "i16be", "i32be", "i64be", "f32be", "f64be"
};
constexpr int kDefaultType = 2; // i32

const std::vector<const char*>& next_labels() {
    static const std::vector<const char*> labels = [] {
        std::vector<const char*> list;
        for (const auto& c : session::ScanSession::next_conditions()) list.push_back(c.label);
        return list;
    }();
    return labels;
}

const char* const kFloatModes[] = {"rounded", "truncated", "exact"}; // in FloatMatchMode order

// A finished job hands back the step that applies its result on the UI thread
using ApplyResult = std::function<void()>;

enum class Tab { Keep, PointerScanner, Memory, MemoryMap, Hotkeys, Scripts, Dissect, Watch, Disasm, Radar, Speedhack, Diff, PETools, EngineInspector, LuaScript }; // Keep: leave the tab the user chose

const char* const kHotkeyActions[] = {"Toggle freeze", "Set to", "Add"}; // in table::Hotkey::Action order

struct App {
    // Presses of the table's hotkeys arrive on the hotkey thread and are shown by the UI each frame.
    // Declared before the session, so they outlive its hotkey thread.
    std::mutex hotkey_mutex;
    std::vector<std::pair<std::string, session::Outcome>> hotkey_events;

    // The target, its search, noise map, cheat table (with the freeze and hotkey threads) and pointer
    // paths. Scans run as jobs on a worker thread, and the UI doesn't touch the search while one runs.
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
    bool status_timed = true; // a finished job adds its time to the status, unless it failed

    std::vector<std::string> edit_buffers; // per-entry value text while typing
    std::string table_note;                // what reconciling permanent entries found after attach / load
    int editing_row = -1;
    std::string table_path = "table.json";

    // Smart track: guided unknown-value search that ranks candidates. The tracker is only touched by
    // jobs; the UI draws the copy of the best candidates taken after each observation.
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

    // Memory tab: the memory around an address, each 4 bytes read as what they most likely are
    view::MemoryView memory;
    std::vector<uintptr_t> memory_back;        // where Back returns to after following pointers
    std::vector<uintptr_t> memory_forward;     // where Forward returns to after Back
    std::string memory_input;
    std::chrono::steady_clock::time_point memory_refreshed;
    Tab select_tab = Tab::Keep;                // switch to this tab on this frame
    uintptr_t memory_selected_addr = 0;        // currently selected address in hex view
    int inspector_type_idx = 0;                // data inspector write type index
    std::string inspector_write_buf;           // data inspector write value text
    std::string inspector_status;              // data inspector status feedback

    // Hotkeys tab: the hotkey being made
    int hotkey_row = 0;
    std::string hotkey_keys;
    int hotkey_action = 0;
    std::string hotkey_value;
    bool hotkey_recording = false; // the next key pressed in this window becomes hotkey_keys
    std::string hotkey_note;
    bool memory_scroll = false;         // scroll the opened address into view when its row is drawn

    // Scripts tab: the script being written
    std::string script_name;
    std::string script_body =
        "[ENABLE]\n\n[DISABLE]\n";
    std::string script_note;
    int editing_script = -1; // the row whose body is loaded in the editor, or -1

    // Dissect tab: the object being read as a struct
    std::string dissect_input;
    int dissect_bytes = 128;
    std::optional<view::StructLayout> dissect_result;
    std::string dissect_note;
    bool dissect_pending = false; // run the dissection once, next frame it's attached (for --view + --tab dissect)
    std::string dissect_compare_input;
    bool dissect_compare_diff_only = false;
    std::optional<view::StructComparison> dissect_compare_result;

    // Watch tab: "find what writes/accesses an address"
    std::string watch_input;
    int watch_size_index = 2; // 1/2/4/8 -> index into {1,2,4,8}
    std::string watch_note;
    int watch_selected_hit = -1;

    // Speedhack tab
    float speedhack_multiplier = 1.0f;
    std::string speedhack_note;

    // Memory Diff tab
    std::string diff_addr_input;
    int diff_size_bytes = 128;
    view::DiffSummary diff_last_summary;
    std::string diff_status;

    // PE & ELF Tools tab
    std::string pe_module_input;
    std::optional<debugger::PEInfo> pe_current_info;
    std::optional<debugger::ELFInfo> elf_current_info;
    std::string pe_status;

    // Engine Inspector tab (Unity / Unreal)
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

    // Disasm tab: interactive disassembly, CFG & Ultimap profiler
    std::string disasm_input;
    int disasm_count = 15;
    int disasm_view_mode = 0; // 0: List, 1: Control-Flow Graph (CFG), 2: Ultimap Profiler
    std::optional<debugger::ControlFlowGraph> disasm_cfg;
    std::string ultimap_module_filter;
    std::vector<debugger::UltimapFunction> ultimap_candidates;
    std::vector<debugger::DecodedInstruction> disasm_instructions;
    std::vector<uintptr_t> disasm_back;
    int disasm_selected_row = -1;
    std::string disasm_asm_input;
    std::string disasm_note;
    std::string dbg_status_note;
    int dbg_backend_index = 0; // 0: Win32 Debug API, 1: VEH In-Process
    std::string bp_condition_input;
    bool bp_trace_mode = false;

    // Dissect studio controls
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

    // Live Value Oscilloscope
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

    bool track_pending = false; // --track: start once the noise is learned

    // 3D Radar & Coordinates
    view::VectorDetector vector_detector;
    std::string radar_coord_addr;
    std::string radar_wp_name;
    std::string radar_note;
    int radar_format_idx = 0; // 0: Float x3 (12B), 1: Double x3 UE5 (24B)
    float radar_zoom = 100.0f;
    std::vector<view::VectorCandidate> radar_candidates;
    std::vector<view::Vector3d> radar_trail;

    // When the target exits, wait for the same program to start again and attach to it
    bool auto_reattach = true;
    std::chrono::steady_clock::time_point next_reattach_check;
    uint32_t restart_pid = 0;                              // the new process, once seen
    std::chrono::steady_clock::time_point restart_seen_at; // attach a few seconds later, once it has set up

    // Hook Engine (Scripts tab)
    std::string hook_target_input;
    std::string hook_payload_or_dest;
    bool hook_detour_mode = false;
    std::string hook_note;

    // Lua Scripting Studio
    std::string lua_script = "-- New Cheat Engine Lua Script\nprint('Hello from Lua 5.4!')\n";
    std::string lua_console_output = "[*] Lua 5.4 ready. Type code and click 'Run Script'.\n";
};

scanner::DataType type_at(int index) {
    return *utils::parse_data_type(kTypeNames[index]);
}

int type_index_of(scanner::DataType type) {
    for (int i = 0; i < IM_ARRAYSIZE(kTypeNames); ++i) {
        if (type_at(i) == type) return i;
    }
    return kDefaultType;
}

bool is_numeric(scanner::DataType type) {
    return scanner::dispatch_numeric(type, []<typename T>() {});
}

bool is_attached(const App& app) {
    return app.session.attached();
}

scanner::FloatMatchMode float_mode(const App& app) {
    return static_cast<scanner::FloatMatchMode>(app.float_mode);
}

// What a table or scan operation did, as the status line
void show(App& app, const session::Outcome& outcome) {
    app.status = outcome.message;
    app.status_timed = outcome.ok;
}

bool job_running(const App& app) {
    return app.job.valid();
}

// Sizes in multiples of the font height, so the layout follows the screen's DPI scale
float em(float n) {
    return ImGui::GetFontSize() * n;
}

long long elapsed_ms(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
}

void start_job(App& app, std::string label, std::function<ApplyResult()> work) {
    app.job_label = std::move(label);
    app.job_start = std::chrono::steady_clock::now();
    app.job = std::async(std::launch::async, std::move(work));
}

void poll_job(App& app) {
    if (!app.job.valid() || app.job.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;

    const long long ms = elapsed_ms(app.job_start);
    try {
        auto apply = app.job.get();
        app.status_timed = true;
        apply();
        if (app.status_timed) app.status += " (" + std::to_string(ms) + " ms)";
    } catch (const std::exception& e) {
        app.status = app.job_label + " failed: " + e.what() + ". Use Undo to go back.";
    }
}

// ---- Actions -------------------------------------------------------------------------------------

void refresh_processes(App& app) {
    app.processes = hal::IProcess::list_processes();
    std::sort(app.processes.begin(), app.processes.end(), [](const hal::ProcessInfo& a, const hal::ProcessInfo& b) {
        return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
    });
    app.selected_process = -1;
}

// prefix: status text to keep in front of the result (e.g. what attach reported)
void learn_noise(App& app, const std::string& prefix = "") {
    start_job(app, "Learning noise (leave the target alone)", [&app, prefix]() -> ApplyResult {
        auto noise = app.session.learn_noise();
        return [&app, noise, prefix]() {
            app.session.set_noise(noise);
            app.status = prefix + "Noise: " + app.session.describe_noise() + ".";
        };
    });
}

// What permanent entries found after a restart (see table::reconcile), one line per entry
std::string describe_reconciled(const std::vector<session::TableKeeper::ReconcileLine>& lines) {
    std::string text;
    for (const auto& line : lines) {
        if (!text.empty()) text += "\n";
        text += line.description + ": " + session::describe_reconcile(line.result) + ".";
    }
    return text;
}

// The pointer scan runs as a job on a copy of the entry; applying it fails if the entry changed meanwhile
void make_entry_permanent(App& app, size_t index) {
    const auto entry = app.session.table().entry(index);
    if (!entry) return;
    start_job(app, "Finding pointer paths", [&app, entry = *entry, index]() -> ApplyResult {
        auto paths = std::make_shared<std::vector<scanner::PointerPath>>(app.session.find_permanent_paths(entry));
        return [&app, entry, index, paths]() {
            const auto outcome = app.session.table().make_permanent(index, entry, *paths);
            show(app, outcome);
            if (outcome.ok) app.status += " Save the table.";
        };
    });
}

void attach(App& app, const hal::ProcessInfo& info, const std::string& note = "") {
    app.tracker.reset(); // attaching is disabled while a job runs, so no job is using it
    app.track_stage = App::TrackStage::Off;
    unregister_hotkeys();
    app.track_best.clear();
    app.editing_row = -1;
    app.memory.clear(); // addresses of the previous process
    app.memory_back.clear();

    const auto report = app.session.attach(info.pid);
    app.table_note = describe_reconciled(report.reconciled);
    if (report.ok) {
        app.attached_label = info.name + " (PID " + std::to_string(info.pid) + ", " +
                             std::to_string(app.session.process().pointer_size() * 8) + "-bit)";
        app.status = note + "Attached to " + app.attached_label + ".";
        if (report.unfrozen > 0) {
            app.status += " Unfroze " + std::to_string(report.unfrozen) + " heap entries of the previous process.";
        }
        if (report.read_only) {
            app.status += " Only read access was granted: writing and freezing won't work (run as Administrator).";
        }
        if (!report.table_note.empty()) app.status += " " + report.table_note;
        if (!report.scripts_note.empty()) app.status += " " + report.scripts_note;
        learn_noise(app, app.status + " ");
    } else {
        app.attached_label.clear();
        app.status = "Could not attach to " + info.name + ". Try running as Administrator.";
    }
}

// Every frame: once the target has exited, look for the same program once a second, and attach to a
// new instance a few seconds after it appears (so it has set up the objects the table's pointers use).
// Attaching re-finds permanent entries and the freeze thread resumes on its own.
void tick_reattach(App& app) {
    const std::string name = app.session.process().name();
    if (!app.auto_reattach || job_running(app) || !app.session.exited() || name.empty()) {
        app.restart_pid = 0;
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    if (app.restart_pid != 0) {
        if (now - app.restart_seen_at < std::chrono::seconds(3)) return;
        const uint32_t pid = app.restart_pid;
        app.restart_pid = 0;
        for (const auto& p : hal::IProcess::list_processes()) {
            if (p.pid == pid) {
                attach(app, p, "Re-attached after a restart. ");
                return;
            }
        }
        return; // it went away again; keep looking
    }

    if (now < app.next_reattach_check) return;
    app.next_reattach_check = now + std::chrono::seconds(1);
    if (auto restarted = app.session.find_restart()) {
        app.restart_pid = restarted->pid;
        app.restart_seen_at = now;
        app.status = name + " started again (PID " + std::to_string(restarted->pid) + "); attaching in a moment.";
        return;
    }
    app.status = name + " exited. Waiting for it to start again.";
}

// Scans run on the worker thread: the session checks the input and scans, the UI shows the outcome
void first_scan(App& app) {
    const std::string type = kTypeNames[app.type_index];
    const bool numeric = is_numeric(type_at(app.type_index));
    if (numeric && app.scan_xor_mode && !app.unknown_value) {
        const std::string val = app.first_value;
        const std::string key = app.scan_xor_key.empty() ? "auto" : app.scan_xor_key;
        start_job(app, "XOR Scan", [&app, type, val, key]() -> ApplyResult {
            auto outcome = app.session.scans().first_scan_xor(type, val, key);
            return [&app, outcome]() {
                if (!outcome.ok) return show(app, outcome);
                app.status = "XOR scan: " + app.session.scans().describe() +
                             (outcome.message.empty() ? "" : " (" + outcome.message + ")") + ".";
            };
        });
        return;
    }
    const bool unknown = numeric && app.unknown_value;
    const std::string input = unknown ? "?" : app.first_value;
    start_job(app, unknown ? "Snapshot" : "First scan", [&app, type, input, mode = float_mode(app)]() -> ApplyResult {
        auto outcome = app.session.scans().first_scan(type, input, mode);
        return [&app, outcome]() {
            if (!outcome.ok) return show(app, outcome);
            const auto& scans = app.session.scans();
            app.status = scans.state().snapshot
                ? "Snapshot taken: " + scans.describe() + ". Change the value, then run a next scan."
                : "First scan: " + scans.describe() + (outcome.message.empty() ? "" : ", " + outcome.message) + ".";
        };
    });
}

void next_scan(App& app) {
    const std::string condition = session::ScanSession::next_conditions()[app.next_index].name;
    start_job(app, "Next scan", [&app, condition, v1 = app.next_value1, v2 = app.next_value2,
                                 mode = float_mode(app)]() -> ApplyResult {
        auto outcome = app.session.scans().next_scan(condition, v1, v2, mode);
        return [&app, outcome]() {
            if (!outcome.ok) return show(app, outcome);
            app.status = "Next scan: " + app.session.scans().describe() + " left" +
                         (outcome.message.empty() ? "" : ", " + outcome.message) + ".";
        };
    });
}

void undo(App& app) {
    if (app.session.scans().undo()) app.status = "Back to " + app.session.scans().describe() + ".";
}

void add_result_to_table(App& app, size_t row) {
    show(app, app.session.table().add_result(app.session.scans().state().results, row, ""));
}

// Shows the memory around an address in the Memory tab; remember: Back returns to the one shown now.
// Reads the target's modules under the table lock, so never call it while drawing the table.
void open_memory(App& app, uintptr_t address, bool remember = true) {
    if (address == 0) return;
    if (remember && !app.memory.empty() && app.memory.address() != address) {
        app.memory_back.push_back(app.memory.address());
        app.memory_forward.clear();
    }
    app.memory.set_address(address, 16, 48);
    app.memory_input = utils::format_address(address);
    app.memory_selected_addr = address;
    app.session.refresh(app.memory);
    app.memory_refreshed = std::chrono::steady_clock::now();
    app.select_tab = Tab::Memory;
    app.memory_scroll = true;
}

// ---- Smart track ---------------------------------------------------------------------------------

constexpr size_t TRACK_SHOWN = 50;
constexpr size_t TRACK_MAX_HANDOVER = 5'000'000; // candidates turned into results when tracking stops

// Runs on the UI thread after a tracker job finished
void refresh_track(App& app) {
    app.track_best = app.tracker->top(TRACK_SHOWN);
    app.track_events = app.tracker->events();
    app.track_summary = std::to_string(app.tracker->candidate_count()) + " candidates" +
        (app.tracker->is_ranked() ? ", ranked" : " (snapshot, " + std::to_string(app.tracker->memory_bytes() / 1024) + " KB)");
    app.last_quiet = std::chrono::steady_clock::now();
}

void start_tracking(App& app) {
    // Auto type follows i32, f32 and f64 together and lets the scoring pick the type
    auto types = app.track_auto_type ? scanner::ValueTracker::auto_types()
                                     : std::vector<scanner::DataType>{type_at(app.type_index)};
    app.tracker = app.session.new_tracker(std::move(types)); // ignores the learned noise too
    app.track_best.clear();
    app.track_stop_requested = false;
    start_job(app, "Snapshot", [&app]() -> ApplyResult {
        app.tracker->start();
        return [&app]() {
            refresh_track(app);
            app.track_stage = App::TrackStage::Quiet;
            app.status = "Smart track: " + app.track_summary + ". Leave the value alone, then press \"I'll change it now\".";
            if (!register_hotkeys()) app.status += " Some hotkeys are taken by another program.";
        };
    });
}

void track_event(App& app, const scanner::Expectation& expected) {
    start_job(app, "Checking", [&app, expected]() -> ApplyResult {
        app.tracker->observe_event(expected);
        return [&app]() {
            refresh_track(app);
            app.track_stage = App::TrackStage::Quiet;
            app.status = "Smart track: " + app.track_summary + ". Leave the value alone again.";
            beep(1320, 90); // checked: the user may be in the game
        };
    });
}

void stop_tracking(App& app) {
    if (app.tracker->candidate_count() <= TRACK_MAX_HANDOVER) {
        const auto type = app.tracker->best_type();
        app.session.scans().replace(app.tracker->to_results(), type);
        app.status = "Smart track stopped: " + app.session.scans().describe() + ", best first.";
    } else {
        app.status = "Smart track stopped with too many candidates to list; change the value a few times next time.";
    }
    app.tracker.reset();
    app.track_stage = App::TrackStage::Off;
    app.track_best.clear();
    app.track_stop_requested = false;
    unregister_hotkeys();
    app.session.table().refresh_hotkeys(); // table keys smart track was holding can fire again
}

// Hotkeys pressed while the game was in front: Num0 "I'll change it", then Num- / Num+ / Num* once changed
void process_hotkeys(App& app) {
    using Kind = scanner::Expectation::Kind;
    size_t handled = 0;
    for (; handled < g_hotkeys_pressed.size(); ++handled) {
        if (job_running(app)) break; // keep the rest for a later frame
        const int action = g_hotkeys_pressed[handled];
        if (app.track_stage == App::TrackStage::Off) continue;

        if (action == HOTKEY_READY) {
            if (app.track_stage == App::TrackStage::Quiet) {
                app.track_stage = App::TrackStage::Changing;
                app.status = "Smart track: change the value, then press Num- / Num+ / Num*.";
                beep(880, 80);
            }
        } else if (app.track_stage != App::TrackStage::Changing) {
            beep(220, 200); // press Num0 before changing the value, or the change counts as noise
        } else {
            track_event(app, {action == HOTKEY_DOWN ? Kind::Decreased : action == HOTKEY_UP ? Kind::Increased : Kind::Changed});
        }
    }
    g_hotkeys_pressed.erase(g_hotkeys_pressed.begin(), g_hotkeys_pressed.begin() + static_cast<std::ptrdiff_t>(handled));
}

// Every frame: while the user leaves the value alone, keep watching for values that change on their own
void tick_tracking(App& app) {
    if (app.track_pending && !job_running(app)) {
        app.track_pending = false;
        start_tracking(app);
        return;
    }
    if (app.track_stage == App::TrackStage::Off || job_running(app)) return;
    if (app.track_stop_requested) {
        stop_tracking(app);
        return;
    }
    if (app.track_stage != App::TrackStage::Quiet || elapsed_ms(app.last_quiet) < 500) return;

    start_job(app, "Watching", [&app]() -> ApplyResult {
        app.tracker->observe_quiet();
        return [&app]() {
            refresh_track(app);
            app.status = "Smart track: watching for values that change on their own - " + app.track_summary + ".";
        };
    });
}

// ---- Panels --------------------------------------------------------------------------------------

void draw_process_bar(App& app) {
    if (app.processes.empty()) refresh_processes(app);

    ImGui::BeginDisabled(job_running(app));
    if (ImGui::Button("Refresh")) refresh_processes(app);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(8));
    ImGui::InputTextWithHint("##filter", "filter processes", &app.process_filter);
    ImGui::SameLine();

    const std::string preview = app.selected_process >= 0
        ? app.processes[app.selected_process].name + " (" + std::to_string(app.processes[app.selected_process].pid) + ")"
        : std::string("select a process");
    ImGui::SetNextItemWidth(em(13));
    if (ImGui::BeginCombo("##process", preview.c_str())) {
        std::string filter = app.process_filter;
        std::transform(filter.begin(), filter.end(), filter.begin(), ::tolower);
        for (int i = 0; i < static_cast<int>(app.processes.size()); ++i) {
            std::string name = app.processes[i].name;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            if (!filter.empty() && name.find(filter) == std::string::npos) continue;

            const std::string label = app.processes[i].name + " (" + std::to_string(app.processes[i].pid) + ")";
            if (ImGui::Selectable(label.c_str(), i == app.selected_process)) app.selected_process = i;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(app.selected_process < 0);
    if (ImGui::Button("Attach")) attach(app, app.processes[app.selected_process]);
    ImGui::EndDisabled();
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::Checkbox("Auto re-attach", &app.auto_reattach);
    ImGui::SameLine();
    if (is_attached(app)) ImGui::Text("Attached: %s", app.attached_label.c_str());
    else if (app.session.exited()) ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.3f, 1.0f), "%s exited", app.session.process().name().c_str());
    else ImGui::TextDisabled("Not attached");
}

void draw_scan_controls(App& app) {
    ImGui::BeginDisabled(!is_attached(app) || job_running(app) || app.track_stage != App::TrackStage::Off);

    // Buttons share one width so the input fields line up in front of them
    const ImGuiStyle& style = ImGui::GetStyle();
    const float button_width = ImGui::CalcTextSize("First Scan").x + style.FramePadding.x * 2;
    const float before_button = -(button_width + style.ItemSpacing.x);

    ImGui::SetNextItemWidth(em(5));
    ImGui::Combo("Type", &app.type_index, kTypeNames, IM_ARRAYSIZE(kTypeNames));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(7));
    ImGui::Combo("Floats", &app.float_mode, kFloatModes, IM_ARRAYSIZE(kFloatModes));
    const bool numeric = is_numeric(type_at(app.type_index));
    if (numeric) {
        ImGui::SameLine();
        ImGui::Checkbox("Unknown value", &app.unknown_value);
        if (!app.unknown_value) {
            ImGui::SameLine();
            ImGui::Checkbox("XOR", &app.scan_xor_mode);
            if (app.scan_xor_mode) {
                ImGui::SameLine();
                ImGui::SetNextItemWidth(em(8));
                ImGui::InputTextWithHint("##xor_key", "key (0x.. or auto)", &app.scan_xor_key);
            }
        }
    }

    if (!(numeric && app.unknown_value)) {
        const char* hint = numeric ? "value" : (type_at(app.type_index) == scanner::DataType::AOB ? "48 8B ? ? 89" : "text");
        ImGui::SetNextItemWidth(before_button);
        ImGui::InputTextWithHint("##first_value", hint, &app.first_value);
        ImGui::SameLine();
    }
    if (ImGui::Button("First Scan", ImVec2(button_width, 0))) first_scan(app);

    ImGui::SetNextItemWidth(em(8));
    ImGui::Combo("##next_condition", &app.next_index, next_labels().data(), static_cast<int>(next_labels().size()));
    const int value_count = session::ScanSession::next_conditions()[app.next_index].value_count;
    const float undo_width = ImGui::CalcTextSize("Undo").x + style.FramePadding.x * 2 + style.ItemSpacing.x;
    if (value_count >= 1) {
        ImGui::SameLine();
        // Fill the row up to the buttons; two values split the space
        const float space = ImGui::GetContentRegionAvail().x + before_button - undo_width;
        ImGui::SetNextItemWidth(value_count == 2 ? (space - style.ItemSpacing.x) / 2 : space);
        ImGui::InputTextWithHint("##next_value1", value_count == 2 ? "from" : "value", &app.next_value1);
    }
    if (value_count >= 2) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x + before_button - undo_width);
        ImGui::InputTextWithHint("##next_value2", "to", &app.next_value2);
    }
    ImGui::SameLine();
    if (ImGui::Button("Next Scan", ImVec2(button_width, 0))) next_scan(app);
    ImGui::SameLine();
    // A running scan job changes the history: only look at it when none runs
    ImGui::BeginDisabled(job_running(app) || !app.session.scans().can_undo());
    if (ImGui::Button("Undo")) undo(app);
    ImGui::EndDisabled();

    // Noise: learned after attaching; relearn while leaving the target alone, or stop ignoring it
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Noise: %s", app.session.describe_noise().c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Relearn")) learn_noise(app);
    ImGui::SameLine();
    ImGui::BeginDisabled(!app.session.noise());
    if (ImGui::SmallButton("Clear")) {
        app.session.set_noise(nullptr);
        app.status = "Noise cleared: scans look at every address again.";
    }
    ImGui::EndDisabled();

    ImGui::EndDisabled();
}

void draw_tracking(App& app) {
    using Stage = App::TrackStage;
    using Kind = scanner::Expectation::Kind;

    if (app.track_stage == Stage::Off) {
        const bool can_track = app.track_auto_type || is_numeric(type_at(app.type_index));
        ImGui::BeginDisabled(!is_attached(app) || job_running(app) || !can_track);
        if (ImGui::Button("Smart track")) start_tracking(app);
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::Checkbox("Auto type", &app.track_auto_type);
        ImGui::SameLine();
        ImGui::TextDisabled(app.track_auto_type ? "(i32 / f32 / f64)" : "(the type above)");
        return;
    }

    const std::string tracked = app.tracker->types().size() > 1 ? "auto type"
                                                                 : utils::format_data_type(app.tracker->types().front());
    ImGui::Text("Smart track (%s): %s", tracked.c_str(), app.track_summary.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Stop")) app.track_stop_requested = true; // applied when no job is running

    if (app.track_stage == Stage::Quiet) {
        ImGui::TextWrapped("Leave the value alone: values that change on their own lose points.");
        ImGui::TextDisabled("From the game: Num0 = I'll change it, then Num- down / Num+ up / Num* changed "
                            "(or Ctrl+Shift+1, then 2 / 3 / 4)");
        // A watch job may still be running; it finishes and no new one starts
        if (ImGui::Button("I'll change it now")) app.track_stage = Stage::Changing;
    } else {
        ImGui::TextWrapped("Change the value in the game, then say how it changed:");
        ImGui::BeginDisabled(job_running(app));
        if (ImGui::Button("Went up")) track_event(app, {Kind::Increased});
        ImGui::SameLine();
        if (ImGui::Button("Went down")) track_event(app, {Kind::Decreased});
        ImGui::SameLine();
        if (ImGui::Button("Changed")) track_event(app, {Kind::Changed});
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(6));
        ImGui::InputTextWithHint("##track_value", "new value", &app.track_value);
        ImGui::SameLine();
        if (ImGui::Button("It's now")) {
            const auto mode = static_cast<scanner::FloatMatchMode>(app.float_mode);
            if (auto expected = scanner::parse_expectation(app.track_value, mode)) {
                track_event(app, *expected);
            } else {
                app.status = "'" + app.track_value + "' is not a number.";
            }
        }
        ImGui::EndDisabled();
    }

    if (app.track_events == 0) {
        ImGui::TextDisabled("The ranked candidates appear after your first change.");
        return;
    }
    if (app.track_best.empty()) return;
    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("track_best", 6, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(10.5f));
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(2.6f));
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, em(6));
    ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed, em(3));
    ImGui::TableSetupColumn("Why");
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(1.8f));
    ImGui::TableHeadersRow();

    std::optional<size_t> add_row;
    std::optional<size_t> view_row;
    for (size_t i = 0; i < app.track_best.size(); ++i) {
        const auto& c = app.track_best[i];
        ImGui::TableNextRow();
        ImGui::PushID(static_cast<int>(i));
        ImGui::TableNextColumn();
        if (ImGui::Selectable(utils::format_address(c.address).c_str())) view_row = i; // the memory around it
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(utils::format_data_type(c.value.type).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(c.value.to_string().c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%d", c.score);
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(c.reason.c_str());
        ImGui::TableNextColumn();
        if (ImGui::SmallButton("+")) add_row = i;
        ImGui::PopID();
    }
    ImGui::EndTable();

    if (add_row) {
        const auto& c = app.track_best[*add_row];
        show(app, app.session.table().add_address(c.address, c.value.type, ""));
    }
    if (view_row) open_memory(app, app.track_best[*view_row].address);
}

void draw_results(App& app) {
    if (app.track_stage != App::TrackStage::Off) return; // the smart track panel shows the candidates
    if (job_running(app)) {
        ImGui::Text("%s ... %.1f s", app.job_label.c_str(), elapsed_ms(app.job_start) / 1000.0);
        return;
    }
    const auto& scans = app.session.scans();
    if (scans.state().snapshot) {
        ImGui::TextWrapped("%s. Change the value in the target, then run a next scan "
                           "(Changed / Unchanged / Increased / Decreased ...).", scans.describe().c_str());
        return;
    }

    const auto& results = scans.state().results;
    ImGui::Text("%zu results  (click: the memory around it, double-click or +: add to the cheat table)", results.count());

    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("results", 4, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(10.5f));
    ImGui::TableSetupColumn("Value");
    ImGui::TableSetupColumn("Previous");
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(1.8f));
    ImGui::TableHeadersRow();

    std::optional<size_t> add_row;
    std::optional<size_t> view_row;
    std::vector<uint8_t> live(results.value_size());
    ImGuiListClipper clipper; // only the visible rows are drawn (and read from the target)
    clipper.Begin(static_cast<int>(results.count()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto i = static_cast<size_t>(row);
            ImGui::TableNextRow();
            ImGui::PushID(row);

            ImGui::TableNextColumn();
            const std::string address = utils::format_address(results.address(i));
            if (ImGui::Selectable(address.c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) add_row = i;
                else view_row = i;
            }

            ImGui::TableNextColumn();
            std::string current = "??";
            if (!live.empty() && app.session.process().read_raw(results.address(i), live.data(), live.size())) {
                if (auto v = scanner::value_from_bytes(results.type(), live.data(), live.size())) current = v->to_string();
            }
            ImGui::TextUnformatted(current.c_str());

            ImGui::TableNextColumn();
            if (auto prev = scanner::value_from_bytes(results.type(), results.previous_bytes(i), results.value_size())) {
                ImGui::TextUnformatted(prev->to_string().c_str());
            }

            ImGui::TableNextColumn();
            if (ImGui::SmallButton("+")) add_row = i;
            ImGui::PopID();
        }
    }
    ImGui::EndTable();

    if (add_row) add_result_to_table(app, *add_row);
    if (view_row) open_memory(app, results.address(*view_row));
}

// A click in the table, applied once the table lock is released (the operations take the lock themselves)
struct TableAction {
    enum class Kind { None, Freeze, Unfreeze, Write, Remove, Keep, View, Keys, Writes, Plot } kind = Kind::None;
    size_t row = 0;
    std::string value;    // Write
    uintptr_t address{0}; // View: where the entry leads now
};

void apply_table_action(App& app, const TableAction& action) {
    using Kind = TableAction::Kind;
    auto& keeper = app.session.table();
    switch (action.kind) {
        case Kind::None: break;
        case Kind::Freeze: show(app, keeper.freeze(action.row, std::nullopt)); break; // at its current value
        case Kind::Unfreeze: show(app, keeper.unfreeze(action.row)); break;
        case Kind::Write: show(app, keeper.set_value(action.row, action.value)); break;
        case Kind::Remove:
            show(app, keeper.remove(action.row));
            if (action.row < app.edit_buffers.size()) {
                app.edit_buffers.erase(app.edit_buffers.begin() + static_cast<std::ptrdiff_t>(action.row));
            }
            app.editing_row = -1;
            break;
        case Kind::Keep: make_entry_permanent(app, action.row); break;
        case Kind::View:
            if (action.address) open_memory(app, action.address);
            else app.status = "This entry doesn't lead to an address in the target now.";
            break;
        case Kind::Keys:
            app.hotkey_row = static_cast<int>(action.row);
            app.select_tab = Tab::Hotkeys;
            break;
        case Kind::Writes:
            if (action.address) {
                app.watch_input = utils::format_address(action.address);
                app.select_tab = Tab::Watch;
                app.watch_note = "Press \"Find writes\", then change the value in the game.";
            } else {
                app.status = "This entry doesn't lead to an address in the target now.";
            }
            break;
        case Kind::Plot:
            app.plot_entry_index = static_cast<int>(action.row);
            app.plot_count = 0;
            app.plot_head = 0;
            app.plot_min = 0.0f;
            app.plot_max = 100.0f;
            break;
    }
}

TableAction draw_table_rows(App& app, table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules);

void draw_cheat_table(App& app) {
    auto& keeper = app.session.table();

    ImGui::SetNextItemWidth(-em(14));
    ImGui::InputTextWithHint("##table_path", "table.json or table.ct", &app.table_path);
    ImGui::SameLine();
    if (ImGui::Button("Save")) show(app, keeper.save(app.table_path));
    ImGui::SameLine();
    if (ImGui::Button("Load")) {
        std::vector<session::TableKeeper::ReconcileLine> reconciled;
        const auto loaded = keeper.load(app.table_path, &reconciled);
        show(app, loaded);
        if (loaded.ok) {
            app.editing_row = -1;
            app.table_note = describe_reconciled(reconciled);
            if (const std::string tbl_lua = keeper.lua_script(); !tbl_lua.empty()) {
                app.lua_script = tbl_lua;
            }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Export .CT")) {
        std::string ct_path = app.table_path.empty() ? "table.ct" : app.table_path;
        if (ct_path.size() < 3 || (ct_path.compare(ct_path.size() - 3, 3, ".ct") != 0 && ct_path.compare(ct_path.size() - 3, 3, ".CT") != 0)) {
            ct_path += ".ct";
        }
        show(app, keeper.save(ct_path));
    }
    ImGui::SameLine();
    if (ImGui::Button("Export Trainer")) {
        ImGui::OpenPopup("ExportTrainerPopup");
    }
    if (ImGui::BeginPopup("ExportTrainerPopup")) {
        ImGui::Text("Choose Trainer Target:");
        ImGui::Separator();
        if (ImGui::MenuItem("Standalone Native Win32 GUI (.cpp)")) {
            std::string err;
            bool ok = false;
            keeper.with([&](const table::CheatTable& t, const auto&) {
                std::string proc = is_attached(app) ? app.session.process().name() : t.process_name;
                ok = table::export_standalone_trainer_file("standalone_trainer_gui.cpp", t, proc, err, table::TrainerKind::GUI);
            });
            if (ok) app.status = "Exported GUI trainer to standalone_trainer_gui.cpp (Compile with: g++ -O2 -mwindows standalone_trainer_gui.cpp -o trainer_gui.exe)";
            else app.status = "GUI Trainer export failed: " + err;
        }
        if (ImGui::MenuItem("Standalone Console Trainer (.cpp)")) {
            std::string err;
            bool ok = false;
            keeper.with([&](const table::CheatTable& t, const auto&) {
                std::string proc = is_attached(app) ? app.session.process().name() : t.process_name;
                ok = table::export_standalone_trainer_file("standalone_trainer_console.cpp", t, proc, err, table::TrainerKind::Console);
            });
            if (ok) app.status = "Exported Console trainer to standalone_trainer_console.cpp (Compile with: g++ -O2 -mconsole standalone_trainer_console.cpp -o trainer.exe)";
            else app.status = "Console Trainer export failed: " + err;
        }
        ImGui::EndPopup();
    }
    // Where the table lives between runs (the file above is for sharing or keeping a copy)
    const auto library_file = keeper.library_file();
    if (!library_file.empty()) {
        ImGui::TextDisabled("Kept in the library, saved by itself: %s", library_file.string().c_str());
    } else if (!keeper.library().empty()) {
        ImGui::TextDisabled("Attach to a program and its table opens from the library: %s", keeper.library().string().c_str());
    }
    if (!app.table_note.empty()) {
        ImGui::TextDisabled("After restart:");
        ImGui::TextWrapped("%s", app.table_note.c_str());
    }

    TableAction action;
    keeper.with([&](table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules) {
        action = draw_table_rows(app, t, modules); // the freeze thread waits meanwhile
    });
    apply_table_action(app, action);
}

// The rows, drawn under the table lock: the description is edited in place, any other click is returned
TableAction draw_table_rows(App& app, table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules) {
    using Kind = TableAction::Kind;
    TableAction action;
    auto& entries = t.entries;
    app.edit_buffers.resize(entries.size());
    const bool attached = is_attached(app);
    auto& process = app.session.process();

    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
                                  ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;
    if (!ImGui::BeginTable("cheat_table", 6, flags, ImVec2(0, em(14)))) return action;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Freeze", ImGuiTableColumnFlags_WidthFixed, em(3.8f));
    ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 1.2f);
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(2.6f));
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch, 2.0f);
    // Wide enough for its seven small buttons: Keep, View, Writes, Plot, Ptr, Keys n, X
    const ImGuiStyle& style = ImGui::GetStyle();
    const float actions_width = ImGui::CalcTextSize("KeepViewWritesPlotPtrKeys 9X").x + 7 * 2 * style.FramePadding.x +
                                6 * style.ItemSpacing.x;
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, actions_width);
    ImGui::TableHeadersRow();

    for (size_t i = 0; i < entries.size(); ++i) {
        auto& e = entries[i];
        const auto row = static_cast<int>(i);
        const auto current = attached ? table::read_entry(e, process, modules) : std::nullopt;
        auto act = [&action, i](Kind kind, std::string value = {}, uintptr_t address = 0) {
            action = TableAction{kind, i, std::move(value), address};
        };

        ImGui::TableNextRow();
        ImGui::PushID(row);

        ImGui::TableNextColumn();
        bool frozen = e.frozen_value.has_value();
        if (ImGui::Checkbox("##freeze", &frozen)) act(frozen ? Kind::Freeze : Kind::Unfreeze);

        ImGui::TableNextColumn();
        if (!e.group.empty()) {
            ImGui::TextDisabled("[%s]", e.group.c_str());
            ImGui::SameLine();
        }
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputTextWithHint("##description", "description", &e.description);
        if (ImGui::BeginPopupContextItem("##row_ctx")) {
            ImGui::Text("Group / Folder:");
            ImGui::SetNextItemWidth(em(12));
            ImGui::InputTextWithHint("##entry_group", "e.g. Player Stats", &e.group);
            ImGui::EndPopup();
        }

        ImGui::TableNextColumn();
        ImGui::TextUnformatted(utils::format_data_type(e.type).c_str());

        // Shows the live value; typing a new one and pressing Enter writes it (or pick from dropdown)
        ImGui::TableNextColumn();
        if (app.editing_row != row) app.edit_buffers[i] = current ? session::value_text(*current) : "??";
        const float dd_reserve = e.dropdown.empty() ? 0.0f : em(2.0f);
        ImGui::SetNextItemWidth(-FLT_MIN - dd_reserve);
        if (ImGui::InputText("##value", &app.edit_buffers[i], ImGuiInputTextFlags_EnterReturnsTrue)) {
            act(Kind::Write, app.edit_buffers[i]);
        }
        if (ImGui::IsItemActive()) app.editing_row = row;
        else if (app.editing_row == row) app.editing_row = -1;
        if (!e.dropdown.empty()) {
            ImGui::SameLine();
            if (ImGui::BeginCombo("##dd", "", ImGuiComboFlags_NoPreview)) {
                for (const auto& [k, lbl] : e.dropdown) {
                    const std::string item_lbl = k + " : " + lbl;
                    if (ImGui::Selectable(item_lbl.c_str(), app.edit_buffers[i] == k)) {
                        act(Kind::Write, k);
                    }
                }
                ImGui::EndCombo();
            }
        }

        ImGui::TableNextColumn();
        ImGui::TextUnformatted(e.location_string().c_str());

        ImGui::TableNextColumn();
        // Keep: pointer paths that find a heap value again after a restart (static addresses already do)
        const bool is_static = !e.is_absolute() && e.location.offsets.empty();
        ImGui::BeginDisabled(!attached || job_running(app) || is_static || !e.alternatives.empty());
        if (ImGui::SmallButton(e.alternatives.empty() ? "Keep" : "Kept")) act(Kind::Keep);
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip(is_static ? "A static address: it already survives restarts."
                                        : "Find pointer paths so this value is found again after the game restarts.");
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("View")) act(Kind::View, {}, attached ? e.address(process, modules) : 0);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("The memory around it: neighbouring values of the same object.");
        ImGui::SameLine();
        if (ImGui::SmallButton("Writes")) act(Kind::Writes, {}, attached ? e.address(process, modules) : 0);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Find what code writes to this value (hardware breakpoint, Watch tab).");
        ImGui::SameLine();
        if (ImGui::SmallButton("Plot")) act(Kind::Plot, {}, attached ? e.address(process, modules) : 0);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Open Live Oscilloscope / Waveform plot for this value.");
        ImGui::SameLine();
        if (ImGui::SmallButton("Ptr")) {
            const uintptr_t address = attached ? e.address(process, modules) : 0;
            if (address) {
                app.ptr_target = utils::format_address(address);
                if (is_numeric(e.type)) app.ptr_add_type = type_index_of(e.type);
                app.select_tab = Tab::PointerScanner;
                app.status = "Pointer scanner target set to " + app.ptr_target + ": press Scan.";
            }
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Find pointer paths that lead to it (Pointer scanner tab).");
        ImGui::SameLine();
        const std::string keys_label = e.hotkeys.empty() ? "Keys" : "Keys " + std::to_string(e.hotkeys.size());
        if (ImGui::SmallButton(keys_label.c_str())) act(Kind::Keys);
        if (ImGui::IsItemHovered()) {
            std::string tip = "Keys that work while the game is in front.";
            for (const auto& h : e.hotkeys) tip += "\n" + h.to_string();
            ImGui::SetTooltip("%s", tip.c_str());
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("X")) act(Kind::Remove);
        ImGui::PopID();
    }
    ImGui::EndTable();
    return action;
}

void draw_pointer_scanner(App& app) {
    ImGui::BeginDisabled(!is_attached(app) || job_running(app));
    ImGui::SetNextItemWidth(em(10));
    ImGui::InputTextWithHint("Address", "0x...", &app.ptr_target);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(5.5f));
    ImGui::InputInt("Depth", &app.ptr_depth);
    app.ptr_depth = std::clamp(app.ptr_depth, 1, 8);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(4));
    ImGui::InputScalar("Max offset", ImGuiDataType_U32, &app.ptr_offset, nullptr, nullptr, "%X",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::Checkbox("Neg offsets", &app.ptr_allow_neg);
    if (app.ptr_allow_neg) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(4));
        ImGui::InputScalar("Max neg", ImGuiDataType_U32, &app.ptr_neg_offset, nullptr, nullptr, "%X",
                           ImGuiInputTextFlags_CharsHexadecimal);
    }
    ImGui::SetNextItemWidth(em(10));
    ImGui::InputTextWithHint("Base module", "any module", &app.ptr_module);
    ImGui::SameLine();

    if (ImGui::Button("Scan")) {
        const uintptr_t target = utils::parse_address(app.ptr_target);
        if (target == 0) {
            app.status = "Enter the address to find pointers to.";
        } else {
            scanner::PointerScanOptions options;
            options.max_depth = static_cast<size_t>(app.ptr_depth);
            options.max_offset = app.ptr_offset;
            options.max_negative_offset = app.ptr_allow_neg ? app.ptr_neg_offset : 0;
            options.base_module = app.ptr_module;
            start_job(app, "Pointer scan", [&app, target, options]() -> ApplyResult {
                auto result = std::make_shared<scanner::PointerScanResult>(
                    scanner::PointerScanner(app.session.process_ptr()).scan(target, options));
                return [&app, result]() {
                    app.session.pointer_paths() = std::move(result->paths);
                    app.status = "Pointer scan: " + std::to_string(app.session.pointer_paths().size()) + " paths" +
                                 (result->truncated ? " (hit the search limit: lower the depth or max offset)" : "") +
                                 ". Restart the target, find the value again, then Rescan.";
                };
            });
        }
    }
    ImGui::SameLine();
    auto& paths = app.session.pointer_paths(); // only a finished pointer scan job replaces them
    ImGui::BeginDisabled(paths.empty());
    if (ImGui::Button("Rescan")) {
        const uintptr_t target = utils::parse_address(app.ptr_target);
        const size_t before = paths.size();
        paths = scanner::PointerScanner::verify_paths(app.session.process(), paths, target);
        app.status = "Rescan: " + std::to_string(paths.size()) + " of " + std::to_string(before) +
                     " paths still lead to " + app.ptr_target + ".";
    }
    ImGui::EndDisabled();
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(4));
    ImGui::Combo("Add as", &app.ptr_add_type, kTypeNames, 10); // numeric types only

    ImGui::BeginDisabled(!is_attached(app) || job_running(app));
    ImGui::SetNextItemWidth(em(13));
    ImGui::InputTextWithHint("##ptr_map_path", "pointers.ncem", &app.ptr_map_path);
    ImGui::SameLine();
    if (ImGui::Button("Save Map (.ncem)")) {
        const std::string path = app.ptr_map_path.empty() ? "pointers.ncem" : app.ptr_map_path;
        start_job(app, "Save PointerMap", [&app, path]() -> ApplyResult {
            const bool ok = app.session.build_and_save_pointer_map(path);
            return [&app, ok, path]() {
                app.status = ok ? ("Saved binary PointerMap to " + path)
                                : ("Failed building/saving PointerMap to " + path);
            };
        });
    }
    ImGui::SameLine();
    if (ImGui::Button("Scan Saved Map")) {
        const uintptr_t target = utils::parse_address(app.ptr_target);
        const std::string path = app.ptr_map_path.empty() ? "pointers.ncem" : app.ptr_map_path;
        if (target == 0) {
            app.status = "Enter a target address before scanning a saved PointerMap.";
        } else {
            scanner::PointerScanOptions options;
            options.max_depth = static_cast<size_t>(app.ptr_depth);
            options.max_offset = app.ptr_offset;
            options.max_negative_offset = app.ptr_allow_neg ? app.ptr_neg_offset : 0;
            options.base_module = app.ptr_module;
            start_job(app, "Scan Saved Map", [&app, path, target, options]() -> ApplyResult {
                auto res = std::make_shared<scanner::PointerScanResult>(
                    app.session.scan_saved_pointer_map(path, target, options));
                return [&app, res, path]() {
                    app.session.pointer_paths() = std::move(res->paths);
                    app.status = "Scanned " + path + " (" + std::to_string(res->pointer_map_size) +
                                 " ptrs): " + std::to_string(app.session.pointer_paths().size()) + " paths.";
                };
            });
        }
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(paths.empty());
    if (ImGui::Button("Compare Saved Map")) {
        const uintptr_t target = utils::parse_address(app.ptr_target);
        const std::string path = app.ptr_map_path.empty() ? "pointers.ncem" : app.ptr_map_path;
        if (target != 0) {
            scanner::PointerScanOptions options;
            options.max_depth = static_cast<size_t>(app.ptr_depth);
            options.max_offset = app.ptr_offset;
            options.max_negative_offset = app.ptr_allow_neg ? app.ptr_neg_offset : 0;
            options.base_module = app.ptr_module;
            start_job(app, "Compare PointerMap", [&app, path, target, options]() -> ApplyResult {
                auto new_res = app.session.scan_saved_pointer_map(path, target, options);
                auto kept = scanner::PointerScanner::intersect_paths(app.session.pointer_paths(), new_res.paths);
                return [&app, kept = std::move(kept), n = new_res.paths.size()]() mutable {
                    const size_t before = app.session.pointer_paths().size();
                    app.session.pointer_paths() = std::move(kept);
                    app.status = "Map Compare: " + std::to_string(before) + " x " + std::to_string(n) +
                                 " -> " + std::to_string(app.session.pointer_paths().size()) + " common path(s).";
                };
            });
        }
    }
    ImGui::EndDisabled();
    ImGui::EndDisabled();

    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_ScrollY;
    if (!ImGui::BeginTable("pointer_paths", 2, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Path (best first)");
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(3));
    ImGui::TableHeadersRow();

    std::optional<size_t> add_row;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(paths.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            ImGui::TableNextRow();
            ImGui::PushID(row);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(paths[static_cast<size_t>(row)].to_string().c_str());
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Add")) add_row = static_cast<size_t>(row);
            ImGui::PopID();
        }
    }
    ImGui::EndTable();

    if (add_row) show(app, app.session.table().add_pointer(paths[*add_row], type_at(app.ptr_add_type), ""));
}

// The Memory tab: a live view of the memory around an address, each 4 bytes read as what they most likely
// are. Neighbouring values of the found one (max health, ammo, position) usually sit right next to it.
void draw_memory(App& app) {
    auto& memory = app.memory;
    ImGui::BeginDisabled(!is_attached(app));
    ImGui::SetNextItemWidth(em(11));
    const bool entered = ImGui::InputTextWithHint("##memory_address", "0x...", &app.memory_input,
                                                  ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Go") || entered) {
        const uintptr_t address = utils::parse_address(app.memory_input);
        if (address) open_memory(app, address);
        else app.status = "Enter the address to look at.";
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(app.memory_back.empty());
    if (ImGui::Button("< Back")) {
        const uintptr_t previous = app.memory_back.back();
        app.memory_back.pop_back();
        if (!app.memory.empty()) app.memory_forward.push_back(app.memory.address());
        open_memory(app, previous, false);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(app.memory_forward.empty());
    if (ImGui::Button("Forward >")) {
        const uintptr_t next_addr = app.memory_forward.back();
        app.memory_forward.pop_back();
        if (!app.memory.empty()) app.memory_back.push_back(app.memory.address());
        open_memory(app, next_addr, false);
    }
    ImGui::EndDisabled();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("yellow: changed, grey: noise | Click row or [*] to inspect");

    if (memory.empty()) {
        ImGui::TextWrapped("Click a result's address, a smart track candidate, or View in the cheat table to see the "
                           "memory around it. Values of the same object (max health, ammo, position) usually sit "
                           "right next to the one you found.");
        return;
    }

    // Live: read again 5 times a second
    const auto now = std::chrono::steady_clock::now();
    if (now - app.memory_refreshed >= std::chrono::milliseconds(200)) {
        app.session.refresh(memory);
        app.memory_refreshed = now;
    }

    if (app.memory_selected_addr == 0 && !memory.empty()) {
        app.memory_selected_addr = memory.address();
    }

    const float avail_w = ImGui::GetContentRegionAvail().x;
    float inspector_w = em(22.0f);
    if (inspector_w > avail_w * 0.45f) inspector_w = avail_w * 0.45f;
    const float slots_w = avail_w - inspector_w - ImGui::GetStyle().ItemSpacing.x;

    // --- Left Pane: Interactive Memory Slots Table ---
    ImGui::BeginChild("MemorySlotsRegion", ImVec2(slots_w, 0), true);

    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV;
    if (ImGui::BeginTable("memory", 6, flags, ImVec2(0, 0))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, em(4));
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(10.5f));
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, em(7));
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(2.4f));
        ImGui::TableSetupColumn("Value");
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(4.4f));
        ImGui::TableHeadersRow();

        const ImVec4 changed_color(1.0f, 0.85f, 0.25f, 1.0f);
        const ImVec4 noise_color = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
        std::optional<size_t> add_row;
        std::optional<uintptr_t> follow;
        const auto& slots = memory.slots();
        for (size_t i = 0; i < slots.size(); ++i) {
            const auto& s = slots[i];
            ImGui::TableNextRow();
            if (s.address == app.memory_selected_addr) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.20f, 0.45f, 0.70f, 0.40f)));
            } else if (i == memory.focus()) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, ImGui::GetColorU32(ImVec4(0.26f, 0.40f, 0.70f, 0.25f)));
            }
            ImGui::PushID(static_cast<int>(i));

            ImGui::TableNextColumn();
            if (ImGui::Selectable(view::format_offset(s.offset).c_str(), s.address == app.memory_selected_addr,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap)) {
                app.memory_selected_addr = s.address;
                app.inspector_write_buf = s.value_text();
            }
            if (i == memory.focus() && app.memory_scroll) {
                ImGui::SetScrollHereY(0.3f);
                app.memory_scroll = false;
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(utils::format_address(s.address).c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", s.bytes_text().c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(s.type_name());

            ImGui::TableNextColumn();
            const bool just_changed = memory.value_age(i) < 5;
            if (s.noisy) ImGui::PushStyleColor(ImGuiCol_Text, noise_color);
            else if (just_changed) ImGui::PushStyleColor(ImGuiCol_Text, changed_color);
            ImGui::TextUnformatted(s.value_text().c_str());
            if (just_changed || s.noisy) ImGui::PopStyleColor();
            if (s.noisy && ImGui::IsItemHovered()) ImGui::SetTooltip("Changes on its own (learned noise): scans ignore it.");

            ImGui::TableNextColumn();
            if (s.guess == view::Guess::Pointer) {
                if (ImGui::SmallButton("Go")) follow = static_cast<uintptr_t>(s.wide);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Follow the pointer (Back returns here).");
                ImGui::SameLine();
            } else if (s.readable && s.guess != view::Guess::Continued && s.guess != view::Guess::Text) {
                if (ImGui::SmallButton("+")) add_row = i;
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Add to the cheat table as %s.", utils::format_data_type(s.data_type()).c_str());
                }
                ImGui::SameLine();
            }
            if (ImGui::SmallButton("[*]")) {
                app.memory_selected_addr = s.address;
                app.inspector_write_buf = s.value_text();
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Select and inspect in Data Inspector");

            ImGui::PopID();
        }
        ImGui::EndTable();

        if (add_row) show(app, app.session.table().add_address(slots[*add_row].address, slots[*add_row].data_type(), ""));
        if (follow) open_memory(app, *follow);
    }
    ImGui::EndChild();

    // --- Right Pane: Live Multi-Type Data Inspector Studio ---
    ImGui::SameLine();
    ImGui::BeginChild("DataInspectorRegion", ImVec2(0, 0), true);

    ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "Data Inspector");
    ImGui::Separator();

    const uintptr_t sel_addr = app.memory_selected_addr ? app.memory_selected_addr : memory.address();
    ImGui::Text("Target: 0x%llX", static_cast<unsigned long long>(sel_addr));
    if (memory.address() != 0) {
        const int64_t rel = static_cast<int64_t>(sel_addr) - static_cast<int64_t>(memory.address());
        ImGui::TextDisabled("Offset: %s", view::format_offset(rel).c_str());
    }
    ImGui::Spacing();

    uint8_t raw_buf[8] = {0};
    bool read_ok = false;
    if (is_attached(app) && sel_addr != 0) {
        read_ok = app.session.process().read_raw(sel_addr, raw_buf, sizeof(raw_buf));
    }

    if (!read_ok) {
        ImGui::TextDisabled("(Unable to read memory)");
    } else {
        const int8_t i8 = *reinterpret_cast<const int8_t*>(raw_buf);
        const uint8_t u8 = *reinterpret_cast<const uint8_t*>(raw_buf);
        const int16_t i16 = *reinterpret_cast<const int16_t*>(raw_buf);
        const uint16_t u16 = *reinterpret_cast<const uint16_t*>(raw_buf);
        const int32_t i32 = *reinterpret_cast<const int32_t*>(raw_buf);
        const uint32_t u32 = *reinterpret_cast<const uint32_t*>(raw_buf);
        const int64_t i64 = *reinterpret_cast<const int64_t*>(raw_buf);
        const uint64_t u64 = *reinterpret_cast<const uint64_t*>(raw_buf);
        const float f32 = *reinterpret_cast<const float*>(raw_buf);
        const double f64 = *reinterpret_cast<const double*>(raw_buf);

        if (ImGui::BeginTable("inspector_table", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(4.5f));
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

            auto show_row = [](const char* t, const std::string& v) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", t);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(v.c_str());
            };

            show_row("Int8", std::to_string(i8));
            show_row("UInt8", std::to_string(u8));
            show_row("Int16", std::to_string(i16));
            show_row("UInt16", std::to_string(u16));
            show_row("Int32", std::to_string(i32));
            show_row("UInt32", std::to_string(u32));
            show_row("Int64", std::to_string(i64));
            show_row("UInt64", std::to_string(u64));

            char fbuf[32];
            std::snprintf(fbuf, sizeof(fbuf), "%.6g", f32);
            show_row("Float", fbuf);

            char dbuf[32];
            std::snprintf(dbuf, sizeof(dbuf), "%.8g", f64);
            show_row("Double", dbuf);

            // Big-Endian values for Console Emulators (Dolphin, RPCS3, CEMU)
            show_row("Int16 (BE)", std::to_string(scanner::swap_bytes(i16)));
            show_row("Int32 (BE)", std::to_string(scanner::swap_bytes(i32)));
            char fbebuf[32];
            std::snprintf(fbebuf, sizeof(fbebuf), "%.6g", scanner::swap_bytes(f32));
            show_row("Float (BE)", fbebuf);
            show_row("Int64 (BE)", std::to_string(scanner::swap_bytes(i64)));
            char dbebuf[32];
            std::snprintf(dbebuf, sizeof(dbebuf), "%.8g", scanner::swap_bytes(f64));
            show_row("Double (BE)", dbebuf);

            // Pointer row
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("Pointer");
            ImGui::TableNextColumn();
            const uintptr_t ptr_val = static_cast<uintptr_t>(u64);
            char pbuf[32];
            std::snprintf(pbuf, sizeof(pbuf), "0x%llX", static_cast<unsigned long long>(ptr_val));
            ImGui::TextUnformatted(pbuf);
            if (ptr_val != 0) {
                ImGui::SameLine();
                if (ImGui::SmallButton("Jump")) {
                    open_memory(app, ptr_val);
                }
            }

            // ASCII row
            char ascii_str[9] = {0};
            for (int b = 0; b < 8; ++b) {
                const char c = static_cast<char>(raw_buf[b]);
                ascii_str[b] = (c >= 32 && c <= 126) ? c : '.';
            }
            show_row("ASCII", ascii_str);

            ImGui::EndTable();
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.5f, 1.0f), "Modify Memory");

    static const char* const kEditTypes[] = {
        "Int32", "Float", "Int64", "Int16", "Int8", "Double", "Hex Bytes",
        "Int32 (BE)", "Float (BE)", "Int64 (BE)", "Int16 (BE)", "Double (BE)"
    };
    ImGui::SetNextItemWidth(em(6.5f));
    ImGui::Combo("##edit_type", &app.inspector_type_idx, kEditTypes, IM_ARRAYSIZE(kEditTypes));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-em(0.2f));
    ImGui::InputTextWithHint("##edit_val", "Value / hex...", &app.inspector_write_buf);

    if (ImGui::Button("Write") && is_attached(app) && sel_addr != 0) {
        try {
            bool ok = false;
            switch (app.inspector_type_idx) {
                case 0: { // Int32
                    const int32_t val = static_cast<int32_t>(std::stol(app.inspector_write_buf, nullptr, 0));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 1: { // Float
                    const float val = std::stof(app.inspector_write_buf);
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 2: { // Int64
                    const int64_t val = static_cast<int64_t>(std::stoll(app.inspector_write_buf, nullptr, 0));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 3: { // Int16
                    const int16_t val = static_cast<int16_t>(std::stoi(app.inspector_write_buf, nullptr, 0));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 4: { // Int8
                    const int8_t val = static_cast<int8_t>(std::stoi(app.inspector_write_buf, nullptr, 0));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 5: { // Double
                    const double val = std::stod(app.inspector_write_buf);
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 6: { // Hex Bytes
                    std::stringstream ss(app.inspector_write_buf);
                    std::string token;
                    std::vector<uint8_t> bytes;
                    while (ss >> token) {
                        try {
                            bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
                        } catch (...) {}
                    }
                    if (!bytes.empty()) {
                        ok = app.session.process().write_raw(sel_addr, bytes.data(), bytes.size());
                    }
                    break;
                }
                case 7: { // Int32 (BE)
                    const int32_t val = scanner::swap_bytes(static_cast<int32_t>(std::stol(app.inspector_write_buf, nullptr, 0)));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 8: { // Float (BE)
                    const float val = scanner::swap_bytes(std::stof(app.inspector_write_buf));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 9: { // Int64 (BE)
                    const int64_t val = scanner::swap_bytes(static_cast<int64_t>(std::stoll(app.inspector_write_buf, nullptr, 0)));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 10: { // Int16 (BE)
                    const int16_t val = scanner::swap_bytes(static_cast<int16_t>(std::stoi(app.inspector_write_buf, nullptr, 0)));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
                case 11: { // Double (BE)
                    const double val = scanner::swap_bytes(std::stod(app.inspector_write_buf));
                    ok = app.session.process().write_raw(sel_addr, &val, sizeof(val));
                    break;
                }
            }
            if (ok) {
                app.inspector_status = "[+] Written successfully!";
                app.session.refresh(app.memory);
            } else {
                app.inspector_status = "[-] Write failed (protected memory).";
            }
        } catch (const std::exception& e) {
            app.inspector_status = std::string("[!] Error: ") + e.what();
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("+ Table") && sel_addr != 0) {
        scanner::DataType dt = scanner::DataType::Int32;
        switch (app.inspector_type_idx) {
            case 0: dt = scanner::DataType::Int32; break;
            case 1: dt = scanner::DataType::Float; break;
            case 2: dt = scanner::DataType::Int64; break;
            case 3: dt = scanner::DataType::Int16; break;
            case 4: dt = scanner::DataType::Int8; break;
            case 5: dt = scanner::DataType::Double; break;
            case 7: dt = scanner::DataType::Int32BE; break;
            case 8: dt = scanner::DataType::FloatBE; break;
            case 9: dt = scanner::DataType::Int64BE; break;
            case 10: dt = scanner::DataType::Int16BE; break;
            case 11: dt = scanner::DataType::DoubleBE; break;
            default: dt = scanner::DataType::Int32; break;
        }
        show(app, app.session.table().add_address(sel_addr, dt, ""));
    }

    if (!app.inspector_status.empty()) {
        ImGui::Spacing();
        ImGui::TextWrapped("%s", app.inspector_status.c_str());
    }

    ImGui::EndChild();
}

// The key pressed in this window right now, with its modifiers ("Ctrl+F1"), or empty
std::string pressed_combo() {
    static const std::vector<std::pair<ImGuiKey, std::string>> keys = [] {
        std::vector<std::pair<ImGuiKey, std::string>> list;
        for (int i = 0; i < 24; ++i) list.emplace_back(static_cast<ImGuiKey>(ImGuiKey_F1 + i), "F" + std::to_string(i + 1));
        for (int i = 0; i < 26; ++i) list.emplace_back(static_cast<ImGuiKey>(ImGuiKey_A + i), std::string(1, static_cast<char>('A' + i)));
        for (int i = 0; i < 10; ++i) {
            list.emplace_back(static_cast<ImGuiKey>(ImGuiKey_0 + i), std::to_string(i));
            list.emplace_back(static_cast<ImGuiKey>(ImGuiKey_Keypad0 + i), "Num" + std::to_string(i));
        }
        const std::pair<ImGuiKey, const char*> named[] = {
            {ImGuiKey_KeypadAdd, "Num+"}, {ImGuiKey_KeypadSubtract, "Num-"}, {ImGuiKey_KeypadMultiply, "Num*"},
            {ImGuiKey_KeypadDivide, "Num/"}, {ImGuiKey_KeypadDecimal, "Num."}, {ImGuiKey_Insert, "Insert"},
            {ImGuiKey_Delete, "Delete"}, {ImGuiKey_Home, "Home"}, {ImGuiKey_End, "End"}, {ImGuiKey_PageUp, "PageUp"},
            {ImGuiKey_PageDown, "PageDown"}, {ImGuiKey_UpArrow, "Up"}, {ImGuiKey_DownArrow, "Down"},
            {ImGuiKey_LeftArrow, "Left"}, {ImGuiKey_RightArrow, "Right"}, {ImGuiKey_Space, "Space"}, {ImGuiKey_Pause, "Pause"},
        };
        for (const auto& [key, name] : named) list.emplace_back(key, name);
        return list;
    }();

    const ImGuiIO& io = ImGui::GetIO();
    for (const auto& [key, name] : keys) {
        if (!ImGui::IsKeyPressed(key, false)) continue;
        std::string combo;
        if (io.KeyCtrl) combo += "Ctrl+";
        if (io.KeyAlt) combo += "Alt+";
        if (io.KeyShift) combo += "Shift+";
        if (io.KeySuper) combo += "Win+";
        return combo + name;
    }
    return {};
}

// Presses of the table's hotkeys (made while the game is in front): show what they did, and beep
void show_table_hotkeys(App& app) {
    std::vector<std::pair<std::string, session::Outcome>> events;
    {
        std::lock_guard<std::mutex> lock(app.hotkey_mutex);
        events.swap(app.hotkey_events);
    }
    for (const auto& [combo, outcome] : events) {
        app.status = "Hotkey " + combo + ": " + outcome.message;
        beep(outcome.ok ? 1320 : 220, outcome.ok ? 90 : 200);
    }
}

// The Hotkeys tab: every hotkey of the table, and a row to make a new one
void draw_hotkeys(App& app) {
    auto& keeper = app.session.table();
    struct Bound {
        size_t row;
        std::string entry;
        table::Hotkey hotkey;
    };
    std::vector<std::string> names;
    std::vector<Bound> bound;
    keeper.with([&](const table::CheatTable& t, const std::vector<hal::ModuleInfo>&) {
        for (size_t i = 0; i < t.entries.size(); ++i) {
            const auto& e = t.entries[i];
            names.push_back("#" + std::to_string(i) + " " + (e.description.empty() ? e.location_string() : e.description));
            for (const auto& h : e.hotkeys) bound.push_back({i, names.back(), h});
        }
    });
    if (names.empty()) {
        ImGui::TextWrapped("Add values to the cheat table first, then give them keys that work while the game is in "
                           "front: freeze and unfreeze, set a value, or add to it.");
        return;
    }
    app.hotkey_row = std::clamp(app.hotkey_row, 0, static_cast<int>(names.size()) - 1);

    ImGui::SetNextItemWidth(em(8));
    if (ImGui::BeginCombo("##hotkey_entry", names[app.hotkey_row].c_str())) {
        for (int i = 0; i < static_cast<int>(names.size()); ++i) {
            if (ImGui::Selectable(names[i].c_str(), i == app.hotkey_row)) app.hotkey_row = i;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(7));
    ImGui::InputTextWithHint("##hotkey_keys", "F1, Ctrl+F2", &app.hotkey_keys);
    ImGui::SameLine();
    if (ImGui::Button(app.hotkey_recording ? "Press a key..." : "Record")) app.hotkey_recording = !app.hotkey_recording;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Click, then press the key (with Ctrl / Alt / Shift if you like). Esc cancels.");
    if (app.hotkey_recording) {
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            app.hotkey_recording = false;
        } else if (const std::string combo = pressed_combo(); !combo.empty()) {
            app.hotkey_keys = combo;
            app.hotkey_recording = false;
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(6.5f));
    ImGui::Combo("##hotkey_action", &app.hotkey_action, kHotkeyActions, IM_ARRAYSIZE(kHotkeyActions));
    if (app.hotkey_action != 0) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(5));
        ImGui::InputTextWithHint("##hotkey_value", app.hotkey_action == 1 ? "value" : "100 / -10", &app.hotkey_value);
    }
    ImGui::SameLine();
    if (ImGui::Button("Add##hotkey")) {
        const auto outcome = keeper.add_hotkey(static_cast<size_t>(app.hotkey_row), app.hotkey_keys,
                                               static_cast<table::Hotkey::Action>(app.hotkey_action), app.hotkey_value);
        show(app, outcome);
        app.hotkey_note = outcome.message;
    }
    if (!app.hotkey_note.empty()) ImGui::TextWrapped("%s", app.hotkey_note.c_str());
    ImGui::TextDisabled("They work while the game is in front: a high beep means done, a low one failed. Saved with the table.");

    const auto taken = keeper.hotkeys_taken();
    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV;
    if (!ImGui::BeginTable("hotkeys", 3, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Entry", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Hotkey", ImGuiTableColumnFlags_WidthStretch, 1.6f);
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(1.8f));
    ImGui::TableHeadersRow();

    std::optional<size_t> remove;
    for (size_t i = 0; i < bound.size(); ++i) {
        const auto& b = bound[i];
        ImGui::TableNextRow();
        ImGui::PushID(static_cast<int>(i));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(b.entry.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(b.hotkey.to_string().c_str());
        if (std::find(taken.begin(), taken.end(), b.hotkey.keys) != taken.end()) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "another program holds it: it won't fire");
        }
        ImGui::TableNextColumn();
        if (ImGui::SmallButton("X")) remove = i;
        ImGui::PopID();
    }
    ImGui::EndTable();
    if (remove) show(app, keeper.remove_hotkey(bound[*remove].row, bound[*remove].hotkey.keys));
}

// The Scripts tab: Auto-Assembler scripts saved in the table, with an editor and on/off toggles
void draw_scripts(App& app) {
    auto& keeper = app.session.table();

    ImGui::TextWrapped("Auto-Assembler scripts patch the game's own code (an \"infinite health\" hook, for "
                       "example). Use them with offline / single-player games you run yourself; anti-cheat "
                       "treats this as cheating.");
    ImGui::Separator();

    // The list of saved scripts
    struct Row { size_t index; std::string name; bool enabled; };
    std::vector<Row> rows;
    keeper.with([&](const table::CheatTable& t, const std::vector<hal::ModuleInfo>&) {
        for (size_t i = 0; i < t.scripts.size(); ++i) rows.push_back({i, t.scripts[i].name, t.scripts[i].enabled});
    });

    if (!rows.empty()) {
        const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
        if (ImGui::BeginTable("scripts", 3, flags, ImVec2(0, em(8)))) {
            ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, em(2.5f));
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(8));
            ImGui::TableHeadersRow();
            std::optional<size_t> remove;
            std::optional<std::pair<size_t, bool>> toggle;
            std::optional<size_t> edit;
            for (const auto& r : rows) {
                ImGui::TableNextRow();
                ImGui::PushID(static_cast<int>(r.index));
                ImGui::TableNextColumn();
                bool on = r.enabled;
                if (ImGui::Checkbox("##on", &on)) toggle = {r.index, on};
                ImGui::TableNextColumn();
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted(r.name.c_str());
                ImGui::TableNextColumn();
                if (ImGui::SmallButton("Edit")) edit = r.index;
                ImGui::SameLine();
                if (ImGui::SmallButton("X")) remove = r.index;
                ImGui::PopID();
            }
            ImGui::EndTable();
            if (toggle) show(app, keeper.set_script_enabled(toggle->first, toggle->second));
            if (edit) {
                if (const auto s = keeper.script(*edit)) {
                    app.script_name = s->name;
                    app.script_body = s->body;
                    app.editing_script = static_cast<int>(*edit);
                    app.script_note = "Editing '" + s->name + "'. Save puts the changes back (and turns it off).";
                }
            }
            if (remove) show(app, keeper.remove_script(*remove));
        }
    } else {
        ImGui::TextDisabled("No scripts yet. Write one below, with [ENABLE] and [DISABLE] sections.");
    }

    ImGui::Separator();
    ImGui::SetNextItemWidth(em(13));
    ImGui::InputTextWithHint("##script_name", "script name", &app.script_name);
    ImGui::SameLine();
    const bool editing = app.editing_script >= 0;
    if (ImGui::Button(editing ? "Save changes" : "Add script")) {
        if (app.script_name.empty()) {
            app.script_note = "Give the script a name.";
        } else if (editing) {
            const auto s = keeper.script(static_cast<size_t>(app.editing_script));
            session::Outcome done = s && s->name == app.script_name
                ? keeper.set_script_body(static_cast<size_t>(app.editing_script), app.script_body)
                : session::Outcome::fail("The name changed; remove the old one and add this as new.");
            show(app, done);
            app.script_note = done.message;
            if (done.ok) { app.editing_script = -1; }
        } else {
            const auto done = keeper.add_script(app.script_name, app.script_body);
            show(app, done);
            app.script_note = done.message;
        }
    }
    if (editing) {
        ImGui::SameLine();
        if (ImGui::Button("New")) {
            app.editing_script = -1;
            app.script_name.clear();
            app.script_body = "[ENABLE]\n\n[DISABLE]\n";
            app.script_note.clear();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Templates...")) ImGui::OpenPopup("script_templates_popup");
    if (ImGui::BeginPopup("script_templates_popup")) {
        if (ImGui::MenuItem("AOB Hook Injection Template")) {
            app.script_name = "AOB_Hook";
            app.script_body =
                "[ENABLE]\n"
                "// Replace target.exe and pattern with your target\n"
                "aobscanmodule(INJECT, target.exe, 48 89 5C 24 ? ?)\n"
                "alloc(newmem, $1000, INJECT)\n"
                "label(code)\n"
                "label(return)\n\n"
                "newmem:\n"
                "  // Custom code here\n"
                "  // mov [rcx+0x10], #9999\n\n"
                "code:\n"
                "  // original code\n"
                "  // mov [rcx+0x10], eax\n"
                "  jmp return\n\n"
                "INJECT:\n"
                "  jmp newmem\n"
                "  nop\n"
                "return:\n"
                "registersymbol(INJECT)\n\n"
                "[DISABLE]\n"
                "INJECT:\n"
                "  // original code bytes\n"
                "  db 48 89 5C 24 08\n\n"
                "unregistersymbol(INJECT)\n"
                "dealloc(newmem)\n";
            app.script_note = "Loaded AOB Hook template into editor.";
        }
        if (ImGui::MenuItem("Code Cave / Alloc Variable Template")) {
            app.script_name = "Alloc_Variable";
            app.script_body =
                "[ENABLE]\n"
                "alloc(myvar, 4)\n"
                "registersymbol(myvar)\n\n"
                "myvar:\n"
                "  dd #100\n\n"
                "[DISABLE]\n"
                "dealloc(myvar)\n"
                "unregistersymbol(myvar)\n";
            app.script_note = "Loaded Alloc template into editor.";
        }
        if (ImGui::MenuItem("NOP Instruction Patch Template")) {
            app.script_name = "NOP_Patch";
            app.script_body =
                "[ENABLE]\n"
                "// Replace address with target address or symbol\n"
                "0x140001000:\n"
                "  nop\n"
                "  nop\n\n"
                "[DISABLE]\n"
                "0x140001000:\n"
                "  // original bytes\n"
                "  db 90 90\n";
            app.script_note = "Loaded NOP Patch template into editor.";
        }
        if (ImGui::MenuItem("Hybrid {$lua} + AutoAssembler Template")) {
            app.script_name = "Lua_Hybrid";
            app.script_body =
                "[ENABLE]\n"
                "{$lua}\n"
                "print('[AA Enable] Scanning & setting up...')\n"
                "define('MYVAL', '999')\n"
                "{$asm}\n"
                "alloc(var_slot, 8)\n"
                "registersymbol(var_slot)\n"
                "var_slot:\n"
                "  dq #MYVAL\n\n"
                "[DISABLE]\n"
                "dealloc(var_slot)\n"
                "unregistersymbol(var_slot)\n";
            app.script_note = "Loaded Hybrid {$lua} template into editor.";
        }
        ImGui::EndPopup();
    }
    if (!app.script_note.empty()) ImGui::TextWrapped("%s", app.script_note.c_str());

    if (ImGui::CollapsingHeader("Hook Engine (Live Code Caves & Detours)")) {
        const bool att = is_attached(app);
        ImGui::BeginDisabled(!att);
        ImGui::Checkbox("Detour Jump (Target -> Dest)##hook_mode", &app.hook_detour_mode);
        ImGui::SetNextItemWidth(em(12));
        ImGui::InputTextWithHint("##hook_target", "Target address (0x...)", &app.hook_target_input);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(16));
        ImGui::InputTextWithHint("##hook_arg2",
                                 app.hook_detour_mode ? "Destination address (0x...)" : "Payload hex bytes (e.g. 90 90)",
                                 &app.hook_payload_or_dest);
        ImGui::SameLine();
        if (ImGui::Button("Install Hook")) {
            const uintptr_t target = utils::parse_address(app.hook_target_input);
            if (target == 0) {
                app.hook_note = "Invalid target address.";
            } else if (app.hook_detour_mode) {
                const uintptr_t dest = utils::parse_address(app.hook_payload_or_dest);
                if (dest == 0) {
                    app.hook_note = "Invalid detour destination address.";
                } else if (auto info = app.session.hook_detour(target, dest)) {
                    app.hook_note = "Detour installed at " + utils::format_address(info->target_address) +
                                    " -> tramp " + utils::format_address(info->trampoline_address);
                } else {
                    app.hook_note = "Failed to install detour hook.";
                }
            } else {
                std::vector<uint8_t> bytes;
                std::string hex;
                bool valid_hex = true;
                for (size_t i = 0; i < app.hook_payload_or_dest.size(); ++i) {
                    const unsigned char c = static_cast<unsigned char>(app.hook_payload_or_dest[i]);
                    if (std::isspace(c) || c == ',' || c == ';') continue;
                    if (c == '0' && i + 1 < app.hook_payload_or_dest.size() &&
                        (app.hook_payload_or_dest[i + 1] == 'x' || app.hook_payload_or_dest[i + 1] == 'X')) {
                        ++i;
                        continue;
                    }
                    if (!std::isxdigit(c)) { valid_hex = false; break; }
                    hex.push_back(static_cast<char>(c));
                }
                if (!valid_hex || hex.empty() || (hex.size() % 2) != 0) {
                    app.hook_note = "Invalid hex payload bytes (example: 90 90).";
                } else {
                    for (size_t i = 0; i < hex.size(); i += 2) {
                        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
                    }
                    if (auto info = app.session.hook_payload(target, bytes)) {
                        app.hook_note = "Cave hook installed at " + utils::format_address(info->target_address) +
                                        " -> cave " + utils::format_address(info->cave_address);
                    } else {
                        app.hook_note = "Failed to install payload cave hook.";
                    }
                }
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Unhook All")) {
            app.session.unhook_all();
            app.hook_note = "Removed all active HookEngine hooks.";
        }
        ImGui::EndDisabled();
        if (!app.hook_note.empty()) ImGui::TextWrapped("%s", app.hook_note.c_str());

        const auto hooks = app.session.active_hooks();
        if (!hooks.empty() && ImGui::BeginTable("##active_hooks", 5, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthFixed, em(10));
            ImGui::TableSetupColumn("Cave / Dest", ImGuiTableColumnFlags_WidthFixed, em(10));
            ImGui::TableSetupColumn("Trampoline", ImGuiTableColumnFlags_WidthFixed, em(10));
            ImGui::TableSetupColumn("Stolen", ImGuiTableColumnFlags_WidthFixed, em(4));
            ImGui::TableSetupColumn("Actions");
            ImGui::TableHeadersRow();
            for (const auto& h : hooks) {
                ImGui::PushID(static_cast<int>(h.target_address & 0x7FFFFFFF));
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(utils::format_address(h.target_address).c_str());
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(utils::format_address(h.cave_address ? h.cave_address : h.destination_address).c_str());
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(utils::format_address(h.trampoline_address).c_str());
                ImGui::TableSetColumnIndex(3); ImGui::Text("%zu", h.stolen_bytes_count);
                ImGui::TableSetColumnIndex(4);
                if (ImGui::SmallButton("Disasm")) {
                    app.disasm_input = utils::format_address(h.target_address);
                    app.select_tab = Tab::Disasm;
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Remove")) {
                    app.session.unhook(h.target_address);
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }

    ImGui::InputTextMultiline("##script_body", &app.script_body,
                              ImVec2(-FLT_MIN, std::max(em(8), ImGui::GetContentRegionAvail().y)),
                              ImGuiInputTextFlags_AllowTabInput);
}

// The Dissect tab: interactive ReClass-style live struct studio
void draw_dissect(App& app) {
    // Launched with an address to dissect: do it once, now that a process is attached
    if (app.dissect_pending && is_attached(app)) {
        app.dissect_pending = false;
        if (const uintptr_t address = utils::parse_address(app.dissect_input)) {
            view::StructureDissector d(app.session.process_ptr());
            app.dissect_result = d.dissect(address, static_cast<size_t>(app.dissect_bytes),
                                           app.session.process().get_modules());
        }
    }

    if (!app.dissect_history.empty()) {
        if (ImGui::Button("< Back")) {
            uintptr_t prev = app.dissect_history.back();
            app.dissect_history.pop_back();
            app.dissect_input = utils::format_address(prev);
            view::StructureDissector d(app.session.process_ptr());
            app.dissect_result = d.dissect(prev, static_cast<size_t>(app.dissect_bytes),
                                           app.session.process().get_modules());
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Go back to the parent struct.");
        ImGui::SameLine();
    }

    ImGui::SetNextItemWidth(em(12));
    ImGui::InputTextWithHint("##dissect_addr", "0x... or a result/entry address", &app.dissect_input);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(4.5f));
    ImGui::InputInt("bytes", &app.dissect_bytes);
    app.dissect_bytes = std::clamp(app.dissect_bytes, 8, 4096);
    ImGui::SameLine();
    ImGui::BeginDisabled(!is_attached(app) || job_running(app));
    if (ImGui::Button("Dissect")) {
        const uintptr_t address = utils::parse_address(app.dissect_input);
        if (address == 0) {
            app.dissect_note = "Enter the object's address (e.g. a pointer value from the Memory tab).";
            app.dissect_result.reset();
        } else {
            view::StructureDissector d(app.session.process_ptr());
            app.dissect_result = d.dissect(address, static_cast<size_t>(app.dissect_bytes),
                                           app.session.process().get_modules());
            app.dissect_note.clear();
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::Checkbox("Live 60fps", &app.dissect_live_update);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Refresh field values 60 times a second and highlight changes.");

    if (app.dissect_result && !app.dissect_result->fields.empty()) {
        ImGui::SameLine();
        if (ImGui::Button("Copy C++")) {
            ImGui::SetClipboardText(app.dissect_result->to_cpp().c_str());
            app.dissect_note = "Copied the C++ struct to the clipboard.";
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy JSON")) {
            auto json_escape = [](const std::string& s) {
                std::string out;
                out.reserve(s.size() + 8);
                for (unsigned char c : s) {
                    if (c == '"') out += "\\\"";
                    else if (c == '\\') out += "\\\\";
                    else if (c == '\n') out += "\\n";
                    else if (c == '\r') out += "\\r";
                    else if (c == '\t') out += "\\t";
                    else if (c >= 0x20) out.push_back(static_cast<char>(c));
                }
                return out;
            };
            std::function<std::string(const view::StructLayout&, int)> emit_layout;
            emit_layout = [&](const view::StructLayout& lay, int depth) -> std::string {
                std::string pad(static_cast<size_t>(depth * 2), ' ');
                std::ostringstream js;
                js << pad << "{\n";
                js << pad << "  \"address\": \"" << utils::format_address(lay.address) << "\",\n";
                js << pad << "  \"class_name\": \"" << json_escape(lay.class_name) << "\",\n";
                js << pad << "  \"size\": " << lay.size << ",\n";
                js << pad << "  \"fields\": [\n";
                for (size_t fi = 0; fi < lay.fields.size(); ++fi) {
                    const auto& fld = lay.fields[fi];
                    js << pad << "    { \"offset\": " << fld.offset
                       << ", \"size\": " << fld.size
                       << ", \"type\": \"" << json_escape(fld.type) << "\""
                       << ", \"name\": \"" << json_escape(fld.name) << "\""
                       << ", \"value\": \"" << json_escape(fld.value) << "\"";
                    if (fld.child_pointer != 0) {
                        js << ", \"child_pointer\": \"" << utils::format_address(fld.child_pointer) << "\"";
                        auto it_child = app.dissect_children.find(fld.child_pointer);
                        if (depth < 2 && it_child != app.dissect_children.end() && app.dissect_expanded.count(fld.child_pointer)) {
                            js << ", \"child\": \n" << emit_layout(it_child->second, depth + 2) << pad << "    ";
                        }
                    }
                    js << " }" << (fi + 1 < lay.fields.size() ? "," : "") << "\n";
                }
                js << pad << "  ]\n";
                js << pad << "}";
                return js.str();
            };
            ImGui::SetClipboardText(emit_layout(*app.dissect_result, 0).c_str());
            app.dissect_note = "Copied the struct JSON schema to the clipboard.";
        }
    }
    if (!app.dissect_note.empty()) ImGui::TextWrapped("%s", app.dissect_note.c_str());

    if (ImGui::CollapsingHeader("Multi-Struct Side-by-Side Compare (Player vs Enemies)")) {
        ImGui::SetNextItemWidth(em(26));
        ImGui::InputTextWithHint("##cmp_addrs", "Space/comma addresses (e.g. 0x10000, 0x10200, 0x10400)", &app.dissect_compare_input);
        ImGui::SameLine();
        ImGui::Checkbox("Differences Only", &app.dissect_compare_diff_only);
        ImGui::SameLine();
        ImGui::BeginDisabled(!is_attached(app));
        if (ImGui::Button("Compare Instances")) {
            std::vector<uintptr_t> addrs;
            std::string normalized = app.dissect_compare_input;
            for (char& ch : normalized) if (ch == ',' || ch == ';') ch = ' ';
            std::istringstream iss(normalized);
            std::string tok;
            while (iss >> tok) {
                if (uintptr_t a = utils::parse_address(tok)) addrs.push_back(a);
            }
            if (addrs.size() < 2) {
                app.dissect_note = "Enter 2 or more hex addresses to compare side-by-side.";
            } else {
                view::StructureDissector d(app.session.process_ptr());
                app.dissect_compare_result = d.compare(addrs, static_cast<size_t>(app.dissect_bytes),
                                                       app.session.process().get_modules(), false);
                app.dissect_note = "Compared " + std::to_string(addrs.size()) + " instances (" +
                                   std::to_string(app.dissect_compare_result->rows.size()) + " fields).";
            }
        }
        if (app.dissect_compare_result) {
            ImGui::SameLine();
            if (ImGui::Button("Refresh##cmp")) {
                app.dissect_compare_result->refresh(app.session.process(), app.session.process().get_modules());
            }
            ImGui::SameLine();
            if (ImGui::Button("Copy Diff")) {
                ImGui::SetClipboardText(app.dissect_compare_result->to_report(app.dissect_compare_diff_only).c_str());
                app.dissect_note = "Copied comparison table to clipboard.";
            }
        }
        ImGui::EndDisabled();

        if (app.dissect_compare_result && !app.dissect_compare_result->rows.empty()) {
            const auto& cmp = *app.dissect_compare_result;
            if (app.dissect_live_update && is_attached(app)) {
                app.dissect_compare_result->refresh(app.session.process(), app.session.process().get_modules());
            }
            const int cols = 3 + static_cast<int>(cmp.labels.size());
            if (ImGui::BeginTable("cmp_structs_tbl", cols,
                                  ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV | ImGuiTableFlags_ScrollY,
                                  ImVec2(0, em(11)))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, em(4.5f));
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(5));
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, em(7));
                for (const auto& lbl : cmp.labels) ImGui::TableSetupColumn(lbl.c_str());
                ImGui::TableHeadersRow();

                for (const auto& r : cmp.rows) {
                    if (app.dissect_compare_diff_only && !r.differs) continue;
                    ImGui::TableNextRow();
                    if (r.differs) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(100, 65, 20, 90));
                    ImGui::TableNextColumn(); ImGui::Text("+0x%zX", r.offset);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(r.type.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(r.name.c_str());
                    for (const auto& v : r.values) {
                        ImGui::TableNextColumn();
                        if (r.differs) ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%s", v.c_str());
                        else ImGui::TextUnformatted(v.c_str());
                    }
                }
                ImGui::EndTable();
            }
        }
    }

    if (!app.dissect_result) {
        ImGui::TextDisabled("Reads an object as a C++ struct: the vtable, the class name from RTTI, and each field "
                            "by what it is. Click a pointer's address in the Memory tab, then paste it here.");
        return;
    }

    // Live update field values
    if (app.dissect_live_update && is_attached(app)) {
        app.dissect_result->refresh_values(app.session.process(), app.session.process().get_modules());
    }

    auto& layout = *app.dissect_result;
    if (!layout.class_name.empty()) {
        ImGui::Text("class %s", layout.class_name.c_str());
        if (layout.vtable_functions) { ImGui::SameLine(); ImGui::TextDisabled("(vtable: %zu functions)", layout.vtable_functions); }
    } else if (layout.vtable_functions) {
        ImGui::TextDisabled("vtable with %zu functions (no RTTI name)", layout.vtable_functions);
    } else {
        ImGui::TextDisabled("no vtable found at this address");
    }

    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("dissect", 6, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, em(4));
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(5.5f));
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, em(7));
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, em(8.5f));
    ImGui::TableSetupColumn("Note", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, em(9.5f));
    ImGui::TableHeadersRow();

    std::optional<size_t> add_field_index;
    std::optional<uintptr_t> inspect_pointer_target;
    std::optional<std::pair<size_t, std::string>> change_type_req;

    static const char* kCycleTypes[] = {"int32_t", "float", "int64_t", "double", "void*", "int16_t", "int8_t"};

    for (size_t i = 0; i < layout.fields.size(); ++i) {
        auto& f = layout.fields[i];
        ImGui::TableNextRow();
        ImGui::PushID(static_cast<int>(i));

        ImGui::TableNextColumn();
        ImGui::Text("+0x%zx", f.offset);

        ImGui::TableNextColumn();
        if (ImGui::SmallButton(f.type.c_str())) {
            std::string next_t = "int32_t";
            for (size_t t = 0; t < IM_ARRAYSIZE(kCycleTypes); ++t) {
                if (f.type == kCycleTypes[t]) {
                    next_t = kCycleTypes[(t + 1) % IM_ARRAYSIZE(kCycleTypes)];
                    break;
                }
            }
            change_type_req = {i, next_t};
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Click to cycle type (int32 -> float -> int64 -> double -> void* -> int16 -> int8).");

        ImGui::TableNextColumn();
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputTextWithHint("##fname", "name", &f.name);

        ImGui::TableNextColumn();
        if (f.changed) {
            ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.4f, 1.0f), "%s", f.value.c_str());
        } else {
            ImGui::TextUnformatted(f.value.c_str());
        }

        ImGui::TableNextColumn();
        ImGui::TextUnformatted(f.note.c_str());

        ImGui::TableNextColumn();
        if (f.child_pointer != 0) {
            const bool expanded = app.dissect_expanded.count(f.child_pointer) > 0;
            if (ImGui::SmallButton(expanded ? "[-]" : "[+]")) {
                if (expanded) {
                    app.dissect_expanded.erase(f.child_pointer);
                } else {
                    if (!app.dissect_children.count(f.child_pointer) && is_attached(app)) {
                        view::StructureDissector d(app.session.process_ptr());
                        app.dissect_children[f.child_pointer] = d.dissect(
                            f.child_pointer, std::min<size_t>(static_cast<size_t>(app.dissect_bytes), 256),
                            app.session.process().get_modules());
                    }
                    app.dissect_expanded.insert(f.child_pointer);
                }
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Expand/collapse child struct inline.");
            ImGui::SameLine();
            if (ImGui::SmallButton("Inspect ->")) inspect_pointer_target = f.child_pointer;
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Dissect child object at %s", utils::format_address(f.child_pointer).c_str());
            ImGui::SameLine();
        }
        if (ImGui::SmallButton("+ Table")) add_field_index = i;
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Add this field to the active Cheat Table.");

        ImGui::PopID();

        if (f.child_pointer != 0 && app.dissect_expanded.count(f.child_pointer)) {
            auto it_child = app.dissect_children.find(f.child_pointer);
            if (it_child != app.dissect_children.end()) {
                if (app.dissect_live_update && is_attached(app)) {
                    it_child->second.refresh_values(app.session.process(), app.session.process().get_modules());
                }
                const auto& cl = it_child->second;
                for (size_t ci = 0; ci < cl.fields.size(); ++ci) {
                    const auto& cf = cl.fields[ci];
                    ImGui::TableNextRow();
                    ImGui::PushID(static_cast<int>(100000 + i * 256 + ci));
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("  +0x%zx", cf.offset);
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", cf.type.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", cf.name.c_str());
                    ImGui::TableNextColumn();
                    if (cf.changed) {
                        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.4f, 1.0f), "%s", cf.value.c_str());
                    } else {
                        ImGui::TextUnformatted(cf.value.c_str());
                    }
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", cf.note.c_str());
                    ImGui::TableNextColumn();
                    if (cf.child_pointer != 0) {
                        if (ImGui::SmallButton("Inspect ->")) inspect_pointer_target = cf.child_pointer;
                    }
                    ImGui::PopID();
                }
            }
        }
    }
    ImGui::EndTable();

    if (change_type_req && is_attached(app)) {
        layout.set_field_type(change_type_req->first, change_type_req->second, app.session.process());
    }

    if (inspect_pointer_target && *inspect_pointer_target != 0) {
        app.dissect_history.push_back(layout.address);
        app.dissect_input = utils::format_address(*inspect_pointer_target);
        view::StructureDissector d(app.session.process_ptr());
        app.dissect_result = d.dissect(*inspect_pointer_target, static_cast<size_t>(app.dissect_bytes),
                                       app.session.process().get_modules());
    }

    if (add_field_index && *add_field_index < layout.fields.size()) {
        const auto& f = layout.fields[*add_field_index];
        scanner::DataType dt = scanner::DataType::Int32;
        if (f.type == "float") dt = scanner::DataType::Float;
        else if (f.type == "double") dt = scanner::DataType::Double;
        else if (f.type == "int64_t" || f.type == "uint64_t") dt = scanner::DataType::Int64;
        else if (f.type == "int16_t" || f.type == "uint16_t") dt = scanner::DataType::Int16;
        else if (f.type == "int8_t" || f.type == "uint8_t") dt = scanner::DataType::Int8;
        else if (f.type.find("char[") != std::string::npos) dt = scanner::DataType::String;
        std::string desc = (layout.class_name.empty() ? "Struct" : layout.class_name) + "." + (f.name.empty() ? ("field_" + utils::format_address(f.offset)) : f.name);
        show(app, app.session.table().add_address(layout.address + f.offset, dt, desc));
    }
}

// Live Value Oscilloscope: plots waveform of a monitored value over time
void draw_oscilloscope(App& app) {
    if (app.plot_entry_index < 0) return;
    bool open = true;
    ImGui::SetNextWindowSize(ImVec2(em(26), em(16)), ImGuiCond_FirstUseEver);
    std::string title = "Live Oscilloscope - Entry #" + std::to_string(app.plot_entry_index) + "###plot_window";
    if (ImGui::Begin(title.c_str(), &open)) {
        if (!is_attached(app)) {
            ImGui::TextDisabled("Target not attached.");
        } else {
            float cur_val = 0.0f;
            std::string desc;
            app.session.table().with([&](const table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules) {
                if (static_cast<size_t>(app.plot_entry_index) < t.entries.size()) {
                    const auto& e = t.entries[app.plot_entry_index];
                    desc = e.description;
                    if (auto val = table::read_entry(e, app.session.process(), modules)) {
                        scanner::dispatch_numeric(e.type, [&]<typename T>() {
                            if constexpr (std::is_arithmetic_v<T>) {
                                if (std::holds_alternative<T>(val->value)) {
                                    cur_val = static_cast<float>(std::get<T>(val->value));
                                }
                            }
                        });
                    }
                }
            });
            app.push_plot(cur_val);

            ImGui::Text("Monitoring: %s", desc.empty() ? ("Entry #" + std::to_string(app.plot_entry_index)).c_str() : desc.c_str());
            ImGui::Text("Current: %.3f", cur_val);
            ImGui::SameLine();
            ImGui::TextDisabled("(Min: %.2f | Max: %.2f)", app.plot_min, app.plot_max);

            std::vector<float> ordered(app.plot_count);
            for (size_t i = 0; i < app.plot_count; ++i) {
                size_t idx = (app.plot_head + app.kPlotCapacity - app.plot_count + i) % app.kPlotCapacity;
                ordered[i] = app.plot_history[idx];
            }

            ImGui::PlotLines("##waveform", ordered.data(), static_cast<int>(ordered.size()), 0, nullptr,
                             app.plot_min, app.plot_max, ImVec2(-FLT_MIN, em(8.5f)));
        }
    }
    ImGui::End();
    if (!open) app.plot_entry_index = -1;
}

// The Watch tab: "find what writes (or accesses) this address" with a hardware breakpoint
void draw_watch(App& app) {
    static const int kSizes[] = {1, 2, 4, 8};
    static const char* const kSizeNames[] = {"1 byte", "2 bytes", "4 bytes", "8 bytes"};

    ImGui::TextWrapped("Sets a hardware breakpoint and lists the code that touches the address. Enter the "
                       "address (from a result or a table entry), start the watch, change the value in the "
                       "game, and the instruction that changed it shows below with its base pointer.");
    ImGui::Separator();

    ImGui::SetNextItemWidth(em(12));
    ImGui::InputTextWithHint("##watch_addr", "0x...", &app.watch_input);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(6));
    ImGui::Combo("##watch_size", &app.watch_size_index, kSizeNames, IM_ARRAYSIZE(kSizeNames));

    const bool attached = is_attached(app);
    const auto active_watches = app.session.watched_addresses();
    const bool slots_full = active_watches.size() >= 4;
    ImGui::BeginDisabled(!attached || slots_full);
    if (ImGui::Button("Find writes")) {
        const uintptr_t a = utils::parse_address(app.watch_input);
        if (!a) app.watch_note = "Enter the address to watch.";
        else if (!app.session.watch(a, static_cast<size_t>(kSizes[app.watch_size_index]), debugger::WatchKind::Write)) {
            app.watch_note = "Could not start the watch (check privileges or address alignment).";
        } else {
            app.watch_note = "Watching writes (DR0-DR3). Change the value in the game.";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Find reads/writes")) {
        const uintptr_t a = utils::parse_address(app.watch_input);
        if (a && app.session.watch(a, static_cast<size_t>(kSizes[app.watch_size_index]), debugger::WatchKind::Access)) {
            app.watch_note = "Watching reads and writes (DR0-DR3). Use the value in the game.";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Find executes")) {
        const uintptr_t a = utils::parse_address(app.watch_input);
        if (a && app.session.watch(a, 1, debugger::WatchKind::Execute)) {
            app.watch_note = "Watching code execution (HW Execute BP).";
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!app.session.watching());
    if (ImGui::Button("Stop All")) { app.session.stop_watch(); app.watch_note = "Stopped all watches."; }
    ImGui::EndDisabled();

    if (!active_watches.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "active DR slots: %zu/4", active_watches.size());
        for (size_t wi = 0; wi < active_watches.size(); ++wi) {
            ImGui::PushID(static_cast<int>(wi + 1000));
            ImGui::BulletText("DR%zu: %s", wi, utils::format_address(active_watches[wi]).c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("x")) {
                app.session.stop_watch_address(active_watches[wi]);
            }
            ImGui::PopID();
        }
    }
    if (!app.watch_note.empty()) ImGui::TextWrapped("%s", app.watch_note.c_str());

    const auto hits = app.session.watch_hits();
    if (hits.empty()) {
        ImGui::TextDisabled(app.session.watching() ? "No writes yet - change the value in the game."
                                                   : "Start a watch to see what touches the address.");
        return;
    }

    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("watch_hits", 5, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthFixed, em(11));
    ImGui::TableSetupColumn("Disassembly", ImGuiTableColumnFlags_WidthStretch, 1.4f);
    ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, em(3));
    ImGui::TableSetupColumn("Base pointer", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(12.5f));
    ImGui::TableHeadersRow();

    std::optional<uintptr_t> scan_base;
    for (size_t i = 0; i < hits.size(); ++i) {
        const auto& h = hits[i];
        ImGui::TableNextRow();
        ImGui::PushID(static_cast<int>(i));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(h.location.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(h.disassembly.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%zu", h.count);
        ImGui::TableNextColumn();
        if (!h.base_register.empty() && h.base_pointer()) {
            ImGui::Text("%s = %s +0x%llx", h.base_register.c_str(), utils::format_address(h.base_pointer()).c_str(),
                        static_cast<unsigned long long>(h.base_offset));
        } else {
            ImGui::TextDisabled("(static / no base)");
        }
        ImGui::TableNextColumn();
        if (h.instruction) {
            if (ImGui::SmallButton("Disasm")) {
                app.disasm_input = utils::format_address(h.instruction);
                app.select_tab = Tab::Disasm;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Open in Disassembly view to inspect or NOP.");
            ImGui::SameLine();
        }
        if (ImGui::SmallButton("Regs")) {
            app.watch_selected_hit = static_cast<int>(i);
            ImGui::OpenPopup("Registers Inspector");
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Inspect full CPU register snapshot (RAX, RBX, RCX, RDX, etc.) at hit.");
        ImGui::SameLine();
        if (!h.base_register.empty() && h.base_pointer()) {
            if (ImGui::SmallButton("Scan")) scan_base = h.base_pointer();
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Pointer-scan the base pointer for a path that survives restarts.");
        }
        ImGui::PopID();
    }
    ImGui::EndTable();

    if (app.watch_selected_hit >= 0 && app.watch_selected_hit < static_cast<int>(hits.size())) {
        const auto& hit = hits[app.watch_selected_hit];
        bool p_open = true;
        ImGui::SetNextWindowSize(ImVec2(em(38), em(26)), ImGuiCond_FirstUseEver);
        if (ImGui::BeginPopupModal("Registers Inspector", &p_open)) {
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Instruction: %s (%s)",
                               hit.location.c_str(), utils::format_address(hit.instruction).c_str());
            ImGui::TextWrapped("Disassembly: %s", hit.disassembly.c_str());
            ImGui::Separator();

            const auto& r = hit.registers;

            auto draw_reg_row = [](const char* name1, uint64_t val1, const char* name2, uint64_t val2) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%-6s", name1);
                ImGui::SameLine();
                ImGui::Text("0x%016llX (%lld)", static_cast<unsigned long long>(val1), static_cast<long long>(val1));

                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%-6s", name2);
                ImGui::SameLine();
                ImGui::Text("0x%016llX (%lld)", static_cast<unsigned long long>(val2), static_cast<long long>(val2));
            };

            if (ImGui::BeginTable("regs_table", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn("Registers (Group A)", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Registers (Group B)", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                draw_reg_row("RAX", r.rax, "R8",  r.r8);
                draw_reg_row("RBX", r.rbx, "R9",  r.r9);
                draw_reg_row("RCX", r.rcx, "R10", r.r10);
                draw_reg_row("RDX", r.rdx, "R11", r.r11);
                draw_reg_row("RSI", r.rsi, "R12", r.r12);
                draw_reg_row("RDI", r.rdi, "R13", r.r13);
                draw_reg_row("RBP", r.rbp, "R14", r.r14);
                draw_reg_row("RSP", r.rsp, "R15", r.r15);
                draw_reg_row("RIP", r.rip, "EFL", r.eflags);

                ImGui::EndTable();
            }

            ImGui::Separator();
            // Breakdown EFLAGS
            const uint64_t ef = r.eflags;
            ImGui::Text("Flags: CF=%d  PF=%d  AF=%d  ZF=%d  SF=%d  TF=%d  IF=%d  DF=%d  OF=%d",
                        (int)(ef & 1), (int)((ef >> 2) & 1), (int)((ef >> 4) & 1),
                        (int)((ef >> 6) & 1), (int)((ef >> 7) & 1), (int)((ef >> 8) & 1),
                        (int)((ef >> 9) & 1), (int)((ef >> 10) & 1), (int)((ef >> 11) & 1));

            ImGui::Spacing();
            if (ImGui::Button("Close", ImVec2(em(6), 0)) || !p_open) {
                app.watch_selected_hit = -1;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

    if (scan_base) {
        app.ptr_target = utils::format_address(*scan_base);
        app.select_tab = Tab::PointerScanner;
        app.status = "Pointer scanner target set to the base pointer " + app.ptr_target + ": press Scan.";
    }
}

// The Disasm tab: interactive disassembly, live instruction patching, and single-step debugging
void draw_disasm(App& app) {
    ImGui::TextWrapped("Interactive x86-64 Disassembler & Step Debugger: set INT 3 breakpoints, single-step instructions (F7/F8), and inspect live call stack.");
    ImGui::Separator();

    const bool attached = is_attached(app);
    auto* dbg = app.session.step_debugger();
    const bool dbg_attached = dbg && dbg->is_attached();
    const bool dbg_paused = dbg && dbg->is_paused();
    const uintptr_t cur_rip = dbg ? dbg->current_rip() : 0;

    // --- Interactive Debugger Control Toolbar ---
    ImGui::BeginDisabled(!attached);

    static const char* const kDbgBackends[] = {"Win32 DebugAPI", "VEH (In-Process)"};
    if (!dbg_attached) {
        ImGui::SetNextItemWidth(em(10));
        ImGui::Combo("##dbg_backend", &app.dbg_backend_index, kDbgBackends, IM_ARRAYSIZE(kDbgBackends));
        ImGui::SameLine();
        if (ImGui::Button("Attach Debugger")) {
            auto be = (app.dbg_backend_index == 1) ? debugger::DebugBackend::VEH : debugger::DebugBackend::Win32DebugAPI;
            if (app.session.dbg_attach(be)) {
                app.dbg_status_note = std::string("Debugger attached (") + kDbgBackends[app.dbg_backend_index] + ").";
            } else {
                app.dbg_status_note = "Attach failed: " + (dbg ? dbg->last_error() : std::string("unknown error"));
            }
        }
    } else {
        if (ImGui::Button("Detach Debugger")) {
            app.session.dbg_detach();
            app.dbg_status_note = "Debugger detached.";
        }
        ImGui::SameLine();
        ImGui::TextDisabled("[%s]", dbg->backend() == debugger::DebugBackend::VEH ? "VEH" : "Win32");
    }

    ImGui::SameLine();
    ImGui::BeginDisabled(!dbg_attached);

    if (!dbg_paused) {
        if (ImGui::Button("Pause")) {
            if (app.session.dbg_pause()) {
                app.dbg_status_note = "Target paused at RIP.";
            }
        }
    } else {
        if (ImGui::Button("Resume (F9)") || ImGui::IsKeyPressed(ImGuiKey_F9)) {
            app.session.dbg_resume();
            app.dbg_status_note = "Resumed execution.";
        }
    }

    ImGui::SameLine();
    ImGui::BeginDisabled(!dbg_paused);

    if (ImGui::Button("Step Into (F7)") || (dbg_paused && ImGui::IsKeyPressed(ImGuiKey_F7))) {
        if (app.session.dbg_step_into()) {
            app.dbg_status_note = "Stepped 1 instruction.";
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Execute single instruction (F7), entering functions if CALL.");

    ImGui::SameLine();
    if (ImGui::Button("Step Over (F8)") || (dbg_paused && ImGui::IsKeyPressed(ImGuiKey_F8))) {
        if (app.session.dbg_step_over()) {
            app.dbg_status_note = "Stepping over...";
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Execute single instruction, stepping over CALLs (F8).");

    ImGui::SameLine();
    if (ImGui::Button("Step Out")) {
        if (app.session.dbg_step_out()) {
            app.dbg_status_note = "Stepping out of current function...";
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Execute until current function returns.");

    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(4.5f));
    ImGui::InputInt("##trace_steps", &app.trace_step_count, 0, 0);
    app.trace_step_count = std::clamp(app.trace_step_count, 1, 200);
    ImGui::SameLine();
    if (ImGui::Button("Break & Trace")) {
        int ran = 0;
        for (int s = 0; s < app.trace_step_count; ++s) {
            if (!app.session.dbg_step_into()) break;
            ++ran;
            for (int w = 0; w < 200 && dbg && !dbg->is_paused(); ++w) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            if (!dbg || !dbg->is_paused()) break;
        }
        app.dbg_status_note = "Break & Trace executed " + std::to_string(ran) + " step(s).";
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Single-step N instructions and record registers into Execution Trace Log.");

    ImGui::EndDisabled(); // !dbg_paused
    ImGui::EndDisabled(); // !dbg_attached
    ImGui::EndDisabled(); // !attached

    // Debugger state badge
    ImGui::SameLine();
    if (!dbg_attached) {
        ImGui::TextDisabled("[DEBUGGER: IDLE]");
    } else if (dbg_paused) {
        if (dbg->state() == debugger::DebuggerState::PausedAtBreakpoint) {
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "[PAUSED AT BREAKPOINT: %s]", utils::format_address(cur_rip).c_str());
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.2f, 1.0f), "[PAUSED AT STEP: %s]", utils::format_address(cur_rip).c_str());
        }
    } else {
        ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.4f, 1.0f), "[DEBUGGER: RUNNING]");
    }

    if (!app.dbg_status_note.empty()) {
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "[*] %s", app.dbg_status_note.c_str());
    }

    ImGui::SetNextItemWidth(em(20));
    ImGui::InputTextWithHint("##bp_cond", "BP Condition (e.g. rax == 100 && dword[rcx+8] > 0)", &app.bp_condition_input);
    ImGui::SameLine();
    ImGui::Checkbox("Tracepoint (Log & Continue)", &app.bp_trace_mode);

    ImGui::Spacing();
    ImGui::Separator();

    // Disassembly location controls
    auto load_disasm = [&](uintptr_t addr, bool push_back) {
        if (addr == 0) {
            app.disasm_note = "Please enter a valid memory address.";
            app.disasm_instructions.clear();
            return;
        }
        if (push_back) {
            if (const uintptr_t cur = utils::parse_address(app.disasm_input); cur != 0 && cur != addr) {
                app.disasm_back.push_back(cur);
            }
        }
        app.disasm_input = utils::format_address(addr);
        size_t buf_size = static_cast<size_t>(app.disasm_count) * 15;
        std::vector<uint8_t> code(buf_size);
        if (app.session.process().read_raw(addr, code.data(), buf_size)) {
            const bool is_64 = (app.session.process().pointer_size() != 4);
            app.disasm_instructions = debugger::Disassembler::disassemble_range(
                code.data(), buf_size, addr, static_cast<size_t>(app.disasm_count), is_64);
            app.session.annotate_disassembly(app.disasm_instructions);
            app.disasm_selected_row = app.disasm_instructions.empty() ? -1 : 0;
            app.disasm_note.clear();
        } else {
            app.disasm_note = "Could not read memory at " + utils::format_address(addr);
            app.disasm_instructions.clear();
        }
    };

    if (!app.disasm_back.empty()) {
        if (ImGui::Button("< Back##disasm")) {
            uintptr_t prev = app.disasm_back.back();
            app.disasm_back.pop_back();
            load_disasm(prev, false);
        }
        ImGui::SameLine();
    }
    ImGui::SetNextItemWidth(em(12));
    ImGui::InputTextWithHint("##disasm_addr", "address (e.g. 0x7FF...)", &app.disasm_input);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(6));
    ImGui::SliderInt("##count", &app.disasm_count, 5, 50, "%d insts");
    ImGui::SameLine();
    ImGui::BeginDisabled(!attached || job_running(app));
    if (ImGui::Button("Disassemble")) {
        load_disasm(utils::parse_address(app.disasm_input), false);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("-16") && utils::parse_address(app.disasm_input) > 16) {
        load_disasm(utils::parse_address(app.disasm_input) - 16, false);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("+Next") && !app.disasm_instructions.empty()) {
        const auto& last = app.disasm_instructions.back();
        load_disasm(last.address + last.length, false);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Build CFG")) {
        const uintptr_t entry = utils::parse_address(app.disasm_input);
        if (entry) {
            app.disasm_cfg = app.session.build_cfg(entry, 256, 32);
            app.disasm_view_mode = 1;
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::TextUnformatted("|");
    ImGui::SameLine();
    if (ImGui::RadioButton("List", app.disasm_view_mode == 0)) app.disasm_view_mode = 0;
    ImGui::SameLine();
    if (ImGui::RadioButton("CFG Graph", app.disasm_view_mode == 1)) app.disasm_view_mode = 1;
    ImGui::SameLine();
    if (ImGui::RadioButton("Ultimap", app.disasm_view_mode == 2)) app.disasm_view_mode = 2;

    if (app.disasm_view_mode == 2) {
        ImGui::SeparatorText("Ultimap Execution Frequency Profiler");
        ImGui::SetNextItemWidth(em(12));
        ImGui::InputTextWithHint("##um_mod", "Module filter (optional)", &app.ultimap_module_filter);
        ImGui::SameLine();
        ImGui::BeginDisabled(!attached);
        if (ImGui::Button("Discover")) {
            app.session.ultimap().discover_functions(app.session.process(), app.ultimap_module_filter, 256);
            app.ultimap_candidates = app.session.ultimap().ranked_candidates();
        }
        ImGui::SameLine();
        if (ImGui::Button("Arm Tracepoints") && dbg_attached) {
            if (auto* dc = app.session.debug_coordinator()) app.session.ultimap().arm_tracepoints(*dc);
        }
        ImGui::SameLine();
        if (ImGui::Button("Begin Window")) {
            if (auto* dc = app.session.debug_coordinator()) app.session.ultimap().sync_from_debugger(*dc);
            app.session.ultimap().begin_action_window();
            app.ultimap_candidates = app.session.ultimap().ranked_candidates();
        }
        ImGui::SameLine();
        if (ImGui::Button("Mark Idle")) {
            if (auto* dc = app.session.debug_coordinator()) app.session.ultimap().sync_from_debugger(*dc);
            app.session.ultimap().mark_idle_noisy();
            app.ultimap_candidates = app.session.ultimap().ranked_candidates();
        }
        ImGui::SameLine();
        if (ImGui::Button("Keep Executed")) {
            if (auto* dc = app.session.debug_coordinator()) app.session.ultimap().sync_from_debugger(*dc);
            app.session.ultimap().keep_only_executed();
            app.ultimap_candidates = app.session.ultimap().ranked_candidates();
        }
        ImGui::SameLine();
        if (ImGui::Button("Reset##um")) {
            app.session.ultimap().reset();
            app.ultimap_candidates = app.session.ultimap().ranked_candidates();
        }
        ImGui::EndDisabled();

        ImGui::Text("Active Candidates: %zu / %zu", app.session.ultimap().active_count(), app.session.ultimap().total_count());
        if (!app.ultimap_candidates.empty() && ImGui::BeginTable("um_tbl", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(16)))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(11));
            ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, em(5));
            ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, em(10));
            ImGui::TableHeadersRow();
            for (const auto& f : app.ultimap_candidates) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(f.address).c_str());
                ImGui::TableNextColumn(); ImGui::Text("%zu", f.window_hits);
                ImGui::TableNextColumn(); ImGui::Text("%s!%s", f.module_name.c_str(), f.name.c_str());
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(f.address & 0x7FFFFFFF));
                if (ImGui::SmallButton("CFG")) {
                    app.disasm_input = utils::format_address(f.address);
                    app.disasm_cfg = app.session.build_cfg(f.address, 256, 32);
                    app.disasm_view_mode = 1;
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        return;
    }

    if (app.disasm_view_mode == 1) {
        if (!app.disasm_cfg || app.disasm_cfg->blocks.empty()) {
            ImGui::TextDisabled("Enter an entry address above and click 'Build CFG' to inspect the Control-Flow Graph.");
            return;
        }
        const auto& cfg = *app.disasm_cfg;
        ImGui::Text("Control-Flow Graph: %zu Basic Blocks, %zu Branch Edges", cfg.blocks.size(), cfg.edges.size());
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(8));
        ImGui::SliderFloat("##cfg_zoom", &app.cfg_zoom, 0.5f, 2.0f, "Zoom %.2fx");
        ImGui::SameLine();
        if (ImGui::SmallButton("Reset View##cfg")) {
            app.cfg_zoom = 1.0f;
            app.cfg_pan_x = 0.0f;
            app.cfg_pan_y = 0.0f;
        }
        ImGui::SameLine();
        ImGui::TextDisabled("(Middle/Right-drag to pan, Ctrl+Wheel zoom)");

        std::optional<uintptr_t> cfg_jump_addr;
        std::optional<uintptr_t> cfg_toggle_bp;
        if (ImGui::BeginChild("cfg_canvas", ImVec2(0, ImGui::GetContentRegionAvail().y), true, ImGuiWindowFlags_HorizontalScrollbar)) {
            if (ImGui::IsWindowHovered()) {
                if (ImGui::IsMouseDragging(ImGuiMouseButton_Middle) || ImGui::IsMouseDragging(ImGuiMouseButton_Right)) {
                    const ImVec2 d = ImGui::GetIO().MouseDelta;
                    app.cfg_pan_x += d.x;
                    app.cfg_pan_y += d.y;
                }
                if (ImGui::GetIO().KeyCtrl && ImGui::GetIO().MouseWheel != 0.0f) {
                    app.cfg_zoom = std::clamp(app.cfg_zoom + ImGui::GetIO().MouseWheel * 0.1f, 0.5f, 2.0f);
                }
            }

            ImDrawList* dl = ImGui::GetWindowDrawList();
            const ImVec2 cursor_start = ImGui::GetCursorScreenPos();
            const float z = app.cfg_zoom;
            const ImVec2 origin(cursor_start.x + app.cfg_pan_x, cursor_start.y + app.cfg_pan_y);
            const float col_w = em(20) * z;
            const float box_w = em(18) * z;
            const float pad_y = em(2.4f) * z;
            const float row_h = em(1.1f) * z;
            const float hdr_h = em(1.5f) * z;

            int max_level = 0;
            int max_lane  = 0;
            for (const auto& b : cfg.blocks) {
                max_level = std::max(max_level, b.level);
                max_lane  = std::max(max_lane,  b.lane);
            }

            std::vector<float> level_heights(static_cast<size_t>(max_level) + 1, em(4.5f) * z);
            auto block_height = [&](const debugger::BasicBlock& b) -> float {
                const float h = em(2.0f) * z + static_cast<float>(std::max<size_t>(1, b.instructions.size())) * row_h;
                return std::max(em(4.5f) * z, h);
            };
            for (const auto& b : cfg.blocks) {
                if (b.level >= 0 && b.level <= max_level) {
                    level_heights[static_cast<size_t>(b.level)] =
                        std::max(level_heights[static_cast<size_t>(b.level)], block_height(b));
                }
            }

            std::vector<float> level_y(static_cast<size_t>(max_level) + 2, 20.0f);
            for (int lv = 0; lv <= max_level; ++lv) {
                level_y[static_cast<size_t>(lv + 1)] =
                    level_y[static_cast<size_t>(lv)] + level_heights[static_cast<size_t>(lv)] + pad_y;
            }

            auto box_rect = [&](const debugger::BasicBlock& b) -> std::pair<ImVec2, ImVec2> {
                const float x = origin.x + 20.0f + b.lane * col_w;
                const float y = origin.y + level_y[static_cast<size_t>(std::max(0, b.level))];
                return {ImVec2(x, y), ImVec2(x + box_w, y + block_height(b))};
            };

            for (const auto& e : cfg.edges) {
                if (e.from_block >= cfg.blocks.size() || e.to_block >= cfg.blocks.size()) continue;
                auto [p1, p2] = box_rect(cfg.blocks[e.from_block]);
                auto [q1, q2] = box_rect(cfg.blocks[e.to_block]);
                const ImVec2 src_pt((p1.x + p2.x) * 0.5f, p2.y);
                const ImVec2 dst_pt((q1.x + q2.x) * 0.5f, q1.y);
                const ImU32 col = (e.kind == debugger::CFGEdge::Kind::TrueBranch)  ? IM_COL32(80, 220, 120, 220)
                                : (e.kind == debugger::CFGEdge::Kind::FalseBranch) ? IM_COL32(235, 95, 95, 220)
                                                                                   : IM_COL32(100, 190, 245, 220);
                dl->AddBezierCubic(src_pt, ImVec2(src_pt.x, src_pt.y + 24.0f * z),
                                   ImVec2(dst_pt.x, dst_pt.y - 24.0f * z), dst_pt, col, 2.0f);
                dl->AddCircleFilled(dst_pt, 4.0f * z, col);
            }

            const float font_sz = ImGui::GetFontSize() * z;
            for (const auto& b : cfg.blocks) {
                auto [r0, r1] = box_rect(b);
                const bool has_bp = dbg && dbg->has_breakpoint(b.start_address);
                dl->AddRectFilled(r0, r1, IM_COL32(28, 32, 42, 235), 6.0f);
                dl->AddRect(r0, r1,
                            has_bp ? IM_COL32(235, 70, 70, 255)
                                   : (b.id == 0 ? IM_COL32(80, 220, 150, 255) : IM_COL32(110, 130, 165, 220)),
                            6.0f, 0, has_bp ? 2.2f : 1.5f);
                std::string hdr = "#" + std::to_string(b.id) + " " + utils::format_address(b.start_address);
                dl->AddText(nullptr, font_sz, ImVec2(r0.x + 8.0f, r0.y + 5.0f), IM_COL32(255, 210, 100, 255), hdr.c_str());

                ImGui::PushID(static_cast<int>(b.id));
                ImGui::SetCursorScreenPos(ImVec2(r1.x - em(5.0f), r0.y + 3.0f));
                if (ImGui::SmallButton("Go")) cfg_jump_addr = b.start_address;
                ImGui::SameLine();
                if (ImGui::SmallButton(has_bp ? "BP*" : "BP")) cfg_toggle_bp = b.start_address;
                ImGui::PopID();

                float ty = r0.y + hdr_h;
                for (const auto& insn : b.instructions) {
                    dl->AddText(nullptr, font_sz, ImVec2(r0.x + 8.0f, ty), IM_COL32(220, 225, 235, 255), insn.full_text.c_str());
                    ty += row_h;
                }
            }

            ImGui::SetCursorScreenPos(cursor_start);
            const float total_w = 40.0f + std::max(0.0f, app.cfg_pan_x) + static_cast<float>(max_lane + 1) * col_w;
            const float total_h = std::max(0.0f, app.cfg_pan_y) + level_y[static_cast<size_t>(max_level + 1)] + 20.0f;
            ImGui::Dummy(ImVec2(std::max(total_w, 200.0f), std::max(total_h, 200.0f)));
        }
        ImGui::EndChild();
        if (cfg_jump_addr && *cfg_jump_addr != 0) {
            load_disasm(*cfg_jump_addr, true);
            app.disasm_view_mode = 0;
        }
        if (cfg_toggle_bp && *cfg_toggle_bp != 0 && dbg) {
            if (dbg->has_breakpoint(*cfg_toggle_bp)) dbg->remove_breakpoint(*cfg_toggle_bp);
            else dbg->set_breakpoint(*cfg_toggle_bp, "cfg-bp", false, app.bp_condition_input, app.bp_trace_mode);
        }
        return;
    }

    // Auto-update disassembly to follow RIP if paused at new RIP
    if (dbg_paused && cur_rip != 0 && utils::parse_address(app.disasm_input) != cur_rip) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Follow RIP")) {
            load_disasm(cur_rip, true);
        }
    }

    // Inline Assemble box (patches selected row or current top address)
    if (attached && !app.disasm_instructions.empty()) {
        ImGui::SetNextItemWidth(em(22));
        ImGui::InputTextWithHint("##disasm_asm", "Assemble inline (e.g. mov eax, #999 or nop)", &app.disasm_asm_input);
        ImGui::SameLine();
        if (ImGui::Button("Assemble")) {
            const size_t idx = (app.disasm_selected_row >= 0 && static_cast<size_t>(app.disasm_selected_row) < app.disasm_instructions.size())
                ? static_cast<size_t>(app.disasm_selected_row) : 0;
            const auto& target_inst = app.disasm_instructions[idx];
            assembler::X86Assembler enc(app.session.process().pointer_size() != 4);
            std::string err;
            auto encoded = enc.encode(app.disasm_asm_input, target_inst.address, err);
            if (!encoded) {
                app.disasm_note = "Assemble error: " + err;
            } else {
                std::vector<uint8_t> patch = std::move(encoded->bytes);
                if (patch.size() < target_inst.length) {
                    patch.resize(target_inst.length, 0x90); // NOP-pad remainder cleanly
                }
                if (app.session.process().write_raw(target_inst.address, patch.data(), patch.size(), true)) {
                    app.disasm_note = "Assembled '" + app.disasm_asm_input + "' @ " + utils::format_address(target_inst.address);
                    load_disasm(utils::parse_address(app.disasm_input), false);
                } else {
                    app.disasm_note = "Failed writing assembled bytes to target.";
                }
            }
        }
    }

    if (!app.disasm_note.empty()) ImGui::TextWrapped("%s", app.disasm_note.c_str());

    if (app.disasm_instructions.empty()) {
        ImGui::TextDisabled("Enter an address above or click \"Disasm\" on a hit in the Watch tab.");
        return;
    }

    // Two-panel layout: Disassembly table on left, Live Registers & Call Stack on right
    if (dbg_paused) {
        ImGui::Columns(2, "disasm_debugger_cols", true);
        ImGui::SetColumnWidth(0, ImGui::GetWindowWidth() * 0.65f);
    }

    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("disasm_table", 5, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) {
        if (ImGui::IsWindowHovered() && ImGui::GetIO().MouseWheel != 0.0f && attached) {
            const uintptr_t cur_top = utils::parse_address(app.disasm_input);
            if (ImGui::GetIO().MouseWheel > 0.0f && cur_top > 4) {
                load_disasm(cur_top - 4, false);
            } else if (ImGui::GetIO().MouseWheel < 0.0f && app.disasm_instructions.size() > 1) {
                load_disasm(app.disasm_instructions[1].address, false);
            }
        }
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("BP", ImGuiTableColumnFlags_WidthFixed, em(3));
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(11));
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, em(9));
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, em(14));
        ImGui::TableHeadersRow();

        std::optional<size_t> nop_index;
        std::optional<uintptr_t> follow_addr;
        for (size_t i = 0; i < app.disasm_instructions.size(); ++i) {
            const auto& inst = app.disasm_instructions[i];
            const bool is_bp = dbg && dbg->has_breakpoint(inst.address);
            const bool is_rip = (dbg_paused && inst.address == cur_rip);
            const bool is_sel = (app.disasm_selected_row == static_cast<int>(i));

            ImGui::TableNextRow();
            if (is_rip) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImColor(80, 80, 20, 120));
            } else if (is_sel) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImColor(40, 70, 110, 90));
            }
            ImGui::PushID(static_cast<int>(i));

            // BP column
            ImGui::TableNextColumn();
            if (is_bp) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.2f, 0.2f, 1.0f));
                if (ImGui::Selectable(" [X]", false)) {
                    dbg->remove_breakpoint(inst.address);
                }
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Breakpoint set! Click to remove.");
            } else {
                if (ImGui::Selectable("  -", false)) {
                    if (dbg) {
                        if (!dbg->set_breakpoint(inst.address, "user-bp", false, app.bp_condition_input, app.bp_trace_mode)) {
                            app.dbg_status_note = "BP error: " + dbg->last_error();
                        } else {
                            app.dbg_status_note = std::string(app.bp_trace_mode ? "Tracepoint" : "Breakpoint") +
                                                  " set at " + utils::format_address(inst.address);
                        }
                    }
                }
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Click to set BP/Tracepoint (uses condition & Tracepoint toggle above).");
            }

            // Address column
            ImGui::TableNextColumn();
            if (is_rip) {
                ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.2f, 1.0f), "=> %s", utils::format_address(inst.address).c_str());
            } else {
                const std::string addr_lbl = utils::format_address(inst.address);
                if (ImGui::Selectable(addr_lbl.c_str(), is_sel)) {
                    app.disasm_selected_row = static_cast<int>(i);
                }
            }

            // Bytes column
            ImGui::TableNextColumn();
            std::ostringstream bytes_ss;
            for (size_t b = 0; b < std::min<size_t>(inst.bytes.size(), 4); ++b) {
                bytes_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inst.bytes[b]) << " ";
            }
            ImGui::TextUnformatted(bytes_ss.str().c_str());

            // Instruction column + optional symbol
            ImGui::TableNextColumn();
            if (is_rip) {
                ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.3f, 1.0f), "%s %s", inst.mnemonic.c_str(), inst.operands.c_str());
            } else {
                ImGui::Text("%s %s", inst.mnemonic.c_str(), inst.operands.c_str());
            }
            if (!inst.resolved_symbol.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f), "; %s", inst.resolved_symbol.c_str());
            }

            // Actions
            ImGui::TableNextColumn();
            if (inst.branch_target != 0) {
                if (ImGui::SmallButton("Go")) follow_addr = inst.branch_target;
                ImGui::SameLine();
            }
            if (ImGui::SmallButton("NOP")) nop_index = i;
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy")) ImGui::SetClipboardText(inst.full_text.empty() ? (inst.mnemonic + " " + inst.operands).c_str() : inst.full_text.c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Sig")) {
                auto sig = utils::SignatureGenerator::generate(app.session.process(), inst.address);
                if (sig) {
                    app.disasm_note = "Generated Sig: " + sig->pattern + (sig->is_unique ? " (Unique ✓)" : " (Multiple matches)");
                    ImGui::SetClipboardText(sig->pattern.c_str());
                } else {
                    app.disasm_note = "Failed generating signature for instruction.";
                }
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("AA")) {
                std::string generated = app.session.generate_aob_hook_script(inst.address);
                if (!generated.empty()) {
                    app.editing_script = -1;
                    app.script_name = "Hook_" + utils::format_address(inst.address);
                    app.script_body = std::move(generated);
                    app.script_note = "Generated one-click AOB Code-Cave script for " + utils::format_address(inst.address) + ".";
                    app.select_tab = Tab::Scripts;
                } else {
                    app.disasm_note = "Failed generating AOB Auto-Assembler hook script.";
                }
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Generate full [ENABLE]/[DISABLE] AOB Code-Cave script and open Scripts tab.");
            ImGui::SameLine();
            if (ImGui::SmallButton("X-Refs")) {
                const uintptr_t xref_target = inst.address;
                start_job(app, "Find X-Refs", [&app, xref_target]() -> ApplyResult {
                    auto refs = app.session.find_references(xref_target, 0, 256);
                    return [&app, xref_target, refs = std::move(refs)]() mutable {
                        app.disasm_xref_target = xref_target;
                        app.disasm_xrefs = std::move(refs);
                        app.disasm_note = "Found " + std::to_string(app.disasm_xrefs.size()) +
                                          " X-Ref(s) referencing " + utils::format_address(xref_target) + ".";
                    };
                });
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Find calls/jumps/references pointing to this instruction address.");

            ImGui::PopID();
        }
        ImGui::EndTable();

        if (follow_addr && *follow_addr != 0) {
            load_disasm(*follow_addr, true);
        } else if (nop_index && *nop_index < app.disasm_instructions.size()) {
            const auto& inst = app.disasm_instructions[*nop_index];
            std::vector<uint8_t> nops(inst.length, 0x90);
            if (app.session.process().write_raw(inst.address, nops.data(), nops.size())) {
                app.disasm_note = "NOPed " + std::to_string(inst.length) + " bytes at " + utils::format_address(inst.address);
                load_disasm(utils::parse_address(app.disasm_input), false);
            }
        }
    }

    // Right column: Live Registers & Call Stack Unwind
    if (dbg_paused) {
        ImGui::NextColumn();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Live CPU Registers (TID: %u)", dbg->active_thread_id());
        ImGui::Separator();

        const auto& r = dbg->registers();
        auto reg_text = [](const char* name, uint64_t val) {
            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%-4s", name);
            ImGui::SameLine();
            ImGui::Text("0x%016llX", static_cast<unsigned long long>(val));
        };

        reg_text("RAX", r.rax); reg_text("RBX", r.rbx);
        reg_text("RCX", r.rcx); reg_text("RDX", r.rdx);
        reg_text("RSI", r.rsi); reg_text("RDI", r.rdi);
        reg_text("RBP", r.rbp); reg_text("RSP", r.rsp);
        reg_text("RIP", r.rip); reg_text("EFL", r.eflags);
        reg_text("R8 ", r.r8);  reg_text("R9 ", r.r9);
        reg_text("R10", r.r10); reg_text("R11", r.r11);
        reg_text("R12", r.r12); reg_text("R13", r.r13);
        reg_text("R14", r.r14); reg_text("R15", r.r15);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Call Stack Frames");
        auto stack = dbg->get_call_stack(8);
        if (stack.empty()) {
            ImGui::TextDisabled("(No stack frames recovered)");
        } else {
            for (size_t i = 0; i < stack.size(); ++i) {
                ImGui::BulletText("#%zu %s", i, stack[i].symbol_name.c_str());
            }
        }

        ImGui::Columns(1);
    }

    if (dbg) {
        auto traces = dbg->get_trace_log();
        if (!traces.empty()) {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.7f, 1.0f), "Execution Trace Log (%zu entries)", traces.size());
            ImGui::SameLine();
            if (ImGui::SmallButton("Clear Trace")) dbg->clear_trace_log();
            if (ImGui::BeginTable("trace_log", 5, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter,
                                  ImVec2(0, em(8)))) {
                ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, em(3));
                ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, em(4));
                ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthFixed, em(12));
                ImGui::TableSetupColumn("RAX / RCX", ImGuiTableColumnFlags_WidthFixed, em(18));
                ImGui::TableSetupColumn("Disassembly", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                for (size_t ti = 0; ti < traces.size(); ++ti) {
                    const auto& te = traces[ti];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::Text("%zu", te.sequence);
                    ImGui::TableNextColumn(); ImGui::Text("%u", te.thread_id);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(te.symbol.c_str());
                    ImGui::TableNextColumn(); ImGui::Text("0x%llX / 0x%llX",
                                                          static_cast<unsigned long long>(te.registers.rax),
                                                          static_cast<unsigned long long>(te.registers.rcx));
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(te.disassembly.c_str());
                }
                ImGui::EndTable();
            }
        }
    }

    if (app.disasm_xref_target != 0) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.95f, 0.78f, 0.35f, 1.0f), "Cross-References to %s (%zu hit(s))",
                           utils::format_address(app.disasm_xref_target).c_str(), app.disasm_xrefs.size());
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear X-Refs")) {
            app.disasm_xref_target = 0;
            app.disasm_xrefs.clear();
        }
        if (!app.disasm_xrefs.empty() && ImGui::BeginTable("xrefs_tbl", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter,
                                                           ImVec2(0, em(7.5f)))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Caller / From", ImGuiTableColumnFlags_WidthFixed, em(11));
            ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, em(5.5f));
            ImGui::TableSetupColumn("Module / Instruction", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(4));
            ImGui::TableHeadersRow();
            std::optional<uintptr_t> jump_to;
            for (size_t xi = 0; xi < app.disasm_xrefs.size(); ++xi) {
                const auto& xr = app.disasm_xrefs[xi];
                ImGui::TableNextRow();
                ImGui::PushID(static_cast<int>(80000 + xi));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(xr.from_address).c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(xr.kind.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%s%s%s", xr.module_name.empty() ? "" : xr.module_name.c_str(),
                            xr.module_name.empty() ? "" : "  ", xr.instruction.c_str());
                ImGui::TableNextColumn();
                if (ImGui::SmallButton("Go")) jump_to = xr.from_address;
                ImGui::PopID();
            }
            ImGui::EndTable();
            if (jump_to && *jump_to != 0) load_disasm(*jump_to, true);
        }
    }
}

void draw_radar(App& app) {
    if (!is_attached(app)) {
        ImGui::TextDisabled("Attach to a target process to use the 3D Radar and Coordinates detector.");
        return;
    }

    ImGui::Text("Player 3D Coordinates & Interactive Radar");
    ImGui::Separator();

    const bool busy = job_running(app);
    static const char* const kVecFmts[] = {"Float x3 (12B)", "Double x3 UE5 (24B)"};
    ImGui::SetNextItemWidth(em(12));
    ImGui::InputTextWithHint("##coord_addr", "Address (e.g. 0x7FF...)", &app.radar_coord_addr);
    ImGui::SameLine();
    ImGui::BeginDisabled(busy);
    ImGui::SetNextItemWidth(em(10));
    ImGui::Combo("##vec_fmt", &app.radar_format_idx, kVecFmts, IM_ARRAYSIZE(kVecFmts));
    ImGui::SameLine();
    if (ImGui::Button("Snapshot")) {
        const auto fmt = (app.radar_format_idx == 1) ? view::VectorFormat::Double3 : view::VectorFormat::Float3;
        start_job(app, "Coord Snapshot", [&app, fmt]() -> ApplyResult {
            size_t c = app.vector_detector.take_snapshot(app.session.process(), hal::FilterFlags::DefaultScanFilter, fmt);
            return [&app, c, fmt]() {
                app.radar_candidates.clear();
                app.radar_note = "Snapshotted " + std::to_string(c) + " " +
                                 (fmt == view::VectorFormat::Double3 ? "Double3 (UE5)" : "Float3") +
                                 " vectors. Stand still -> Filter Still, or move -> Filter Moved.";
            };
        });
    }
    ImGui::SameLine();
    if (ImGui::Button("Filter Still")) {
        start_job(app, "Filter Still", [&app]() -> ApplyResult {
            size_t rem = app.vector_detector.filter_stationary(app.session.process(), 0.05);
            return [&app, rem]() {
                app.radar_note = "Eliminated jittering noise! Remaining snapshot candidates: " + std::to_string(rem);
            };
        });
    }
    ImGui::SameLine();
    if (ImGui::Button("Filter Moved")) {
        start_job(app, "Filter Moved", [&app]() -> ApplyResult {
            auto hits = app.vector_detector.filter_moved(app.session.process(), 0.5, 2000.0);
            return [&app, hits = std::move(hits)]() mutable {
                app.radar_candidates = std::move(hits);
                if (!app.radar_candidates.empty()) {
                    if (app.radar_coord_addr.empty()) {
                        app.radar_coord_addr = utils::format_address(app.radar_candidates[0].address);
                        app.radar_trail.clear();
                    }
                    app.radar_note = "Narrowed to " + std::to_string(app.radar_candidates.size()) +
                                     " moved vector(s). Pick the exact player coordinate below.";
                } else {
                    app.radar_note = "No moving vectors in snapshot. Re-snapshot or move farther.";
                }
            };
        });
    }
    ImGui::SameLine();
    if (ImGui::Button("Detect Motion")) {
        start_job(app, "Detect Motion", [&app]() -> ApplyResult {
            auto hits = app.vector_detector.detect_motion(app.session.process(), 0.5f, 2000.0f);
            return [&app, hits = std::move(hits)]() mutable {
                app.radar_candidates = std::move(hits);
                if (!app.radar_candidates.empty()) {
                    app.radar_coord_addr = utils::format_address(app.radar_candidates[0].address);
                    app.radar_trail.clear();
                    app.radar_note = "Detected " + std::to_string(app.radar_candidates.size()) +
                                     " moving vectors! Top candidate: " + app.radar_coord_addr;
                } else {
                    app.radar_note = "No moving vectors found. Move your character and try again.";
                }
            };
        });
    }
    ImGui::EndDisabled();

    ImGui::BeginDisabled(busy);
    if (ImGui::Button("Auto-Find & Plot UE Actors")) {
        auto found = app.session.find_unreal_globals();
        if (found.found_names) app.unreal_gnames_input = utils::format_address(found.fname_pool_va);
        if (found.found_objects) app.unreal_gobjects_input = utils::format_address(found.guobject_array_va);
        if (found.found_world) app.unreal_uworld_input = utils::format_address(found.gworld_va);
        const uintptr_t uw = utils::parse_address(app.unreal_uworld_input);
        const uintptr_t gn = utils::parse_address(app.unreal_gnames_input);
        if (uw && gn) {
            app.unreal_actors = app.session.dump_unreal_actors(uw, gn);
            app.radar_plot_actors = true;
            app.radar_note = "Loaded " + std::to_string(app.unreal_actors.size()) +
                             " Unreal Actor(s) from GWorld=" + utils::format_address(uw) + ".";
        } else {
            app.radar_note = "Auto-Finder: GWorld=" + (found.found_world ? utils::format_address(found.gworld_va) : std::string("?")) +
                             " GNames=" + (found.found_names ? utils::format_address(found.fname_pool_va) : std::string("?")) +
                             ". Set missing addresses in Engine Inspector.";
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox("Overlay UE Actors", &app.radar_plot_actors);
    if (!app.unreal_actors.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("(%zu actors)", app.unreal_actors.size());
    }
    ImGui::EndDisabled();

    if (!app.radar_note.empty()) ImGui::TextWrapped("%s", app.radar_note.c_str());

    if (!app.radar_candidates.empty()) {
        if (ImGui::BeginTable("radar_cands", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(6.5f)))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(11));
            ImGui::TableSetupColumn("Delta", ImGuiTableColumnFlags_WidthFixed, em(6));
            ImGui::TableSetupColumn("Current (X, Y, Z)", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Use", ImGuiTableColumnFlags_WidthFixed, em(5));
            ImGui::TableHeadersRow();
            const size_t show_n = std::min<size_t>(app.radar_candidates.size(), 200);
            for (size_t i = 0; i < show_n; ++i) {
                const auto& c = app.radar_candidates[i];
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(c.address).c_str());
                ImGui::TableNextColumn(); ImGui::Text("%.2f", c.delta_dist_d);
                ImGui::TableNextColumn(); ImGui::Text("%.2f, %.2f, %.2f", c.current_d.x, c.current_d.y, c.current_d.z);
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(i));
                if (ImGui::SmallButton("Track")) {
                    app.radar_coord_addr = utils::format_address(c.address);
                    app.radar_format_idx = (c.format == view::VectorFormat::Double3) ? 1 : 0;
                    app.radar_trail.clear();
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }

    const uintptr_t addr = utils::parse_address(app.radar_coord_addr);
    const auto active_fmt = (app.radar_format_idx == 1) ? view::VectorFormat::Double3 : view::VectorFormat::Float3;
    std::optional<view::Vector3d> vec_opt;
    if (active_fmt == view::VectorFormat::Double3) {
        vec_opt = view::VectorDetector::read_vector_d(app.session.process(), addr);
    } else if (auto vf = view::VectorDetector::read_vector(app.session.process(), addr)) {
        vec_opt = view::Vector3d{vf->x, vf->y, vf->z};
    }

    if (vec_opt) {
        view::Vector3d pos = *vec_opt;
        if (app.radar_trail.empty() || app.radar_trail.back().distance_to(pos) > 0.1) {
            app.radar_trail.push_back(pos);
            if (app.radar_trail.size() > 150) app.radar_trail.erase(app.radar_trail.begin());
        }

        ImGui::Columns(2, "radar_layout", false);
        ImGui::SetColumnWidth(0, em(22));

        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.4f, 1.0f), "Coordinates (%s):",
                           active_fmt == view::VectorFormat::Double3 ? "UE5 Double3" : "Float3");
        ImGui::Text("X: %.3f", pos.x);
        ImGui::Text("Y: %.3f", pos.y);
        ImGui::Text("Z: %.3f", pos.z);

        auto nudge_cur = [&](double dx, double dy, double dz) {
            if (active_fmt == view::VectorFormat::Double3) view::VectorDetector::nudge_d(app.session.process(), addr, dx, dy, dz);
            else view::VectorDetector::nudge(app.session.process(), addr, static_cast<float>(dx), static_cast<float>(dy), static_cast<float>(dz));
        };

        ImGui::Spacing();
        ImGui::Text("Nudge Position:");
        if (ImGui::Button("-10 X")) nudge_cur(-10, 0, 0);
        ImGui::SameLine();
        if (ImGui::Button("+10 X")) nudge_cur(+10, 0, 0);
        ImGui::SameLine();
        if (ImGui::Button("-10 Y")) nudge_cur(0, -10, 0);
        ImGui::SameLine();
        if (ImGui::Button("+10 Y")) nudge_cur(0, +10, 0);

        if (ImGui::Button("-10 Z (Down)")) nudge_cur(0, 0, -10);
        ImGui::SameLine();
        if (ImGui::Button("+10 Z (Up)"))   nudge_cur(0, 0, +10);

        ImGui::SetNextItemWidth(em(12));
        ImGui::SliderFloat("Radar Range", &app.radar_zoom, 25.0f, 2000.0f, "%.0f units");

        ImGui::Separator();
        ImGui::Text("Waypoint Bookmarks:");
        ImGui::SetNextItemWidth(em(10));
        ImGui::InputTextWithHint("##wp_name", "Waypoint name", &app.radar_wp_name);
        ImGui::SameLine();
        if (ImGui::Button("Save Pos")) {
            if (app.radar_wp_name.empty()) app.radar_wp_name = "Point " + std::to_string(app.vector_detector.waypoints().size() + 1);
            app.vector_detector.add_waypoint_d(app.radar_wp_name, pos, active_fmt);
            app.radar_wp_name.clear();
        }

        const auto& wps = app.vector_detector.waypoints();
        for (size_t i = 0; i < wps.size(); ++i) {
            ImGui::PushID(static_cast<int>(i));
            ImGui::Text("%s (%.1f, %.1f, %.1f)", wps[i].name.c_str(), wps[i].position_d.x, wps[i].position_d.y, wps[i].position_d.z);
            ImGui::SameLine();
            if (ImGui::SmallButton("TP")) {
                if (active_fmt == view::VectorFormat::Double3) view::VectorDetector::write_vector_d(app.session.process(), addr, wps[i].position_d);
                else view::VectorDetector::write_vector(app.session.process(), addr, wps[i].position_d.to_f32());
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Del")) {
                app.vector_detector.remove_waypoint(i);
                ImGui::PopID();
                break;
            }
            ImGui::PopID();
        }

        if (!app.unreal_actors.empty()) {
            ImGui::Separator();
            ImGui::Text("Unreal Actors (%zu):", app.unreal_actors.size());
            if (ImGui::BeginChild("radar_actors_list", ImVec2(0, em(6.5f)), true)) {
                for (size_t ai = 0; ai < app.unreal_actors.size(); ++ai) {
                    const auto& act = app.unreal_actors[ai];
                    ImGui::PushID(static_cast<int>(50000 + ai));
                    if (ImGui::SmallButton("Dissect")) {
                        app.dissect_input = utils::format_address(act.address);
                        app.dissect_pending = true;
                        app.select_tab = Tab::Dissect;
                    }
                    ImGui::SameLine();
                    if (act.has_location) {
                        const double dist = std::sqrt((act.x - pos.x) * (act.x - pos.x) +
                                                      (act.y - pos.y) * (act.y - pos.y) +
                                                      (act.z - pos.z) * (act.z - pos.z));
                        ImGui::Text("%s (%.0fm)", act.name.empty() ? act.class_name.c_str() : act.name.c_str(), dist);
                    } else {
                        ImGui::TextDisabled("%s", act.name.empty() ? act.class_name.c_str() : act.name.c_str());
                    }
                    ImGui::PopID();
                }
            }
            ImGui::EndChild();
        }

        ImGui::NextColumn();

        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 canvas_p0 = ImGui::GetCursorScreenPos();
        ImVec2 canvas_sz = ImGui::GetContentRegionAvail();
        if (canvas_sz.x < 100.0f) canvas_sz.x = 100.0f;
        if (canvas_sz.y < 100.0f) canvas_sz.y = 100.0f;
        ImVec2 canvas_p1 = ImVec2(canvas_p0.x + canvas_sz.x, canvas_p0.y + canvas_sz.y);

        draw_list->AddRectFilled(canvas_p0, canvas_p1, IM_COL32(20, 24, 32, 255));
        draw_list->AddRect(canvas_p0, canvas_p1, IM_COL32(60, 70, 90, 255));

        ImVec2 center = ImVec2(canvas_p0.x + canvas_sz.x * 0.5f, canvas_p0.y + canvas_sz.y * 0.5f);
        float radius = std::min(canvas_sz.x, canvas_sz.y) * 0.45f;

        draw_list->AddCircle(center, radius * 0.33f, IM_COL32(40, 60, 50, 180), 32);
        draw_list->AddCircle(center, radius * 0.66f, IM_COL32(40, 60, 50, 180), 32);
        draw_list->AddCircle(center, radius, IM_COL32(50, 80, 60, 255), 32);

        draw_list->AddLine(ImVec2(center.x - radius, center.y), ImVec2(center.x + radius, center.y), IM_COL32(40, 70, 50, 150));
        draw_list->AddLine(ImVec2(center.x, center.y - radius), ImVec2(center.x, center.y + radius), IM_COL32(40, 70, 50, 150));

        draw_list->AddText(ImVec2(center.x - 4, center.y - radius + 2), IM_COL32(100, 255, 120, 255), "N");
        draw_list->AddText(ImVec2(center.x - 4, center.y + radius - 14), IM_COL32(100, 255, 120, 255), "S");
        draw_list->AddText(ImVec2(center.x + radius - 12, center.y - 7), IM_COL32(100, 255, 120, 255), "E");
        draw_list->AddText(ImVec2(center.x - radius + 4, center.y - 7), IM_COL32(100, 255, 120, 255), "W");

        const float scale = radius / std::max(app.radar_zoom, 1.0f);
        for (size_t i = 1; i < app.radar_trail.size(); ++i) {
            float dx1 = static_cast<float>(app.radar_trail[i - 1].x - pos.x) * scale;
            float dy1 = static_cast<float>(app.radar_trail[i - 1].y - pos.y) * scale;
            float dx2 = static_cast<float>(app.radar_trail[i].x - pos.x) * scale;
            float dy2 = static_cast<float>(app.radar_trail[i].y - pos.y) * scale;
            draw_list->AddLine(ImVec2(center.x + dx1, center.y - dy1),
                               ImVec2(center.x + dx2, center.y - dy2), IM_COL32(0, 220, 100, 130), 2.0f);
        }

        // Plot saved Waypoints relative to current player position on the radar
        for (const auto& wp : app.vector_detector.waypoints()) {
            float wx = static_cast<float>(wp.position_d.x - pos.x) * scale;
            float wy = static_cast<float>(wp.position_d.y - pos.y) * scale;
            const float dist_px = std::sqrt(wx * wx + wy * wy);
            if (dist_px > radius - 8.0f && dist_px > 0.001f) {
                const float clamp = (radius - 8.0f) / dist_px;
                wx *= clamp;
                wy *= clamp;
            }
            const ImVec2 wpt(center.x + wx, center.y - wy);
            draw_list->AddQuadFilled(ImVec2(wpt.x, wpt.y - 5), ImVec2(wpt.x + 5, wpt.y),
                                     ImVec2(wpt.x, wpt.y + 5), ImVec2(wpt.x - 5, wpt.y),
                                     IM_COL32(80, 200, 255, 255));
            draw_list->AddText(ImVec2(wpt.x + 7, wpt.y - 7), IM_COL32(150, 230, 255, 255), wp.name.c_str());
        }

        if (app.radar_plot_actors) {
            for (const auto& act : app.unreal_actors) {
                if (!act.has_location) continue;
                float ax = static_cast<float>(act.x - pos.x) * scale;
                float ay = static_cast<float>(act.y - pos.y) * scale;
                const float dist_px = std::sqrt(ax * ax + ay * ay);
                if (dist_px > radius - 8.0f && dist_px > 0.001f) {
                    const float clamp = (radius - 8.0f) / dist_px;
                    ax *= clamp;
                    ay *= clamp;
                }
                const ImVec2 apt(center.x + ax, center.y - ay);
                draw_list->AddCircleFilled(apt, 4.5f, IM_COL32(255, 95, 70, 235));
                draw_list->AddCircle(apt, 6.0f, IM_COL32(255, 200, 140, 180));
                const std::string& lbl = act.name.empty() ? act.class_name : act.name;
                if (!lbl.empty()) {
                    draw_list->AddText(ImVec2(apt.x + 7, apt.y - 7), IM_COL32(255, 180, 140, 240), lbl.c_str());
                }
            }
        }

        draw_list->AddCircleFilled(center, 5.0f, IM_COL32(255, 220, 0, 255));
        draw_list->AddCircle(center, 8.0f, IM_COL32(255, 255, 255, 200));

        ImGui::Dummy(canvas_sz);
        ImGui::Columns(1);
    } else {
        ImGui::TextDisabled("Enter a valid coordinates address above, or use Snapshot -> Filter Still/Moved.");
    }
}

// The Speedhack tab: dilates or slows down game time progression
void draw_speedhack(App& app) {
    ImGui::TextWrapped("Dilates or slows down game time progression by hooking QueryPerformanceCounter and GetTickCount64 inside the target process.");
    ImGui::Separator();

    const bool attached = is_attached(app);
    const bool installed = app.session.speedhack_installed();
    const bool enabled = app.session.speedhack_enabled();
    const double current_speed = app.session.speedhack_speed();

    ImGui::Text("Target Status: ");
    ImGui::SameLine();
    if (!attached) {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Not attached");
    } else {
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Attached (PID %u)", app.session.process().get_pid());
        ImGui::SameLine();
        ImGui::Text(" | Hook: ");
        ImGui::SameLine();
        if (installed) {
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Installed");
        } else {
            ImGui::TextDisabled("Standby (installs on enable)");
        }
        ImGui::SameLine();
        ImGui::Text(" | State: ");
        ImGui::SameLine();
        if (enabled) {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "ACTIVE (%.2fx)", current_speed);
        } else {
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "DISABLED / NORMAL");
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::BeginDisabled(!attached);

    ImGui::Text("Speed Multiplier: ");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(16));
    ImGui::SliderFloat("##speed_slider", &app.speedhack_multiplier, 0.1f, 20.0f, "%.2fx", ImGuiSliderFlags_Logarithmic);
    ImGui::SameLine();
    if (ImGui::Button("Apply Speed")) {
        if (app.session.set_speed(static_cast<double>(app.speedhack_multiplier))) {
            app.speedhack_note = "Speed multiplier updated to " + std::to_string(app.speedhack_multiplier) + "x";
        } else {
            app.speedhack_note = "Failed to update speed.";
        }
    }

    ImGui::Spacing();
    ImGui::Text("Quick Presets:");
    ImGui::SameLine();
    auto preset_btn = [&](const char* label, float spd) {
        if (ImGui::Button(label)) {
            app.speedhack_multiplier = spd;
            app.session.set_speed(static_cast<double>(spd));
            app.speedhack_note = std::string("Applied preset: ") + label;
        }
        ImGui::SameLine();
    };

    preset_btn("0.25x Slow", 0.25f);
    preset_btn("0.5x", 0.5f);
    preset_btn("1.0x Normal", 1.0f);
    preset_btn("2.0x Fast", 2.0f);
    preset_btn("5.0x Turbo", 5.0f);
    preset_btn("10.0x Ultra", 10.0f);
    ImGui::NewLine();

    ImGui::Spacing();
    if (!enabled) {
        if (ImGui::Button("Enable Speedhack", ImVec2(em(14), em(2.5f)))) {
            app.session.set_speed(static_cast<double>(app.speedhack_multiplier));
            if (app.session.enable_speedhack()) {
                app.speedhack_note = "Speedhack enabled successfully.";
            } else {
                app.speedhack_note = "Failed to enable speedhack. Ensure Administrator privileges.";
            }
        }
    } else {
        if (ImGui::Button("Disable Speedhack", ImVec2(em(14), em(2.5f)))) {
            if (app.session.disable_speedhack()) {
                app.speedhack_note = "Speedhack disabled (returned to 1.0x normal time).";
            } else {
                app.speedhack_note = "Failed to disable speedhack.";
            }
        }
    }

    ImGui::EndDisabled();

    if (!app.speedhack_note.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "[*] %s", app.speedhack_note.c_str());
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextDisabled("Technical details:");
    ImGui::BulletText("Speedhack detours QueryPerformanceCounter & GetTickCount64 via code cave trampolines.");
    ImGui::BulletText("Base time offsets are atomically synchronized on speed shifts to avoid physics jumps or game lockups.");
    ImGui::BulletText("Fully safe for single-player games, offline emulators, and replay analysis.");
}

void draw_diff(App& app) {
    ImGui::TextWrapped("Take two memory snapshots of a region (before and after a game action) to instantly pinpoint what bytes changed.");
    ImGui::Separator();

    ImGui::SetNextItemWidth(em(12));
    ImGui::InputTextWithHint("##diff_addr", "Address (e.g. 0x7FF...)", &app.diff_addr_input);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(7));
    ImGui::InputInt("##diff_size", &app.diff_size_bytes, 16, 64);
    if (app.diff_size_bytes < 16) app.diff_size_bytes = 16;
    if (app.diff_size_bytes > 65536) app.diff_size_bytes = 65536;

    const bool attached = is_attached(app);
    ImGui::BeginDisabled(!attached);

    if (ImGui::Button("Take Snapshot A")) {
        const uintptr_t a = utils::parse_address(app.diff_addr_input);
        if (!a) {
            app.diff_status = "Please enter a valid address.";
        } else if (app.session.diff_snapshot_a(a, static_cast<size_t>(app.diff_size_bytes))) {
            app.diff_status = "Snapshot A captured (" + std::to_string(app.diff_size_bytes) + " bytes). Perform action in game, then click Snapshot B.";
        } else {
            app.diff_status = "Failed to capture Snapshot A from memory.";
        }
    }

    ImGui::SameLine();
    ImGui::BeginDisabled(!app.session.memory_diff().has_snapshot_a());
    if (ImGui::Button("Take Snapshot B & Diff")) {
        if (app.session.diff_snapshot_b()) {
            app.diff_last_summary = app.session.diff_compare();
            app.diff_status = "Compared snapshots: " + std::to_string(app.diff_last_summary.changed_bytes) +
                              " of " + std::to_string(app.diff_last_summary.total_bytes) + " bytes changed (" +
                              std::to_string(static_cast<int>(app.diff_last_summary.changed_percentage)) + "%).";
        } else {
            app.diff_status = "Failed to capture Snapshot B.";
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        app.session.diff_clear();
        app.diff_last_summary = {};
        app.diff_status = "Diff cleared.";
    }

    ImGui::EndDisabled();

    if (!app.diff_status.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "[*] %s", app.diff_status.c_str());
    }

    ImGui::Separator();

    if (app.diff_last_summary.total_bytes > 0) {
        ImGui::Text("Base: %s | Total: %zu bytes | Changed: %zu (%.1f%%)",
                    utils::format_address(app.diff_last_summary.address).c_str(),
                    app.diff_last_summary.total_bytes,
                    app.diff_last_summary.changed_bytes,
                    app.diff_last_summary.changed_percentage);

        if (app.diff_last_summary.diffs.empty()) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Identical! No byte differences detected between Snapshot A and B.");
        } else {
            const ImGuiTableFlags tbl_flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                                              ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable;
            if (ImGui::BeginTable("diff_results", 5, tbl_flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, em(5));
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableSetupColumn("Snapshot A (Old)", ImGuiTableColumnFlags_WidthFixed, em(9));
                ImGui::TableSetupColumn("Snapshot B (New)", ImGuiTableColumnFlags_WidthFixed, em(9));
                ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (size_t i = 0; i < app.diff_last_summary.diffs.size(); ++i) {
                    const auto& d = app.diff_last_summary.diffs[i];
                    ImGui::TableNextRow();
                    ImGui::PushID(static_cast<int>(i));

                    ImGui::TableNextColumn();
                    ImGui::Text("+0x%04llX", static_cast<unsigned long long>(d.address - app.diff_last_summary.address));

                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(utils::format_address(d.address).c_str());

                    ImGui::TableNextColumn();
                    ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.5f, 1.0f), "0x%02X ('%c')", d.old_val,
                                       std::isprint(d.old_val) ? static_cast<char>(d.old_val) : '.');

                    ImGui::TableNextColumn();
                    ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "0x%02X ('%c')", d.new_val,
                                       std::isprint(d.new_val) ? static_cast<char>(d.new_val) : '.');

                    ImGui::TableNextColumn();
                    if (ImGui::SmallButton("Hex View")) {
                        open_memory(app, d.address, false);
                        app.select_tab = Tab::Memory;
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Add Table")) {
                        app.session.table().add_address(d.address, scanner::DataType::UInt8, "Diff " + utils::format_address(d.address));
                    }

                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
    } else {
        ImGui::TextDisabled("No active comparison. Capture Snapshot A, make changes in game, then click Snapshot B.");
    }
}

void draw_pe_tools(App& app) {
    ImGui::TextWrapped("Inspect Portable Executable (PE32/PE32+) and ELF32/ELF64 headers, sections/segments, exports/symbols, and imports.");
    ImGui::Separator();

    const bool attached = is_attached(app);
    auto modules = attached ? app.session.process().get_modules() : std::vector<hal::ModuleInfo>{};

    if (app.pe_module_input.empty() && !modules.empty()) {
        app.pe_module_input = modules.front().name;
    }

    auto analyze_selected_binary = [&](const std::string& input) {
        app.pe_current_info.reset();
        app.elf_current_info.reset();
        const uintptr_t parsed_a = utils::parse_address(input);
        auto elf = parsed_a ? app.session.analyze_elf(parsed_a) : app.session.analyze_module_elf(input);
        if (elf && elf->is_valid) {
            app.elf_current_info = std::move(elf);
            app.pe_status = "Successfully parsed ELF headers for: " + input;
            return;
        }
        auto pe = parsed_a ? app.session.analyze_pe(parsed_a) : app.session.analyze_module(input);
        if (pe && pe->is_valid) {
            app.pe_current_info = std::move(pe);
            app.pe_status = "Successfully parsed PE headers for: " + input;
            return;
        }
        app.pe_status = "Failed to parse PE or ELF headers for: " + input;
    };

    ImGui::SetNextItemWidth(em(13));
    ImGui::InputTextWithHint("##pe_mod_in", "Module name or 0xAddress", &app.pe_module_input);
    ImGui::SameLine();
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Analyze Module")) {
        analyze_selected_binary(app.pe_module_input);
    }
    ImGui::EndDisabled();

    if (!modules.empty()) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(12));
        if (ImGui::BeginCombo("##mod_select", "Loaded Modules...")) {
            for (const auto& m : modules) {
                const bool selected = (app.pe_module_input == m.name);
                if (ImGui::Selectable(m.name.c_str(), selected)) {
                    app.pe_module_input = m.name;
                    analyze_selected_binary(m.name);
                }
            }
            ImGui::EndCombo();
        }
    }

    if (!app.pe_status.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "[*] %s", app.pe_status.c_str());
    }

    ImGui::Separator();

    if (app.elf_current_info && app.elf_current_info->is_valid) {
        const auto& elf = *app.elf_current_info;
        ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.5f, 1.0f), "Format: %s (%s) | Machine: %s | Size: %s",
                           elf.is_64bit ? "ELF64" : "ELF32",
                           elf.type_name.c_str(),
                           elf.machine_name.c_str(),
                           session::format_size(elf.image_size).c_str());
        ImGui::Text("Image Base: %s | Entry Point: %s",
                    utils::format_address(elf.image_base).c_str(),
                    utils::format_address(elf.entry_point).c_str());
        ImGui::Spacing();

        if (ImGui::BeginTabBar("##elf_details_tabs")) {
            if (ImGui::BeginTabItem("Segments / Sections")) {
                const ImGuiTableFlags tbl_flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
                if (ImGui::BeginTable("elf_sec", 4, tbl_flags, ImVec2(0, em(14)))) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, em(9));
                    ImGui::TableSetupColumn("Virtual Addr", ImGuiTableColumnFlags_WidthFixed, em(11));
                    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, em(8));
                    ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    for (const auto& sec : elf.sections) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(sec.name.c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(sec.virtual_address).c_str());
                        ImGui::TableNextColumn(); ImGui::Text("%llu", static_cast<unsigned long long>(sec.size));
                        ImGui::TableNextColumn();
                        std::string perm;
                        if (sec.is_readable) perm += "R";
                        if (sec.is_writable) perm += "W";
                        if (sec.is_executable) perm += "X";
                        ImGui::TextUnformatted(perm.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Dynamic Symbols")) {
                ImGui::Text("Total Symbols: %zu | Needed Libs: %zu", elf.symbols.size(), elf.needed_libraries.size());
                const ImGuiTableFlags tbl_flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
                if (ImGui::BeginTable("elf_syms", 3, tbl_flags, ImVec2(0, em(14)))) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_WidthFixed, em(11));
                    ImGui::TableSetupColumn("Scope", ImGuiTableColumnFlags_WidthFixed, em(6));
                    ImGui::TableSetupColumn("Symbol Name", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    for (const auto& s : elf.symbols) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(s.va).c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(s.is_exported ? "EXP" : "LOC");
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(s.name.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        return;
    }

    if (app.pe_current_info && app.pe_current_info->is_valid) {
        const auto& pe = *app.pe_current_info;
        ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.5f, 1.0f), "Architecture: %s | Subsystem: %s | Size: %s",
                           pe.is_64bit ? "x86-64 (PE32+)" : "x86 (PE32)",
                           pe.subsystem.c_str(),
                           session::format_size(pe.image_size).c_str());
        ImGui::Text("Image Base: %s | Entry Point: %s",
                    utils::format_address(pe.image_base).c_str(),
                    utils::format_address(pe.entry_point).c_str());
        ImGui::Spacing();

        if (ImGui::BeginTabBar("pe_sub_tabs")) {
            if (ImGui::BeginTabItem("Sections")) {
                const ImGuiTableFlags tbl_flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
                if (ImGui::BeginTable("pe_sections", 5, tbl_flags)) {
                    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, em(8));
                    ImGui::TableSetupColumn("Virtual Address", ImGuiTableColumnFlags_WidthFixed, em(11));
                    ImGui::TableSetupColumn("Virtual Size", ImGuiTableColumnFlags_WidthFixed, em(8));
                    ImGui::TableSetupColumn("Raw Size", ImGuiTableColumnFlags_WidthFixed, em(8));
                    ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (const auto& sec : pe.sections) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%s", sec.name.c_str());

                        ImGui::TableNextColumn();
                        ImGui::Text("0x%08X", sec.virtual_address);

                        ImGui::TableNextColumn();
                        ImGui::Text("0x%08X", sec.virtual_size);

                        ImGui::TableNextColumn();
                        ImGui::Text("0x%08X", sec.raw_size);

                        ImGui::TableNextColumn();
                        std::string perm;
                        if (sec.is_readable) perm += "R";
                        if (sec.is_writable) perm += "W";
                        if (sec.is_executable) perm += "X (Code)";
                        ImGui::Text("%s", perm.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Exports")) {
                ImGui::Text("Total Exported Functions: %zu", pe.exports.size());
                const ImGuiTableFlags tbl_flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
                if (ImGui::BeginTable("pe_exports", 4, tbl_flags, ImVec2(0, em(15)))) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, em(5));
                    ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, em(8));
                    ImGui::TableSetupColumn("Address (VA)", ImGuiTableColumnFlags_WidthFixed, em(11));
                    ImGui::TableSetupColumn("Function Name", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (const auto& exp : pe.exports) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::Text("%u", exp.ordinal);

                        ImGui::TableNextColumn();
                        ImGui::Text("0x%08X", exp.rva);

                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(utils::format_address(exp.va).c_str());

                        ImGui::TableNextColumn();
                        ImGui::Text("%s%s", exp.name.c_str(), exp.is_forwarded ? (" -> " + exp.forwarder_name).c_str() : "");
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Imports")) {
                ImGui::Text("Total Imported Modules: %zu", pe.imports.size());
                for (const auto& imp : pe.imports) {
                    if (ImGui::TreeNode(imp.module_name.c_str())) {
                        for (const auto& fn : imp.functions) {
                            ImGui::BulletText("IAT: %s  %s", utils::format_address(fn.iat_va).c_str(), fn.name.c_str());
                        }
                        ImGui::TreePop();
                    }
                }
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }
    } else {
        ImGui::TextDisabled("Select a module above and click 'Analyze Module' to inspect its PE or ELF structure.");
    }
}

void draw_engine_inspector(App& app) {
    ImGui::TextWrapped("Inspect Unity (Mono / IL2CPP global-metadata.dat) classes & fields, or Unreal Engine GNames / GUObjectArray runtime structures.");
    ImGui::Separator();

    const bool attached = is_attached(app);
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Detect Game Engine")) {
        app.engine_detection = app.session.detect_game_engine();
        app.engine_status = app.engine_detection.engine_name + ": " + app.engine_detection.details;
        if (app.engine_detection.gnames_hint != 0 && app.unreal_gnames_input.empty()) {
            app.unreal_gnames_input = utils::format_address(app.engine_detection.gnames_hint);
        }
        if (app.engine_detection.gobjects_hint != 0 && app.unreal_gobjects_input.empty()) {
            app.unreal_gobjects_input = utils::format_address(app.engine_detection.gobjects_hint);
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f), "%s", app.engine_detection.engine_name.c_str());
    if (!app.engine_status.empty()) {
        ImGui::TextDisabled("%s", app.engine_status.c_str());
    }

    if (ImGui::BeginTabBar("##engine_subtabs")) {
        if (ImGui::BeginTabItem("Unity (Mono / IL2CPP)")) {
            ImGui::SetNextItemWidth(em(16));
            ImGui::InputTextWithHint("##meta_path", "Path to global-metadata.dat", &app.unity_meta_path);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(em(10));
            ImGui::InputTextWithHint("##unity_filter", "Filter class", &app.unity_filter);
            ImGui::SameLine();
            if (ImGui::Button("Parse File")) {
                app.unity_report = app.session.inspect_unity_metadata(app.unity_meta_path, app.unity_filter, 256);
                if (!app.unity_report->valid) app.engine_status = app.unity_report->error;
                else app.engine_status = "Parsed IL2CPP v" + std::to_string(app.unity_report->version) +
                                         " (" + std::to_string(app.unity_report->types.size()) + " types)";
            }
            ImGui::SameLine();
            ImGui::BeginDisabled(!attached);
            if (ImGui::Button("Scan RAM Metadata")) {
                app.unity_report = app.session.inspect_unity_metadata_memory(0, app.unity_filter, 256);
                if (!app.unity_report->valid) app.engine_status = app.unity_report->error;
                else app.engine_status = "Extracted IL2CPP RAM Metadata v" + std::to_string(app.unity_report->version) +
                                         " (" + std::to_string(app.unity_report->types.size()) + " types)";
            }
            ImGui::EndDisabled();
            ImGui::SetNextItemWidth(em(13));
            ImGui::InputTextWithHint("##unity_obj_addr", "IL2CPP Object 0xAddr", &app.unity_obj_input);
            ImGui::SameLine();
            ImGui::BeginDisabled(!attached);
            if (ImGui::Button("Dissect Live Object")) {
                const uintptr_t obj = utils::parse_address(app.unity_obj_input);
                if (obj) {
                    app.engine_dissected_obj = app.session.dissect_unity_object(obj);
                    app.engine_status = "Reflected Unity Object " + app.engine_dissected_obj->class_name +
                                        " (" + std::to_string(app.engine_dissected_obj->fields.size()) + " fields)";
                }
            }
            ImGui::EndDisabled();
            if (app.unity_report && app.unity_report->valid) {
                for (const auto& t : app.unity_report->types) {
                    std::string label = (t.namespaze.empty() ? t.name : (t.namespaze + "." + t.name)) +
                                        " [" + std::to_string(t.fields.size()) + " fields]";
                    if (ImGui::TreeNode(label.c_str())) {
                        for (const auto& f : t.fields) {
                            ImGui::BulletText("%s (token 0x%X)", f.name.c_str(), f.token);
                        }
                        ImGui::TreePop();
                    }
                }
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Unreal (GNames / GObjects / Actors)")) {
            ImGui::BeginDisabled(!attached);
            if (ImGui::Button("Auto-Find UE Globals")) {
                auto found = app.session.find_unreal_globals();
                if (found.found_names) app.unreal_gnames_input = utils::format_address(found.fname_pool_va);
                if (found.found_objects) app.unreal_gobjects_input = utils::format_address(found.guobject_array_va);
                if (found.found_world) app.unreal_uworld_input = utils::format_address(found.gworld_va);
                app.engine_status = std::string("Auto-Finder: GNames=") +
                                    (found.found_names ? app.unreal_gnames_input : "?") +
                                    " GObjects=" + (found.found_objects ? app.unreal_gobjects_input : "?") +
                                    " GWorld=" + (found.found_world ? app.unreal_uworld_input : "?");
            }
            ImGui::EndDisabled();
            ImGui::SetNextItemWidth(em(12));
            ImGui::InputTextWithHint("##ue_gnames", "GNames / FNamePool 0xAddr", &app.unreal_gnames_input);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(em(12));
            ImGui::InputTextWithHint("##ue_gobj", "GUObjectArray 0xAddr", &app.unreal_gobjects_input);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(em(9));
            ImGui::InputTextWithHint("##ue_filter", "Filter", &app.unreal_filter);
            ImGui::SameLine();
            ImGui::BeginDisabled(!attached);
            if (ImGui::Button("Dump Unreal")) {
                const uintptr_t gn = utils::parse_address(app.unreal_gnames_input);
                const uintptr_t go = utils::parse_address(app.unreal_gobjects_input);
                app.unreal_names = gn ? app.session.scan_unreal_names(gn, app.unreal_offsets, 8, 512) : std::vector<view::UnrealNameEntry>{};
                app.unreal_objects = (go && gn) ? app.session.dump_unreal_objects(go, gn, app.unreal_offsets, app.unreal_filter, 256)
                                                : std::vector<view::UnrealObjectInfo>{};
                app.engine_status = "Decoded " + std::to_string(app.unreal_names.size()) + " FNames, " +
                                    std::to_string(app.unreal_objects.size()) + " UObjects.";
            }
            ImGui::SetNextItemWidth(em(13));
            ImGui::InputTextWithHint("##ue_uworld", "GWorld / UWorld* 0xAddr", &app.unreal_uworld_input);
            ImGui::SameLine();
            if (ImGui::Button("Dump World Actors")) {
                const uintptr_t uw = utils::parse_address(app.unreal_uworld_input);
                const uintptr_t gn = utils::parse_address(app.unreal_gnames_input);
                if (uw && gn) {
                    app.unreal_actors = app.session.dump_unreal_actors(uw, gn, app.unreal_offsets);
                    app.engine_status = "Dumped " + std::to_string(app.unreal_actors.size()) + " Actors from UWorld.";
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Auto-Calibrate Offsets")) {
                uintptr_t sample = utils::parse_address(app.unreal_uworld_input);
                if (sample == 0 && !app.unreal_objects.empty()) sample = app.unreal_objects[0].address;
                const uintptr_t gn = utils::parse_address(app.unreal_gnames_input);
                if (sample && gn) {
                    auto cal = app.session.calibrate_unreal_offsets(sample, gn, app.unreal_offsets);
                    if (cal.ok) {
                        app.unreal_offsets = cal.offsets;
                        app.engine_status = "Calibrated UE offsets:";
                        for (const auto& n : cal.notes) app.engine_status += " | " + n;
                    } else {
                        app.engine_status = "Auto-Calibrate could not match PersistentLevel / RootComponent FFields.";
                    }
                } else {
                    app.engine_status = "Provide GWorld or Dump Objects + GNames before calibrating.";
                }
            }
            ImGui::EndDisabled();

            if (!app.unreal_objects.empty() && ImGui::BeginTable("ue_objs", 5, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(10)))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Idx", ImGuiTableColumnFlags_WidthFixed, em(4));
                ImGui::TableSetupColumn("UObject VA", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableSetupColumn("Class", ImGuiTableColumnFlags_WidthFixed, em(10));
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Inspect", ImGuiTableColumnFlags_WidthFixed, em(7));
                ImGui::TableHeadersRow();
                for (const auto& o : app.unreal_objects) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::Text("%u", o.index);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(o.address).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(o.class_name.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(o.name.c_str());
                    ImGui::TableNextColumn();
                    ImGui::PushID(static_cast<int>(o.index));
                    if (ImGui::SmallButton("FField")) {
                        const uintptr_t gn = utils::parse_address(app.unreal_gnames_input);
                        app.engine_dissected_obj = app.session.dissect_unreal_object(o.address, gn, app.unreal_offsets);
                    }
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            if (!app.unreal_actors.empty() && ImGui::BeginTable("ue_actors", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(8)))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Actor VA", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableSetupColumn("Class", ImGuiTableColumnFlags_WidthFixed, em(10));
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Position (X,Y,Z)", ImGuiTableColumnFlags_WidthFixed, em(16));
                ImGui::TableHeadersRow();
                for (const auto& a : app.unreal_actors) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(a.address).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(a.class_name.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(a.name.c_str());
                    ImGui::TableNextColumn();
                    if (a.has_location) ImGui::Text("%.1f, %.1f, %.1f", a.x, a.y, a.z);
                    else ImGui::TextDisabled("-");
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    if (app.engine_dissected_obj && !app.engine_dissected_obj->fields.empty()) {
        ImGui::SeparatorText(("Reflected Class Layout: " + app.engine_dissected_obj->class_name).c_str());
        for (const auto& f : app.engine_dissected_obj->fields) {
            ImGui::BulletText("+0x%04zX  (%s) %s = %s", f.offset, f.type.c_str(), f.name.c_str(), f.value.c_str());
        }
    }
}

void draw_memory_map(App& app) {
    if (!is_attached(app)) {
        ImGui::TextDisabled("Attach to a process to inspect memory regions, loaded modules, and OS threads.");
        return;
    }

    ImGui::SetNextItemWidth(em(16));
    ImGui::InputTextWithHint("##memmap_filter", "Filter module / protection...", &app.mem_map_filter);
    std::string flt = app.mem_map_filter;
    for (char& ch : flt) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

    if (ImGui::BeginTabBar("memmap_subtabs")) {
        if (ImGui::BeginTabItem("Loaded Modules")) {
            const auto mods = app.session.process().get_modules();
            if (ImGui::BeginTable("mm_mods", 5, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable,
                                  ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Module Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, em(7));
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableHeadersRow();
                for (size_t i = 0; i < mods.size(); ++i) {
                    const auto& m = mods[i];
                    std::string ml = m.name + " " + m.path;
                    for (char& ch : ml) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                    if (!flt.empty() && ml.find(flt) == std::string::npos) continue;
                    ImGui::TableNextRow();
                    ImGui::PushID(static_cast<int>(i));
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(m.name.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(m.base_address).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(session::format_size(m.size).c_str());
                    ImGui::TableNextColumn(); ImGui::TextDisabled("%s", m.path.c_str());
                    ImGui::TableNextColumn();
                    if (ImGui::SmallButton("Mem")) open_memory(app, m.base_address, true);
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Disasm")) {
                        app.disasm_input = utils::format_address(m.base_address);
                        app.select_tab = Tab::Disasm;
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("PE")) {
                        app.pe_module_input = m.name;
                        app.pe_current_info = app.session.analyze_module(m.name);
                        app.select_tab = Tab::PETools;
                    }
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Memory Regions")) {
            const auto regs = app.session.process().query_regions();
            if (ImGui::BeginTable("mm_regs", 5, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable,
                                  ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableSetupColumn("End", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, em(7));
                ImGui::TableSetupColumn("Protection", ImGuiTableColumnFlags_WidthFixed, em(7));
                ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, em(9));
                ImGui::TableHeadersRow();
                for (size_t i = 0; i < regs.size(); ++i) {
                    const auto& r = regs[i];
                    std::string prot;
                    if (r.is_readable) prot += 'R';
                    if (r.is_writable) prot += 'W';
                    if (r.is_executable) prot += 'X';
                    if (r.is_guard) prot += 'G';
                    std::string pl = prot;
                    for (char& ch : pl) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                    if (!flt.empty() && pl.find(flt) == std::string::npos) continue;
                    ImGui::TableNextRow();
                    ImGui::PushID(static_cast<int>(10000 + i));
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(r.base_address).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(r.end_address()).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(session::format_size(r.size).c_str());
                    ImGui::TableNextColumn();
                    if (r.is_executable && r.is_writable) ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.35f, 1.0f), "%s", prot.c_str());
                    else ImGui::TextUnformatted(prot.c_str());
                    ImGui::TableNextColumn();
                    if (ImGui::SmallButton("Mem")) open_memory(app, r.base_address, true);
                    if (r.is_executable) {
                        ImGui::SameLine();
                        if (ImGui::SmallButton("Disasm")) {
                            app.disasm_input = utils::format_address(r.base_address);
                            app.select_tab = Tab::Disasm;
                        }
                    }
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("OS Threads")) {
            const auto threads = app.session.list_threads();
            if (ImGui::BeginTable("mm_threads", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV,
                                  ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Thread ID (TID)", ImGuiTableColumnFlags_WidthFixed, em(10));
                ImGui::TableSetupColumn("Owner PID", ImGuiTableColumnFlags_WidthFixed, em(9));
                ImGui::TableSetupColumn("Base Priority", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                for (const auto& t : threads) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::Text("%u", t.tid);
                    ImGui::TableNextColumn(); ImGui::Text("%u", t.owner_pid);
                    ImGui::TableNextColumn(); ImGui::Text("%d", t.base_priority);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void draw_lua_studio(App& app) {
    ImGui::SeparatorText("Lua 5.4 Scripting Studio & Interactive Console");
    ImGui::TextDisabled("Run custom scripts using Cheat Engine APIs: readInteger, writeInteger, autoAssemble, setSpeed, etc.");

    ImGui::BeginGroup();
    if (ImGui::Button("Run Script (F5)")) {
        auto res = app.session.run_lua(app.lua_script);
        if (!res.output.empty()) {
            app.lua_console_output += res.output;
        }
        if (res.success) {
            app.lua_console_output += "[+] Script executed successfully.\n";
        } else {
            app.lua_console_output += "[-] Error: " + res.error + "\n";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear Output")) {
        app.lua_console_output.clear();
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset Lua VM")) {
        app.session.reset_lua();
        app.lua_console_output += "[*] Lua VM state reloaded.\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Template: Read HP")) {
        app.lua_script = "-- Read and print Health\nlocal base = getAddress('game.exe')\nprint('Base address:', toHex(base))\nlocal hp = readInteger(base + 0x1000)\nprint('Current HP:', hp)\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Template: Speedhack")) {
        app.lua_script = "-- Speedhack automation\nsetSpeed(2.0)\nprint('Speed multiplier is now:', getSpeed())\nsleep(1000)\nsetSpeed(1.0)\nprint('Speed restored to normal.')\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Template: AOBScan & Scan")) {
        app.lua_script =
            "-- Automated scan + AOB inspection\n"
            "local ok, count = firstScan('int32', 100)\n"
            "print('Scan ok:', ok, 'count:', count)\n"
            "local res = getScanResults(5)\n"
            "for i, r in ipairs(res) do\n"
            "  print(i, toHex(r.address), r.value)\n"
            "end\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Template: BP Hook")) {
        app.lua_script =
            "-- Live register manipulation when breakpoint hits\n"
            "function debugger_onBreakpoint()\n"
            "  print('BP hit at', toHex(RIP), 'RAX=', RAX)\n"
            "  -- RAX = 9999\n"
            "  return 1 -- 1 = auto-continue, 0 = pause debugger\n"
            "end\n"
            "print('Registered debugger_onBreakpoint()')\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Save to Table")) {
        app.session.table().set_lua_script(app.lua_script);
        app.lua_console_output += "[+] Saved Lua script into Cheat Table (<LuaScript>).\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Load from Table")) {
        const std::string s = app.session.table().lua_script();
        if (!s.empty()) {
            app.lua_script = s;
            app.lua_console_output += "[*] Loaded Lua script from Cheat Table.\n";
        } else {
            app.lua_console_output += "[*] Current table has no saved <LuaScript>.\n";
        }
    }
    ImGui::EndGroup();

    ImGui::Spacing();
    ImGui::Text("Lua Script Source:");
    ImGui::InputTextMultiline("##lua_code", &app.lua_script, ImVec2(-1.0f, em(12)), ImGuiInputTextFlags_AllowTabInput);

    ImGui::Spacing();
    ImGui::Text("Script Console Output:");
    ImGui::BeginChild("lua_output", ImVec2(-1.0f, em(10)), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(app.lua_console_output.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();
}

void draw_ui(App& app) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("New Cheat Engine", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                 ImGuiWindowFlags_NoBringToFrontOnFocus);

    draw_process_bar(app);
    ImGui::SameLine();
    if (ImGui::SmallButton("Ctrl+K Palette")) {
        app.cmd_palette_open = true;
        app.cmd_palette_filter.clear();
        ImGui::OpenPopup("Command Palette##nce_cmd_palette");
    }
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_K, false)) {
        app.cmd_palette_open = true;
        app.cmd_palette_filter.clear();
        ImGui::OpenPopup("Command Palette##nce_cmd_palette");
    }
    if (app.cmd_palette_open) {
        ImGui::SetNextWindowSize(ImVec2(em(28), em(18)), ImGuiCond_Appearing);
        if (ImGui::BeginPopupModal("Command Palette##nce_cmd_palette", &app.cmd_palette_open)) {
            if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputTextWithHint("##cmd_pal_filter", "Jump to tab or tool... (Esc to close)", &app.cmd_palette_filter);
            if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
                app.cmd_palette_open = false;
                ImGui::CloseCurrentPopup();
            }
            struct PalItem { const char* title; const char* keywords; Tab tab; int submode; };
            static const PalItem kItems[] = {
                {"Pointer Scanner", "ptr pointer scan paths", Tab::PointerScanner, -1},
                {"Memory Viewer & Hex Editor", "mem hex view write", Tab::Memory, -1},
                {"Modules, Memory Map & Threads", "modules regions memory map threads rwx", Tab::MemoryMap, -1},
                {"Hotkeys Manager", "hotkey keybind toggle", Tab::Hotkeys, -1},
                {"Auto-Assembler Scripts", "aa script aob cave hook", Tab::Scripts, -1},
                {"Structure Dissector (Tree & JSON)", "dissect struct rtti vtable json tree", Tab::Dissect, -1},
                {"Hardware Watch (What Writes/Accesses)", "watch hw bp access write", Tab::Watch, -1},
                {"Disassembler & Debugger", "disasm asm step bp trace", Tab::Disasm, 0},
                {"Interactive CFG Graph (Pan & Zoom)", "cfg graph blocks branch pan zoom", Tab::Disasm, 1},
                {"Ultimap Profiler", "ultimap rank function hits", Tab::Disasm, 2},
                {"3D Radar & Unreal Actors Overlay", "radar 3d coords actors waypoint", Tab::Radar, -1},
                {"Speedhack Controller", "speed time scale", Tab::Speedhack, -1},
                {"Memory Snapshot Diff", "diff snapshot compare", Tab::Diff, -1},
                {"PE / ELF Binary Tools", "pe elf exports imports sections", Tab::PETools, -1},
                {"Engine Inspector (Unity / Unreal GWorld)", "engine unity il2cpp unreal gworld fname", Tab::EngineInspector, -1},
                {"Lua 5.4 Scripting Studio", "lua console script", Tab::LuaScript, -1},
            };
            std::string filt = app.cmd_palette_filter;
            for (char& ch : filt) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (ImGui::BeginChild("cmd_pal_list", ImVec2(0, 0), true)) {
                for (const auto& it : kItems) {
                    std::string hay = std::string(it.title) + " " + it.keywords;
                    for (char& ch : hay) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                    if (!filt.empty() && hay.find(filt) == std::string::npos) continue;
                    if (ImGui::Selectable(it.title)) {
                        app.select_tab = it.tab;
                        if (it.submode >= 0) app.disasm_view_mode = it.submode;
                        app.cmd_palette_open = false;
                        ImGui::CloseCurrentPopup();
                    }
                }
            }
            ImGui::EndChild();
            ImGui::EndPopup();
        }
    }
    ImGui::TextWrapped("%s", app.status.c_str());
    ImGui::Separator();

    if (ImGui::BeginTable("layout", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV,
                          ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("scan", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("table", ImGuiTableColumnFlags_WidthStretch, 1.32f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        draw_scan_controls(app);
        ImGui::Separator();
        draw_tracking(app);
        ImGui::Separator();
        draw_results(app);

        ImGui::TableNextColumn();
        ImGui::SeparatorText("Cheat table");
        draw_cheat_table(app);
        if (ImGui::BeginTabBar("tools", ImGuiTabBarFlags_FittingPolicyScroll | ImGuiTabBarFlags_TabListPopupButton)) {
            auto flags_for = [&](Tab tab) { return app.select_tab == tab ? ImGuiTabItemFlags_SetSelected : 0; };
            const ImGuiTabItemFlags pointer_flags = flags_for(Tab::PointerScanner);
            const ImGuiTabItemFlags memory_flags = flags_for(Tab::Memory);
            const ImGuiTabItemFlags memmap_flags = flags_for(Tab::MemoryMap);
            const ImGuiTabItemFlags hotkey_flags = flags_for(Tab::Hotkeys);
            const ImGuiTabItemFlags scripts_flags = flags_for(Tab::Scripts);
            const ImGuiTabItemFlags dissect_flags = flags_for(Tab::Dissect);
            const ImGuiTabItemFlags watch_flags = flags_for(Tab::Watch);
            const ImGuiTabItemFlags disasm_flags = flags_for(Tab::Disasm);
            const ImGuiTabItemFlags radar_flags = flags_for(Tab::Radar);
            const ImGuiTabItemFlags speedhack_flags = flags_for(Tab::Speedhack);
            const ImGuiTabItemFlags diff_flags = flags_for(Tab::Diff);
            const ImGuiTabItemFlags pe_flags = flags_for(Tab::PETools);
            const ImGuiTabItemFlags eng_flags = flags_for(Tab::EngineInspector);
            const ImGuiTabItemFlags lua_flags = flags_for(Tab::LuaScript);
            app.select_tab = Tab::Keep;
            if (ImGui::BeginTabItem("Pointer scanner", nullptr, pointer_flags)) {
                draw_pointer_scanner(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Memory", nullptr, memory_flags)) {
                draw_memory(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Memory Map", nullptr, memmap_flags)) {
                draw_memory_map(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Hotkeys", nullptr, hotkey_flags)) {
                draw_hotkeys(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Scripts", nullptr, scripts_flags)) {
                draw_scripts(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Dissect", nullptr, dissect_flags)) {
                draw_dissect(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Watch", nullptr, watch_flags)) {
                draw_watch(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Disasm", nullptr, disasm_flags)) {
                draw_disasm(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Radar / 3D", nullptr, radar_flags)) {
                draw_radar(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Speedhack", nullptr, speedhack_flags)) {
                draw_speedhack(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Mem Diff", nullptr, diff_flags)) {
                draw_diff(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("PE / ELF Tools", nullptr, pe_flags)) {
                draw_pe_tools(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Engine Inspector", nullptr, eng_flags)) {
                draw_engine_inspector(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Lua Script", nullptr, lua_flags)) {
                draw_lua_studio(app);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::EndTable();
    }
    ImGui::End();

    draw_oscilloscope(app);
}

std::string to_utf8(const wchar_t* text) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    std::string out(size > 0 ? size - 1 : 0, '\0');
    if (size > 1) WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), size, nullptr, nullptr);
    return out;
}

struct LaunchOptions {
    std::string pid;
    std::string table;
    std::string screenshot; // render a few frames in a hidden window, save the last one as a BMP and exit
    std::string track;      // start smart track for this type right away (with --pid)
    int wait_seconds = 0;   // with --screenshot: capture no earlier than this
    std::string view;       // open the Memory tab at this address (with --pid)
    std::string tab;        // start on this tab: pointers, memory or hotkeys
    std::string watch;      // start a write-watch on this address (with --pid)
    std::string library;    // the table library folder ("off": none); default: the user's application data
};

// nce_gui.exe [--pid <pid>] [--table <file.json>] [--track <type|auto>] [--view <address>]
//             [--tab pointers|memory|hotkeys] [--library <folder>|off]
//             [--screenshot <file.bmp> [--wait <seconds>]]
LaunchOptions parse_command_line() {
    LaunchOptions options;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return options;

    for (int i = 1; i + 1 < argc; i += 2) {
        const std::wstring option = argv[i];
        const std::string value = to_utf8(argv[i + 1]);
        if (option == L"--pid") options.pid = value;
        else if (option == L"--table") options.table = value;
        else if (option == L"--screenshot") options.screenshot = value;
        else if (option == L"--track") options.track = value;
        else if (option == L"--wait") options.wait_seconds = std::atoi(value.c_str());
        else if (option == L"--view") options.view = value;
        else if (option == L"--watch") options.watch = value;
        else if (option == L"--tab") options.tab = value;
        else if (option == L"--library") options.library = value;
    }
    LocalFree(argv);
    return options;
}

void apply_launch_options(App& app, const LaunchOptions& options) {
    if (!options.pid.empty()) {
        refresh_processes(app);
        for (const auto& p : app.processes) {
            if (std::to_string(p.pid) == options.pid) attach(app, p);
        }
    }
    if (!options.table.empty()) {
        app.table_path = options.table;
        std::vector<session::TableKeeper::ReconcileLine> reconciled;
        const auto loaded = app.session.table().load(options.table, &reconciled);
        if (!loaded.ok) app.status = loaded.message;
        else app.table_note = describe_reconciled(reconciled);
    }
    if (!options.view.empty() && is_attached(app)) open_memory(app, utils::parse_address(options.view), false);
    if (options.tab == "pointers") app.select_tab = Tab::PointerScanner;
    else if (options.tab == "memory") app.select_tab = Tab::Memory;
    else if (options.tab == "hotkeys") app.select_tab = Tab::Hotkeys;
    else if (options.tab == "scripts") app.select_tab = Tab::Scripts;
    else if (options.tab == "dissect") app.select_tab = Tab::Dissect;
    else if (options.tab == "watch") app.select_tab = Tab::Watch;
    else if (options.tab == "disasm") app.select_tab = Tab::Disasm;
    else if (options.tab == "radar") app.select_tab = Tab::Radar;
    else if (options.tab == "speedhack") app.select_tab = Tab::Speedhack;
    else if (options.tab == "diff") app.select_tab = Tab::Diff;
    else if (options.tab == "pe") app.select_tab = Tab::PETools;
    if (options.tab == "dissect" && !options.view.empty()) {
        app.dissect_input = options.view;
        app.dissect_pending = true; // dissected on the first attached frame
    }
    if (!options.watch.empty() && is_attached(app)) {
        app.watch_input = options.watch;
        if (const uintptr_t a = utils::parse_address(options.watch)) {
            app.session.watch(a, 4, debugger::WatchKind::Write);
        }
    }
    if (!options.track.empty() && is_attached(app)) {
        if (options.track == "auto") {
            app.track_auto_type = true;
            app.track_pending = true;
        } else if (auto type = utils::parse_data_type(options.track); type && is_numeric(*type)) {
            app.type_index = type_index_of(*type);
            app.track_auto_type = false;
            app.track_pending = true;
        }
    }
}

// Saves the frame that was just rendered (call before Present) as a top-down 32-bit BMP
bool save_back_buffer(const std::string& path) {
    ID3D11Texture2D* back_buffer = nullptr;
    if (FAILED(g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer)))) return false;

    D3D11_TEXTURE2D_DESC desc;
    back_buffer->GetDesc(&desc);
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.MiscFlags = 0;

    ID3D11Texture2D* staging = nullptr;
    const bool created = SUCCEEDED(g_device->CreateTexture2D(&desc, nullptr, &staging));
    if (created) g_device_context->CopyResource(staging, back_buffer);
    back_buffer->Release();
    if (!created) return false;

    bool saved = false;
    D3D11_MAPPED_SUBRESOURCE mapped{};
    if (SUCCEEDED(g_device_context->Map(staging, 0, D3D11_MAP_READ, 0, &mapped))) {
        BITMAPINFOHEADER info{};
        info.biSize = sizeof(info);
        info.biWidth = static_cast<LONG>(desc.Width);
        info.biHeight = -static_cast<LONG>(desc.Height); // top-down rows
        info.biPlanes = 1;
        info.biBitCount = 32;
        info.biCompression = BI_RGB;
        info.biSizeImage = desc.Width * desc.Height * 4;

        BITMAPFILEHEADER header{};
        header.bfType = 0x4D42; // "BM"
        header.bfOffBits = sizeof(header) + sizeof(info);
        header.bfSize = header.bfOffBits + info.biSizeImage;

        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(&header), sizeof(header));
        out.write(reinterpret_cast<const char*>(&info), sizeof(info));
        std::vector<uint8_t> row(desc.Width * 4);
        for (UINT y = 0; y < desc.Height; ++y) {
            const auto* src = static_cast<const uint8_t*>(mapped.pData) + y * mapped.RowPitch;
            for (UINT x = 0; x < desc.Width; ++x) { // RGBA -> BGRA
                row[x * 4 + 0] = src[x * 4 + 2];
                row[x * 4 + 1] = src[x * 4 + 1];
                row[x * 4 + 2] = src[x * 4 + 0];
                row[x * 4 + 3] = src[x * 4 + 3];
            }
            out.write(reinterpret_cast<const char*>(row.data()), static_cast<std::streamsize>(row.size()));
        }
        saved = static_cast<bool>(out);
        g_device_context->Unmap(staging, 0);
    }
    staging->Release();
    return saved;
}

} // anonymous namespace

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int) {
    const LaunchOptions options = parse_command_line();
    const bool screenshot_mode = !options.screenshot.empty();
    ImGui_ImplWin32_EnableDpiAwareness();

    WNDCLASSEXW wc{sizeof(wc), CS_CLASSDC, window_proc, 0, 0, instance, nullptr, nullptr, nullptr, nullptr,
                   L"NewCheatEngine", nullptr};
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"New Cheat Engine", WS_OVERLAPPEDWINDOW, 100, 100, 1400, 860,
                              nullptr, nullptr, wc.hInstance, nullptr);

    g_window = hwnd;
    if (!create_device(hwnd)) {
        cleanup_device();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        MessageBoxW(nullptr, L"Could not create a Direct3D 11 device.", L"New Cheat Engine", MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, screenshot_mode ? SW_HIDE : SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    // Crisp text on high-DPI screens: build the font at the monitor's scale instead of stretching it
    const float dpi_scale = ImGui_ImplWin32_GetDpiScaleForHwnd(hwnd);
    ImFontConfig font_config;
    font_config.SizePixels = 13.0f * dpi_scale;
    io.Fonts->AddFontDefault(&font_config);
    ImGui::StyleColorsDark();
    ImGui::GetStyle().ScaleAllSizes(dpi_scale);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_device_context);

    App app;
    // Each program's table opens by itself on attach and is saved while it changes
    if (options.library == "off") app.session.table().set_library({});
    else if (!options.library.empty()) {
        app.session.table().set_library(std::filesystem::path(std::u8string(options.library.begin(), options.library.end())));
    } else {
        app.session.table().set_library(session::default_library_folder());
    }
    app.session.table().on_hotkey([&app](const std::string& combo, const session::Outcome& outcome) {
        std::lock_guard<std::mutex> lock(app.hotkey_mutex); // on the hotkey thread: the UI shows it next frame
        app.hotkey_events.emplace_back(combo, outcome);
    });
    apply_launch_options(app, options);

    constexpr int SCREENSHOT_FRAME = 10; // let tables settle their column widths first
    int frame = 0;
    const auto started = std::chrono::steady_clock::now();
    int exit_code = 0;
    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (!screenshot_mode && g_swap_chain_occluded &&
            g_swap_chain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            Sleep(10); // minimized or hidden
            continue;
        }
        g_swap_chain_occluded = false;

        if (g_resize_width != 0 && g_resize_height != 0) {
            cleanup_render_target();
            g_swap_chain->ResizeBuffers(0, g_resize_width, g_resize_height, DXGI_FORMAT_UNKNOWN, 0);
            g_resize_width = g_resize_height = 0;
            create_render_target();
        }

        poll_job(app);
        tick_reattach(app);
        process_hotkeys(app);
        show_table_hotkeys(app);
        tick_tracking(app);

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        draw_ui(app);
        ImGui::Render();

        const float clear_color[4] = {0.08f, 0.08f, 0.10f, 1.0f};
        g_device_context->OMSetRenderTargets(1, &g_render_target, nullptr);
        g_device_context->ClearRenderTargetView(g_render_target, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Capture once the startup work (attach, noise learning, --track snapshot) has finished
        if (screenshot_mode && ++frame >= SCREENSHOT_FRAME && !job_running(app) && !app.track_pending &&
            elapsed_ms(started) >= options.wait_seconds * 1000LL) {
            exit_code = save_back_buffer(options.screenshot) ? 0 : 1;
            done = true;
        }

        const HRESULT hr = g_swap_chain->Present(1, 0); // vsync
        g_swap_chain_occluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    unregister_hotkeys();
    if (app.job.valid()) app.job.wait(); // let a running scan finish before tearing down

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_device();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return exit_code;
}
