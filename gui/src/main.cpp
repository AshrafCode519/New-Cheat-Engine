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
#include "utils/hex_utils.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
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

const char* const kTypeNames[] = {"i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "str", "wstr", "aob"};
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

enum class Tab { Keep, PointerScanner, Memory, Hotkeys }; // Keep: leave the tab the user chose

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
    std::string ptr_module;
    int ptr_add_type = kDefaultType;

    // Memory tab: the memory around an address, each 4 bytes read as what they most likely are
    view::MemoryView memory;
    std::vector<uintptr_t> memory_back; // where Back returns to after following pointers
    std::string memory_input;
    std::chrono::steady_clock::time_point memory_refreshed;
    Tab select_tab = Tab::Keep;         // switch to this tab on this frame

    // Hotkeys tab: the hotkey being made
    int hotkey_row = 0;
    std::string hotkey_keys;
    int hotkey_action = 0;
    std::string hotkey_value;
    bool hotkey_recording = false; // the next key pressed in this window becomes hotkey_keys
    std::string hotkey_note;
    bool memory_scroll = false;         // scroll the opened address into view when its row is drawn

    bool track_pending = false; // --track: start once the noise is learned

    // When the target exits, wait for the same program to start again and attach to it
    bool auto_reattach = true;
    std::chrono::steady_clock::time_point next_reattach_check;
    uint32_t restart_pid = 0;                              // the new process, once seen
    std::chrono::steady_clock::time_point restart_seen_at; // attach a few seconds later, once it has set up
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
    const bool unknown = is_numeric(type_at(app.type_index)) && app.unknown_value;
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
    if (remember && !app.memory.empty() && app.memory.address() != address) app.memory_back.push_back(app.memory.address());
    app.memory.set_address(address, 16, 48);
    app.memory_input = utils::format_address(address);
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
    ImGui::SetNextItemWidth(em(10));
    ImGui::InputTextWithHint("##filter", "filter processes", &app.process_filter);
    ImGui::SameLine();

    const std::string preview = app.selected_process >= 0
        ? app.processes[app.selected_process].name + " (" + std::to_string(app.processes[app.selected_process].pid) + ")"
        : std::string("select a process");
    ImGui::SetNextItemWidth(em(20));
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
    enum class Kind { None, Freeze, Unfreeze, Write, Remove, Keep, View, Keys } kind = Kind::None;
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
    }
}

TableAction draw_table_rows(App& app, table::CheatTable& t, const std::vector<hal::ModuleInfo>& modules);

void draw_cheat_table(App& app) {
    auto& keeper = app.session.table();
    const bool attached = is_attached(app);

    ImGui::SetNextItemWidth(-em(8));
    ImGui::InputTextWithHint("##table_path", "table.json", &app.table_path);
    ImGui::SameLine();
    if (ImGui::Button("Save")) show(app, keeper.save(app.table_path));
    ImGui::SameLine();
    if (ImGui::Button("Load")) {
        const auto loaded = keeper.load(app.table_path);
        show(app, loaded);
        if (loaded.ok) {
            app.editing_row = -1;
            app.table_note = attached ? describe_reconciled(keeper.reconcile()) : std::string();
        }
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
    // Wide enough for its five small buttons: Keep, View, Ptr, Keys n, X
    const ImGuiStyle& style = ImGui::GetStyle();
    const float actions_width = ImGui::CalcTextSize("KeepViewPtrKeys 9X").x + 5 * 2 * style.FramePadding.x +
                                4 * style.ItemSpacing.x;
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
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputTextWithHint("##description", "description", &e.description);

        ImGui::TableNextColumn();
        ImGui::TextUnformatted(utils::format_data_type(e.type).c_str());

        // Shows the live value; typing a new one and pressing Enter writes it
        ImGui::TableNextColumn();
        if (app.editing_row != row) app.edit_buffers[i] = current ? session::value_text(*current) : "??";
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::InputText("##value", &app.edit_buffers[i], ImGuiInputTextFlags_EnterReturnsTrue)) {
            act(Kind::Write, app.edit_buffers[i]);
        }
        if (ImGui::IsItemActive()) app.editing_row = row;
        else if (app.editing_row == row) app.editing_row = -1;

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
    if (ImGui::Button("Back")) {
        const uintptr_t previous = app.memory_back.back();
        app.memory_back.pop_back();
        open_memory(app, previous, false);
    }
    ImGui::EndDisabled();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("yellow: changed, grey: noise");

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

    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                  ImGuiTableFlags_BordersV;
    if (!ImGui::BeginTable("memory", 6, flags, ImVec2(0, ImGui::GetContentRegionAvail().y))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, em(4));
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(10.5f));
    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, em(7));
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(2.4f));
    ImGui::TableSetupColumn("Value");
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(2.2f));
    ImGui::TableHeadersRow();

    const ImVec4 changed_color(1.0f, 0.85f, 0.25f, 1.0f);
    const ImVec4 noise_color = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    std::optional<size_t> add_row;
    std::optional<uintptr_t> follow;
    const auto& slots = memory.slots();
    for (size_t i = 0; i < slots.size(); ++i) {
        const auto& s = slots[i];
        ImGui::TableNextRow();
        if (i == memory.focus()) {
            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, ImGui::GetColorU32(ImVec4(0.26f, 0.40f, 0.70f, 0.45f)));
        }
        ImGui::PushID(static_cast<int>(i));

        ImGui::TableNextColumn();
        ImGui::TextUnformatted(view::format_offset(s.offset).c_str());
        if (i == memory.focus() && app.memory_scroll) {
            ImGui::SetScrollHereY(0.3f); // the opened address a third of the way down
            app.memory_scroll = false;
        }
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(utils::format_address(s.address).c_str());
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", s.bytes_text().c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(s.type_name());

        ImGui::TableNextColumn();
        // Noise changes all the time, so it would always look just changed: grey wins
        const bool just_changed = memory.value_age(i) < 5; // within the last second
        if (s.noisy) ImGui::PushStyleColor(ImGuiCol_Text, noise_color);
        else if (just_changed) ImGui::PushStyleColor(ImGuiCol_Text, changed_color);
        ImGui::TextUnformatted(s.value_text().c_str());
        if (just_changed || s.noisy) ImGui::PopStyleColor();
        if (s.noisy && ImGui::IsItemHovered()) ImGui::SetTooltip("Changes on its own (learned noise): scans ignore it.");

        ImGui::TableNextColumn();
        if (s.guess == view::Guess::Pointer) {
            if (ImGui::SmallButton("Go")) follow = static_cast<uintptr_t>(s.wide);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Follow the pointer (Back returns here).");
        } else if (s.readable && s.guess != view::Guess::Continued && s.guess != view::Guess::Text) {
            if (ImGui::SmallButton("+")) add_row = i;
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Add to the cheat table as %s.", utils::format_data_type(s.data_type()).c_str());
            }
        }
        ImGui::PopID();
    }
    ImGui::EndTable();

    if (add_row) show(app, app.session.table().add_address(slots[*add_row].address, slots[*add_row].data_type(), ""));
    if (follow) open_memory(app, *follow);
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

void draw_ui(App& app) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("New Cheat Engine", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                 ImGuiWindowFlags_NoBringToFrontOnFocus);

    draw_process_bar(app);
    ImGui::TextWrapped("%s", app.status.c_str());
    ImGui::Separator();

    if (ImGui::BeginTable("layout", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV,
                          ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("scan", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("table", ImGuiTableColumnFlags_WidthStretch, 1.2f);
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
        if (ImGui::BeginTabBar("tools")) {
            auto flags_for = [&](Tab tab) { return app.select_tab == tab ? ImGuiTabItemFlags_SetSelected : 0; };
            const ImGuiTabItemFlags pointer_flags = flags_for(Tab::PointerScanner);
            const ImGuiTabItemFlags memory_flags = flags_for(Tab::Memory);
            const ImGuiTabItemFlags hotkey_flags = flags_for(Tab::Hotkeys);
            app.select_tab = Tab::Keep;
            if (ImGui::BeginTabItem("Pointer scanner", nullptr, pointer_flags)) {
                draw_pointer_scanner(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Memory", nullptr, memory_flags)) {
                draw_memory(app);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Hotkeys", nullptr, hotkey_flags)) {
                draw_hotkeys(app);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::EndTable();
    }
    ImGui::End();
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
        const auto loaded = app.session.table().load(options.table);
        if (!loaded.ok) app.status = loaded.message;
        else if (is_attached(app)) app.table_note = describe_reconciled(app.session.table().reconcile());
    }
    if (!options.view.empty() && is_attached(app)) open_memory(app, utils::parse_address(options.view), false);
    if (options.tab == "pointers") app.select_tab = Tab::PointerScanner;
    else if (options.tab == "memory") app.select_tab = Tab::Memory;
    else if (options.tab == "hotkeys") app.select_tab = Tab::Hotkeys;
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
