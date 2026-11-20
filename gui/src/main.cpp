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

#include "hal/process.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "scanner/value_tracker.hpp"
#include "table/cheat_table.hpp"
#include "utils/hex_utils.hpp"
#include "utils/text_encoding.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
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

struct NextCondition {
    const char* label;
    scanner::ScanCondition cond;
    int value_count;
};
const NextCondition kNextConditions[] = {
    {"Exact value",  scanner::ScanCondition::ExactValue,  1},
    {"Changed",      scanner::ScanCondition::Changed,     0},
    {"Unchanged",    scanner::ScanCondition::Unchanged,   0},
    {"Increased",    scanner::ScanCondition::Increased,   0},
    {"Decreased",    scanner::ScanCondition::Decreased,   0},
    {"Greater than", scanner::ScanCondition::GreaterThan, 1},
    {"Less than",    scanner::ScanCondition::LessThan,    1},
    {"Between",      scanner::ScanCondition::Between,     2},
    {"Increased by", scanner::ScanCondition::IncreasedBy, 1},
    {"Decreased by", scanner::ScanCondition::DecreasedBy, 1},
};
const char* const kNextLabels[] = {"Exact value", "Changed", "Unchanged", "Increased", "Decreased",
                                   "Greater than", "Less than", "Between", "Increased by", "Decreased by"};

const char* const kFloatModes[] = {"rounded", "truncated", "exact"};

struct ScanState {
    scanner::ScanResults results;
    std::shared_ptr<scanner::MemorySnapshot> snapshot; // set after an unknown-value first scan
    scanner::DataType type{scanner::DataType::Int32};
};

// A finished job hands back the step that applies its result on the UI thread
using ApplyResult = std::function<void()>;

constexpr size_t MAX_UNDO_STEPS = 5;

struct App {
    std::shared_ptr<hal::IProcess> process = hal::IProcess::create();
    std::unique_ptr<scanner::MemoryScanner> scanner;
    std::vector<hal::ProcessInfo> processes;
    std::string process_filter;
    int selected_process = -1;
    std::string attached_label;

    ScanState state;
    std::vector<ScanState> history; // undo steps; only the newest snapshot is kept
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

    // The freeze thread writes frozen entries, so the table and the module list are guarded by table_mutex
    std::mutex table_mutex;
    table::CheatTable table;
    std::vector<hal::ModuleInfo> modules;
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
    std::vector<scanner::PointerPath> pointer_paths;

    // Addresses that change on their own, learned for a few seconds after attaching; every scan ignores them
    std::shared_ptr<scanner::NoiseMap> noise;
    bool track_pending = false; // --track: start once the noise is learned

    std::atomic<bool> freeze_running{true};
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
    return app.process && app.process->is_attached();
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

// A value as the user would type it back (text without quotes)
std::string value_text(const scanner::ScanValue& value) {
    if (value.type == scanner::DataType::String) return std::get<std::string>(value.value);
    if (value.type == scanner::DataType::String16) {
        const auto& bytes = std::get<std::vector<uint8_t>>(value.value);
        return utils::utf16le_to_utf8(bytes.data(), bytes.size());
    }
    return value.to_string();
}

std::string describe(const ScanState& state) {
    if (state.snapshot) {
        return std::to_string(state.snapshot->candidate_count()) + " candidates (snapshot, " +
               std::to_string(state.snapshot->memory_bytes() / 1024) + " KB)";
    }
    return std::to_string(state.results.count()) + " results";
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
        apply();
        app.status += " (" + std::to_string(ms) + " ms)";
    } catch (const std::exception& e) {
        app.status = app.job_label + " failed: " + e.what() + ". Use Undo to go back.";
    }
}

// Moves the current scan state into the undo history (a snapshot state drops older entries)
void push_history(App& app) {
    if (app.state.snapshot) app.history.clear();
    app.history.push_back(std::move(app.state));
    if (app.history.size() > MAX_UNDO_STEPS) app.history.erase(app.history.begin());
    app.state = {};
}

// For f32/f64 under the rounded/truncated mode: the [low, high] range an exact value stands for
std::optional<std::pair<scanner::ScanValue, scanner::ScanValue>> float_range(const App& app, scanner::DataType type,
                                                                            const std::string& text) {
    if (type != scanner::DataType::Float && type != scanner::DataType::Double) return std::nullopt;
    auto range = utils::float_match_range(text, static_cast<scanner::FloatMatchMode>(app.float_mode));
    if (!range) return std::nullopt;
    if (type == scanner::DataType::Float) {
        return std::make_pair(scanner::ScanValue::of(type, static_cast<float>(range->first)),
                              scanner::ScanValue::of(type, static_cast<float>(range->second)));
    }
    return std::make_pair(scanner::ScanValue::of(type, range->first), scanner::ScanValue::of(type, range->second));
}

// ---- Actions -------------------------------------------------------------------------------------

void refresh_processes(App& app) {
    app.processes = hal::IProcess::list_processes();
    std::sort(app.processes.begin(), app.processes.end(), [](const hal::ProcessInfo& a, const hal::ProcessInfo& b) {
        return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
    });
    app.selected_process = -1;
}

std::string describe_noise(const App& app) {
    if (!app.noise || app.noise->empty()) return "none known";
    std::string text = std::to_string(app.noise->noisy_slots()) + " addresses ignored";
    if (app.noise->skipped_bytes() > 0) {
        text += ", " + std::to_string(app.noise->skipped_bytes() / 1024) + " KB skipped";
    }
    return text;
}

void learn_noise(App& app) {
    start_job(app, "Learning noise (leave the target alone)", [&app]() -> ApplyResult {
        auto noise = std::make_shared<scanner::NoiseMap>();
        noise->learn(*app.process);
        return [&app, noise]() {
            app.noise = noise;
            app.scanner->set_noise_map(noise);
            app.status = "Noise: " + describe_noise(app) + ".";
        };
    });
}

// Permanent entries carry several pointer paths; after a restart they find the value's new address
// (see table::reconcile). Call with table_mutex held.
std::string reconcile_table(App& app) {
    std::string summary;
    for (auto& e : app.table.entries) {
        if (e.alternatives.empty()) continue;
        const auto r = table::reconcile(e, *app.process, app.modules);
        const std::string name = e.description.empty() ? e.location_string() : e.description;
        if (r.resolved == 0) summary += " " + name + ": not found here.";
        else if (r.ambiguous) summary += " " + name + ": unsure, check its value.";
        else summary += " " + name + ": found" + (r.by_context ? " (by its surroundings)." : ".");
    }
    return summary;
}

void make_entry_permanent(App& app, size_t index) {
    const table::TableEntry entry = app.table.entries[index]; // called with table_mutex held
    const auto modules = app.modules;
    start_job(app, "Finding pointer paths", [&app, entry, modules, index]() -> ApplyResult {
        auto paths = std::make_shared<std::vector<scanner::PointerPath>>(
            table::find_permanent_paths(entry, app.process, modules));
        return [&app, entry, index, paths]() {
            std::lock_guard<std::mutex> lock(app.table_mutex);
            auto& entries = app.table.entries;
            // The table may have changed while the scan ran: only update the same entry
            const bool same = index < entries.size() && entries[index].location.module_name == entry.location.module_name &&
                              entries[index].location.base_offset == entry.location.base_offset &&
                              entries[index].location.offsets == entry.location.offsets;
            if (paths->empty()) {
                app.status = "No static pointer path leads to it; it stays valid only until a restart.";
            } else if (!same) {
                app.status = "The table changed during the search; press Keep again.";
            } else {
                table::make_permanent(entries[index], *paths, *app.process, app.modules);
                app.status = "Kept: " + entries[index].location_string() + " (+" +
                             std::to_string(entries[index].alternatives.size()) +
                             " paths that find it after a restart). Save the table.";
            }
        };
    });
}

void attach(App& app, const hal::ProcessInfo& info) {
    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(app.table_mutex);
        // Absolute addresses belong to the previous process; module-relative entries stay frozen
        for (auto& e : app.table.entries) {
            if (e.is_absolute()) e.frozen_value.reset();
        }
        ok = app.process->attach(info.pid);
        app.modules = ok ? app.process->get_modules() : std::vector<hal::ModuleInfo>{};
        app.table_note = ok ? reconcile_table(app) : std::string();
    }

    app.state = {};
    app.history.clear();
    app.tracker.reset(); // attaching is disabled while a job runs, so no job is using it
    app.track_stage = App::TrackStage::Off;
    app.track_best.clear();
    app.scanner = ok ? std::make_unique<scanner::MemoryScanner>(app.process) : nullptr;
    app.noise.reset(); // learned for the previous process
    if (ok) {
        app.attached_label = info.name + " (PID " + std::to_string(info.pid) + ", " +
                             std::to_string(app.process->pointer_size() * 8) + "-bit)";
        app.status = "Attached to " + app.attached_label + ".";
        learn_noise(app);
    } else {
        app.attached_label.clear();
        app.status = "Could not attach to " + info.name + ". Try running as Administrator.";
    }
}

void first_scan(App& app) {
    const scanner::DataType type = type_at(app.type_index);
    const std::string text = app.first_value;

    if (is_numeric(type) && app.unknown_value) {
        push_history(app);
        start_job(app, "Snapshot", [&app, type]() -> ApplyResult {
            auto snapshot = std::make_shared<scanner::MemorySnapshot>(
                app.scanner->first_scan_unknown(type, scanner::get_data_type_size(type)));
            return [&app, snapshot, type]() {
                app.state.type = type;
                app.state.snapshot = snapshot;
                app.status = "Snapshot taken: " + describe(app.state) + ". Change the value, then run a next scan.";
            };
        });
        return;
    }

    std::function<scanner::ScanResults()> scan;
    if (type == scanner::DataType::AOB) {
        if (!utils::parse_aob_pattern(text)) {
            app.status = "Invalid AOB pattern. Example: 48 8B ? ? 89";
            return;
        }
        scan = [&app, text] { return app.scanner->first_scan_aob(text, 1); };
    } else if (type == scanner::DataType::String || type == scanner::DataType::String16) {
        const bool utf16 = (type == scanner::DataType::String16);
        if (text.empty() || (utf16 && !utils::utf8_to_utf16le(text))) {
            app.status = "Type the text to search for.";
            return;
        }
        scan = [&app, text, utf16] { return app.scanner->first_scan_string(text, utf16, 1); };
    } else {
        auto value = utils::parse_scan_value(type, text);
        if (!value) {
            app.status = "'" + text + "' is not a valid " + utils::format_data_type(type) + " value.";
            return;
        }
        const size_t alignment = scanner::get_data_type_size(type);
        if (auto range = float_range(app, type, text)) {
            scan = [&app, type, range, alignment] {
                return app.scanner->first_scan(type, scanner::ScanCondition::Between, range->first, range->second, alignment);
            };
        } else {
            scan = [&app, type, value, alignment] {
                return app.scanner->first_scan(type, scanner::ScanCondition::ExactValue, *value, {}, alignment);
            };
        }
    }

    push_history(app);
    start_job(app, "First scan", [&app, scan, type]() -> ApplyResult {
        auto results = std::make_shared<scanner::ScanResults>(scan());
        return [&app, results, type]() {
            app.state.type = type;
            app.state.results = std::move(*results);
            app.status = "First scan: " + describe(app.state) + ".";
        };
    });
}

void next_scan(App& app) {
    if (app.state.results.empty() && !app.state.snapshot) {
        app.status = "Run a first scan first.";
        return;
    }

    const auto& spec = kNextConditions[app.next_index];
    const scanner::DataType type = app.state.type;
    scanner::ScanCondition cond = spec.cond;

    if (!is_numeric(type) && cond != scanner::ScanCondition::Changed && cond != scanner::ScanCondition::Unchanged) {
        app.status = "Text and AOB results only support Changed / Unchanged.";
        return;
    }

    scanner::ScanValue val1;
    scanner::ScanValue val2;
    if (spec.value_count >= 1) {
        auto parsed = utils::parse_scan_value(type, app.next_value1);
        if (!parsed) {
            app.status = "'" + app.next_value1 + "' is not a valid " + utils::format_data_type(type) + " value.";
            return;
        }
        val1 = *parsed;
    }
    if (spec.value_count >= 2) {
        auto parsed = utils::parse_scan_value(type, app.next_value2);
        if (!parsed) {
            app.status = "'" + app.next_value2 + "' is not a valid " + utils::format_data_type(type) + " value.";
            return;
        }
        val2 = *parsed;
    }
    if (cond == scanner::ScanCondition::ExactValue) {
        if (auto range = float_range(app, type, app.next_value1)) {
            cond = scanner::ScanCondition::Between;
            val1 = range->first;
            val2 = range->second;
        }
    }

    push_history(app);
    const ScanState* previous = &app.history.back(); // stays put: scans and undo are disabled while the job runs
    start_job(app, "Next scan", [&app, previous, cond, val1, val2]() -> ApplyResult {
        auto next = std::make_shared<ScanState>();
        next->type = previous->type;
        if (previous->snapshot) {
            // Stay a snapshot until the candidates take less memory as a results list
            auto filtered = std::make_shared<scanner::MemorySnapshot>(
                app.scanner->filter_snapshot(*previous->snapshot, cond, val1, val2));
            const size_t result_bytes = filtered->candidate_count() *
                                        (sizeof(uintptr_t) + 2 * scanner::get_data_type_size(filtered->type));
            if (result_bytes <= filtered->memory_bytes()) {
                next->results = scanner::MemoryScanner::snapshot_to_results(*filtered);
            } else {
                next->snapshot = filtered;
            }
        } else {
            next->results = app.scanner->next_scan(previous->results, cond, val1, val2);
        }
        return [&app, next]() {
            app.state = std::move(*next);
            app.status = "Next scan: " + describe(app.state) + " left.";
        };
    });
}

void undo(App& app) {
    if (app.history.empty()) return;
    app.state = std::move(app.history.back());
    app.history.pop_back();
    app.status = "Back to " + describe(app.state) + ".";
}

void add_result_to_table(App& app, size_t row) {
    const auto& r = app.state.results;
    std::lock_guard<std::mutex> lock(app.table_mutex);
    app.table.entries.push_back(table::make_entry(r.address(row), r.type(), app.modules, "", r.value_size()));
    const auto& e = app.table.entries.back();
    app.status = "Added " + e.location_string() + (e.is_absolute() ? " (heap address: valid until the target restarts)" : "") + ".";
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
    app.tracker = std::make_unique<scanner::ValueTracker>(app.process, std::move(types));
    app.tracker->set_noise_map(app.noise);
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
        push_history(app);
        app.state.type = app.tracker->best_type();
        app.state.results = app.tracker->to_results();
        app.status = "Smart track stopped: " + describe(app.state) + ", best first.";
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

void freeze_worker(App* app) {
    while (app->freeze_running) {
        {
            std::lock_guard<std::mutex> lock(app->table_mutex);
            if (is_attached(*app)) {
                for (const auto& e : app->table.entries) {
                    if (e.frozen_value) table::write_entry(e, *e.frozen_value, *app->process, app->modules);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
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
    if (is_attached(app)) ImGui::Text("Attached: %s", app.attached_label.c_str());
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
    ImGui::Combo("##next_condition", &app.next_index, kNextLabels, IM_ARRAYSIZE(kNextLabels));
    const int value_count = kNextConditions[app.next_index].value_count;
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
    ImGui::BeginDisabled(app.history.empty());
    if (ImGui::Button("Undo")) undo(app);
    ImGui::EndDisabled();

    // Noise: learned after attaching; relearn while leaving the target alone, or stop ignoring it
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Noise: %s", describe_noise(app).c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Relearn")) learn_noise(app);
    ImGui::SameLine();
    ImGui::BeginDisabled(!app.noise);
    if (ImGui::SmallButton("Clear")) {
        app.noise.reset();
        app.scanner->set_noise_map(nullptr);
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
    for (size_t i = 0; i < app.track_best.size(); ++i) {
        const auto& c = app.track_best[i];
        ImGui::TableNextRow();
        ImGui::PushID(static_cast<int>(i));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(utils::format_address(c.address).c_str());
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
        std::lock_guard<std::mutex> lock(app.table_mutex);
        app.table.entries.push_back(table::make_entry(c.address, c.value.type, app.modules));
        app.status = "Added " + app.table.entries.back().location_string() + " to the cheat table.";
    }
}

void draw_results(App& app) {
    if (app.track_stage != App::TrackStage::Off) return; // the smart track panel shows the candidates
    if (job_running(app)) {
        ImGui::Text("%s ... %.1f s", app.job_label.c_str(), elapsed_ms(app.job_start) / 1000.0);
        return;
    }
    if (app.state.snapshot) {
        ImGui::TextWrapped("%s. Change the value in the target, then run a next scan "
                           "(Changed / Unchanged / Increased / Decreased ...).", describe(app.state).c_str());
        return;
    }

    const auto& results = app.state.results;
    ImGui::Text("%zu results  (double-click or + to add to the cheat table)", results.count());

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
            if (ImGui::Selectable(address.c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap) &&
                ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                add_row = i;
            }

            ImGui::TableNextColumn();
            std::string current = "??";
            if (!live.empty() && app.process->read_raw(results.address(i), live.data(), live.size())) {
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
}

void draw_cheat_table(App& app) {
    std::lock_guard<std::mutex> lock(app.table_mutex);
    auto& entries = app.table.entries;
    app.edit_buffers.resize(entries.size());
    const bool attached = is_attached(app);

    ImGui::SetNextItemWidth(-em(8));
    ImGui::InputTextWithHint("##table_path", "table.json", &app.table_path);
    ImGui::SameLine();
    if (ImGui::Button("Save")) {
        if (app.table.process_name.empty() && !app.modules.empty()) app.table.process_name = app.modules.front().name;
        app.status = table::save_table(app.table_path, app.table)
            ? "Saved " + std::to_string(entries.size()) + " entries to " + app.table_path + "."
            : "Could not write " + app.table_path + ".";
    }
    ImGui::SameLine();
    if (ImGui::Button("Load")) {
        if (auto loaded = table::load_table(app.table_path)) {
            app.table = std::move(*loaded);
            app.editing_row = -1;
            app.status = "Loaded " + std::to_string(entries.size()) + " entries for " + app.table.process_name + ".";
            app.table_note = attached ? reconcile_table(app) : std::string();
        } else {
            app.status = "Could not read a table from " + app.table_path + ".";
        }
        return; // entries changed under us; draw them next frame
    }
    if (!app.table_note.empty()) ImGui::TextWrapped("After restart:%s", app.table_note.c_str());

    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
                                  ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;
    if (!ImGui::BeginTable("cheat_table", 6, flags, ImVec2(0, em(14)))) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Freeze", ImGuiTableColumnFlags_WidthFixed, em(3.8f));
    ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 1.2f);
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, em(2.6f));
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch, 2.0f);
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(10.5f));
    ImGui::TableHeadersRow();

    std::optional<size_t> remove_row;
    for (size_t i = 0; i < entries.size(); ++i) {
        auto& e = entries[i];
        const auto row = static_cast<int>(i);
        const auto current = attached ? table::read_entry(e, *app.process, app.modules) : std::nullopt;

        ImGui::TableNextRow();
        ImGui::PushID(row);

        ImGui::TableNextColumn();
        bool frozen = e.frozen_value.has_value();
        if (ImGui::Checkbox("##freeze", &frozen)) {
            if (!frozen) e.frozen_value.reset();
            else if (current) e.frozen_value = value_text(*current);
            else app.status = "Can't read the value to freeze it.";
        }

        ImGui::TableNextColumn();
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputTextWithHint("##description", "description", &e.description);

        ImGui::TableNextColumn();
        ImGui::TextUnformatted(utils::format_data_type(e.type).c_str());

        // Shows the live value; typing a new one and pressing Enter writes it
        ImGui::TableNextColumn();
        if (app.editing_row != row) app.edit_buffers[i] = current ? value_text(*current) : "??";
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::InputText("##value", &app.edit_buffers[i], ImGuiInputTextFlags_EnterReturnsTrue)) {
            if (attached && table::write_entry(e, app.edit_buffers[i], *app.process, app.modules)) {
                if (e.frozen_value) e.frozen_value = app.edit_buffers[i];
                app.status = "Wrote " + app.edit_buffers[i] + ".";
            } else {
                app.status = "Could not write '" + app.edit_buffers[i] + "'.";
            }
        }
        if (ImGui::IsItemActive()) app.editing_row = row;
        else if (app.editing_row == row) app.editing_row = -1;

        ImGui::TableNextColumn();
        ImGui::TextUnformatted(e.location_string().c_str());

        ImGui::TableNextColumn();
        // Keep: pointer paths that find a heap value again after a restart (static addresses already do)
        const bool is_static = !e.is_absolute() && e.location.offsets.empty();
        ImGui::BeginDisabled(!attached || job_running(app) || is_static || !e.alternatives.empty());
        if (ImGui::SmallButton(e.alternatives.empty() ? "Keep" : "Kept")) make_entry_permanent(app, i);
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip(is_static ? "A static address: it already survives restarts."
                                        : "Find pointer paths so this value is found again after the game restarts.");
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Pointers")) {
            const uintptr_t address = attached ? e.address(*app.process, app.modules) : 0;
            if (address) {
                app.ptr_target = utils::format_address(address);
                if (is_numeric(e.type)) app.ptr_add_type = type_index_of(e.type);
                app.status = "Pointer scanner target set to " + app.ptr_target + ". Open 'Pointer scanner' and press Scan.";
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("X")) remove_row = i;
        ImGui::PopID();
    }
    ImGui::EndTable();

    if (remove_row) {
        entries.erase(entries.begin() + static_cast<std::ptrdiff_t>(*remove_row));
        app.edit_buffers.erase(app.edit_buffers.begin() + static_cast<std::ptrdiff_t>(*remove_row));
        app.editing_row = -1;
    }
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
                    scanner::PointerScanner(app.process).scan(target, options));
                return [&app, result]() {
                    app.pointer_paths = std::move(result->paths);
                    app.status = "Pointer scan: " + std::to_string(app.pointer_paths.size()) + " paths" +
                                 (result->truncated ? " (hit the search limit: lower the depth or max offset)" : "") +
                                 ". Restart the target, find the value again, then Rescan.";
                };
            });
        }
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(app.pointer_paths.empty());
    if (ImGui::Button("Rescan")) {
        const uintptr_t target = utils::parse_address(app.ptr_target);
        const size_t before = app.pointer_paths.size();
        app.pointer_paths = scanner::PointerScanner::verify_paths(*app.process, app.pointer_paths, target);
        app.status = "Rescan: " + std::to_string(app.pointer_paths.size()) + " of " + std::to_string(before) +
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
    clipper.Begin(static_cast<int>(app.pointer_paths.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            ImGui::TableNextRow();
            ImGui::PushID(row);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(app.pointer_paths[static_cast<size_t>(row)].to_string().c_str());
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Add")) add_row = static_cast<size_t>(row);
            ImGui::PopID();
        }
    }
    ImGui::EndTable();

    if (add_row) {
        std::lock_guard<std::mutex> lock(app.table_mutex);
        app.table.entries.push_back(table::make_entry(app.pointer_paths[*add_row], type_at(app.ptr_add_type)));
        app.status = "Added " + app.table.entries.back().location_string() + " to the cheat table.";
    }
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
        ImGui::SeparatorText("Pointer scanner");
        draw_pointer_scanner(app);

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
};

// nce_gui.exe [--pid <pid>] [--table <file.json>] [--screenshot <file.bmp>]
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
        if (auto loaded = table::load_table(options.table)) {
            std::lock_guard<std::mutex> lock(app.table_mutex);
            app.table = std::move(*loaded);
            if (is_attached(app)) app.table_note = reconcile_table(app);
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
    apply_launch_options(app, options);
    std::thread freeze_thread(freeze_worker, &app);

    constexpr int SCREENSHOT_FRAME = 10; // let tables settle their column widths first
    int frame = 0;
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
        process_hotkeys(app);
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
        if (screenshot_mode && ++frame >= SCREENSHOT_FRAME && !job_running(app) && !app.track_pending) {
            exit_code = save_back_buffer(options.screenshot) ? 0 : 1;
            done = true;
        }

        const HRESULT hr = g_swap_chain->Present(1, 0); // vsync
        g_swap_chain_occluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    unregister_hotkeys();
    app.freeze_running = false;
    freeze_thread.join();
    if (app.job.valid()) app.job.wait(); // let a running scan finish before tearing down

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_device();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return exit_code;
}
