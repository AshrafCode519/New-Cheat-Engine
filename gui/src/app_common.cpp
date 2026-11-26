#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include "app_state.hpp"
#include <nlohmann/json.hpp>

namespace nce::gui {

std::vector<int> g_hotkeys_pressed;

#ifdef _WIN32
void* g_hwnd_native = nullptr;

void beep(uint32_t frequency, uint32_t ms) {
    std::thread([frequency, ms] { Beep(static_cast<DWORD>(frequency), static_cast<DWORD>(ms)); }).detach();
}

bool register_hotkeys() {
    HWND hwnd = static_cast<HWND>(g_hwnd_native);
    const UINT numpad[] = {VK_NUMPAD0, VK_SUBTRACT, VK_ADD, VK_MULTIPLY};
    bool ok = true;
    for (int action = HOTKEY_READY; action <= HOTKEY_CHANGED; ++action) {
        ok &= RegisterHotKey(hwnd, action, MOD_NOREPEAT, numpad[action - 1]) != FALSE;
        ok &= RegisterHotKey(hwnd, action + 10, MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT, '0' + action) != FALSE;
    }
    return ok;
}

void unregister_hotkeys() {
    HWND hwnd = static_cast<HWND>(g_hwnd_native);
    for (int action = HOTKEY_READY; action <= HOTKEY_CHANGED; ++action) {
        UnregisterHotKey(hwnd, action);
        UnregisterHotKey(hwnd, action + 10);
    }
}
#else
void* g_sdl_win_native = nullptr;
bool register_hotkeys() { return false; }
void unregister_hotkeys() {}
void beep(uint32_t, uint32_t) {}
#endif

const std::vector<const char*>& next_labels() {
    static const std::vector<const char*> labels = [] {
        std::vector<const char*> list;
        for (const auto& c : session::ScanSession::next_conditions()) list.push_back(c.label);
        return list;
    }();
    return labels;
}

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

void show(App& app, const session::Outcome& outcome) {
    app.status = outcome.message;
    app.status_timed = outcome.ok;
}

bool job_running(const App& app) {
    return app.job.valid();
}

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

void refresh_processes(App& app) {
    app.processes = app.session.list_processes();
    std::sort(app.processes.begin(), app.processes.end(), [](const hal::ProcessInfo& a, const hal::ProcessInfo& b) {
        const size_t n = std::min(a.name.size(), b.name.size());
        for (size_t i = 0; i < n; ++i) {
            const int ca = std::tolower(static_cast<unsigned char>(a.name[i]));
            const int cb = std::tolower(static_cast<unsigned char>(b.name[i]));
            if (ca != cb) return ca < cb;
        }
        return a.name.size() < b.name.size();
    });
    app.selected_process = -1;
}

void learn_noise(App& app, const std::string& prefix) {
    start_job(app, "Learning noise (leave the target alone)", [&app, prefix]() -> ApplyResult {
        auto noise = app.session.learn_noise();
        return [&app, noise, prefix]() {
            app.session.set_noise(noise);
            app.status = prefix + "Noise: " + app.session.describe_noise() + ".";
        };
    });
}

std::string describe_reconciled(const std::vector<session::TableKeeper::ReconcileLine>& lines) {
    std::string text;
    for (const auto& line : lines) {
        if (!text.empty()) text += "\n";
        text += line.description + ": " + session::describe_reconcile(line.result) + ".";
    }
    return text;
}

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

void attach(App& app, const hal::ProcessInfo& info, const std::string& note) {
    app.tracker.reset();
    app.track_stage = App::TrackStage::Off;
    unregister_hotkeys();
    app.track_best.clear();
    app.editing_row = -1;
    app.memory.clear();
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
        return;
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

void open_memory(App& app, uintptr_t address, bool remember) {
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

constexpr size_t TRACK_SHOWN = 50;
constexpr size_t TRACK_MAX_HANDOVER = 5'000'000;

void refresh_track(App& app) {
    app.track_best = app.tracker->top(TRACK_SHOWN);
    app.track_events = app.tracker->events();
    app.track_summary = std::to_string(app.tracker->candidate_count()) + " candidates" +
        (app.tracker->is_ranked() ? ", ranked" : " (snapshot, " + std::to_string(app.tracker->memory_bytes() / 1024) + " KB)");
    app.last_quiet = std::chrono::steady_clock::now();
}

void start_tracking(App& app) {
    auto types = app.track_auto_type ? scanner::ValueTracker::auto_types()
                                     : std::vector<scanner::DataType>{type_at(app.type_index)};
    app.tracker = app.session.new_tracker(std::move(types));
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
            beep(1320, 90);
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
    app.session.table().refresh_hotkeys();
}

void process_hotkeys(App& app) {
    using Kind = scanner::Expectation::Kind;
    size_t handled = 0;
    for (; handled < g_hotkeys_pressed.size(); ++handled) {
        if (job_running(app)) break;
        const int action = g_hotkeys_pressed[handled];
        if (app.track_stage == App::TrackStage::Off) continue;

        if (action == HOTKEY_READY) {
            if (app.track_stage == App::TrackStage::Quiet) {
                app.track_stage = App::TrackStage::Changing;
                app.status = "Smart track: change the value, then press Num- / Num+ / Num*.";
                beep(880, 80);
            }
        } else if (app.track_stage != App::TrackStage::Changing) {
            beep(220, 200);
        } else {
            track_event(app, {action == HOTKEY_DOWN ? Kind::Decreased : action == HOTKEY_UP ? Kind::Increased : Kind::Changed});
        }
    }
    g_hotkeys_pressed.erase(g_hotkeys_pressed.begin(), g_hotkeys_pressed.begin() + static_cast<std::ptrdiff_t>(handled));
}

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

std::filesystem::path workspace_config_path() {
    return session::default_library_folder().parent_path() / "workspace_v3.json";
}

void apply_workspace_theme(const App& app) {
    if (app.workspace_dark_theme) {
        ImGui::StyleColorsDark();
        ImGuiStyle& s = ImGui::GetStyle();
        s.FrameRounding = 3.0f;
        s.GrabRounding = 3.0f;
        s.Colors[ImGuiCol_Header] = ImVec4(0.18f, 0.36f, 0.56f, 0.85f);
        s.Colors[ImGuiCol_TabActive] = ImVec4(0.18f, 0.38f, 0.58f, 1.00f);
    } else {
        ImGui::StyleColorsLight();
    }
    ImGui::GetIO().FontGlobalScale = std::clamp(app.workspace_font_scale, 0.8f, 1.6f);
}

void load_workspace_config(App& app) {
    std::ifstream in(workspace_config_path(), std::ios::binary);
    if (!in) return;
    try {
        nlohmann::json j;
        in >> j;
        if (j.contains("dark_theme")) app.workspace_dark_theme = j["dark_theme"].get<bool>();
        if (j.contains("font_scale")) app.workspace_font_scale = std::clamp(j["font_scale"].get<float>(), 0.8f, 1.6f);
        if (j.contains("table_path")) app.table_path = j["table_path"].get<std::string>();
        if (j.contains("remote_host")) app.remote_host = j["remote_host"].get<std::string>();
        if (j.contains("remote_port")) app.remote_port = j["remote_port"].get<int>();
        if (j.contains("auto_reattach")) app.auto_reattach = j["auto_reattach"].get<bool>();
        if (j.contains("unity_meta_path")) app.unity_meta_path = j["unity_meta_path"].get<std::string>();
        if (j.contains("ptr_map_path")) app.ptr_map_path = j["ptr_map_path"].get<std::string>();
    } catch (...) {
    }
}

void save_workspace_config(const App& app) {
    std::error_code ec;
    const auto p = workspace_config_path();
    std::filesystem::create_directories(p.parent_path(), ec);
    nlohmann::json j = {
        {"dark_theme", app.workspace_dark_theme},
        {"font_scale", app.workspace_font_scale},
        {"table_path", app.table_path},
        {"remote_host", app.remote_host},
        {"remote_port", app.remote_port},
        {"auto_reattach", app.auto_reattach},
        {"unity_meta_path", app.unity_meta_path},
        {"ptr_map_path", app.ptr_map_path},
    };
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (out) out << j.dump(2);
}

} // namespace nce::gui
