#include "../app_state.hpp"

namespace nce::gui {

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
    if (app.session.is_remote()) {
        if (ImGui::SmallButton("Disconnect Remote")) {
            app.session.disconnect_remote();
            refresh_processes(app);
            app.status = "Disconnected remote host; back on local processes.";
        }
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.35f, 0.90f, 1.0f, 1.0f), "[REMOTE %s%s]",
                           app.session.remote_endpoint().c_str(),
                           app.session.remote_encrypted() ? " | NCE3 Enc" : "");
    } else {
        if (ImGui::SmallButton("Remote...")) {
            app.remote_error.clear();
            ImGui::OpenPopup("RemoteHostPopup");
        }
        if (ImGui::BeginPopup("RemoteHostPopup")) {
            ImGui::TextUnformatted("Connect to nce_server (TCP):");
            ImGui::SetNextItemWidth(em(12));
            ImGui::InputText("Host", &app.remote_host);
            ImGui::SetNextItemWidth(em(7));
            ImGui::InputInt("Port", &app.remote_port);
            ImGui::SetNextItemWidth(em(12));
            ImGui::InputTextWithHint("Token", "optional auth secret", &app.remote_token);
            if (!app.remote_error.empty()) {
                ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", app.remote_error.c_str());
            }
            if (ImGui::Button("Connect")) {
                const uint16_t port = static_cast<uint16_t>(std::clamp(app.remote_port, 1, 65535));
                const auto res = app.session.connect_remote(app.remote_host, port, app.remote_token);
                show(app, res);
                if (res.ok) {
                    app.remote_error.clear();
                    refresh_processes(app);
                    ImGui::CloseCurrentPopup();
                } else {
                    app.remote_error = res.message;
                }
            }
            ImGui::EndPopup();
        }
    }
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
    ImGui::TextWrapped("%zu results  (click: the memory around it, double-click or +: add to the cheat table)", results.count());

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
    ImGui::SameLine();
    ImGui::BeginDisabled(!is_attached(app));
    if (ImGui::Button("Migrate Sigs")) {
        const auto rep = app.session.migrate_table_signatures();
        app.status = "Signature migration: anchored=" + std::to_string(rep.total_anchored) +
                     " updated=" + std::to_string(rep.updated) +
                     " verified=" + std::to_string(rep.verified) +
                     " failed=" + std::to_string(rep.failed);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Scan modules for AOB signature anchors and auto-repair shifted addresses after a patch.");
    }
    ImGui::SameLine();
    if (ImGui::Button("Anchor AOB")) {
        app.anchor_row = std::max(0, app.anchor_row);
        app.anchor_error.clear();
        ImGui::OpenPopup("AnchorSigPopup");
    }
    ImGui::EndDisabled();
    if (ImGui::BeginPopup("AnchorSigPopup")) {
        ImGui::TextUnformatted("Bind entry to a code instruction AOB signature:");
        ImGui::InputInt("Entry #", &app.anchor_row);
        ImGui::InputTextWithHint("Code Addr", "0x... or module+offset", &app.anchor_code_addr);
        ImGui::InputInt("Struct Offset", &app.anchor_struct_offset);
        if (!app.anchor_error.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", app.anchor_error.c_str());
        }
        if (ImGui::Button("Create Anchor")) {
            const uintptr_t ca = utils::parse_address(app.anchor_code_addr);
            if (app.anchor_row >= 0 && ca != 0) {
                const auto out = app.session.anchor_entry_signature(
                    static_cast<size_t>(app.anchor_row), ca, app.anchor_struct_offset);
                show(app, out);
                if (out.ok) {
                    app.anchor_error.clear();
                    ImGui::CloseCurrentPopup();
                } else {
                    app.anchor_error = out.message;
                }
            } else {
                app.anchor_error = "Provide a valid entry index and instruction address.";
            }
        }
        ImGui::EndPopup();
    }
    if (const std::string tbl_lua = keeper.lua_script(); !tbl_lua.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.35f, 1.0f), "Table carries <LuaScript> (%zu B).", tbl_lua.size());
        ImGui::SameLine();
        if (ImGui::SmallButton("Run Table Lua")) {
            show(app, app.session.run_table_lua_script());
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Inspect in Lua Studio")) {
            app.lua_script = tbl_lua;
            app.select_tab = Tab::LuaScript;
        }
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

} // namespace nce::gui
