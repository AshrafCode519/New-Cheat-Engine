#include "../app_state.hpp"

namespace nce::gui {

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

} // namespace nce::gui
