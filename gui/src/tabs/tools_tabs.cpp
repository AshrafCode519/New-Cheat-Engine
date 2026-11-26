#include "../app_state.hpp"

namespace nce::gui {

void draw_speedhack(App& app) {
    ImGui::TextWrapped("Dilates or slows down game time progression by hooking QueryPerformanceCounter and GetTickCount64 inside the target process.");
    ImGui::Separator();

    const bool remote_mode = app.session.is_remote();
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

    if (remote_mode) {
        ImGui::TextColored(ImVec4(0.35f, 0.90f, 1.0f, 1.0f), "Remote NCE3 Speedhack active (executes on host agent).");
    }
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

    ImGui::SameLine();
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Scan Hybrid PE+ELF")) {
        app.hybrid_modules = app.session.inspect_hybrid_modules();
        app.pe_status = std::string(app.session.is_proton_or_wine() ? "Proton/Wine hybrid mode: " : "Hybrid scan: ") +
                        std::to_string(app.hybrid_modules.size()) + " modules inspected.";
    }
    ImGui::EndDisabled();

    if (!app.pe_status.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "[*] %s", app.pe_status.c_str());
    }

    if (!app.hybrid_modules.empty()) {
        if (ImGui::BeginTable("hybrid_mods", 5, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter,
                              ImVec2(0, em(8)))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Format", ImGuiTableColumnFlags_WidthFixed, em(5));
            ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, em(10));
            ImGui::TableSetupColumn("Syms", ImGuiTableColumnFlags_WidthFixed, em(5));
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(5));
            ImGui::TableHeadersRow();
            for (size_t hi = 0; hi < app.hybrid_modules.size(); ++hi) {
                const auto& hm = app.hybrid_modules[hi];
                ImGui::TableNextRow();
                ImGui::PushID(static_cast<int>(90000 + hi));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(hm.name.c_str());
                ImGui::TableNextColumn(); ImGui::Text("%s%s", hm.format.c_str(), hm.has_dwarf ? "+DWARF" : "");
                ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(hm.base_address).c_str());
                ImGui::TableNextColumn(); ImGui::Text("%zu", hm.export_or_symbol_count);
                ImGui::TableNextColumn();
                if (ImGui::SmallButton("Inspect")) {
                    app.pe_module_input = hm.name;
                    analyze_selected_binary(hm.name);
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }

    ImGui::Separator();

    // NCE v3.0: Anti-Debug / IAT Hook / RWX Cave Inspector + Local MSF 7.00 .PDB Symbol Reader
    ImGui::SeparatorText("Protection Inspector & Local MSF 7.00 .PDB Symbols");
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Scan Anti-Debug / IAT Hooks / RWX")) {
        app.prot_report = app.session.inspect_protections();
        app.pe_status = app.prot_report->summary;
    }
    ImGui::EndDisabled();
    if (app.prot_report) {
        const auto& pr = *app.prot_report;
        ImGui::SameLine();
        ImGui::TextColored(pr.risk_score >= 50 ? ImVec4(1.0f, 0.45f, 0.45f, 1.0f) : ImVec4(0.4f, 0.95f, 0.5f, 1.0f),
                           "Risk Score: %d/100 (%zu findings)", pr.risk_score, pr.findings.size());
        if (!pr.findings.empty() && ImGui::BeginTable("prot_findings", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(7)))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, em(5));
            ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, em(8));
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(10));
            ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const auto& f : pr.findings) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(f.severity.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(f.category.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(f.address).c_str());
                ImGui::TableNextColumn(); ImGui::Text("%s (%s)", f.description.c_str(), f.mitigation.c_str());
            }
            ImGui::EndTable();
        }
    }

    if (app.pdb_module_input.empty() && !app.pe_module_input.empty()) {
        app.pdb_module_input = app.pe_module_input;
    }
    ImGui::SetNextItemWidth(em(10));
    ImGui::InputTextWithHint("##pdb_mod", "Module name", &app.pdb_module_input);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(14));
    ImGui::InputTextWithHint("##pdb_path", "Optional path\\file.pdb", &app.pdb_path_input);
    ImGui::SameLine();
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Load .PDB")) {
        (void)app.session.load_pdb(app.pdb_module_input, app.pdb_path_input, app.pdb_status);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(10));
    ImGui::InputTextWithHint("##pdb_query", "Search PDB sym...", &app.pdb_search_input);
    ImGui::SameLine();
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Find Sym")) {
        app.pdb_hits = app.session.search_pdb_symbols(app.pdb_search_input, 64);
    }
    ImGui::EndDisabled();
    if (!app.pdb_status.empty()) ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f), "%s", app.pdb_status.c_str());
    if (!app.pdb_hits.empty() && ImGui::BeginTable("pdb_hits_tbl", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(6)))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, em(9));
        ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, em(7));
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& [mname, sym] : app.pdb_hits) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(mname.c_str());
            ImGui::TableNextColumn(); ImGui::Text("+0x%X", sym.rva);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(sym.name.c_str());
        }
        ImGui::EndTable();
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

    ImGui::SeparatorText("One-Click C++20 SDK.hpp Dumper & Godot Summary");
    ImGui::SetNextItemWidth(em(11));
    ImGui::InputTextWithHint("##sdk_flt", "Class filter (optional)", &app.sdk_filter);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em(12));
    ImGui::InputTextWithHint("##sdk_out", "SDK.hpp", &app.sdk_out_path);
    ImGui::SameLine();
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Dump SDK Preview")) {
        app.sdk_preview = app.session.dump_sdk_header(app.sdk_filter, 256);
        app.engine_status = "Generated C++20 SDK preview (" + std::to_string(app.sdk_preview.size()) + " bytes).";
    }
    ImGui::SameLine();
    if (ImGui::Button("Save SDK.hpp") && !app.sdk_out_path.empty()) {
        app.sdk_preview = app.session.dump_sdk_header(app.sdk_filter, 512);
        std::ofstream f(app.sdk_out_path, std::ios::binary | std::ios::trunc);
        if (f) {
            f << app.sdk_preview;
            app.engine_status = "Saved SDK header to " + app.sdk_out_path;
        }
    }
    ImGui::EndDisabled();
    if (!app.sdk_preview.empty()) {
        ImGui::BeginChild("sdk_prev_box", ImVec2(-1.0f, em(8)), true, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::TextUnformatted(app.sdk_preview.c_str());
        ImGui::EndChild();
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

    // Compact visual allocation map bar across committed memory regions
    {
        const auto visual_regs = app.session.process().query_regions();
        if (!visual_regs.empty()) {
            const float bar_w = std::max(120.0f, ImGui::GetContentRegionAvail().x);
            const float bar_h = em(1.4f);
            const ImVec2 p0 = ImGui::GetCursorScreenPos();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            dl->AddRectFilled(p0, ImVec2(p0.x + bar_w, p0.y + bar_h), IM_COL32(28, 28, 34, 255));
            const size_t shown = std::min<size_t>(visual_regs.size(), 160);
            const float slice = bar_w / static_cast<float>(shown);
            for (size_t ri = 0; ri < shown; ++ri) {
                const auto& r = visual_regs[ri];
                ImU32 col = IM_COL32(110, 110, 125, 255);
                if (r.is_executable && r.is_writable) col = IM_COL32(230, 75, 75, 255);
                else if (r.is_executable) col = IM_COL32(75, 200, 110, 255);
                else if (r.is_writable) col = IM_COL32(80, 150, 235, 255);
                else if (r.is_guard) col = IM_COL32(235, 195, 65, 255);
                const float x1 = p0.x + static_cast<float>(ri) * slice;
                dl->AddRectFilled(ImVec2(x1, p0.y + 1), ImVec2(std::max(x1 + 1.0f, x1 + slice), p0.y + bar_h - 1), col);
            }
            dl->AddRect(p0, ImVec2(p0.x + bar_w, p0.y + bar_h), IM_COL32(85, 85, 100, 255));
            ImGui::InvisibleButton("##memmap_vis", ImVec2(bar_w, bar_h));
            if (ImGui::IsItemHovered()) {
                const float rel = std::clamp((ImGui::GetIO().MousePos.x - p0.x) / bar_w, 0.0f, 0.9999f);
                const auto& r = visual_regs[static_cast<size_t>(rel * static_cast<float>(shown))];
                ImGui::SetTooltip("%s (%s) %s%s%s", utils::format_address(r.base_address).c_str(),
                                  session::format_size(r.size).c_str(),
                                  r.is_readable ? "R" : "", r.is_writable ? "W" : "", r.is_executable ? "X" : "");
            }
        }
    }

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
    ImGui::InputTextMultiline("##lua_code", &app.lua_script, ImVec2(-1.0f, em(9)), ImGuiInputTextFlags_AllowTabInput);

    // Interactive REPL + Live Watch Expressions
    ImGui::SetNextItemWidth(-em(7));
    const bool repl_submit = ImGui::InputTextWithHint(
        "##lua_repl", "Lua REPL > e.g. readInteger(0x...) or 10 + 20", &app.lua_repl_input,
        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if ((repl_submit || ImGui::Button("Eval##lua")) && !app.lua_repl_input.empty()) {
        app.lua_console_output += "> " + app.lua_repl_input + "\n";
        const auto res = app.session.eval_lua_expression(app.lua_repl_input);
        if (!res.output.empty()) app.lua_console_output += res.output + "\n";
        if (!res.success) app.lua_console_output += "[-] " + res.error + "\n";
        app.lua_repl_input.clear();
    }

    ImGui::SetNextItemWidth(-em(7));
    const bool watch_submit = ImGui::InputTextWithHint(
        "##lua_watch_in", "Live Lua watch expr (e.g. readFloat('game.exe+0x100'))",
        &app.lua_watch_expr_input, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if ((watch_submit || ImGui::Button("Watch##lua")) && !app.lua_watch_expr_input.empty()) {
        app.lua_watches.push_back({app.lua_watch_expr_input, "", true});
        app.lua_watch_expr_input.clear();
    }

    if (!app.lua_watches.empty()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= app.next_lua_watch_eval) {
            app.next_lua_watch_eval = now + std::chrono::milliseconds(250);
            for (auto& w : app.lua_watches) {
                const auto r = app.session.eval_lua_expression(w.expr);
                w.ok = r.success;
                w.value = r.success ? r.output : r.error;
            }
        }
        if (ImGui::BeginTable("lua_watches_tbl", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter, ImVec2(0, em(4.5f)))) {
            ImGui::TableSetupColumn("Expression", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, em(14));
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, em(3));
            ImGui::TableHeadersRow();
            int erase_idx = -1;
            for (size_t wi = 0; wi < app.lua_watches.size(); ++wi) {
                ImGui::TableNextRow();
                ImGui::PushID(static_cast<int>(95000 + wi));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(app.lua_watches[wi].expr.c_str());
                ImGui::TableNextColumn();
                if (!app.lua_watches[wi].ok) ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", app.lua_watches[wi].value.c_str());
                else ImGui::TextUnformatted(app.lua_watches[wi].value.c_str());
                ImGui::TableNextColumn();
                if (ImGui::SmallButton("X")) erase_idx = static_cast<int>(wi);
                ImGui::PopID();
            }
            ImGui::EndTable();
            if (erase_idx >= 0) app.lua_watches.erase(app.lua_watches.begin() + erase_idx);
        }
    }

    ImGui::Spacing();
    ImGui::Text("Script Console Output:");
    ImGui::BeginChild("lua_output", ImVec2(-1.0f, em(6)), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(app.lua_console_output.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();

    ImGui::SeparatorText("Lua Plugins (plugins/*.lua)");
    if (ImGui::Button("Rescan Plugins")) {
        const size_t n = app.session.plugins().scan_plugins();
        app.lua_console_output += "[*] Rescanned plugins: found " + std::to_string(n) + ".\n";
    }
    const auto& pls = app.session.plugins().plugins();
    if (pls.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("Place .lua scripts inside ./plugins/ to extend NCE.");
    } else if (ImGui::BeginTable("lua_plugins_tbl", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter, ImVec2(0, em(5.5f)))) {
        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, em(9));
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, em(6));
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, em(6));
        ImGui::TableHeadersRow();
        for (size_t pi = 0; pi < pls.size(); ++pi) {
            const auto& pl = pls[pi];
            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(97000 + pi));
            ImGui::TableNextColumn(); ImGui::TextUnformatted(pl.id.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s v%s", pl.name.c_str(), pl.version.c_str());
            ImGui::TableNextColumn(); ImGui::TextUnformatted(pl.loaded ? "Loaded" : (pl.enabled ? "Enabled" : "Off"));
            ImGui::TableNextColumn();
            if (pl.enabled) {
                if (ImGui::SmallButton("Disable")) app.session.plugins().disable_plugin(pl.id);
            } else {
                if (ImGui::SmallButton("Enable")) {
                    if (app.session.plugins().enable_plugin(pl.id)) app.lua_console_output += "[+] Loaded plugin " + pl.id + "\n";
                    else app.lua_console_output += "[-] Failed loading plugin " + pl.id + "\n";
                }
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}


} // namespace nce::gui
