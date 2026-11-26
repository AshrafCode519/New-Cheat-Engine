#include "../app_state.hpp"

namespace nce::gui {

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
    const bool remote_mode = app.session.is_remote();
    const auto active_watches = app.session.watched_addresses();
    const bool slots_full = active_watches.size() >= 4;
    if (remote_mode) {
        ImGui::TextColored(ImVec4(0.35f, 0.90f, 1.0f, 1.0f), "Remote NCE3 Watch active (runs on host agent).");
    }
    ImGui::BeginDisabled(!attached);
    ImGui::BeginDisabled(slots_full);
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
    if (ImGui::Button("Stealth GuardPage (No DR)")) {
        const uintptr_t a = utils::parse_address(app.watch_input);
        if (!a) app.watch_note = "Enter the address to watch.";
        else if (app.session.watch(a, static_cast<size_t>(kSizes[app.watch_size_index]), debugger::WatchKind::GuardPage)) {
            app.watch_note = "Stealth PAGE_GUARD trap armed (DR0-DR3 left untouched).";
        } else {
            app.watch_note = "GuardPage watch failed (requires Win32 DebugAPI target).";
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

    const bool remote_mode = app.session.is_remote();
    const bool attached = is_attached(app);
    auto* dbg = app.session.step_debugger();
    const auto rdbg = (remote_mode && attached) ? app.session.remote_debug_state() : std::nullopt;
    const bool dbg_attached = remote_mode ? (rdbg && rdbg->attached) : (dbg && dbg->is_attached());
    const bool dbg_paused = remote_mode
        ? (rdbg && (rdbg->state == static_cast<uint8_t>(debugger::DebuggerState::PausedAtBreakpoint) ||
                    rdbg->state == static_cast<uint8_t>(debugger::DebuggerState::PausedAtStep)))
        : (dbg && dbg->is_paused());
    const uintptr_t cur_rip = remote_mode ? (rdbg ? static_cast<uintptr_t>(rdbg->regs[8]) : 0) : (dbg ? dbg->current_rip() : 0);

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
        ImGui::TextDisabled("[%s]", remote_mode ? "NCE3-Remote" : (dbg && dbg->backend() == debugger::DebugBackend::VEH ? "VEH" : "Win32"));
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
        const bool at_bp = remote_mode
            ? (rdbg && rdbg->state == static_cast<uint8_t>(debugger::DebuggerState::PausedAtBreakpoint))
            : (dbg && dbg->state() == debugger::DebuggerState::PausedAtBreakpoint);
        if (at_bp) {
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
    ImGui::SameLine();
    if (ImGui::SmallButton("Decompile")) {
        const uintptr_t entry = utils::parse_address(app.disasm_input);
        if (entry) {
            const uintptr_t st = utils::parse_address(app.decomp_struct_addr);
            app.decomp_result = app.session.decompile_function(entry, st, 256);
            app.disasm_view_mode = 3;
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
    ImGui::SameLine();
    if (ImGui::RadioButton("Pseudo-C", app.disasm_view_mode == 3)) app.disasm_view_mode = 3;
    ImGui::SameLine();
    if (ImGui::RadioButton("Causality", app.disasm_view_mode == 4)) app.disasm_view_mode = 4;
    ImGui::SameLine();
    if (ImGui::RadioButton("Micro-Emu / Taint", app.disasm_view_mode == 5)) app.disasm_view_mode = 5;

    if (app.disasm_view_mode == 5) {
        ImGui::SeparatorText("Safe Copy-On-Write Micro-Emulator & Backward Taint Slicer");
        if (app.emu_addr_input.empty()) app.emu_addr_input = app.disasm_input;
        if (app.taint_entry_input.empty()) app.taint_entry_input = app.disasm_input;
        ImGui::SetNextItemWidth(em(11));
        ImGui::InputTextWithHint("##emu_addr", "Entry 0xAddr", &app.emu_addr_input);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(4.5f));
        ImGui::InputInt("Steps##emu", &app.emu_steps, 0, 0);
        app.emu_steps = std::clamp(app.emu_steps, 1, 256);
        ImGui::SameLine();
        ImGui::BeginDisabled(!attached);
        if (ImGui::Button("Dry-Run Emulate")) {
            const uintptr_t ea = utils::parse_address(app.emu_addr_input);
            if (ea) {
                debugger::Registers init{};
                if (dbg && dbg->is_attached()) init = dbg->registers();
                app.emu_result = app.session.emulate_code(ea, init, static_cast<size_t>(app.emu_steps));
            }
        }
        ImGui::EndDisabled();

        if (app.emu_result) {
            const auto& er = *app.emu_result;
            ImGui::Text("Steps: %zu | Completed: %s | Final RAX=0x%llX RCX=0x%llX RDX=0x%llX%s",
                        er.steps_executed, er.completed ? "Yes" : "No",
                        static_cast<unsigned long long>(er.final_regs.rax),
                        static_cast<unsigned long long>(er.final_regs.rcx),
                        static_cast<unsigned long long>(er.final_regs.rdx),
                        er.fault_reason.empty() ? "" : (" | Note: " + er.fault_reason).c_str());
            if (!er.trace.empty() && ImGui::BeginTable("emu_trace_tbl", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(10)))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(11));
                ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("RAX After", ImGuiTableColumnFlags_WidthFixed, em(10));
                ImGui::TableSetupColumn("RSP After", ImGuiTableColumnFlags_WidthFixed, em(10));
                ImGui::TableHeadersRow();
                for (const auto& s : er.trace) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(s.address).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.disassembly.c_str());
                    ImGui::TableNextColumn(); ImGui::Text("0x%llX", static_cast<unsigned long long>(s.rax_after));
                    ImGui::TableNextColumn(); ImGui::Text("0x%llX", static_cast<unsigned long long>(s.rsp_after));
                }
                ImGui::EndTable();
            }
        }

        ImGui::SeparatorText("Backward Register Taint Slice");
        ImGui::SetNextItemWidth(em(10));
        ImGui::InputTextWithHint("##taint_entry", "Func Entry 0x...", &app.taint_entry_input);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(10));
        ImGui::InputTextWithHint("##taint_sink", "Sink 0x...", &app.taint_sink_input);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(em(6));
        ImGui::InputTextWithHint("##taint_reg", "rax", &app.taint_reg_input);
        ImGui::SameLine();
        ImGui::BeginDisabled(!attached);
        if (ImGui::Button("Trace Origin")) {
            const uintptr_t ea = utils::parse_address(app.taint_entry_input);
            const uintptr_t sa = utils::parse_address(app.taint_sink_input);
            if (ea && sa && !app.taint_reg_input.empty()) {
                app.taint_steps = app.session.trace_backward_taint(ea, sa, app.taint_reg_input);
            }
        }
        ImGui::EndDisabled();
        if (!app.taint_steps.empty() && ImGui::BeginTable("taint_tbl", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV, ImVec2(0, em(9)))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, em(11));
            ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Origin Note", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const auto& ts : app.taint_steps) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(utils::format_address(ts.address).c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(ts.instruction.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(ts.origin_note.c_str());
            }
            ImGui::EndTable();
        }
        return;
    }

    if (app.disasm_view_mode == 3) {
        ImGui::SeparatorText("Pseudo-C Decompiler (CFG -> Structured C + Struct Fields)");
        ImGui::SetNextItemWidth(em(14));
        ImGui::InputTextWithHint("##decomp_struct", "Optional Struct Ptr (0x...)", &app.decomp_struct_addr);
        ImGui::SameLine();
        ImGui::BeginDisabled(!attached);
        if (ImGui::Button("Refresh Decompile")) {
            const uintptr_t entry = utils::parse_address(app.disasm_input);
            if (entry) {
                app.decomp_result = app.session.decompile_function(entry, utils::parse_address(app.decomp_struct_addr), 256);
            }
        }
        ImGui::EndDisabled();
        if (app.decomp_result) {
            ImGui::SameLine();
            if (ImGui::Button("Copy Pseudo-C")) ImGui::SetClipboardText(app.decomp_result->code.c_str());
            ImGui::BeginChild("decomp_code_box", ImVec2(-1.0f, em(24)), true, ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::TextUnformatted(app.decomp_result->code.c_str());
            ImGui::EndChild();
        } else {
            ImGui::TextDisabled("Enter a function address and click Decompile to lift assembly into Pseudo-C.");
        }
        return;
    }

    if (app.disasm_view_mode == 4) {
        ImGui::SeparatorText("Execution Causality & Time-Travel Timeline");
        ImGui::SetNextItemWidth(em(12));
        ImGui::InputTextWithHint("##tl_watch", "Watch Mem Addr (0x...)", &app.timeline_watch_addr);
        ImGui::SameLine();
        if (ImGui::Button("Capture Trace")) {
            const size_t n = app.session.capture_timeline_from_trace(utils::parse_address(app.timeline_watch_addr));
            app.disasm_note = "Captured " + std::to_string(n) + " debugger trace events into timeline.";
        }
        ImGui::SameLine();
        if (ImGui::Button("Capture Watch Hits")) {
            const size_t n = app.session.capture_timeline_from_watch(utils::parse_address(app.timeline_watch_addr));
            app.disasm_note = "Captured " + std::to_string(n) + " AccessWatcher hits into timeline.";
        }
        ImGui::SameLine();
        if (ImGui::Button("< Back")) app.session.timeline().step_backward();
        ImGui::SameLine();
        if (ImGui::Button("Next >")) app.session.timeline().step_forward();
        ImGui::SameLine();
        if (ImGui::Button("Clear##tl")) app.session.timeline().clear();

        auto& tl = app.session.timeline();
        if (tl.empty()) {
            ImGui::TextDisabled("Timeline is empty. Capture debugger tracepoints or AccessWatcher hits.");
        } else {
            int cur_idx = static_cast<int>(tl.cursor());
            const int max_idx = static_cast<int>(tl.count() - 1);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::SliderInt("##tl_scrub", &cur_idx, 0, max_idx, "Event %d")) {
                tl.seek(static_cast<size_t>(cur_idx));
            }
            if (auto ev = tl.current()) {
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f), "%s", ev->summary.c_str());
                ImGui::Text("RAX=0x%llX  RBX=0x%llX  RCX=0x%llX  RDX=0x%llX  RSI=0x%llX  RDI=0x%llX",
                            static_cast<unsigned long long>(ev->registers.rax),
                            static_cast<unsigned long long>(ev->registers.rbx),
                            static_cast<unsigned long long>(ev->registers.rcx),
                            static_cast<unsigned long long>(ev->registers.rdx),
                            static_cast<unsigned long long>(ev->registers.rsi),
                            static_cast<unsigned long long>(ev->registers.rdi));
                if (!ev->reg_deltas.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Register Deltas vs previous step:");
                    for (const auto& rd : ev->reg_deltas) {
                        ImGui::BulletText("%s: 0x%llX -> 0x%llX", rd.name.c_str(),
                                          static_cast<unsigned long long>(rd.before),
                                          static_cast<unsigned long long>(rd.after));
                    }
                }
                if (!ev->memory_deltas.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "Watched Memory Mutations:");
                    for (const auto& md : ev->memory_deltas) {
                        ImGui::BulletText("%s: 0x%02X -> 0x%02X", utils::format_address(md.address).c_str(),
                                          static_cast<unsigned>(md.before), static_cast<unsigned>(md.after));
                    }
                }
            }
            const auto report = tl.format_report(0, 128);
            ImGui::BeginChild("tl_list", ImVec2(-1.0f, em(12)), true);
            ImGui::TextUnformatted(report.c_str());
            ImGui::EndChild();
        }
        return;
    }

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

} // namespace nce::gui
