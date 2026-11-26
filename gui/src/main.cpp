// New Cheat Engine v3.0 - modular graphical front end (Win32+DX11 / SDL2+OpenGL3).

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <d3d11.h>
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
#else
#define SDL_MAIN_HANDLED
#include <SDL.h>
#include <SDL_opengl.h>
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"
#endif

#include "app_state.hpp"

namespace {

using namespace nce;
using namespace nce::gui;

#ifdef _WIN32
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
    if (res == DXGI_ERROR_UNSUPPORTED) {
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
            if ((wparam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

std::string to_utf8(const wchar_t* text) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    std::string out(size > 0 ? size - 1 : 0, '\0');
    if (size > 1) WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), size, nullptr, nullptr);
    return out;
}
#endif

struct LaunchOptions {
    std::string pid;
    std::string table;
    std::string screenshot;
    std::string track;
    int wait_seconds = 0;
    std::string view;
    std::string tab;
    std::string watch;
    std::string library;
};

void parse_launch_option(LaunchOptions& options, const std::string& option, const std::string& value) {
    if (option == "--pid") options.pid = value;
    else if (option == "--table") options.table = value;
    else if (option == "--screenshot") options.screenshot = value;
    else if (option == "--track") options.track = value;
    else if (option == "--wait") options.wait_seconds = std::atoi(value.c_str());
    else if (option == "--view") options.view = value;
    else if (option == "--watch") options.watch = value;
    else if (option == "--tab") options.tab = value;
    else if (option == "--library") options.library = value;
}

#ifdef _WIN32
LaunchOptions parse_command_line() {
    LaunchOptions options;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return options;
    for (int i = 1; i + 1 < argc; i += 2) {
        parse_launch_option(options, to_utf8(argv[i]), to_utf8(argv[i + 1]));
    }
    LocalFree(argv);
    return options;
}
#else
LaunchOptions parse_command_line(int argc, char** argv) {
    LaunchOptions options;
    for (int i = 1; i + 1 < argc; i += 2) {
        parse_launch_option(options, argv[i], argv[i + 1]);
    }
    return options;
}
#endif

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
        app.dissect_pending = true;
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

bool write_bmp_bgra(const std::string& path, uint32_t width, uint32_t height, const std::vector<uint8_t>& bgra_top_down) {
    if (width == 0 || height == 0 || bgra_top_down.size() < static_cast<size_t>(width) * height * 4) return false;
    const uint32_t image_size = width * height * 4;
    const uint32_t off_bits = 54;
    const uint32_t file_size = off_bits + image_size;
    auto put_u16 = [](uint8_t* dst, uint16_t v) { dst[0] = static_cast<uint8_t>(v & 0xFF); dst[1] = static_cast<uint8_t>(v >> 8); };
    auto put_u32 = [](uint8_t* dst, uint32_t v) {
        dst[0] = static_cast<uint8_t>(v & 0xFF);
        dst[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        dst[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        dst[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    };

    uint8_t hdr[54]{};
    hdr[0] = 'B';
    hdr[1] = 'M';
    put_u32(hdr + 2, file_size);
    put_u32(hdr + 10, off_bits);
    put_u32(hdr + 14, 40);
    put_u32(hdr + 18, width);
    put_u32(hdr + 22, static_cast<uint32_t>(-static_cast<int32_t>(height)));
    put_u16(hdr + 26, 1);
    put_u16(hdr + 28, 32);
    put_u32(hdr + 34, image_size);

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(hdr), sizeof(hdr));
    out.write(reinterpret_cast<const char*>(bgra_top_down.data()), static_cast<std::streamsize>(image_size));
    return static_cast<bool>(out);
}

#ifdef _WIN32
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
        std::vector<uint8_t> bgra(static_cast<size_t>(desc.Width) * desc.Height * 4);
        for (UINT y = 0; y < desc.Height; ++y) {
            const auto* src = static_cast<const uint8_t*>(mapped.pData) + y * mapped.RowPitch;
            uint8_t* dst = bgra.data() + static_cast<size_t>(y) * desc.Width * 4;
            for (UINT x = 0; x < desc.Width; ++x) {
                dst[x * 4 + 0] = src[x * 4 + 2];
                dst[x * 4 + 1] = src[x * 4 + 1];
                dst[x * 4 + 2] = src[x * 4 + 0];
                dst[x * 4 + 3] = src[x * 4 + 3];
            }
        }
        saved = write_bmp_bgra(path, desc.Width, desc.Height, bgra);
        g_device_context->Unmap(staging, 0);
    }
    staging->Release();
    return saved;
}
#else
bool save_back_buffer(const std::string& path) {
    SDL_Window* win = static_cast<SDL_Window*>(g_sdl_win_native);
    if (!win) return false;
    int w = 0, h = 0;
    SDL_GL_GetDrawableSize(win, &w, &h);
    if (w <= 0 || h <= 0) return false;
    std::vector<uint8_t> rgba(static_cast<size_t>(w) * h * 4);
    glReadPixels(0, 0, w, h, GL_RGBA, GL_UNSIGNED_BYTE, rgba.data());
    std::vector<uint8_t> bgra(rgba.size());
    for (int y = 0; y < h; ++y) {
        const uint8_t* src = rgba.data() + static_cast<size_t>(h - 1 - y) * w * 4;
        uint8_t* dst = bgra.data() + static_cast<size_t>(y) * w * 4;
        for (int x = 0; x < w; ++x) {
            dst[x * 4 + 0] = src[x * 4 + 2];
            dst[x * 4 + 1] = src[x * 4 + 1];
            dst[x * 4 + 2] = src[x * 4 + 0];
            dst[x * 4 + 3] = 255;
        }
    }
    return write_bmp_bgra(path, static_cast<uint32_t>(w), static_cast<uint32_t>(h), bgra);
}
#endif

void init_imgui_context(float dpi_scale) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    const float clamped = std::max(1.0f, dpi_scale);
    ImFontConfig font_config;
    font_config.SizePixels = 13.0f * clamped;
    io.Fonts->AddFontDefault(&font_config);
    ImGui::StyleColorsDark();
    ImGui::GetStyle().ScaleAllSizes(clamped);
}

void init_app_session(App& app, const LaunchOptions& options) {
    if (options.library == "off") {
        app.session.table().set_library({});
    } else if (!options.library.empty()) {
        app.session.table().set_library(std::filesystem::path(std::u8string(options.library.begin(), options.library.end())));
    } else {
        app.session.table().set_library(session::default_library_folder());
        load_workspace_config(app);
    }
    apply_workspace_theme(app);

    app.session.table().on_hotkey([&app](const std::string& combo, const session::Outcome& outcome) {
        std::lock_guard<std::mutex> lock(app.hotkey_mutex);
        app.hotkey_events.emplace_back(combo, outcome);
    });
    apply_launch_options(app, options);
}

void tick_app_logic(App& app) {
    poll_job(app);
    tick_reattach(app);
    process_hotkeys(app);
    show_table_hotkeys(app);
    tick_tracking(app);
}

bool should_capture_screenshot(
    const App& app,
    const LaunchOptions& options,
    bool screenshot_mode,
    int& frame,
    std::chrono::steady_clock::time_point started)
{
    constexpr int SCREENSHOT_FRAME = 10;
    return screenshot_mode && ++frame >= SCREENSHOT_FRAME && !job_running(app) && !app.track_pending &&
           elapsed_ms(started) >= options.wait_seconds * 1000LL;
}

} // namespace

namespace nce::gui {

void draw_ui(App& app) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("New Cheat Engine v3.0", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                 ImGuiWindowFlags_NoBringToFrontOnFocus);

    draw_process_bar(app);
    ImGui::SameLine();
    if (ImGui::SmallButton("Ctrl+K")) {
        app.cmd_palette_open = true;
        app.cmd_palette_filter.clear();
        ImGui::OpenPopup("Command Palette##nce_cmd_palette");
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Open Command Palette (Ctrl+K)");
    ImGui::SameLine();
    if (ImGui::SmallButton("Theme/UI")) {
        ImGui::OpenPopup("WorkspaceThemePopup");
    }
    if (ImGui::BeginPopup("WorkspaceThemePopup")) {
        if (ImGui::Checkbox("Dark Theme", &app.workspace_dark_theme)) {
            apply_workspace_theme(app);
        }
        ImGui::SetNextItemWidth(em(10));
        if (ImGui::SliderFloat("Text Scale", &app.workspace_font_scale, 0.85f, 1.50f, "%.2fx")) {
            apply_workspace_theme(app);
        }
        if (ImGui::Button("Save Workspace JSON")) {
            save_workspace_config(app);
            app.status = "Saved workspace preferences.";
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Updates")) {
        app.updater_popup_open = true;
        ImGui::OpenPopup("Check for Updates##nce_updater");
        if (!app.updater_checked && !job_running(app)) {
            app.updater_status = "Querying GitHub Releases...";
            start_job(app, "Checking for NCE updates", [&app]() -> ApplyResult {
                auto info = utils::Updater::check_for_updates();
                return [&app, info = std::move(info)]() mutable {
                    app.updater_checked = true;
                    app.updater_info = std::move(info);
                    if (!app.updater_info.ok) {
                        app.updater_status = "Update check failed: " + app.updater_info.error;
                    } else if (app.updater_info.update_available) {
                        app.updater_status = "Update available: " + app.updater_info.tag_name +
                                             " (current v" + std::string(utils::kNceVersion) + ")";
                    } else {
                        app.updater_status = "Up to date (v" + std::string(utils::kNceVersion) +
                                             ", latest GitHub " + app.updater_info.tag_name + ").";
                    }
                    app.status = app.updater_status;
                    app.status_timed = false;
                };
            });
        }
    }
    if (app.updater_popup_open) {
        ImGui::SetNextWindowSize(ImVec2(em(30), em(17)), ImGuiCond_Appearing);
        if (ImGui::BeginPopupModal("Check for Updates##nce_updater", &app.updater_popup_open)) {
            ImGui::Text("Installed Version: v%s", utils::kNceVersion);
            if (!app.updater_status.empty()) {
                ImGui::TextWrapped("%s", app.updater_status.c_str());
            }
            ImGui::Spacing();
            ImGui::BeginDisabled(job_running(app));
            if (ImGui::Button("Check Now")) {
                app.updater_status = "Querying GitHub Releases...";
                start_job(app, "Checking for NCE updates", [&app]() -> ApplyResult {
                    auto info = utils::Updater::check_for_updates();
                    return [&app, info = std::move(info)]() mutable {
                        app.updater_checked = true;
                        app.updater_info = std::move(info);
                        if (!app.updater_info.ok) {
                            app.updater_status = "Update check failed: " + app.updater_info.error;
                        } else if (app.updater_info.update_available) {
                            app.updater_status = "Update available: " + app.updater_info.tag_name;
                        } else {
                            app.updater_status = "You are on the latest version (latest GitHub: " + app.updater_info.tag_name + ").";
                        }
                        app.status = app.updater_status;
                        app.status_timed = false;
                    };
                });
            }
            if (app.updater_info.ok && !app.updater_info.asset_url.empty()) {
                ImGui::SameLine();
                const std::string dl_label = "Download " + app.updater_info.asset_name;
                if (ImGui::Button(dl_label.c_str())) {
                    const std::string dl_url = app.updater_info.asset_url;
                    const std::string dl_name = app.updater_info.asset_name;
                    app.updater_status = "Downloading " + dl_name + "...";
                    start_job(app, "Downloading release package", [&app, dl_url, dl_name]() -> ApplyResult {
                        std::string err;
                        const bool ok = utils::Updater::download_file(dl_url, dl_name, err);
                        return [&app, ok, dl_name, err]() {
                            app.updater_status = ok ? ("Downloaded package to ./" + dl_name) : ("Download failed: " + err);
                            app.status = app.updater_status;
                            app.status_timed = ok;
                        };
                    });
                }
            }
            ImGui::EndDisabled();
            if (app.updater_info.ok && !app.updater_info.release_url.empty()) {
                ImGui::SameLine();
                if (ImGui::Button("Open Releases Page")) {
                    (void)utils::Updater::open_url_in_browser(app.updater_info.release_url);
                }
            } else {
                ImGui::SameLine();
                if (ImGui::Button("Open Releases Page")) {
                    (void)utils::Updater::open_url_in_browser("https://github.com/AshrafCode519/New-Cheat-Engine/releases");
                }
            }
            if (!app.updater_info.release_notes.empty()) {
                ImGui::Separator();
                ImGui::BeginChild("upd_notes", ImVec2(0, 0), true);
                ImGui::TextWrapped("%s", app.updater_info.release_notes.c_str());
                ImGui::EndChild();
            }
            ImGui::EndPopup();
        }
    }

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_K, false)) {
        app.cmd_palette_open = true;
        app.cmd_palette_filter.clear();
        ImGui::OpenPopup("Command Palette##nce_cmd_palette");
    }
    if (app.cmd_palette_open) {
        ImGui::SetNextWindowSize(ImVec2(em(28), em(19)), ImGuiCond_Appearing);
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
                {"Hardware & Stealth Guard Watch", "watch hw guard page access write", Tab::Watch, -1},
                {"Disassembler & Debugger", "disasm asm step bp trace", Tab::Disasm, 0},
                {"Interactive CFG Graph (Pan & Zoom)", "cfg graph blocks branch pan zoom", Tab::Disasm, 1},
                {"Ultimap Profiler", "ultimap rank function hits", Tab::Disasm, 2},
                {"Pseudo-C Decompiler", "decompile pseudo c struct", Tab::Disasm, 3},
                {"Execution Causality Timeline", "timeline time travel trace diff", Tab::Disasm, 4},
                {"Micro-Emulator & Backward Taint", "emu emulate taint dry run slice", Tab::Disasm, 5},
                {"3D Radar & Unreal Actors Overlay", "radar 3d coords actors waypoint", Tab::Radar, -1},
                {"Speedhack Controller", "speed time scale", Tab::Speedhack, -1},
                {"Memory Snapshot Diff", "diff snapshot compare", Tab::Diff, -1},
                {"PE/ELF, Protection & Local PDB", "pe elf protection iat pdb symbols", Tab::PETools, -1},
                {"Engine Inspector & C++ SDK Dumper", "engine unity il2cpp unreal godot sdk", Tab::EngineInspector, -1},
                {"Lua 5.4 Studio & Plugin Manager", "lua console script plugin", Tab::LuaScript, -1},
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
            if (ImGui::BeginTabItem("Pointer scanner", nullptr, pointer_flags)) { draw_pointer_scanner(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Memory", nullptr, memory_flags)) { draw_memory(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Memory Map", nullptr, memmap_flags)) { draw_memory_map(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Hotkeys", nullptr, hotkey_flags)) { draw_hotkeys(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Scripts", nullptr, scripts_flags)) { draw_scripts(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Dissect", nullptr, dissect_flags)) { draw_dissect(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Watch", nullptr, watch_flags)) { draw_watch(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Disasm", nullptr, disasm_flags)) { draw_disasm(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Radar / 3D", nullptr, radar_flags)) { draw_radar(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Speedhack", nullptr, speedhack_flags)) { draw_speedhack(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Mem Diff", nullptr, diff_flags)) { draw_diff(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("PE/ELF/Sec", nullptr, pe_flags)) { draw_pe_tools(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Engine & SDK", nullptr, eng_flags)) { draw_engine_inspector(app); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Lua & Plugins", nullptr, lua_flags)) { draw_lua_studio(app); ImGui::EndTabItem(); }
            ImGui::EndTabBar();
        }
        ImGui::EndTable();
    }
    ImGui::End();

    draw_oscilloscope(app);
}

} // namespace nce::gui

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int) {
    const LaunchOptions options = parse_command_line();
    const bool screenshot_mode = !options.screenshot.empty();
    ImGui_ImplWin32_EnableDpiAwareness();

    WNDCLASSEXW wc{sizeof(wc), CS_CLASSDC, window_proc, 0, 0, instance, nullptr, nullptr, nullptr, nullptr,
                   L"NewCheatEngine", nullptr};
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"New Cheat Engine v3.0", WS_OVERLAPPEDWINDOW, 100, 100, 1400, 860,
                              nullptr, nullptr, wc.hInstance, nullptr);

    g_hwnd_native = hwnd;
    if (!create_device(hwnd)) {
        cleanup_device();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        MessageBoxW(nullptr, L"Could not create a Direct3D 11 device.", L"New Cheat Engine", MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, screenshot_mode ? SW_HIDE : SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    init_imgui_context(ImGui_ImplWin32_GetDpiScaleForHwnd(hwnd));
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_device_context);

    App app;
    init_app_session(app, options);

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
            Sleep(10);
            continue;
        }
        g_swap_chain_occluded = false;

        if (g_resize_width != 0 && g_resize_height != 0) {
            cleanup_render_target();
            g_swap_chain->ResizeBuffers(0, g_resize_width, g_resize_height, DXGI_FORMAT_UNKNOWN, 0);
            g_resize_width = g_resize_height = 0;
            create_render_target();
        }

        tick_app_logic(app);

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        draw_ui(app);
        ImGui::Render();

        const float clear_color[4] = {0.08f, 0.08f, 0.10f, 1.0f};
        g_device_context->OMSetRenderTargets(1, &g_render_target, nullptr);
        g_device_context->ClearRenderTargetView(g_render_target, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        if (should_capture_screenshot(app, options, screenshot_mode, frame, started)) {
            exit_code = save_back_buffer(options.screenshot) ? 0 : 1;
            done = true;
        }

        const HRESULT hr = g_swap_chain->Present(1, 0);
        g_swap_chain_occluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    if (options.library != "off" && !screenshot_mode) save_workspace_config(app);
    unregister_hotkeys();
    if (app.job.valid()) app.job.wait();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_device();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return exit_code;
}
#else
int main(int argc, char** argv) {
    const LaunchOptions options = parse_command_line(argc, argv);
    const bool screenshot_mode = !options.screenshot.empty();

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) return 1;

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);

    Uint32 win_flags = SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI;
    if (screenshot_mode) win_flags |= SDL_WINDOW_HIDDEN;
    SDL_Window* window = SDL_CreateWindow("New Cheat Engine v3.0",
                                          SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                          1400, 860, win_flags);
    if (!window) { SDL_Quit(); return 1; }
    g_sdl_win_native = window;

    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    if (!gl_context) {
        g_sdl_win_native = nullptr;
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1);

    int win_w = 0, draw_w = 0;
    SDL_GetWindowSize(window, &win_w, nullptr);
    SDL_GL_GetDrawableSize(window, &draw_w, nullptr);
    const float dpi_scale = (win_w > 0 && draw_w > win_w) ? static_cast<float>(draw_w) / static_cast<float>(win_w) : 1.0f;
    init_imgui_context(dpi_scale);

    ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init("#version 130");

    App app;
    init_app_session(app, options);

    int frame = 0;
    const auto started = std::chrono::steady_clock::now();
    int exit_code = 0;
    bool done = false;
    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) done = true;
            if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE &&
                event.window.windowID == SDL_GetWindowID(window)) {
                done = true;
            }
        }
        if (done) break;

        if (!screenshot_mode && (SDL_GetWindowFlags(window) & SDL_WINDOW_MINIMIZED) != 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        tick_app_logic(app);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();
        draw_ui(app);
        ImGui::Render();

        int dw = 0, dh = 0;
        SDL_GL_GetDrawableSize(window, &dw, &dh);
        glViewport(0, 0, dw, dh);
        glClearColor(0.08f, 0.08f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        if (should_capture_screenshot(app, options, screenshot_mode, frame, started)) {
            exit_code = save_back_buffer(options.screenshot) ? 0 : 1;
            done = true;
        }

        SDL_GL_SwapWindow(window);
    }

    if (options.library != "off" && !screenshot_mode) save_workspace_config(app);
    if (app.job.valid()) app.job.wait();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    g_sdl_win_native = nullptr;
    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return exit_code;
}
#endif
