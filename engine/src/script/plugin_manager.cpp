#include "../../include/script/plugin_manager.hpp"
#include "../../include/session/session.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace nce::script {

namespace {

std::string trim_copy(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

std::string read_text_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

std::filesystem::path PluginManager::default_user_plugins_dir() {
#ifdef _WIN32
    if (const char* appdata = std::getenv("APPDATA")) {
        return std::filesystem::path(appdata) / "NewCheatEngine" / "plugins";
    }
    return std::filesystem::current_path() / "plugins";
#else
    if (const char* home = std::getenv("HOME")) {
        return std::filesystem::path(home) / ".config" / "new-cheat-engine" / "plugins";
    }
    return std::filesystem::current_path() / "plugins";
#endif
}

void PluginManager::clear_search_dirs() {
    m_search_dirs.clear();
}

void PluginManager::add_search_dir(const std::filesystem::path& dir) {
    if (!dir.empty()) m_search_dirs.push_back(dir);
}

void PluginManager::use_default_dirs() {
    m_search_dirs.clear();
    m_search_dirs.push_back(std::filesystem::current_path() / "plugins");
    m_search_dirs.push_back(default_user_plugins_dir());
}

void PluginManager::parse_plugin_metadata(const std::string& code, PluginInfo& info) {
    std::istringstream ss(code);
    std::string line;
    for (int i = 0; i < 32 && std::getline(ss, line); ++i) {
        const std::string t = trim_copy(line);
        auto extract_key = [&](const char* key, std::string& dst) {
            const size_t pos = t.find(key);
            if (pos != std::string::npos) {
                const std::string val = trim_copy(t.substr(pos + std::strlen(key)));
                if (!val.empty()) dst = val;
            }
        };
        extract_key("PLUGIN_NAME:", info.name);
        extract_key("PLUGIN_VERSION:", info.version);
        extract_key("PLUGIN_AUTHOR:", info.author);
        extract_key("PLUGIN_DESC:", info.description);
    }
    if (info.name.empty()) info.name = info.id;
}

size_t PluginManager::scan_plugins() {
    if (m_search_dirs.empty()) use_default_dirs();

    // Remember enabled flags by id across rescans
    std::vector<std::string> previously_enabled;
    for (const auto& p : m_plugins) {
        if (p.enabled) previously_enabled.push_back(p.id);
    }

    m_plugins.clear();
    std::error_code ec;
    for (const auto& dir : m_search_dirs) {
        if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) continue;
        for (const auto& ent : std::filesystem::directory_iterator(dir, ec)) {
            if (!ent.is_regular_file(ec)) continue;
            if (ent.path().extension() != ".lua") continue;
            PluginInfo info;
            info.id = ent.path().stem().string();
            info.file_path = ent.path().string();
            const std::string src = read_text_file(info.file_path);
            parse_plugin_metadata(src, info);
            if (std::find(previously_enabled.begin(), previously_enabled.end(), info.id) != previously_enabled.end()) {
                info.enabled = true;
                info.loaded = true;
            }
            // Avoid duplicates across search dirs
            const bool dup = std::any_of(m_plugins.begin(), m_plugins.end(),
                                         [&](const PluginInfo& x) { return x.id == info.id; });
            if (!dup) m_plugins.push_back(std::move(info));
        }
    }
    std::sort(m_plugins.begin(), m_plugins.end(), [](const PluginInfo& a, const PluginInfo& b) {
        return a.id < b.id;
    });
    return m_plugins.size();
}

bool PluginManager::enable_plugin(const std::string& id) {
    auto it = std::find_if(m_plugins.begin(), m_plugins.end(), [&](const PluginInfo& p) { return p.id == id; });
    if (it == m_plugins.end() || !m_session) return false;

    const std::string code = read_text_file(it->file_path);
    if (code.empty()) {
        it->last_error = "Could not read plugin file";
        return false;
    }

    const auto res = m_session->run_lua(code);
    if (!res.success) {
        it->last_error = res.error;
        it->enabled = false;
        it->loaded = false;
        return false;
    }
    it->enabled = true;
    it->loaded = true;
    it->last_error.clear();
    (void)m_session->run_lua("if type(onPluginEnable) == 'function' then onPluginEnable('" + id + "') end");
    return true;
}

bool PluginManager::disable_plugin(const std::string& id) {
    auto it = std::find_if(m_plugins.begin(), m_plugins.end(), [&](const PluginInfo& p) { return p.id == id; });
    if (it == m_plugins.end()) return false;

    if (m_session) {
        (void)m_session->run_lua("if type(onPluginDisable) == 'function' then onPluginDisable('" + id + "') end");
    }
    for (size_t i = m_commands.size(); i-- > 0;) {
        if (m_commands[i].plugin_id == id) {
            const std::string cmd_name = m_commands[i].command_name;
            m_commands.erase(m_commands.begin() + static_cast<std::ptrdiff_t>(i));
            m_command_callbacks.erase(
                std::remove_if(m_command_callbacks.begin(), m_command_callbacks.end(),
                               [&](const auto& kv) { return kv.first == cmd_name; }),
                m_command_callbacks.end());
        }
    }
    it->enabled = false;
    return true;
}

void PluginManager::register_command(std::string cmd, std::string plugin_id, std::string help_text, std::string lua_fn_name) {
    for (size_t i = 0; i < m_commands.size(); ++i) {
        if (m_commands[i].command_name == cmd) {
            m_commands[i] = {cmd, std::move(plugin_id), std::move(help_text)};
            m_command_callbacks[i].second = std::move(lua_fn_name);
            return;
        }
    }
    m_commands.push_back({cmd, std::move(plugin_id), std::move(help_text)});
    m_command_callbacks.emplace_back(std::move(cmd), std::move(lua_fn_name));
}

bool PluginManager::invoke_command(const std::string& cmd, const std::string& args, std::string& out_msg) {
    if (!m_session) {
        out_msg = "No active session";
        return false;
    }
    for (const auto& [name, fn] : m_command_callbacks) {
        if (name == cmd) {
            std::string escaped;
            for (char c : args) {
                if (c == '\\' || c == '\'') escaped.push_back('\\');
                escaped.push_back(c);
            }
            const auto res = m_session->run_lua("return " + fn + "('" + escaped + "')");
            out_msg = res.success ? res.output : res.error;
            return res.success;
        }
    }
    out_msg = "Unknown plugin command: " + cmd;
    return false;
}

void PluginManager::dispatch_hook(const std::string& hook_fn_name) {
    if (!m_session) return;
    bool any_enabled = std::any_of(m_plugins.begin(), m_plugins.end(), [](const PluginInfo& p) { return p.enabled; });
    if (!any_enabled) return;
    (void)m_session->run_lua("if type(" + hook_fn_name + ") == 'function' then " + hook_fn_name + "() end");
}

} // namespace nce::script
