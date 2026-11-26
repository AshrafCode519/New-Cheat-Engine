#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace nce::session { class Session; }

namespace nce::script {

struct PluginInfo {
    std::string id;       // filename stem (e.g. "auto_health")
    std::string name;     // PLUGIN_NAME or id
    std::string version{"1.0"};
    std::string author;
    std::string description;
    std::string file_path;
    bool enabled{false};
    bool loaded{false};
    std::string last_error;
};

struct PluginCommandInfo {
    std::string command_name;
    std::string plugin_id;
    std::string help_text;
};

// Discovers and manages Lua extension scripts (`plugins/*.lua` and user plugin dir) for NCE v3.0.
class PluginManager {
public:
    explicit PluginManager(session::Session* session = nullptr) : m_session(session) {}

    void set_session(session::Session* session) noexcept { m_session = session; }
    void clear_search_dirs();
    void add_search_dir(const std::filesystem::path& dir);
    void use_default_dirs();

    size_t scan_plugins();
    bool enable_plugin(const std::string& id);
    bool disable_plugin(const std::string& id);

    void register_command(std::string cmd, std::string plugin_id, std::string help_text, std::string lua_fn_name);
    bool invoke_command(const std::string& cmd, const std::string& args, std::string& out_msg);
    void dispatch_hook(const std::string& hook_fn_name);

    [[nodiscard]] const std::vector<PluginInfo>& plugins() const noexcept { return m_plugins; }
    [[nodiscard]] const std::vector<PluginCommandInfo>& commands() const noexcept { return m_commands; }

    [[nodiscard]] static std::filesystem::path default_user_plugins_dir();

private:
    static void parse_plugin_metadata(const std::string& code, PluginInfo& info);

    session::Session* m_session{nullptr};
    std::vector<std::filesystem::path> m_search_dirs;
    std::vector<PluginInfo> m_plugins;
    std::vector<PluginCommandInfo> m_commands;
    std::vector<std::pair<std::string, std::string>> m_command_callbacks; // cmd -> global lua fn
};

} // namespace nce::script
