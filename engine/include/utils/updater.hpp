#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace nce::utils {

inline constexpr const char* kNceVersion = "3.0.0";
inline constexpr const char* kDefaultUpdateRepo = "AshrafCode519/New-Cheat-Engine";

struct UpdateInfo {
    bool ok{false};
    bool update_available{false};
    std::string current_version{kNceVersion};
    std::string latest_version;
    std::string tag_name;
    std::string release_url;
    std::string asset_name;
    std::string asset_url;
    uint64_t asset_size_bytes{0};
    std::string release_notes;
    std::string error;
};

// Queries GitHub Releases for newer NCE versions, parses semantic versions, and downloads release archives.
class Updater {
public:
    [[nodiscard]] static std::array<int, 3> parse_semver(const std::string& raw, bool& out_prerelease);
    [[nodiscard]] static bool is_newer_version(
        const std::string& candidate,
        const std::string& current = kNceVersion);

    [[nodiscard]] static UpdateInfo parse_github_release_json(
        const std::string& json_text,
        const std::string& current_version = kNceVersion,
        bool prefer_windows =
#ifdef _WIN32
            true
#else
            false
#endif
    );

    [[nodiscard]] static UpdateInfo check_for_updates(
        const std::string& repo = kDefaultUpdateRepo,
        const std::string& current_version = kNceVersion);

    static bool download_file(
        const std::string& https_url,
        const std::string& dest_path,
        std::string& out_error);

    static bool open_url_in_browser(const std::string& https_url);
};

} // namespace nce::utils
