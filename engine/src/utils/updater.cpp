#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "../../include/utils/updater.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>

namespace nce::utils {

namespace {

bool is_safe_https_url(const std::string& url) {
    return url.rfind("https://", 0) == 0 && url.size() > 8 &&
           url.find('\r') == std::string::npos &&
           url.find('\n') == std::string::npos &&
           url.find('"') == std::string::npos;
}

bool icontains(const std::string& hay, const std::string& needle) {
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) ==
                      std::tolower(static_cast<unsigned char>(b));
           }) != hay.end();
}

#ifdef _WIN32
std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(n > 0 ? static_cast<size_t>(n) : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

bool winhttp_fetch(const std::string& url, std::string& out_body, std::string& out_err, const std::string* save_path = nullptr) {
    if (!is_safe_https_url(url)) {
        out_err = "Invalid or non-HTTPS URL.";
        return false;
    }

    const std::wstring wurl = to_wide(url);
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{};
    wchar_t path[2048]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2047;
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc)) {
        out_err = "Failed parsing HTTPS URL.";
        return false;
    }

    HINTERNET hSess = WinHttpOpen(L"NewCheatEngine-Updater/3.0",
                                  WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) {
        out_err = "WinHttpOpen failed.";
        return false;
    }

    WinHttpSetTimeouts(hSess, 10000, 10000, 15000, 30000);
    HINTERNET hConn = WinHttpConnect(hSess, host, uc.nPort, 0);
    HINTERNET hReq = hConn ? WinHttpOpenRequest(hConn, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
                           : nullptr;
    if (!hReq) {
        if (hConn) WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        out_err = "Failed creating HTTPS request.";
        return false;
    }

    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof(redir));
    const wchar_t* hdrs = L"Accept: application/vnd.github+json\r\n";
    BOOL ok = WinHttpSendRequest(hReq, hdrs, static_cast<DWORD>(-1), WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
              WinHttpReceiveResponse(hReq, nullptr);
    DWORD status_code = 0;
    DWORD sc_sz = sizeof(status_code);
    if (ok) {
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &sc_sz, WINHTTP_NO_HEADER_INDEX);
    }
    if (!ok || status_code < 200 || status_code >= 300) {
        out_err = !ok ? "HTTPS request failed (offline or blocked)."
                      : ("HTTP status " + std::to_string(status_code));
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        return false;
    }

    std::ofstream fout;
    if (save_path) {
        std::error_code ec;
        std::filesystem::create_directories(std::filesystem::path(*save_path).parent_path(), ec);
        fout.open(*save_path, std::ios::binary | std::ios::trunc);
        if (!fout) {
            out_err = "Could not open destination file for writing: " + *save_path;
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            WinHttpCloseHandle(hSess);
            return false;
        }
    }

    std::vector<char> chunk(16384);
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        const DWORD want = std::min<DWORD>(avail, static_cast<DWORD>(chunk.size()));
        DWORD got = 0;
        if (!WinHttpReadData(hReq, chunk.data(), want, &got) || got == 0) break;
        if (save_path) fout.write(chunk.data(), static_cast<std::streamsize>(got));
        else {
            if (out_body.size() + got > 4u * 1024u * 1024u) {
                out_err = "Response payload exceeded limit.";
                WinHttpCloseHandle(hReq);
                WinHttpCloseHandle(hConn);
                WinHttpCloseHandle(hSess);
                return false;
            }
            out_body.append(chunk.data(), got);
        }
    }
    if (save_path && !fout.good()) {
        out_err = "Failed writing downloaded bytes.";
        ok = FALSE;
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return ok == TRUE;
}
#else
bool posix_curl_fetch(const std::string& url, std::string& out_body, std::string& out_err, const std::string* save_path = nullptr) {
    if (!is_safe_https_url(url)) {
        out_err = "Invalid or non-HTTPS URL.";
        return false;
    }
    int fds[2]{-1, -1};
    if (!save_path && pipe(fds) != 0) {
        out_err = "pipe failed.";
        return false;
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (!save_path) { close(fds[0]); close(fds[1]); }
        out_err = "fork failed.";
        return false;
    }
    if (pid == 0) {
        if (save_path) {
            execlp("curl", "curl", "-fsSL", "--max-time", "30",
                   "-A", "NewCheatEngine-Updater/3.0",
                   "-o", save_path->c_str(), url.c_str(), nullptr);
        } else {
            dup2(fds[1], STDOUT_FILENO);
            close(fds[0]);
            close(fds[1]);
            execlp("curl", "curl", "-fsSL", "--max-time", "15",
                   "-A", "NewCheatEngine-Updater/3.0",
                   "-H", "Accept: application/vnd.github+json", url.c_str(), nullptr);
        }
        _exit(127);
    }
    if (!save_path) {
        close(fds[1]);
        char buf[4096];
        ssize_t n = 0;
        while ((n = read(fds[0], buf, sizeof(buf))) > 0) {
            if (out_body.size() + static_cast<size_t>(n) > 4u * 1024u * 1024u) break;
            out_body.append(buf, static_cast<size_t>(n));
        }
        close(fds[0]);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        out_err = "curl failed (exit " + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) + ").";
        return false;
    }
    return true;
}
#endif

} // namespace

std::array<int, 3> Updater::parse_semver(const std::string& raw, bool& out_prerelease) {
    out_prerelease = false;
    size_t i = 0;
    while (i < raw.size() && (raw[i] == 'v' || raw[i] == 'V' || std::isspace(static_cast<unsigned char>(raw[i])))) {
        ++i;
    }
    const size_t dash = raw.find('-', i);
    const std::string core = (dash == std::string::npos) ? raw.substr(i) : raw.substr(i, dash - i);
    if (dash != std::string::npos) out_prerelease = true;

    std::array<int, 3> parts{0, 0, 0};
    size_t pos = 0;
    for (int idx = 0; idx < 3 && pos < core.size(); ++idx) {
        const size_t dot = core.find('.', pos);
        const std::string seg = (dot == std::string::npos) ? core.substr(pos) : core.substr(pos, dot - pos);
        parts[static_cast<size_t>(idx)] = std::atoi(seg.c_str());
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }
    return parts;
}

bool Updater::is_newer_version(const std::string& candidate, const std::string& current) {
    bool cand_pre = false;
    bool cur_pre = false;
    const auto a = parse_semver(candidate, cand_pre);
    const auto b = parse_semver(current, cur_pre);
    for (size_t i = 0; i < 3; ++i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return cur_pre && !cand_pre;
}

UpdateInfo Updater::parse_github_release_json(
    const std::string& json_text,
    const std::string& current_version,
    bool prefer_windows)
{
    UpdateInfo info;
    info.current_version = current_version;
    try {
        const auto j = nlohmann::json::parse(json_text);
        if (!j.contains("tag_name") || !j["tag_name"].is_string()) {
            info.error = j.contains("message") && j["message"].is_string()
                ? j["message"].get<std::string>()
                : "GitHub response missing tag_name.";
            return info;
        }

        info.tag_name = j["tag_name"].get<std::string>();
        info.latest_version = (!info.tag_name.empty() && (info.tag_name[0] == 'v' || info.tag_name[0] == 'V'))
            ? info.tag_name.substr(1)
            : info.tag_name;
        if (j.contains("html_url") && j["html_url"].is_string()) {
            info.release_url = j["html_url"].get<std::string>();
        }
        if (j.contains("body") && j["body"].is_string()) {
            info.release_notes = j["body"].get<std::string>();
            if (info.release_notes.size() > 1200) {
                info.release_notes.resize(1200);
                info.release_notes += "\n...";
            }
        }

        if (j.contains("assets") && j["assets"].is_array()) {
            const std::string needle = prefer_windows ? "windows" : "linux";
            const std::string ext = prefer_windows ? ".zip" : ".tar.gz";
            for (const auto& a : j["assets"]) {
                if (!a.is_object() || !a.contains("name") || !a.contains("browser_download_url")) continue;
                const std::string aname = a["name"].get<std::string>();
                const std::string aurl = a["browser_download_url"].get<std::string>();
                if (icontains(aname, needle) || icontains(aname, ext)) {
                    info.asset_name = aname;
                    info.asset_url = aurl;
                    if (a.contains("size") && a["size"].is_number_unsigned()) {
                        info.asset_size_bytes = a["size"].get<uint64_t>();
                    }
                    if (icontains(aname, needle)) break;
                }
            }
        }

        info.update_available = is_newer_version(info.tag_name, current_version);
        info.ok = true;
    } catch (const std::exception& e) {
        info.error = std::string("Failed parsing update JSON: ") + e.what();
    }
    return info;
}

UpdateInfo Updater::check_for_updates(const std::string& repo, const std::string& current_version) {
    UpdateInfo info;
    info.current_version = current_version;
    const std::string api_url = "https://api.github.com/repos/" + repo + "/releases/latest";
    std::string body;
    std::string err;
#ifdef _WIN32
    const bool ok = winhttp_fetch(api_url, body, err);
#else
    const bool ok = posix_curl_fetch(api_url, body, err);
#endif
    if (!ok) {
        info.error = err;
        return info;
    }
    return parse_github_release_json(body, current_version);
}

bool Updater::download_file(const std::string& https_url, const std::string& dest_path, std::string& out_error) {
    std::string body_unused;
#ifdef _WIN32
    return winhttp_fetch(https_url, body_unused, out_error, &dest_path);
#else
    return posix_curl_fetch(https_url, body_unused, out_error, &dest_path);
#endif
}

bool Updater::open_url_in_browser(const std::string& https_url) {
    if (!is_safe_https_url(https_url)) return false;
#ifdef _WIN32
    const auto res = reinterpret_cast<uintptr_t>(
        ShellExecuteA(nullptr, "open", https_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
    return res > 32;
#else
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        execlp("xdg-open", "xdg-open", https_url.c_str(), nullptr);
        _exit(127);
    }
    return true;
#endif
}

} // namespace nce::utils
