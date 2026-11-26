#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include "hal/process.hpp"
#include "hal/injector.hpp"
#include "hal/remote_process.hpp"
#include "debugger/micro_emulator.hpp"
#include "debugger/protection_inspector.hpp"
#include "session/session.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace nce;

namespace {

class ChildDummy {
public:
    ChildDummy() = default;
    ~ChildDummy() { terminate_cleanly(); }

    bool start(const std::filesystem::path& exe_path) {
#ifdef _WIN32
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE in_r = nullptr, in_w = nullptr;
        HANDLE out_r = nullptr, out_w = nullptr;
        if (!CreatePipe(&in_r, &in_w, &sa, 0) || !CreatePipe(&out_r, &out_w, &sa, 0)) {
            if (in_r) CloseHandle(in_r);
            if (in_w) CloseHandle(in_w);
            if (out_r) CloseHandle(out_r);
            if (out_w) CloseHandle(out_w);
            return false;
        }
        SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = in_r;
        si.hStdOutput = out_w;
        si.hStdError = out_w;

        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + exe_path.wstring() + L"\"";
        const BOOL ok = CreateProcessW(
            exe_path.c_str(), cmd.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, exe_path.parent_path().c_str(), &si, &pi);

        CloseHandle(in_r);
        CloseHandle(out_w);
        if (!ok) {
            CloseHandle(in_w);
            CloseHandle(out_r);
            return false;
        }
        CloseHandle(pi.hThread);
        m_proc = pi.hProcess;
        m_pid = pi.dwProcessId;
        m_in_write = in_w;
        m_out_read = out_r;
        return true;
#else
        int in_fds[2]{-1, -1};
        int out_fds[2]{-1, -1};
        if (pipe(in_fds) != 0 || pipe(out_fds) != 0) return false;
        pid_t child = fork();
        if (child < 0) {
            close(in_fds[0]); close(in_fds[1]);
            close(out_fds[0]); close(out_fds[1]);
            return false;
        }
        if (child == 0) {
            dup2(in_fds[0], STDIN_FILENO);
            dup2(out_fds[1], STDOUT_FILENO);
            dup2(out_fds[1], STDERR_FILENO);
            close(in_fds[0]); close(in_fds[1]);
            close(out_fds[0]); close(out_fds[1]);
            execl(exe_path.c_str(), exe_path.c_str(), nullptr);
            _exit(127);
        }
        close(in_fds[0]);
        close(out_fds[1]);
        m_child_pid = child;
        m_pid = static_cast<uint32_t>(child);
        m_in_fd = in_fds[1];
        m_out_fd = out_fds[0];
        return true;
#endif
    }

    bool write_line(const std::string& line) {
        const std::string s = line + "\n";
#ifdef _WIN32
        if (!m_in_write) return false;
        DWORD written = 0;
        return WriteFile(m_in_write, s.data(), static_cast<DWORD>(s.size()), &written, nullptr) == TRUE;
#else
        if (m_in_fd < 0) return false;
        const ssize_t n = ::write(m_in_fd, s.data(), s.size());
        return n == static_cast<ssize_t>(s.size());
#endif
    }

    std::string read_until(const std::string& marker, int timeout_ms = 5000) {
        std::string buf;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (buf.find(marker) != std::string::npos) return buf;
#ifdef _WIN32
            DWORD avail = 0;
            if (!PeekNamedPipe(m_out_read, nullptr, 0, nullptr, &avail, nullptr)) break;
            if (avail == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
                continue;
            }
            char tmp[2048];
            DWORD got = 0;
            if (ReadFile(m_out_read, tmp, std::min<DWORD>(avail, sizeof(tmp)), &got, nullptr) && got > 0) {
                buf.append(tmp, got);
            } else {
                break;
            }
#else
            struct pollfd pfd{m_out_fd, POLLIN, 0};
            const int pr = poll(&pfd, 1, 20);
            if (pr > 0 && (pfd.revents & POLLIN)) {
                char tmp[2048];
                const ssize_t got = ::read(m_out_fd, tmp, sizeof(tmp));
                if (got > 0) buf.append(tmp, static_cast<size_t>(got));
                else break;
            } else if (pr > 0 && (pfd.revents & POLLHUP)) {
                break;
            }
#endif
        }
        return buf;
    }

    uint32_t pid() const noexcept { return m_pid; }

    void terminate_cleanly() {
        if (m_closed) return;
        m_closed = true;
        (void)write_line("q");
#ifdef _WIN32
        if (m_in_write) { CloseHandle(m_in_write); m_in_write = nullptr; }
        if (m_out_read) { CloseHandle(m_out_read); m_out_read = nullptr; }
        if (m_proc) {
            if (WaitForSingleObject(m_proc, 2000) != WAIT_OBJECT_0) {
                TerminateProcess(m_proc, 0);
            }
            CloseHandle(m_proc);
            m_proc = nullptr;
        }
#else
        if (m_in_fd >= 0) { close(m_in_fd); m_in_fd = -1; }
        if (m_out_fd >= 0) { close(m_out_fd); m_out_fd = -1; }
        if (m_child_pid > 0) {
            int st = 0;
            if (waitpid(m_child_pid, &st, WNOHANG) == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (waitpid(m_child_pid, &st, WNOHANG) == 0) {
                    kill(m_child_pid, SIGKILL);
                    waitpid(m_child_pid, &st, 0);
                }
            }
            m_child_pid = -1;
        }
#endif
    }

private:
    uint32_t m_pid{0};
    bool m_closed{false};
#ifdef _WIN32
    HANDLE m_proc{nullptr};
    HANDLE m_in_write{nullptr};
    HANDLE m_out_read{nullptr};
#else
    pid_t m_child_pid{-1};
    int m_in_fd{-1};
    int m_out_fd{-1};
#endif
};

uintptr_t extract_hex_after(const std::string& text, const std::string& label) {
    const size_t pos = text.find(label);
    if (pos == std::string::npos) return 0;
    size_t p = pos + label.size();
    return static_cast<uintptr_t>(std::strtoull(text.c_str() + p, nullptr, 16));
}

} // namespace

TEST_CASE("Live OS integration: spawn target_dummy, scan/modify memory, emulate, and encrypted NCE3 loopback") {
    const std::filesystem::path dir(hal::ProcessInjector::executable_directory());
#ifdef _WIN32
    const auto dummy_exe = dir / "target_dummy.exe";
#else
    const auto dummy_exe = dir / "target_dummy";
#endif
    REQUIRE_MESSAGE(std::filesystem::exists(dummy_exe), "Missing binary: ", dummy_exe.string());

    ChildDummy child;
    REQUIRE(child.start(dummy_exe));
    const std::string banner = child.read_until("Enter command > ", 6000);
    INFO("Banner:\n" << banner);
    const uintptr_t health_addr = extract_hex_after(banner, "g_health       @ 0x");
    REQUIRE(health_addr != 0);

    // 1. Live OS attach & read initial health
    auto proc = hal::IProcess::create();
    REQUIRE(proc->attach(child.pid()));
    int32_t hp = 0;
    REQUIRE(proc->read<int32_t>(health_addr, hp));
    CHECK(hp == 1337);

    // 2. Ask target_dummy to decrement health via stdin, verify live memory reflects it
    REQUIRE(child.write_line("1"));
    const std::string step1 = child.read_until("Enter command > ", 4000);
    INFO("Step1:\n" << step1);
    REQUIRE(proc->read<int32_t>(health_addr, hp));
    CHECK(hp == 1237);

    // 3. Write live memory back into child target_dummy and verify target itself prints new value
    REQUIRE(proc->write<int32_t>(health_addr, 9999));
    REQUIRE(child.write_line("5"));
    const std::string step2 = child.read_until("Enter command > ", 4000);
    INFO("Step2:\n" << step2);
    CHECK(step2.find("g_health") != std::string::npos);
    CHECK(step2.find("= 9999") != std::string::npos);

    // 4. Run ProtectionInspector + Safe Copy-On-Write Micro-Emulator against real live process modules
    const auto rep = debugger::ProtectionInspector::inspect(*proc);
    CHECK(!proc->get_modules().empty());
    CHECK(rep.risk_score >= 0);

    const std::vector<uint8_t> cave = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}; // mov eax, 42; ret
    debugger::Registers regs{};
    regs.rsp = 0x700000;
    const auto emu = debugger::MicroEmulator::dry_run_hook(*proc, health_addr, cave, 0x800000, regs, 16);
    CHECK(emu.final_regs.rax == 42);
    CHECK(emu.returned_cleanly);

    proc->detach();

    // 5. Real encrypted TCP NCE3 RemoteServer <-> RemoteProcess reading live child process
    hal::RemoteServer srv;
    REQUIRE(srv.start("127.0.0.1", 0, "live-ci-secret"));
    const uint16_t port = srv.bound_port();
    REQUIRE(port > 0);

    hal::RemoteProcess rproc;
    REQUIRE(rproc.connect("127.0.0.1", port, "live-ci-secret"));
    CHECK(rproc.is_encrypted());
    REQUIRE(rproc.attach(child.pid()));
    int32_t remote_hp = 0;
    REQUIRE(rproc.read<int32_t>(health_addr, remote_hp));
    CHECK(remote_hp == 9999);
    CHECK(!rproc.get_modules().empty());

    rproc.disconnect();
    srv.stop();
    child.terminate_cleanly();
}
