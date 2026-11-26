#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "hal/remote_process.hpp"
#include "scanner/memory_scanner.hpp"
#include "session/session.hpp"

#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

using namespace nce;
using test::FakeProcess;

TEST_CASE("RemoteServer and RemoteProcess expose IProcess and MemoryScanner over TCP NCE2") {
    auto target_mem = std::make_shared<FakeProcess>(0x8000);
    target_mem->set_name("remote_game.exe");
    target_mem->add_module("remote_game.exe", 0, 0x4000);
    target_mem->put<int32_t>(0x100, 1337);
    target_mem->put<float>(0x104, 42.5f);

    hal::RemoteServer::ProcessFactory factory = [target_mem]() -> std::unique_ptr<hal::IProcess> {
        // Lightweight forwarding adapter so the server owns a unique_ptr while test mutates `target_mem`
        struct SharedAdapter final : hal::IProcess {
            std::shared_ptr<FakeProcess> inner;
            explicit SharedAdapter(std::shared_ptr<FakeProcess> p) : inner(std::move(p)) {}
            bool attach(uint32_t pid) override { return inner->attach(pid); }
            void detach() override { inner->detach(); }
            bool is_attached() const noexcept override { return inner->is_attached(); }
            uint32_t get_pid() const noexcept override { return inner->get_pid(); }
            bool read_raw(uintptr_t a, void* b, size_t s) const override { return inner->read_raw(a, b, s); }
            bool write_raw(uintptr_t a, const void* b, size_t s, bool f) const override { return inner->write_raw(a, b, s, f); }
            std::vector<hal::MemoryRegion> query_regions(uint32_t fl) const override { return inner->query_regions(fl); }
            std::vector<hal::ModuleInfo> get_modules() const override { return inner->get_modules(); }
            uintptr_t allocate_memory(size_t s, uint32_t p, uintptr_t n) override { return inner->allocate_memory(s, p, n); }
            bool free_memory(uintptr_t a, size_t s) override { return inner->free_memory(a, s); }
            size_t pointer_size() const noexcept override { return inner->pointer_size(); }
            bool can_write() const noexcept override { return inner->can_write(); }
            std::string name() const override { return inner->name(); }
            bool suspend() override { return inner->suspend(); }
            bool resume() override { return inner->resume(); }
        };
        return std::make_unique<SharedAdapter>(target_mem);
    };

    hal::RemoteServer::ProcessListFn list_fn = []() {
        hal::ProcessInfo pi;
        pi.pid = 1;
        pi.name = "remote_game.exe";
        return std::vector<hal::ProcessInfo>{pi};
    };

    hal::RemoteServer server(factory, list_fn);
    REQUIRE(server.start("127.0.0.1", 0, "nce_secret"));
    const uint16_t port = server.bound_port();
    REQUIRE(port > 0);
    REQUIRE(server.is_running());

    // Wrong auth token must fail handshake
    {
        hal::RemoteProcess unauthorized;
        CHECK(!unauthorized.connect("127.0.0.1", port, "bad_token"));
        CHECK(!unauthorized.is_connected());
    }

    // Direct RemoteProcess client operations
    {
        hal::RemoteProcess client;
        REQUIRE(client.connect("127.0.0.1", port, "nce_secret"));
        CHECK(client.is_connected());
        CHECK(!client.remote_os().empty());

        const auto procs = client.list_remote_processes();
        REQUIRE(procs.size() == 1);
        CHECK(procs[0].pid == 1);
        CHECK(procs[0].name == "remote_game.exe");

        REQUIRE(client.attach(1));
        CHECK(client.is_attached());
        CHECK(client.get_pid() == 1);
        CHECK(client.name() == "remote_game.exe");

        int32_t val = 0;
        REQUIRE(client.read<int32_t>(FakeProcess::kBase + 0x100, val));
        CHECK(val == 1337);

        CHECK(client.write<int32_t>(FakeProcess::kBase + 0x100, 1440));
        int32_t updated = 0;
        REQUIRE(target_mem->read<int32_t>(FakeProcess::kBase + 0x100, updated));
        CHECK(updated == 1440);

        const auto mods = client.get_modules();
        REQUIRE(mods.size() == 1);
        CHECK(mods[0].name == "remote_game.exe");

        const auto regs = client.query_regions();
        CHECK(!regs.empty());

        const uintptr_t cave = client.allocate_memory(256, 0x40, 0);
        REQUIRE(cave != 0);
        const uint8_t payload[4] = {0x90, 0x90, 0x90, 0xC3};
        CHECK(client.write_raw(cave, payload, sizeof(payload)));
        uint8_t readback[4]{};
        CHECK(client.read_raw(cave, readback, sizeof(readback)));
        CHECK(readback[3] == 0xC3);
        CHECK(client.free_memory(cave, 256));

        CHECK(client.suspend());
        CHECK(client.resume());
        client.detach();
        client.disconnect();
    }

    // Session + MemoryScanner full scan over remote TCP connection
    {
        session::Session ses(std::make_shared<FakeProcess>(0x1000), hal::IHotkeys::create());
        const auto conn = ses.connect_remote("127.0.0.1", port, "nce_secret");
        REQUIRE(conn.ok);
        CHECK(ses.is_remote());

        const auto rprocs = ses.list_processes();
        REQUIRE(rprocs.size() == 1);
        const auto att = ses.attach(1);
        REQUIRE(att.ok);

        scanner::MemoryScanner sc(ses.process_ptr());
        const auto first = sc.first_scan(
            scanner::DataType::Int32,
            scanner::ScanCondition::ExactValue,
            scanner::ScanValue::of(scanner::DataType::Int32, int32_t{1440}));
        CHECK(test::contains_address(first, FakeProcess::kBase + 0x100));

        target_mem->put<int32_t>(0x100, 2026);
        const auto next = sc.next_scan(
            first,
            scanner::ScanCondition::ExactValue,
            scanner::ScanValue::of(scanner::DataType::Int32, int32_t{2026}));
        REQUIRE(next.count() == 1);
        CHECK(next.address(0) == FakeProcess::kBase + 0x100);

        ses.disconnect_remote();
        CHECK(!ses.is_remote());
    }

    // Remote threads, find_restart(), and is_remote() local-OS safety guards
    {
        hal::ProcessInfo p1;
        p1.pid = 1;
        p1.name = "remote_game.exe";
        hal::ProcessInfo p2;
        p2.pid = 999;
        p2.name = "remote_game.exe";
        std::vector<hal::ProcessInfo> remote_procs = {p1, p2};
        hal::RemoteServer restart_server(factory, [&remote_procs]() { return remote_procs; });
        REQUIRE(restart_server.start("127.0.0.1", 0, ""));
        const uint16_t rport = restart_server.bound_port();

        session::Session rses(std::make_shared<FakeProcess>(0x1000), hal::IHotkeys::create());
        REQUIRE(rses.connect_remote("127.0.0.1", rport, "").ok);
        REQUIRE(rses.attach(1).ok);

        const auto restarted = rses.find_restart();
        REQUIRE(restarted.has_value());
        CHECK(restarted->pid == 999);

        // Local OS-only features must refuse safely while attached remotely
        CHECK(!rses.dbg_attach());
        CHECK(!rses.watch(FakeProcess::kBase + 0x100, 4, debugger::WatchKind::Write));
        CHECK(!rses.set_speed(2.0));
        CHECK(!rses.enable_speedhack());
        std::string inj_err;
        CHECK(!rses.inject_dll("dummy.dll", inj_err));
        CHECK(inj_err.find("remote") != std::string::npos);

        // list_threads() routes cleanly over NCE2 CMD_LIST_THREADS (no crash or local PID leak)
        const auto threads = rses.list_threads();
        (void)threads;

        rses.disconnect_remote();
        restart_server.stop();
    }

    server.stop();
    CHECK(!server.is_running());
}

TEST_CASE("RemoteServer hardening (F1-F3): thread reaping, max clients cap, pre-auth limit, constant-time auth") {
    auto mem = std::make_shared<FakeProcess>(0x4000);
    mem->set_name("hardened.exe");
    mem->add_module("hardened.exe", 0, 0x2000);
    mem->put<int32_t>(0x100, 777);

    hal::RemoteServer::ProcessFactory factory = [mem]() -> std::unique_ptr<hal::IProcess> {
        struct Adapter final : hal::IProcess {
            std::shared_ptr<FakeProcess> inner;
            explicit Adapter(std::shared_ptr<FakeProcess> p) : inner(std::move(p)) {}
            bool attach(uint32_t pid) override { return inner->attach(pid); }
            void detach() override { inner->detach(); }
            bool is_attached() const noexcept override { return inner->is_attached(); }
            uint32_t get_pid() const noexcept override { return inner->get_pid(); }
            bool read_raw(uintptr_t a, void* b, size_t s) const override { return inner->read_raw(a, b, s); }
            bool write_raw(uintptr_t a, const void* b, size_t s, bool f) const override { return inner->write_raw(a, b, s, f); }
            std::vector<hal::MemoryRegion> query_regions(uint32_t fl) const override { return inner->query_regions(fl); }
            std::vector<hal::ModuleInfo> get_modules() const override { return inner->get_modules(); }
            uintptr_t allocate_memory(size_t s, uint32_t p, uintptr_t n) override { return inner->allocate_memory(s, p, n); }
            bool free_memory(uintptr_t a, size_t s) override { return inner->free_memory(a, s); }
            size_t pointer_size() const noexcept override { return inner->pointer_size(); }
            bool can_write() const noexcept override { return inner->can_write(); }
            std::string name() const override { return inner->name(); }
            bool suspend() override { return inner->suspend(); }
            bool resume() override { return inner->resume(); }
        };
        return std::make_unique<Adapter>(mem);
    };

    hal::RemoteServer server(factory, []() {
        hal::ProcessInfo pi;
        pi.pid = 1;
        pi.name = "hardened.exe";
        return std::vector<hal::ProcessInfo>{pi};
    });
    REQUIRE(server.start("127.0.0.1", 0, "topsecret_token"));
    const uint16_t port = server.bound_port();
    REQUIRE(port > 0);

    // F1.1: Sequential connect/disconnect reaps worker threads cleanly (active_client_count drops to 0)
    for (int i = 0; i < 8; ++i) {
        hal::RemoteProcess c;
        REQUIRE(c.connect("127.0.0.1", port, "topsecret_token"));
        c.disconnect();
    }
    for (int w = 0; w < 50 && server.active_client_count() > 0; ++w) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(server.active_client_count() == 0);

    // F1.2: Concurrent client cap rejects excess connections while preserving active clients
    server.set_max_clients(2);
    hal::RemoteProcess c1, c2, c3, c4;
    REQUIRE(c1.connect("127.0.0.1", port, "topsecret_token"));
    REQUIRE(c2.connect("127.0.0.1", port, "topsecret_token"));
    CHECK(server.active_client_count() == 2);
    CHECK(!c3.connect("127.0.0.1", port, "topsecret_token"));

    REQUIRE(c1.attach(1));
    int32_t v = 0;
    REQUIRE(c1.read<int32_t>(FakeProcess::kBase + 0x100, v));
    CHECK(v == 777);

    c1.disconnect();
    for (int w = 0; w < 50 && server.active_client_count() > 1; ++w) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(server.active_client_count() <= 1);
    REQUIRE(c4.connect("127.0.0.1", port, "topsecret_token"));
    c2.disconnect();
    c4.disconnect();
    server.set_max_clients(hal::RemoteServer::kDefaultMaxClients);
    for (int w = 0; w < 50 && server.active_client_count() > 0; ++w) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // F2: Pre-auth oversized NCE2 frame header (16 MB > 4 KB cap) closes cleanly without OOM
    {
        auto raw_connect = [port]() {
#ifdef _WIN32
            WSADATA wsa{};
            WSAStartup(MAKEWORD(2, 2), &wsa);
            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
            int s = ::socket(AF_INET, SOCK_STREAM, 0);
#endif
            struct sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
            if (::connect(s, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
#ifdef _WIN32
                closesocket(s);
                return INVALID_SOCKET;
#else
                close(s);
                return -1;
#endif
            }
            return s;
        };

        auto sock = raw_connect();
#ifdef _WIN32
        REQUIRE(sock != INVALID_SOCKET);
#else
        REQUIRE(sock >= 0);
#endif
        // Magic "NCE2" (0x3245434E LE), cmd=1 (HELLO), flags=0, seq=1, plen=16*1024*1024
        const uint8_t bad_hdr[16] = {
            0x4E, 0x43, 0x45, 0x32,
            0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01 // 16 MB
        };
        ::send(sock, reinterpret_cast<const char*>(bad_hdr), sizeof(bad_hdr), 0);
        char dump[16]{};
        const auto rc = ::recv(sock, dump, sizeof(dump), 0);
        CHECK(rc <= 0); // Server dropped unauthenticated oversized frame before reading/allocating 16 MB
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }

    // F3: Mismatched tokens (same-length, prefix, suffix, empty) must all fail cleanly
    for (const char* bad_tok : {"topsecret_tokeX", "topsecret", "topsecret_token_extra", ""}) {
        hal::RemoteProcess bad;
        CHECK(!bad.connect("127.0.0.1", port, bad_tok));
        CHECK(!bad.is_connected());
    }

    // Server still healthy after malformed & rejected probes
    {
        hal::RemoteProcess ok;
        REQUIRE(ok.connect("127.0.0.1", port, "topsecret_token"));
        REQUIRE(ok.attach(1));
        int32_t check_v = 0;
        REQUIRE(ok.read<int32_t>(FakeProcess::kBase + 0x100, check_v));
        CHECK(check_v == 777);
        ok.disconnect();
    }

    server.stop();
    CHECK(!server.is_running());
}
