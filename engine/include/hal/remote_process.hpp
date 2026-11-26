#pragma once

#include "process.hpp"
#include "injector.hpp"
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace nce::hal {

// Networked IProcess backend communicating with `nce_server` (or in-process RemoteServer)
// over a framed binary TCP protocol ("NCE2"). Enables remote memory scanning, disassembly,
// and table management across machines, VMs, WSL, and Steam Deck targets.
class RemoteProcess final : public IProcess {
public:
    RemoteProcess() = default;
    ~RemoteProcess() override;

    RemoteProcess(const RemoteProcess&) = delete;
    RemoteProcess& operator=(const RemoteProcess&) = delete;

    bool connect(const std::string& host, uint16_t port, const std::string& auth_token = "");
    void disconnect();

    [[nodiscard]] bool is_connected() const noexcept;
    [[nodiscard]] std::string host() const { return m_host; }
    [[nodiscard]] uint16_t port() const noexcept { return m_port; }
    [[nodiscard]] std::string remote_os() const { return m_remote_os; }
    [[nodiscard]] std::string last_error() const;

    // Lists processes visible to the connected RemoteServer
    [[nodiscard]] std::vector<ProcessInfo> list_remote_processes() const;
    // Lists OS threads belonging to the currently attached remote process
    [[nodiscard]] std::vector<ThreadInfo> list_remote_threads() const;

    // IProcess overrides
    bool attach(uint32_t pid) override;
    void detach() override;
    [[nodiscard]] bool is_attached() const noexcept override { return m_attached; }
    [[nodiscard]] uint32_t get_pid() const noexcept override { return m_pid; }

    bool read_raw(uintptr_t address, void* buffer, size_t size) const override;
    bool write_raw(uintptr_t address, const void* buffer, size_t size, bool force_protection = true) const override;

    [[nodiscard]] std::vector<MemoryRegion> query_regions(uint32_t filter_flags = FilterFlags::DefaultScanFilter) const override;
    [[nodiscard]] std::vector<ModuleInfo> get_modules() const override;

    uintptr_t allocate_memory(size_t size, uint32_t protection = 0x40, uintptr_t near_addr = 0) override;
    bool free_memory(uintptr_t address, size_t size = 0) override;

    [[nodiscard]] size_t pointer_size() const noexcept override { return m_pointer_size; }
    [[nodiscard]] bool can_write() const noexcept override { return m_can_write; }
    [[nodiscard]] std::string name() const override { return m_name; }

    bool suspend() override;
    bool resume() override;

private:
    bool rpc(uint16_t cmd, const std::vector<uint8_t>& req, std::vector<uint8_t>& resp) const;
    void close_socket_locked() const noexcept;

    std::string m_host;
    uint16_t m_port{0};
    std::string m_remote_os;
    std::string m_name;
    mutable std::string m_last_error;

    mutable std::mutex m_io_mutex;
    mutable uintptr_t m_sock{static_cast<uintptr_t>(-1)};
    mutable uint32_t m_seq{1};

    std::atomic<bool> m_attached{false};
    uint32_t m_pid{0};
    size_t m_pointer_size{sizeof(uintptr_t)};
    bool m_can_write{true};
};

// Multi-client TCP daemon exposing a host machine's processes via IProcess over the NCE2 protocol.
class RemoteServer {
public:
    using ProcessFactory = std::function<std::unique_ptr<IProcess>()>;
    using ProcessListFn = std::function<std::vector<ProcessInfo>()>;

    explicit RemoteServer(
        ProcessFactory factory = [] { return IProcess::create(); },
        ProcessListFn list_fn = [] { return IProcess::list_processes(); }
    );
    ~RemoteServer();

    RemoteServer(const RemoteServer&) = delete;
    RemoteServer& operator=(const RemoteServer&) = delete;

    // Starts listening on `bind_host:port` (port=0 picks an ephemeral OS port).
    bool start(const std::string& bind_host, uint16_t port, const std::string& auth_token = "");
    void stop();

    static constexpr size_t kDefaultMaxClients = 64;
    void set_max_clients(size_t max_clients);
    [[nodiscard]] size_t active_client_count() const;

    [[nodiscard]] bool is_running() const noexcept { return m_running.load(); }
    [[nodiscard]] uint16_t bound_port() const noexcept { return m_bound_port.load(); }
    [[nodiscard]] std::string last_error() const;

private:
    struct ClientWorker {
        uintptr_t sock{static_cast<uintptr_t>(-1)};
        std::shared_ptr<std::atomic<bool>> done;
        std::thread thread;
    };

    void accept_loop();
    void handle_client(uintptr_t client_sock, std::shared_ptr<std::atomic<bool>> done);
    void reap_finished_clients() const;

    ProcessFactory m_factory;
    ProcessListFn m_list_fn;
    std::string m_auth_token;

    std::atomic<bool> m_running{false};
    std::atomic<uint16_t> m_bound_port{0};
    uintptr_t m_listen_sock{static_cast<uintptr_t>(-1)};

    std::thread m_accept_thread;
    mutable std::mutex m_clients_mutex;
    mutable std::vector<ClientWorker> m_clients;
    size_t m_max_clients{kDefaultMaxClients};
    mutable std::mutex m_err_mutex;
    std::string m_last_error;
};

} // namespace nce::hal
