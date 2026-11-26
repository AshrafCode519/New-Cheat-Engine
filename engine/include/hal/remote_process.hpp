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
// over a framed binary TCP protocol ("NCE2" / "NCE3" encrypted + remote debug/watch/speed).
struct RemoteWatchHit {
    uintptr_t instruction{0};
    std::string location;
    std::string disassembly;
    std::vector<uint8_t> bytes;
    uint64_t regs[18]{}; // rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,rip,r8..r15,eflags
    size_t count{0};
    std::string base_register;
    int64_t base_offset{0};
};

struct RemoteDebugState {
    bool attached{false};
    uint8_t state{0}; // matches debugger::DebuggerState
    uint32_t active_tid{0};
    uint64_t regs[18]{};
    struct Bp {
        uintptr_t address{0};
        bool enabled{false};
        uint64_t hits{0};
        std::string note;
    };
    std::vector<Bp> breakpoints;
};

class RemoteProcess final : public IProcess {
public:
    RemoteProcess() = default;
    ~RemoteProcess() override;

    RemoteProcess(const RemoteProcess&) = delete;
    RemoteProcess& operator=(const RemoteProcess&) = delete;

    bool connect(const std::string& host, uint16_t port, const std::string& auth_token = "");
    void disconnect();

    [[nodiscard]] bool is_connected() const noexcept;
    [[nodiscard]] bool is_encrypted() const noexcept;
    [[nodiscard]] uint32_t protocol_version() const noexcept { return m_proto_version; }
    [[nodiscard]] std::string host() const { return m_host; }
    [[nodiscard]] uint16_t port() const noexcept { return m_port; }
    [[nodiscard]] std::string remote_os() const { return m_remote_os; }
    [[nodiscard]] std::string last_error() const;

    // Lists processes visible to the connected RemoteServer
    [[nodiscard]] std::vector<ProcessInfo> list_remote_processes() const;
    // Lists OS threads belonging to the currently attached remote process
    [[nodiscard]] std::vector<ThreadInfo> list_remote_threads() const;

    // NCE3 Remote Watch / Debugger / Speedhack RPCs
    bool remote_watch_start(uintptr_t address, size_t size, uint8_t kind);
    bool remote_watch_stop();
    bool remote_watch_clear();
    bool remote_watch_poll(bool& out_active, std::vector<RemoteWatchHit>& out_hits) const;

    bool remote_speed_set(double factor, std::string& out_msg);
    bool remote_speed_reset();

    bool remote_dbg_attach(uint8_t backend, std::string& out_error);
    bool remote_dbg_detach();
    bool remote_dbg_set_bp(uintptr_t address, const std::string& note = "", bool temporary = false,
                           const std::string& condition = "", bool is_tracepoint = false);
    bool remote_dbg_remove_bp(uintptr_t address);
    bool remote_dbg_action(uint8_t action); // 0=resume,1=pause,2=step_into,3=step_over,4=step_out
    bool remote_dbg_state(RemoteDebugState& out_state) const;

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
    mutable uint8_t m_session_key[32]{};
    mutable bool m_encrypted{false};
    uint32_t m_proto_version{2};

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
