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
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "../../include/hal/remote_process.hpp"
#include <algorithm>
#include <cstring>

namespace nce::hal {

namespace {

constexpr uint32_t kProtoMagic = 0x3245434Eu; // "NCE2"
constexpr uint32_t kMaxPayloadBytes = 64u * 1024u * 1024u;

enum ProtoCmd : uint16_t {
    CMD_HELLO = 1,
    CMD_LIST_PROCESSES = 2,
    CMD_ATTACH = 3,
    CMD_DETACH = 4,
    CMD_QUERY_REGIONS = 5,
    CMD_GET_MODULES = 6,
    CMD_READ_MEM = 7,
    CMD_WRITE_MEM = 8,
    CMD_ALLOC_MEM = 9,
    CMD_FREE_MEM = 10,
    CMD_SUSPEND = 11,
    CMD_RESUME = 12,
};

#ifdef _WIN32
using NativeSock = SOCKET;
constexpr NativeSock kInvalidSock = INVALID_SOCKET;
struct WsaInitGuard {
    bool ok{false};
    WsaInitGuard() {
        WSADATA wsa{};
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    }
    ~WsaInitGuard() {
        if (ok) WSACleanup();
    }
};
bool ensure_sockets_init() {
    static WsaInitGuard guard;
    return guard.ok;
}
void close_native_sock(NativeSock s) noexcept {
    if (s != kInvalidSock) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
}
#else
using NativeSock = int;
constexpr NativeSock kInvalidSock = -1;
bool ensure_sockets_init() { return true; }
void close_native_sock(NativeSock s) noexcept {
    if (s >= 0) {
        shutdown(s, SHUT_RDWR);
        close(s);
    }
}
#endif

NativeSock to_native(uintptr_t s) noexcept {
    return static_cast<NativeSock>(s);
}
uintptr_t from_native(NativeSock s) noexcept {
    return static_cast<uintptr_t>(s);
}

bool send_all(NativeSock sock, const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    size_t sent = 0;
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif
    while (sent < len) {
#ifdef _WIN32
        const int chunk = static_cast<int>(std::min<size_t>(len - sent, 0x40000000u));
        const int n = ::send(sock, reinterpret_cast<const char*>(p + sent), chunk, flags);
#else
        const ssize_t n = ::send(sock, p + sent, len - sent, flags);
#endif
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool recv_all(NativeSock sock, void* data, size_t len) {
    auto* p = static_cast<uint8_t*>(data);
    size_t recvd = 0;
    while (recvd < len) {
#ifdef _WIN32
        const int chunk = static_cast<int>(std::min<size_t>(len - recvd, 0x40000000u));
        const int n = ::recv(sock, reinterpret_cast<char*>(p + recvd), chunk, 0);
#else
        const ssize_t n = ::recv(sock, p + recvd, len - recvd, 0);
#endif
        if (n <= 0) return false;
        recvd += static_cast<size_t>(n);
    }
    return true;
}

struct ByteWriter {
    std::vector<uint8_t> buf;
    void u8(uint8_t v) { buf.push_back(v); }
    void u16(uint16_t v) {
        for (int i = 0; i < 2; ++i) buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
    void str(const std::string& s) {
        const uint32_t len = static_cast<uint32_t>(std::min<size_t>(s.size(), 1024u * 1024u));
        u32(len);
        buf.insert(buf.end(), s.data(), s.data() + len);
    }
    void raw(const void* data, size_t len) {
        const auto* p = static_cast<const uint8_t*>(data);
        buf.insert(buf.end(), p, p + len);
    }
};

struct ByteReader {
    const uint8_t* p{nullptr};
    size_t sz{0};
    size_t off{0};
    bool ok{true};

    bool need(size_t n) {
        if (!ok || off > sz || n > sz - off) { ok = false; return false; }
        return true;
    }
    uint8_t u8() { return need(1) ? p[off++] : 0; }
    uint16_t u16() {
        if (!need(2)) return 0;
        uint16_t v = static_cast<uint16_t>(p[off]) | (static_cast<uint16_t>(p[off + 1]) << 8);
        off += 2;
        return v;
    }
    uint32_t u32() {
        if (!need(4)) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[off + i]) << (i * 8);
        off += 4;
        return v;
    }
    uint64_t u64() {
        if (!need(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[off + i]) << (i * 8);
        off += 8;
        return v;
    }
    std::string str() {
        const uint32_t len = u32();
        if (!ok || len > 16u * 1024u * 1024u || !need(len)) { ok = false; return {}; }
        std::string s(reinterpret_cast<const char*>(p + off), len);
        off += len;
        return s;
    }
    bool read_bytes(void* dst, size_t len) {
        if (!need(len)) return false;
        if (len > 0) std::memcpy(dst, p + off, len);
        off += len;
        return true;
    }
};

bool write_frame(NativeSock sock, uint16_t cmd, uint32_t seq, const std::vector<uint8_t>& payload) {
    if (payload.size() > kMaxPayloadBytes) return false;
    ByteWriter hdr;
    hdr.u32(kProtoMagic);
    hdr.u16(cmd);
    hdr.u16(0);
    hdr.u32(seq);
    hdr.u32(static_cast<uint32_t>(payload.size()));
    if (!send_all(sock, hdr.buf.data(), hdr.buf.size())) return false;
    return payload.empty() || send_all(sock, payload.data(), payload.size());
}

bool read_frame(NativeSock sock, uint16_t& out_cmd, uint32_t& out_seq, std::vector<uint8_t>& out_payload) {
    uint8_t hdr_bytes[16]{};
    if (!recv_all(sock, hdr_bytes, sizeof(hdr_bytes))) return false;
    ByteReader r{hdr_bytes, sizeof(hdr_bytes)};
    if (r.u32() != kProtoMagic) return false;
    out_cmd = r.u16();
    (void)r.u16();
    out_seq = r.u32();
    const uint32_t plen = r.u32();
    if (!r.ok || plen > kMaxPayloadBytes) return false;
    out_payload.resize(plen);
    return plen == 0 || recv_all(sock, out_payload.data(), plen);
}

void set_nodelay(NativeSock s) noexcept {
    int one = 1;
#ifdef _WIN32
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
#else
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
}

std::string host_os_label() {
#ifdef _WIN32
    return "windows";
#elif defined(__linux__)
    return "linux";
#else
    return "posix";
#endif
}

} // namespace

RemoteProcess::~RemoteProcess() {
    disconnect();
}

void RemoteProcess::close_socket_locked() const noexcept {
    const NativeSock s = to_native(m_sock);
    if (s != kInvalidSock) {
        close_native_sock(s);
        m_sock = from_native(kInvalidSock);
    }
}

bool RemoteProcess::connect(const std::string& host, uint16_t port, const std::string& auth_token) {
    disconnect();
    if (!ensure_sockets_init()) {
        std::lock_guard<std::mutex> lock(m_io_mutex);
        m_last_error = "Socket subsystem initialization failed";
        return false;
    }

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        std::lock_guard<std::mutex> lock(m_io_mutex);
        m_last_error = "Failed to resolve host '" + host + "'";
        return false;
    }

    NativeSock connected = kInvalidSock;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        NativeSock s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == kInvalidSock) continue;
        if (::connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) {
            connected = s;
            break;
        }
        close_native_sock(s);
    }
    freeaddrinfo(res);

    if (connected == kInvalidSock) {
        std::lock_guard<std::mutex> lock(m_io_mutex);
        m_last_error = "Connection refused by " + host + ":" + port_str;
        return false;
    }

    set_nodelay(connected);
    {
        std::lock_guard<std::mutex> lock(m_io_mutex);
        m_sock = from_native(connected);
        m_host = host;
        m_port = port;
        m_last_error.clear();
    }

    ByteWriter w;
    w.str(auth_token);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_HELLO, w.buf, resp)) {
        disconnect();
        return false;
    }
    ByteReader r{resp.data(), resp.size()};
    const uint32_t status = r.u32();
    const uint32_t ptr_sz = r.u32();
    const std::string os = r.str();
    if (!r.ok || status != 0) {
        disconnect();
        std::lock_guard<std::mutex> lock(m_io_mutex);
        m_last_error = (status == 1) ? "Authentication rejected by remote server" : "Invalid HELLO reply";
        return false;
    }
    m_pointer_size = ptr_sz ? static_cast<size_t>(ptr_sz) : sizeof(uintptr_t);
    m_remote_os = os;
    return true;
}

void RemoteProcess::disconnect() {
    detach();
    std::lock_guard<std::mutex> lock(m_io_mutex);
    close_socket_locked();
    m_host.clear();
    m_port = 0;
    m_remote_os.clear();
}

bool RemoteProcess::is_connected() const noexcept {
    std::lock_guard<std::mutex> lock(m_io_mutex);
    return to_native(m_sock) != kInvalidSock;
}

std::string RemoteProcess::last_error() const {
    std::lock_guard<std::mutex> lock(m_io_mutex);
    return m_last_error;
}

bool RemoteProcess::rpc(uint16_t cmd, const std::vector<uint8_t>& req, std::vector<uint8_t>& resp) const {
    std::lock_guard<std::mutex> lock(m_io_mutex);
    const NativeSock s = to_native(m_sock);
    if (s == kInvalidSock) {
        m_last_error = "Not connected to remote server";
        return false;
    }
    const uint32_t seq = m_seq++;
    if (!write_frame(s, cmd, seq, req)) {
        m_last_error = "Network send failed";
        close_socket_locked();
        return false;
    }
    uint16_t r_cmd = 0;
    uint32_t r_seq = 0;
    if (!read_frame(s, r_cmd, r_seq, resp) || r_cmd != cmd || r_seq != seq) {
        m_last_error = "Network receive/protocol error";
        close_socket_locked();
        return false;
    }
    return true;
}

std::vector<ProcessInfo> RemoteProcess::list_remote_processes() const {
    std::vector<uint8_t> resp;
    if (!rpc(CMD_LIST_PROCESSES, {}, resp)) return {};
    ByteReader r{resp.data(), resp.size()};
    const uint32_t count = r.u32();
    std::vector<ProcessInfo> out;
    if (!r.ok || count > 100000) return out;
    out.reserve(count);
    for (uint32_t i = 0; i < count && r.ok; ++i) {
        ProcessInfo p;
        p.pid = r.u32();
        p.name = r.str();
        if (r.ok) out.push_back(std::move(p));
    }
    return out;
}

bool RemoteProcess::attach(uint32_t pid) {
    ByteWriter w;
    w.u32(pid);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_ATTACH, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    const bool ok = (r.u8() != 0);
    const uint32_t ptr_sz = r.u32();
    const bool writable = (r.u8() != 0);
    const std::string proc_name = r.str();
    if (!r.ok || !ok) {
        m_attached = false;
        return false;
    }
    m_pid = pid;
    m_pointer_size = ptr_sz ? static_cast<size_t>(ptr_sz) : sizeof(uintptr_t);
    m_can_write = writable;
    m_name = proc_name;
    m_attached = true;
    return true;
}

void RemoteProcess::detach() {
    if (!m_attached.exchange(false)) return;
    std::vector<uint8_t> resp;
    (void)rpc(CMD_DETACH, {}, resp);
    m_pid = 0;
    m_name.clear();
}

bool RemoteProcess::read_raw(uintptr_t address, void* buffer, size_t size) const {
    if (!m_attached || (!buffer && size > 0)) return false;
    if (size == 0) return true;
    ByteWriter w;
    w.u64(static_cast<uint64_t>(address));
    w.u32(static_cast<uint32_t>(size));
    std::vector<uint8_t> resp;
    if (!rpc(CMD_READ_MEM, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    if (r.u8() == 0 || !r.ok) return false;
    return r.read_bytes(buffer, size);
}

bool RemoteProcess::write_raw(uintptr_t address, const void* buffer, size_t size, bool force_protection) const {
    if (!m_attached || (!buffer && size > 0)) return false;
    if (size == 0) return true;
    ByteWriter w;
    w.u64(static_cast<uint64_t>(address));
    w.u8(force_protection ? 1 : 0);
    w.u32(static_cast<uint32_t>(size));
    w.raw(buffer, size);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_WRITE_MEM, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

std::vector<MemoryRegion> RemoteProcess::query_regions(uint32_t filter_flags) const {
    if (!m_attached) return {};
    ByteWriter w;
    w.u32(filter_flags);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_QUERY_REGIONS, w.buf, resp)) return {};
    ByteReader r{resp.data(), resp.size()};
    const uint32_t count = r.u32();
    std::vector<MemoryRegion> out;
    if (!r.ok || count > 250000) return out;
    out.reserve(count);
    for (uint32_t i = 0; i < count && r.ok; ++i) {
        MemoryRegion reg;
        reg.base_address = static_cast<uintptr_t>(r.u64());
        reg.size = static_cast<size_t>(r.u64());
        reg.raw_protection = r.u32();
        reg.raw_state = r.u32();
        reg.raw_type = r.u32();
        reg.is_readable = r.u8() != 0;
        reg.is_writable = r.u8() != 0;
        reg.is_executable = r.u8() != 0;
        reg.is_guard = r.u8() != 0;
        reg.is_committed = r.u8() != 0;
        reg.type = static_cast<MemoryType>(r.u32());
        reg.module_name = r.str();
        if (r.ok) out.push_back(std::move(reg));
    }
    return out;
}

std::vector<ModuleInfo> RemoteProcess::get_modules() const {
    if (!m_attached) return {};
    std::vector<uint8_t> resp;
    if (!rpc(CMD_GET_MODULES, {}, resp)) return {};
    ByteReader r{resp.data(), resp.size()};
    const uint32_t count = r.u32();
    std::vector<ModuleInfo> out;
    if (!r.ok || count > 50000) return out;
    out.reserve(count);
    for (uint32_t i = 0; i < count && r.ok; ++i) {
        ModuleInfo m;
        m.name = r.str();
        m.path = r.str();
        m.base_address = static_cast<uintptr_t>(r.u64());
        m.size = static_cast<size_t>(r.u64());
        if (r.ok) out.push_back(std::move(m));
    }
    return out;
}

uintptr_t RemoteProcess::allocate_memory(size_t size, uint32_t protection, uintptr_t near_addr) {
    if (!m_attached) return 0;
    ByteWriter w;
    w.u64(static_cast<uint64_t>(size));
    w.u32(protection);
    w.u64(static_cast<uint64_t>(near_addr));
    std::vector<uint8_t> resp;
    if (!rpc(CMD_ALLOC_MEM, w.buf, resp)) return 0;
    ByteReader r{resp.data(), resp.size()};
    const uint64_t addr = r.u64();
    return r.ok ? static_cast<uintptr_t>(addr) : 0;
}

bool RemoteProcess::free_memory(uintptr_t address, size_t size) {
    if (!m_attached) return false;
    ByteWriter w;
    w.u64(static_cast<uint64_t>(address));
    w.u64(static_cast<uint64_t>(size));
    std::vector<uint8_t> resp;
    if (!rpc(CMD_FREE_MEM, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::suspend() {
    if (!m_attached) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_SUSPEND, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::resume() {
    if (!m_attached) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_RESUME, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

// ---- RemoteServer ---------------------------------------------------------------------------------

RemoteServer::RemoteServer(ProcessFactory factory, ProcessListFn list_fn)
    : m_factory(std::move(factory)), m_list_fn(std::move(list_fn)) {}

RemoteServer::~RemoteServer() {
    stop();
}

std::string RemoteServer::last_error() const {
    std::lock_guard<std::mutex> lock(m_err_mutex);
    return m_last_error;
}

bool RemoteServer::start(const std::string& bind_host, uint16_t port, const std::string& auth_token) {
    stop();
    if (!ensure_sockets_init()) {
        std::lock_guard<std::mutex> lock(m_err_mutex);
        m_last_error = "Socket initialization failed";
        return false;
    }

    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* res = nullptr;
    const std::string host_arg = bind_host.empty() ? "0.0.0.0" : bind_host;
    const std::string port_str = std::to_string(port);
    if (getaddrinfo(host_arg.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        std::lock_guard<std::mutex> lock(m_err_mutex);
        m_last_error = "Failed to bind " + host_arg + ":" + port_str;
        return false;
    }

    NativeSock lsock = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (lsock == kInvalidSock) {
        freeaddrinfo(res);
        std::lock_guard<std::mutex> lock(m_err_mutex);
        m_last_error = "Failed creating listen socket";
        return false;
    }

    int reuse = 1;
#ifdef _WIN32
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif

    if (::bind(lsock, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0 || ::listen(lsock, 16) != 0) {
        freeaddrinfo(res);
        close_native_sock(lsock);
        std::lock_guard<std::mutex> lock(m_err_mutex);
        m_last_error = "Bind/listen failed on " + host_arg + ":" + port_str;
        return false;
    }
    freeaddrinfo(res);

    struct sockaddr_in sin{};
    socklen_t sin_len = sizeof(sin);
    uint16_t actual_port = port;
    if (getsockname(lsock, reinterpret_cast<struct sockaddr*>(&sin), &sin_len) == 0) {
        actual_port = ntohs(sin.sin_port);
    }

    m_auth_token = auth_token;
    m_listen_sock = from_native(lsock);
    m_bound_port.store(actual_port);
    m_running.store(true);
    m_accept_thread = std::thread([this] { accept_loop(); });
    return true;
}

void RemoteServer::stop() {
    if (!m_running.exchange(false)) {
        if (m_accept_thread.joinable()) m_accept_thread.join();
        return;
    }

    const NativeSock lsock = to_native(m_listen_sock);
    m_listen_sock = from_native(kInvalidSock);
    close_native_sock(lsock);

    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (uintptr_t cs : m_client_socks) close_native_sock(to_native(cs));
        m_client_socks.clear();
    }

    if (m_accept_thread.joinable()) m_accept_thread.join();

    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        threads = std::move(m_client_threads);
    }
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    m_bound_port.store(0);
}

void RemoteServer::accept_loop() {
    while (m_running.load()) {
        const NativeSock lsock = to_native(m_listen_sock);
        if (lsock == kInvalidSock) break;
        NativeSock cs = ::accept(lsock, nullptr, nullptr);
        if (cs == kInvalidSock) break;
        set_nodelay(cs);
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        if (!m_running.load()) {
            close_native_sock(cs);
            break;
        }
        const uintptr_t h = from_native(cs);
        m_client_socks.push_back(h);
        m_client_threads.emplace_back([this, h] { handle_client(h); });
    }
}

void RemoteServer::handle_client(uintptr_t client_sock) {
    const NativeSock sock = to_native(client_sock);
    std::unique_ptr<IProcess> proc = m_factory ? m_factory() : IProcess::create();
    bool authed = m_auth_token.empty();

    uint16_t cmd = 0;
    uint32_t seq = 0;
    std::vector<uint8_t> req;
    while (m_running.load() && read_frame(sock, cmd, seq, req)) {
        ByteWriter resp;
        if (cmd == CMD_HELLO) {
            ByteReader r{req.data(), req.size()};
            const std::string token = r.str();
            const bool token_ok = m_auth_token.empty() || (r.ok && token == m_auth_token);
            authed = token_ok;
            resp.u32(token_ok ? 0u : 1u);
            resp.u32(static_cast<uint32_t>(sizeof(uintptr_t)));
            resp.str(host_os_label());
            if (!write_frame(sock, cmd, seq, resp.buf) || !token_ok) break;
            continue;
        }
        if (!authed) break;

        ByteReader r{req.data(), req.size()};
        switch (cmd) {
            case CMD_LIST_PROCESSES: {
                const auto procs = m_list_fn ? m_list_fn() : IProcess::list_processes();
                resp.u32(static_cast<uint32_t>(procs.size()));
                for (const auto& p : procs) {
                    resp.u32(p.pid);
                    resp.str(p.name);
                }
                break;
            }
            case CMD_ATTACH: {
                const uint32_t pid = r.u32();
                const bool ok = r.ok && proc && proc->attach(pid);
                resp.u8(ok ? 1 : 0);
                resp.u32(static_cast<uint32_t>(proc ? proc->pointer_size() : sizeof(uintptr_t)));
                resp.u8((proc && proc->can_write()) ? 1 : 0);
                resp.str(proc ? proc->name() : "");
                break;
            }
            case CMD_DETACH: {
                if (proc) proc->detach();
                resp.u8(1);
                break;
            }
            case CMD_QUERY_REGIONS: {
                const uint32_t flags = r.u32();
                const auto regs = (r.ok && proc) ? proc->query_regions(flags) : std::vector<MemoryRegion>{};
                resp.u32(static_cast<uint32_t>(regs.size()));
                for (const auto& reg : regs) {
                    resp.u64(static_cast<uint64_t>(reg.base_address));
                    resp.u64(static_cast<uint64_t>(reg.size));
                    resp.u32(reg.raw_protection);
                    resp.u32(reg.raw_state);
                    resp.u32(reg.raw_type);
                    resp.u8(reg.is_readable ? 1 : 0);
                    resp.u8(reg.is_writable ? 1 : 0);
                    resp.u8(reg.is_executable ? 1 : 0);
                    resp.u8(reg.is_guard ? 1 : 0);
                    resp.u8(reg.is_committed ? 1 : 0);
                    resp.u32(static_cast<uint32_t>(reg.type));
                    resp.str(reg.module_name);
                }
                break;
            }
            case CMD_GET_MODULES: {
                const auto mods = proc ? proc->get_modules() : std::vector<ModuleInfo>{};
                resp.u32(static_cast<uint32_t>(mods.size()));
                for (const auto& m : mods) {
                    resp.str(m.name);
                    resp.str(m.path);
                    resp.u64(static_cast<uint64_t>(m.base_address));
                    resp.u64(static_cast<uint64_t>(m.size));
                }
                break;
            }
            case CMD_READ_MEM: {
                const uintptr_t addr = static_cast<uintptr_t>(r.u64());
                const uint32_t sz = r.u32();
                if (!r.ok || sz > kMaxPayloadBytes - 4 || !proc) {
                    resp.u8(0);
                    break;
                }
                std::vector<uint8_t> tmp(sz);
                const bool ok = proc->read_raw(addr, tmp.data(), sz);
                resp.u8(ok ? 1 : 0);
                if (ok && sz > 0) resp.raw(tmp.data(), sz);
                break;
            }
            case CMD_WRITE_MEM: {
                const uintptr_t addr = static_cast<uintptr_t>(r.u64());
                const bool force = r.u8() != 0;
                const uint32_t sz = r.u32();
                std::vector<uint8_t> tmp(sz);
                const bool ok = r.ok && proc && r.read_bytes(tmp.data(), sz) && proc->write_raw(addr, tmp.data(), sz, force);
                resp.u8(ok ? 1 : 0);
                break;
            }
            case CMD_ALLOC_MEM: {
                const size_t sz = static_cast<size_t>(r.u64());
                const uint32_t prot = r.u32();
                const uintptr_t near_a = static_cast<uintptr_t>(r.u64());
                const uintptr_t res_addr = (r.ok && proc) ? proc->allocate_memory(sz, prot, near_a) : 0;
                resp.u64(static_cast<uint64_t>(res_addr));
                break;
            }
            case CMD_FREE_MEM: {
                const uintptr_t addr = static_cast<uintptr_t>(r.u64());
                const size_t sz = static_cast<size_t>(r.u64());
                const bool ok = r.ok && proc && proc->free_memory(addr, sz);
                resp.u8(ok ? 1 : 0);
                break;
            }
            case CMD_SUSPEND:
                resp.u8((proc && proc->suspend()) ? 1 : 0);
                break;
            case CMD_RESUME:
                resp.u8((proc && proc->resume()) ? 1 : 0);
                break;
            default:
                resp.u8(0);
                break;
        }
        if (!write_frame(sock, cmd, seq, resp.buf)) break;
    }

    if (proc) proc->detach();
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = std::find(m_client_socks.begin(), m_client_socks.end(), client_sock);
        if (it != m_client_socks.end()) {
            m_client_socks.erase(it);
            close_native_sock(sock);
        }
    }
}

} // namespace nce::hal
