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
#include <sys/time.h>
#include <unistd.h>
#endif

#include "../../include/hal/remote_process.hpp"
#include "../../include/debugger/access_watcher.hpp"
#include "../../include/debugger/debug_coordinator.hpp"
#include "../../include/speedhack/speedhack.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <random>

namespace nce::hal {

namespace {

constexpr uint32_t kProtoMagic = 0x3245434Eu; // "NCE2" (compatible with NCE3 flags)
constexpr uint32_t kMaxPayloadBytes = 64u * 1024u * 1024u;
constexpr uint32_t kPreAuthMaxPayload = 4096u; // 4 KB max frame before authentication completes
constexpr uint16_t kFlagEncrypted = 0x0001u;
constexpr size_t kTagBytes = 16;

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
    CMD_LIST_THREADS = 13,
    // NCE3 Extensions
    CMD_WATCH_START = 20,
    CMD_WATCH_POLL = 21,
    CMD_WATCH_STOP = 22,
    CMD_WATCH_CLEAR = 23,
    CMD_SPEED_SET = 24,
    CMD_SPEED_RESET = 25,
    CMD_DBG_ATTACH = 26,
    CMD_DBG_DETACH = 27,
    CMD_DBG_SET_BP = 28,
    CMD_DBG_REMOVE_BP = 29,
    CMD_DBG_CONTINUE = 30,
    CMD_DBG_STATE = 31,
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

struct Sha256 {
    uint32_t state[8]{
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t total_bits{0};
    uint8_t buf[64]{};
    size_t buf_len{0};

    static uint32_t rotr(uint32_t x, uint32_t n) noexcept {
        return (x >> n) | (x << (32u - n));
    }

    void compress(const uint8_t blk[64]) noexcept {
        static constexpr uint32_t k[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
        };
        uint32_t w[64]{};
        for (size_t i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(blk[i * 4]) << 24) |
                   (static_cast<uint32_t>(blk[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(blk[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(blk[i * 4 + 3]);
        }
        for (size_t i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (size_t i = 0; i < 64; ++i) {
            const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t t1 = h + s1 + ch + k[i] + w[i];
            const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void update(const void* data, size_t len) noexcept {
        const auto* p = static_cast<const uint8_t*>(data);
        total_bits += static_cast<uint64_t>(len) * 8u;
        size_t i = 0;
        if (buf_len > 0) {
            const size_t take = std::min(len, size_t{64} - buf_len);
            std::memcpy(buf + buf_len, p, take);
            buf_len += take;
            i += take;
            if (buf_len == 64) {
                compress(buf);
                buf_len = 0;
            }
        }
        while (i + 64 <= len) {
            compress(p + i);
            i += 64;
        }
        if (i < len) {
            buf_len = len - i;
            std::memcpy(buf, p + i, buf_len);
        }
    }

    std::array<uint8_t, 32> finish() noexcept {
        buf[buf_len++] = 0x80u;
        if (buf_len > 56) {
            while (buf_len < 64) buf[buf_len++] = 0;
            compress(buf);
            buf_len = 0;
        }
        while (buf_len < 56) buf[buf_len++] = 0;
        for (int s = 7; s >= 0; --s) {
            buf[56 + static_cast<size_t>(7 - s)] = static_cast<uint8_t>((total_bits >> (s * 8)) & 0xFFu);
        }
        compress(buf);
        std::array<uint8_t, 32> out{};
        for (size_t i = 0; i < 8; ++i) {
            out[i * 4] = static_cast<uint8_t>((state[i] >> 24) & 0xFFu);
            out[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xFFu);
            out[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xFFu);
            out[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xFFu);
        }
        return out;
    }
};

std::array<uint8_t, 32> hmac_sha256(
    const uint8_t key[32],
    uint8_t dir,
    uint16_t cmd,
    uint32_t seq,
    const uint8_t* data,
    size_t len
) {
    uint8_t ipad[64]{};
    uint8_t opad[64]{};
    for (size_t i = 0; i < 64; ++i) {
        const uint8_t kbyte = (i < 32) ? key[i] : 0;
        ipad[i] = static_cast<uint8_t>(kbyte ^ 0x36u);
        opad[i] = static_cast<uint8_t>(kbyte ^ 0x5cu);
    }
    uint8_t ad[7]{
        dir,
        static_cast<uint8_t>(cmd & 0xFFu),
        static_cast<uint8_t>((cmd >> 8) & 0xFFu),
        static_cast<uint8_t>(seq & 0xFFu),
        static_cast<uint8_t>((seq >> 8) & 0xFFu),
        static_cast<uint8_t>((seq >> 16) & 0xFFu),
        static_cast<uint8_t>((seq >> 24) & 0xFFu)
    };
    Sha256 inner;
    inner.update(ipad, 64);
    inner.update(ad, sizeof(ad));
    if (len > 0) inner.update(data, len);
    const auto ih = inner.finish();

    Sha256 outer;
    outer.update(opad, 64);
    outer.update(ih.data(), ih.size());
    return outer.finish();
}

void xor_keystream(const uint8_t key[32], uint8_t dir, uint32_t seq, uint8_t* data, size_t len) {
    uint8_t blk_hdr[32 + 9]{};
    std::memcpy(blk_hdr, key, 32);
    blk_hdr[32] = dir;
    blk_hdr[33] = static_cast<uint8_t>(seq & 0xFFu);
    blk_hdr[34] = static_cast<uint8_t>((seq >> 8) & 0xFFu);
    blk_hdr[35] = static_cast<uint8_t>((seq >> 16) & 0xFFu);
    blk_hdr[36] = static_cast<uint8_t>((seq >> 24) & 0xFFu);
    uint32_t ctr = 0;
    size_t off = 0;
    while (off < len) {
        blk_hdr[37] = static_cast<uint8_t>(ctr & 0xFFu);
        blk_hdr[38] = static_cast<uint8_t>((ctr >> 8) & 0xFFu);
        blk_hdr[39] = static_cast<uint8_t>((ctr >> 16) & 0xFFu);
        blk_hdr[40] = static_cast<uint8_t>((ctr >> 24) & 0xFFu);
        Sha256 ks;
        ks.update("NCE3-CTR", 8);
        ks.update(blk_hdr, sizeof(blk_hdr));
        const auto pad = ks.finish();
        const size_t take = std::min<size_t>(32, len - off);
        for (size_t i = 0; i < take; ++i) {
            data[off + i] ^= pad[i];
        }
        off += take;
        ++ctr;
    }
}

void fill_random_nonce(uint8_t out[16]) {
    std::random_device rd;
    const auto now_ns = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    Sha256 h;
    for (int i = 0; i < 8; ++i) {
        const uint32_t v = rd();
        h.update(&v, sizeof(v));
    }
    h.update(&now_ns, sizeof(now_ns));
    const auto digest = h.finish();
    std::memcpy(out, digest.data(), 16);
}

void derive_session_key(
    const std::string& token,
    const uint8_t client_nonce[16],
    const uint8_t server_nonce[16],
    uint8_t out_key[32]
) {
    Sha256 h;
    h.update("NCE3-KEY:", 9);
    h.update(token.data(), token.size());
    h.update(client_nonce, 16);
    h.update(server_nonce, 16);
    const auto d = h.finish();
    std::memcpy(out_key, d.data(), 32);
}

bool ct_eq_16(const uint8_t* a, const uint8_t* b) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < kTagBytes; ++i) {
        diff = static_cast<uint8_t>(diff | static_cast<uint8_t>(a[i] ^ b[i]));
    }
    volatile uint8_t keep = diff;
    return keep == 0;
}

bool write_frame(
    NativeSock sock,
    uint16_t cmd,
    uint32_t seq,
    const std::vector<uint8_t>& payload,
    const uint8_t* key = nullptr,
    uint8_t dir = 0
) {
    if (payload.size() > kMaxPayloadBytes) return false;
    uint16_t flags = 0;
    const std::vector<uint8_t>* wire = &payload;
    std::vector<uint8_t> enc;
    if (key != nullptr) {
        flags = kFlagEncrypted;
        enc.resize(payload.size() + kTagBytes);
        if (!payload.empty()) {
            std::memcpy(enc.data(), payload.data(), payload.size());
            xor_keystream(key, dir, seq, enc.data(), payload.size());
        }
        const auto mac = hmac_sha256(key, dir, cmd, seq, enc.data(), payload.size());
        std::memcpy(enc.data() + payload.size(), mac.data(), kTagBytes);
        wire = &enc;
    }

    ByteWriter hdr;
    hdr.u32(kProtoMagic);
    hdr.u16(cmd);
    hdr.u16(flags);
    hdr.u32(seq);
    hdr.u32(static_cast<uint32_t>(wire->size()));
    if (!send_all(sock, hdr.buf.data(), hdr.buf.size())) return false;
    return wire->empty() || send_all(sock, wire->data(), wire->size());
}

bool read_frame(
    NativeSock sock,
    uint16_t& out_cmd,
    uint32_t& out_seq,
    std::vector<uint8_t>& out_payload,
    size_t max_payload,
    const uint8_t* key = nullptr,
    uint8_t dir = 0
) {
    uint8_t hdr_bytes[16]{};
    if (!recv_all(sock, hdr_bytes, sizeof(hdr_bytes))) return false;
    ByteReader r{hdr_bytes, sizeof(hdr_bytes)};
    if (r.u32() != kProtoMagic) return false;
    out_cmd = r.u16();
    const uint16_t flags = r.u16();
    out_seq = r.u32();
    const uint32_t plen = r.u32();
    if (!r.ok || plen > max_payload) return false;
    out_payload.resize(plen);
    if (plen > 0 && !recv_all(sock, out_payload.data(), plen)) return false;

    if (key != nullptr) {
        if ((flags & kFlagEncrypted) == 0 || plen < kTagBytes) return false;
        const size_t ct_len = plen - kTagBytes;
        const auto mac = hmac_sha256(key, dir, out_cmd, out_seq, out_payload.data(), ct_len);
        if (!ct_eq_16(out_payload.data() + ct_len, mac.data())) return false;
        if (ct_len > 0) xor_keystream(key, dir, out_seq, out_payload.data(), ct_len);
        out_payload.resize(ct_len);
    }
    return true;
}

bool constant_time_equals(const std::string& a, const std::string& b) noexcept {
    const size_t min_work = std::max<size_t>(64, std::max(a.size(), b.size()));
    uint8_t diff = static_cast<uint8_t>((a.size() ^ b.size()) != 0 ? 1 : 0);
    for (size_t i = 0; i < min_work; ++i) {
        const uint8_t ca = (i < a.size()) ? static_cast<uint8_t>(a[i]) : 0;
        const uint8_t cb = (i < b.size()) ? static_cast<uint8_t>(b[i]) : 0;
        diff = static_cast<uint8_t>(diff | static_cast<uint8_t>(ca ^ cb));
    }
    volatile uint8_t keep = diff;
    return keep == 0;
}

void set_nodelay(NativeSock s) noexcept {
    int one = 1;
#ifdef _WIN32
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
#else
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
}

void set_recv_timeout(NativeSock s, uint32_t timeout_ms) noexcept {
#ifdef _WIN32
    DWORD ms = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
    struct timeval tv{};
    tv.tv_sec = static_cast<long>(timeout_ms / 1000u);
    tv.tv_usec = static_cast<long>((timeout_ms % 1000u) * 1000u);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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
    m_encrypted = false;
    std::memset(m_session_key, 0, sizeof(m_session_key));
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

    uint8_t client_nonce[16]{};
    ByteWriter w;
    w.str(auth_token);
    if (!auth_token.empty()) {
        fill_random_nonce(client_nonce);
        w.raw(client_nonce, sizeof(client_nonce));
    }
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
    if (!auth_token.empty() && r.need(16)) {
        uint8_t server_nonce[16]{};
        if (r.read_bytes(server_nonce, sizeof(server_nonce))) {
            std::lock_guard<std::mutex> lock(m_io_mutex);
            derive_session_key(auth_token, client_nonce, server_nonce, m_session_key);
            m_encrypted = true;
        }
    }
    m_proto_version = 3;
    return true;
}

void RemoteProcess::disconnect() {
    detach();
    std::lock_guard<std::mutex> lock(m_io_mutex);
    close_socket_locked();
    m_host.clear();
    m_port = 0;
    m_remote_os.clear();
    m_proto_version = 2;
}

bool RemoteProcess::is_connected() const noexcept {
    std::lock_guard<std::mutex> lock(m_io_mutex);
    return to_native(m_sock) != kInvalidSock;
}

bool RemoteProcess::is_encrypted() const noexcept {
    std::lock_guard<std::mutex> lock(m_io_mutex);
    return m_encrypted;
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
    const uint8_t* key = m_encrypted ? m_session_key : nullptr;
    if (!write_frame(s, cmd, seq, req, key, 0x01u)) {
        m_last_error = "Network send failed";
        close_socket_locked();
        return false;
    }
    uint16_t r_cmd = 0;
    uint32_t r_seq = 0;
    if (!read_frame(s, r_cmd, r_seq, resp, kMaxPayloadBytes, key, 0x02u) || r_cmd != cmd || r_seq != seq) {
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

std::vector<ThreadInfo> RemoteProcess::list_remote_threads() const {
    if (!m_attached) return {};
    std::vector<uint8_t> resp;
    if (!rpc(CMD_LIST_THREADS, {}, resp)) return {};
    ByteReader r{resp.data(), resp.size()};
    const uint32_t count = r.u32();
    std::vector<ThreadInfo> out;
    if (!r.ok || count > 100000) return out;
    out.reserve(count);
    for (uint32_t i = 0; i < count && r.ok; ++i) {
        ThreadInfo t;
        t.tid = r.u32();
        t.owner_pid = r.u32();
        t.base_priority = static_cast<int32_t>(r.u32());
        if (r.ok) out.push_back(t);
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

namespace {

void write_regs_array(ByteWriter& w, const debugger::Registers& regs) {
    w.u64(regs.rax); w.u64(regs.rbx); w.u64(regs.rcx); w.u64(regs.rdx);
    w.u64(regs.rsi); w.u64(regs.rdi); w.u64(regs.rbp); w.u64(regs.rsp);
    w.u64(regs.rip);
    w.u64(regs.r8);  w.u64(regs.r9);  w.u64(regs.r10); w.u64(regs.r11);
    w.u64(regs.r12); w.u64(regs.r13); w.u64(regs.r14); w.u64(regs.r15);
    w.u64(regs.eflags);
}

void read_regs_array(ByteReader& r, uint64_t (&regs)[18]) {
    for (size_t i = 0; i < 18; ++i) {
        regs[i] = r.u64();
    }
}

} // namespace

bool RemoteProcess::remote_watch_start(uintptr_t address, size_t size, uint8_t kind) {
    if (!m_attached) return false;
    ByteWriter w;
    w.u64(static_cast<uint64_t>(address));
    w.u32(static_cast<uint32_t>(size));
    w.u8(kind);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_WATCH_START, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_watch_stop() {
    if (!is_connected()) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_WATCH_STOP, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_watch_clear() {
    if (!is_connected()) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_WATCH_CLEAR, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_watch_poll(bool& out_active, std::vector<RemoteWatchHit>& out_hits) const {
    out_active = false;
    out_hits.clear();
    if (!m_attached) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_WATCH_POLL, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    out_active = (r.u8() != 0);
    const uint32_t count = r.u32();
    if (!r.ok || count > 10000) return false;
    out_hits.reserve(count);
    for (uint32_t i = 0; i < count && r.ok; ++i) {
        RemoteWatchHit h;
        h.instruction = static_cast<uintptr_t>(r.u64());
        h.location = r.str();
        h.disassembly = r.str();
        h.base_register = r.str();
        h.base_offset = static_cast<int64_t>(r.u64());
        h.count = static_cast<size_t>(r.u64());
        read_regs_array(r, h.regs);
        const uint32_t blen = r.u32();
        if (!r.ok || blen > 64 || !r.need(blen)) return false;
        h.bytes.resize(blen);
        if (blen > 0 && !r.read_bytes(h.bytes.data(), blen)) return false;
        if (r.ok) out_hits.push_back(std::move(h));
    }
    return r.ok;
}

bool RemoteProcess::remote_speed_set(double factor, std::string& out_msg) {
    out_msg.clear();
    if (!m_attached) {
        out_msg = "Not attached";
        return false;
    }
    uint64_t bits = 0;
    std::memcpy(&bits, &factor, sizeof(bits));
    ByteWriter w;
    w.u64(bits);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_SPEED_SET, w.buf, resp)) {
        out_msg = last_error();
        return false;
    }
    ByteReader r{resp.data(), resp.size()};
    const bool ok = (r.u8() != 0);
    out_msg = r.str();
    return ok && r.ok;
}

bool RemoteProcess::remote_speed_reset() {
    if (!is_connected()) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_SPEED_RESET, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_dbg_attach(uint8_t backend, std::string& out_error) {
    out_error.clear();
    if (!m_attached) {
        out_error = "Not attached";
        return false;
    }
    ByteWriter w;
    w.u8(backend);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_DBG_ATTACH, w.buf, resp)) {
        out_error = last_error();
        return false;
    }
    ByteReader r{resp.data(), resp.size()};
    const bool ok = (r.u8() != 0);
    out_error = r.str();
    return ok && r.ok;
}

bool RemoteProcess::remote_dbg_detach() {
    if (!is_connected()) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_DBG_DETACH, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_dbg_set_bp(uintptr_t address, const std::string& note, bool temporary,
                                      const std::string& condition, bool is_tracepoint) {
    if (!m_attached) return false;
    ByteWriter w;
    w.u64(static_cast<uint64_t>(address));
    w.str(note);
    w.u8(temporary ? 1 : 0);
    w.str(condition);
    w.u8(is_tracepoint ? 1 : 0);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_DBG_SET_BP, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_dbg_remove_bp(uintptr_t address) {
    if (!is_connected()) return false;
    ByteWriter w;
    w.u64(static_cast<uint64_t>(address));
    std::vector<uint8_t> resp;
    if (!rpc(CMD_DBG_REMOVE_BP, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_dbg_action(uint8_t action) {
    if (!m_attached) return false;
    ByteWriter w;
    w.u8(action);
    std::vector<uint8_t> resp;
    if (!rpc(CMD_DBG_CONTINUE, w.buf, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    return r.u8() != 0 && r.ok;
}

bool RemoteProcess::remote_dbg_state(RemoteDebugState& out_state) const {
    out_state = {};
    if (!is_connected()) return false;
    std::vector<uint8_t> resp;
    if (!rpc(CMD_DBG_STATE, {}, resp)) return false;
    ByteReader r{resp.data(), resp.size()};
    out_state.attached = (r.u8() != 0);
    out_state.state = r.u8();
    out_state.active_tid = r.u32();
    read_regs_array(r, out_state.regs);
    const uint32_t bp_count = r.u32();
    if (!r.ok || bp_count > 4096) return false;
    out_state.breakpoints.reserve(bp_count);
    for (uint32_t i = 0; i < bp_count && r.ok; ++i) {
        RemoteDebugState::Bp bp;
        bp.address = static_cast<uintptr_t>(r.u64());
        bp.enabled = (r.u8() != 0);
        bp.hits = r.u64();
        bp.note = r.str();
        if (r.ok) out_state.breakpoints.push_back(std::move(bp));
    }
    return r.ok;
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

void RemoteServer::set_max_clients(size_t max_clients) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    m_max_clients = std::max<size_t>(1, max_clients);
}

void RemoteServer::reap_finished_clients() const {
    std::vector<std::thread> finished;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.begin();
        while (it != m_clients.end()) {
            if (it->done && it->done->load(std::memory_order_acquire)) {
                if (it->thread.joinable()) finished.push_back(std::move(it->thread));
                it = m_clients.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& t : finished) {
        if (t.joinable()) t.join();
    }
}

size_t RemoteServer::active_client_count() const {
    reap_finished_clients();
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    return m_clients.size();
}

void RemoteServer::stop() {
    if (!m_running.exchange(false)) {
        if (m_accept_thread.joinable()) m_accept_thread.join();
        return;
    }

    const NativeSock lsock = to_native(m_listen_sock);
    m_listen_sock = from_native(kInvalidSock);
    close_native_sock(lsock);

    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (auto& w : m_clients) {
            close_native_sock(to_native(w.sock));
            w.sock = from_native(kInvalidSock);
            if (w.thread.joinable()) threads.push_back(std::move(w.thread));
        }
        m_clients.clear();
    }

    if (m_accept_thread.joinable()) m_accept_thread.join();

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

        reap_finished_clients();

        std::lock_guard<std::mutex> lock(m_clients_mutex);
        if (!m_running.load() || m_clients.size() >= m_max_clients) {
            close_native_sock(cs);
            if (!m_running.load()) break;
            continue;
        }
        const uintptr_t h = from_native(cs);
        auto done = std::make_shared<std::atomic<bool>>(false);
        ClientWorker w;
        w.sock = h;
        w.done = done;
        w.thread = std::thread([this, h, done] { handle_client(h, done); });
        m_clients.push_back(std::move(w));
    }
}

void RemoteServer::handle_client(uintptr_t client_sock, std::shared_ptr<std::atomic<bool>> done) {
    const NativeSock sock = to_native(client_sock);
    std::shared_ptr<IProcess> proc(m_factory ? m_factory() : IProcess::create());
    auto dbg = std::make_shared<debugger::DebugCoordinator>(proc);
    debugger::AccessWatcher watcher;
    watcher.set_coordinator(dbg);
    std::unique_ptr<speedhack::Speedhack> speed;

    auto cleanup_target_tools = [&] {
        watcher.stop();
        if (speed) {
            speed->detach();
            speed.reset();
        }
        dbg->detach();
    };

    bool authed = m_auth_token.empty();
    bool crypto_active = false;
    uint8_t session_key[32]{};
    if (!authed) set_recv_timeout(sock, 5000);

    uint16_t cmd = 0;
    uint32_t seq = 0;
    std::vector<uint8_t> req;
    while (m_running.load() &&
           read_frame(sock, cmd, seq, req, authed ? kMaxPayloadBytes : kPreAuthMaxPayload,
                      crypto_active ? session_key : nullptr, 0x01u)) {
        ByteWriter resp;
        if (cmd == CMD_HELLO) {
            ByteReader r{req.data(), req.size()};
            const std::string token = r.str();
            const bool token_ok = m_auth_token.empty() || (r.ok && constant_time_equals(token, m_auth_token));
            authed = token_ok;
            if (token_ok) set_recv_timeout(sock, 0);
            resp.u32(token_ok ? 0u : 1u);
            resp.u32(static_cast<uint32_t>(sizeof(uintptr_t)));
            resp.str(host_os_label());

            bool enable_crypto_after = false;
            if (token_ok && !m_auth_token.empty() && r.need(16)) {
                uint8_t client_nonce[16]{};
                if (r.read_bytes(client_nonce, sizeof(client_nonce))) {
                    uint8_t server_nonce[16]{};
                    fill_random_nonce(server_nonce);
                    derive_session_key(m_auth_token, client_nonce, server_nonce, session_key);
                    resp.raw(server_nonce, sizeof(server_nonce));
                    enable_crypto_after = true;
                }
            }
            if (!write_frame(sock, cmd, seq, resp.buf, nullptr, 0x02u) || !token_ok) break;
            crypto_active = enable_crypto_after;
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
                cleanup_target_tools();
                const bool ok = r.ok && proc && proc->attach(pid);
                resp.u8(ok ? 1 : 0);
                resp.u32(static_cast<uint32_t>(proc ? proc->pointer_size() : sizeof(uintptr_t)));
                resp.u8((proc && proc->can_write()) ? 1 : 0);
                resp.str(proc ? proc->name() : "");
                break;
            }
            case CMD_DETACH: {
                cleanup_target_tools();
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
                if (!r.ok || !proc || !r.need(sz)) {
                    resp.u8(0);
                    break;
                }
                std::vector<uint8_t> tmp(sz);
                const bool ok = r.read_bytes(tmp.data(), sz) && proc->write_raw(addr, tmp.data(), sz, force);
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
            case CMD_LIST_THREADS: {
                const auto threads = (proc && proc->is_attached())
                    ? ProcessInjector::list_threads(proc->get_pid())
                    : std::vector<ThreadInfo>{};
                resp.u32(static_cast<uint32_t>(threads.size()));
                for (const auto& t : threads) {
                    resp.u32(t.tid);
                    resp.u32(t.owner_pid);
                    resp.u32(static_cast<uint32_t>(t.base_priority));
                }
                break;
            }
            case CMD_WATCH_START: {
                const uintptr_t addr = static_cast<uintptr_t>(r.u64());
                const uint32_t sz = r.u32();
                const uint8_t kind_raw = r.u8();
                debugger::WatchKind wk = debugger::WatchKind::Write;
                if (kind_raw == 1) wk = debugger::WatchKind::Access;
                else if (kind_raw == 2) wk = debugger::WatchKind::Execute;
                else if (kind_raw == 3) wk = debugger::WatchKind::GuardPage;
                const bool ok = r.ok && proc && proc->is_attached() && watcher.start(proc, addr, sz, wk);
                resp.u8(ok ? 1 : 0);
                break;
            }
            case CMD_WATCH_POLL: {
                const auto hits = watcher.hits();
                resp.u8(watcher.watching() ? 1 : 0);
                resp.u32(static_cast<uint32_t>(hits.size()));
                for (const auto& h : hits) {
                    resp.u64(static_cast<uint64_t>(h.instruction));
                    resp.str(h.location);
                    resp.str(h.disassembly);
                    resp.str(h.base_register);
                    resp.u64(static_cast<uint64_t>(h.base_offset));
                    resp.u64(static_cast<uint64_t>(h.count));
                    write_regs_array(resp, h.registers);
                    resp.u32(static_cast<uint32_t>(h.bytes.size()));
                    if (!h.bytes.empty()) resp.raw(h.bytes.data(), h.bytes.size());
                }
                break;
            }
            case CMD_WATCH_STOP: {
                watcher.stop();
                resp.u8(1);
                break;
            }
            case CMD_WATCH_CLEAR: {
                watcher.clear();
                resp.u8(1);
                break;
            }
            case CMD_SPEED_SET: {
                const uint64_t bits = r.u64();
                double factor = 1.0;
                std::memcpy(&factor, &bits, sizeof(factor));
                bool ok = false;
                std::string msg;
                if (r.ok && proc && proc->is_attached()) {
                    if (!speed) speed = std::make_unique<speedhack::Speedhack>(proc);
                    ok = (speed->is_installed() || speed->attach()) && speed->set_speed(factor) && speed->enable();
                    msg = ok ? "Remote speedhack applied" : "Remote speedhack unsupported or failed";
                } else {
                    msg = "Target not attached";
                }
                resp.u8(ok ? 1 : 0);
                resp.str(msg);
                break;
            }
            case CMD_SPEED_RESET: {
                if (speed) {
                    speed->detach();
                    speed.reset();
                }
                resp.u8(1);
                break;
            }
            case CMD_DBG_ATTACH: {
                const uint8_t be = r.u8();
                const auto backend = (be == 1) ? debugger::DebugBackend::VEH : debugger::DebugBackend::Win32DebugAPI;
                const bool ok = r.ok && proc && proc->is_attached() && dbg->attach(backend);
                resp.u8(ok ? 1 : 0);
                resp.str(ok ? std::string{} : dbg->last_error());
                break;
            }
            case CMD_DBG_DETACH: {
                dbg->detach();
                resp.u8(1);
                break;
            }
            case CMD_DBG_SET_BP: {
                const uintptr_t addr = static_cast<uintptr_t>(r.u64());
                const std::string note = r.str();
                const bool temp = (r.u8() != 0);
                const std::string cond = r.str();
                const bool trace = (r.u8() != 0);
                const bool ok = r.ok && dbg->set_breakpoint(addr, note, temp, cond, trace);
                resp.u8(ok ? 1 : 0);
                break;
            }
            case CMD_DBG_REMOVE_BP: {
                const uintptr_t addr = static_cast<uintptr_t>(r.u64());
                const bool ok = r.ok && dbg->remove_breakpoint(addr);
                resp.u8(ok ? 1 : 0);
                break;
            }
            case CMD_DBG_CONTINUE: {
                const uint8_t act = r.u8();
                bool ok = false;
                if (r.ok) {
                    if (act == 0) ok = dbg->resume();
                    else if (act == 1) ok = dbg->pause();
                    else if (act == 2) ok = dbg->step_into();
                    else if (act == 3) ok = dbg->step_over();
                    else if (act == 4) ok = dbg->step_out();
                }
                resp.u8(ok ? 1 : 0);
                break;
            }
            case CMD_DBG_STATE: {
                resp.u8(dbg->is_attached() ? 1 : 0);
                resp.u8(static_cast<uint8_t>(dbg->state()));
                resp.u32(dbg->active_thread_id());
                write_regs_array(resp, dbg->registers());
                const auto bps = dbg->get_breakpoints();
                resp.u32(static_cast<uint32_t>(bps.size()));
                for (const auto& bp : bps) {
                    resp.u64(static_cast<uint64_t>(bp.address));
                    resp.u8(bp.is_enabled ? 1 : 0);
                    resp.u64(static_cast<uint64_t>(bp.hit_count));
                    resp.str(bp.note);
                }
                break;
            }
            default:
                resp.u8(0);
                break;
        }
        if (!write_frame(sock, cmd, seq, resp.buf, crypto_active ? session_key : nullptr, 0x02u)) break;
    }

    std::memset(session_key, 0, sizeof(session_key));
    cleanup_target_tools();
    if (proc) proc->detach();
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (auto& w : m_clients) {
            if (w.done == done) {
                if (w.sock != from_native(kInvalidSock)) {
                    close_native_sock(to_native(w.sock));
                    w.sock = from_native(kInvalidSock);
                }
                break;
            }
        }
    }
    if (done) done->store(true, std::memory_order_release);
}

} // namespace nce::hal
