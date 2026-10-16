#include "Socket.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace bot {

namespace {
struct Url {
    bool tls = false;
    std::string host, port, path;
};
Url parse(const std::string& url) {
    Url u;
    std::string rest;
    if (url.rfind("wss://", 0) == 0) u.tls = true, rest = url.substr(6);
    else if (url.rfind("ws://", 0) == 0) rest = url.substr(5);
    else throw std::runtime_error("socket: a relay is ws:// or wss://");
    const auto slash = rest.find('/');
    const auto authority = rest.substr(0, slash);
    u.path = slash == std::string::npos ? "/" : rest.substr(slash);
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(']') == std::string::npos) {
        u.host = authority.substr(0, colon);
        u.port = authority.substr(colon + 1);
    } else {
        u.host = authority;
        u.port = u.tls ? "443" : "80";
    }
    if (u.host.empty()) throw std::runtime_error("socket: no host");
    return u;
}
std::string base64(const std::uint8_t* data, std::size_t n) {
    std::string out(4 * ((n + 2) / 3), '\0');
    const int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), data, int(n));
    out.resize(std::size_t(len));
    return out;
}
using Clock = std::chrono::steady_clock;
int left(Clock::time_point until) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count();
    return ms < 0 ? 0 : int(ms);
}
}  // namespace

struct Socket::Impl {
    int fd = -1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    bool up = false;
    Bytes buffer;  // read, not yet framed

    ~Impl() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
        if (fd >= 0) ::close(fd);
    }
    void write_all(const std::uint8_t* p, std::size_t n) {
        while (n) {
            const long w = ssl ? SSL_write(ssl, p, int(n)) : long(::send(fd, p, n, MSG_NOSIGNAL));
            if (w <= 0) {
                up = false;
                throw std::runtime_error("socket: write failed");
            }
            p += w, n -= std::size_t(w);
        }
    }
    // Some bytes into the buffer, waiting at most until `until`; false on timeout.
    bool fill(Clock::time_point until) {
        if (!(ssl && SSL_pending(ssl) > 0)) {
            pollfd p{fd, POLLIN, 0};
            const int r = ::poll(&p, 1, left(until));
            if (r <= 0) return false;
        }
        std::uint8_t chunk[16384];
        const long n = ssl ? SSL_read(ssl, chunk, sizeof chunk) : long(::recv(fd, chunk, sizeof chunk, 0));
        if (n <= 0) {
            if (ssl && SSL_get_error(ssl, int(n)) == SSL_ERROR_WANT_READ) return true;
            up = false;
            return false;
        }
        buffer.insert(buffer.end(), chunk, chunk + n);
        return true;
    }
    void frame(std::uint8_t opcode, const Bytes& payload) {
        Bytes f;
        f.push_back(std::uint8_t(0x80 | opcode));
        const auto n = payload.size();
        if (n < 126) {
            f.push_back(std::uint8_t(0x80 | n));
        } else if (n < 65536) {
            f.push_back(0x80 | 126);
            f.push_back(std::uint8_t(n >> 8));
            f.push_back(std::uint8_t(n));
        } else {
            f.push_back(0x80 | 127);
            for (int i = 7; i >= 0; --i) f.push_back(std::uint8_t(std::uint64_t(n) >> (8 * i)));
        }
        std::uint8_t mask[4];
        RAND_bytes(mask, 4);
        f.insert(f.end(), mask, mask + 4);
        for (std::size_t i = 0; i < n; ++i) f.push_back(payload[i] ^ mask[i % 4]);
        write_all(f.data(), f.size());
    }
};

Socket::Socket(const std::string& url, int timeout_ms) : impl_(std::make_unique<Impl>()) {
    const auto u = parse(url);
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* found = nullptr;
    if (getaddrinfo(u.host.c_str(), u.port.c_str(), &hints, &found) != 0 || !found) throw std::runtime_error("socket: cannot resolve " + u.host);
    for (auto* a = found; a; a = a->ai_next) {
        impl_->fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (impl_->fd < 0) continue;
        if (::connect(impl_->fd, a->ai_addr, a->ai_addrlen) == 0) break;
        ::close(impl_->fd);
        impl_->fd = -1;
    }
    freeaddrinfo(found);
    if (impl_->fd < 0) throw std::runtime_error("socket: cannot connect to " + u.host);
    if (u.tls) {
        impl_->ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_min_proto_version(impl_->ctx, TLS1_2_VERSION);
        SSL_CTX_set_default_verify_paths(impl_->ctx);
        SSL_CTX_set_verify(impl_->ctx, SSL_VERIFY_PEER, nullptr);
        impl_->ssl = SSL_new(impl_->ctx);
        SSL_set_tlsext_host_name(impl_->ssl, u.host.c_str());
        SSL_set1_host(impl_->ssl, u.host.c_str());
        SSL_set_fd(impl_->ssl, impl_->fd);
        if (SSL_connect(impl_->ssl) != 1) throw std::runtime_error("socket: TLS failed with " + u.host);
    }
    std::uint8_t nonce[16];
    RAND_bytes(nonce, sizeof nonce);
    const auto key = base64(nonce, sizeof nonce);
    const auto host = u.host + ((u.tls && u.port == "443") || (!u.tls && u.port == "80") ? "" : ":" + u.port);
    const auto request = "GET " + u.path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                         "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
    impl_->write_all(reinterpret_cast<const std::uint8_t*>(request.data()), request.size());
    const auto until = Clock::now() + std::chrono::milliseconds(timeout_ms);
    std::string head;
    for (;;) {
        const std::string seen(impl_->buffer.begin(), impl_->buffer.end());
        const auto end = seen.find("\r\n\r\n");
        if (end != std::string::npos) {
            head = seen.substr(0, end);
            impl_->buffer.erase(impl_->buffer.begin(), impl_->buffer.begin() + std::ptrdiff_t(end + 4));
            break;
        }
        if (seen.size() > 16384 || !impl_->fill(until)) throw std::runtime_error("socket: no upgrade from " + u.host);
    }
    const auto expect = [&] {
        const auto text = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::uint8_t digest[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(text.data()), text.size(), digest);
        return base64(digest, sizeof digest);
    }();
    std::string lower = head;
    for (auto& ch : lower) ch = char(std::tolower(static_cast<unsigned char>(ch)));
    if (head.rfind("HTTP/1.1 101", 0) != 0 || lower.find("sec-websocket-accept: " + [&] {
            std::string e = expect;
            for (auto& ch : e) ch = char(std::tolower(static_cast<unsigned char>(ch)));
            return e;
        }()) == std::string::npos)
        throw std::runtime_error("socket: the upgrade did not hold");
    impl_->up = true;
}

Socket::~Socket() {
    if (impl_ && impl_->up) {
        try {
            impl_->frame(0x8, {});
        } catch (...) {
        }
    }
}

bool Socket::open() const { return impl_->up; }

void Socket::send(const Bytes& message) {
    if (!impl_->up) throw std::runtime_error("socket: closed");
    impl_->frame(0x2, message);
}

std::optional<Bytes> Socket::receive(int timeout_ms) {
    const auto until = Clock::now() + std::chrono::milliseconds(timeout_ms);
    Bytes message;
    bool started = false;
    for (;;) {
        auto& b = impl_->buffer;
        // One whole frame in the buffer?
        if (b.size() >= 2) {
            const bool fin = b[0] & 0x80;
            const auto opcode = b[0] & 0x0f;
            const bool masked = b[1] & 0x80;
            std::uint64_t n = b[1] & 0x7f;
            std::size_t at = 2;
            bool whole = true;
            if (n == 126) {
                if (b.size() < 4) whole = false;
                else n = (std::uint64_t(b[2]) << 8) | b[3], at = 4;
            } else if (n == 127) {
                if (b.size() < 10) whole = false;
                else {
                    n = 0;
                    for (int i = 0; i < 8; ++i) n = (n << 8) | b[2 + std::size_t(i)];
                    at = 10;
                }
            }
            if (n > (16u << 20)) {
                impl_->up = false;
                throw std::runtime_error("socket: a message too large");
            }
            std::uint8_t mask[4] = {0, 0, 0, 0};
            if (whole && masked) {
                if (b.size() < at + 4) whole = false;
                else std::memcpy(mask, &b[at], 4), at += 4;
            }
            if (whole && b.size() >= at + n) {
                Bytes payload(b.begin() + std::ptrdiff_t(at), b.begin() + std::ptrdiff_t(at + n));
                if (masked)
                    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] ^= mask[i % 4];
                b.erase(b.begin(), b.begin() + std::ptrdiff_t(at + n));
                if (opcode == 0x9) {
                    impl_->frame(0xA, payload);
                } else if (opcode == 0x8) {
                    impl_->up = false;
                    return std::nullopt;
                } else if (opcode == 0x2 || (opcode == 0x0 && started)) {
                    started = true;
                    message.insert(message.end(), payload.begin(), payload.end());
                    if (fin) return message;
                }
                continue;  // text, pong, or a part: the next frame
            }
        }
        if (!impl_->up || !impl_->fill(until)) return std::nullopt;
    }
}

}  // namespace bot
