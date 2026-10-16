#include "Relay.hpp"

#include <stdexcept>

namespace bot {

namespace {
constexpr std::uint8_t PUT = 1, FETCH = 2, DEL = 3, PAIR_POST = 16, PAIR_FETCH = 17, PAIR_DONE = 20;
}

Relay::Relay(std::string url) : url_(std::move(url)) {}

std::pair<int, Bytes> Relay::call(std::uint8_t op, const Bytes& body) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        try {
            if (!socket_ || !socket_->open()) socket_ = std::make_unique<Socket>(url_);
            const auto id = next_++;
            socket_->send(chat::Writer().u8(1).u8(op).u32(id).raw(body).take());
            for (int waited = 0; waited < 20; ++waited) {
                const auto m = socket_->receive(1000);
                if (!m) {
                    if (!socket_->open()) break;
                    continue;
                }
                if (m->size() < 7 || (*m)[0] != 1 || (*m)[1] != (op | 0x80)) continue;  // a signal, or another answer
                chat::Reader r(*m);
                r.u8(), r.u8();
                if (r.u32() != id) continue;
                const int status = r.u8();
                return {status, r.raw(r.left())};
            }
        } catch (const std::exception&) {
        }
        socket_.reset();  // made again on the next try
    }
    throw std::runtime_error("relay: no answer from " + url_);
}

int Relay::put(const Bytes& envelope) { return call(PUT, envelope).first; }

std::vector<Fetched> Relay::fetch(const std::vector<chat::Key32>& mailboxes) {
    std::vector<Fetched> out;
    for (std::size_t at = 0; at < mailboxes.size(); at += 1024) {
        chat::Writer w;
        const auto n = std::min<std::size_t>(1024, mailboxes.size() - at);
        w.u16(std::uint16_t(n));
        for (std::size_t i = 0; i < n; ++i) w.raw(mailboxes[at + i]);
        const auto [status, body] = call(FETCH, w.take());
        if (status != 0) continue;
        chat::Reader r(body);
        for (unsigned k = r.u16(); k > 0; --k) {
            Fetched f;
            f.mailbox = r.key();
            f.handle = r.fixed<16>();
            f.envelope = r.raw(r.u32());
            out.push_back(std::move(f));
        }
    }
    return out;
}

int Relay::del(const chat::Key32& mailbox, const std::vector<std::array<std::uint8_t, 16>>& handles) {
    chat::Writer w;
    w.raw(mailbox).u16(std::uint16_t(handles.size()));
    for (const auto& h : handles) w.raw(h);
    return call(DEL, w.take()).first;
}

int Relay::pair_post(const chat::Token& token, const Bytes& box) { return call(PAIR_POST, chat::Writer().raw(token).raw(box).take()).first; }

std::vector<Bytes> Relay::pair_fetch(const chat::Token& token) {
    const auto [status, body] = call(PAIR_FETCH, chat::Writer().raw(token).take());
    std::vector<Bytes> out;
    if (status != 0) return out;
    chat::Reader r(body);
    for (unsigned k = r.u16(); k > 0; --k) out.push_back(r.raw(r.u32()));
    return out;
}

int Relay::pair_done(const chat::Token& token) { return call(PAIR_DONE, chat::Writer().raw(token).take()).first; }

}  // namespace bot
