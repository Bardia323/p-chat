// The live path of a native device: the engine's IceTransport (ICE, DTLS
// and SCTP by libdatachannel), as the App's Live - what src/web/Bindings.cpp
// does with the browser's WebRtcTransport, the same framing on the wire, so
// a native device and a browser link with each other. Built only with
// -DSGCHAT_ICE=ON.
#pragma once
#include "chat/App.hpp"
#include "chat/Media.hpp"
#include "sg/net/IceTransport.hpp"

#include <map>

namespace bot {

struct IceLive final : chat::App::Live {
    sg::net::IceTransport transport;
    explicit IceLive(sg::net::IceConfig c) : transport(std::move(c)) {}
    void connect(const std::string& peer) override { transport.connect(peer); }
    bool connected(const std::string& peer) override { return transport.telemetry(peer).connected; }
    // Larger than a data channel takes: in pieces, joined again on arrival.
    std::uint32_t pieces_sent = 0;
    std::map<std::pair<std::string, std::string>, chat::LiveJoin> joining;
    bool send(const std::string& peer, const std::string& channel, const chat::Bytes& bytes) override {
        for (const auto& p : chat::live_pieces(bytes, ++pieces_sent))
            if (transport.send({peer, channel, sg::net::DeliveryClass::Reliable, {}, p}) != sg::net::SendResult::Accepted) return false;
        return true;
    }
    bool send_latest(const std::string& peer, const std::string& channel, const std::string& slot, const chat::Bytes& bytes) override {
        if (bytes.size() > chat::live_piece) return false;
        return transport.send({peer, channel, sg::net::DeliveryClass::Latest, slot, bytes}) == sg::net::SendResult::Accepted;
    }
    bool receive(std::string& peer, std::string& channel, chat::Bytes& bytes) override {
        sg::net::Inbound in;
        while (transport.try_receive(in)) {
            auto whole = joining[{in.peer, in.channel}].take(in.bytes);
            if (!whole) continue;
            peer = in.peer;
            channel = in.channel;
            bytes = std::move(*whole);
            return true;
        }
        return false;
    }
    std::vector<sg::net::IceSignal> signals() override { return transport.signals(); }
    void signal(const std::string& peer, const sg::net::IceSignal& s) override { transport.signal(peer, s); }
    void reconnect(const std::string& peer) override { transport.reconnect(peer); }
    void poll() override {
        transport.poll();
        transport.events();  // delivery uncertainty is met by acknowledgements and the mailbox
    }
};

}  // namespace bot
