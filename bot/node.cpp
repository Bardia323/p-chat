// A p-chat device left on: one of its owner's linked devices, with live
// links to its chats' devices (as a browser has, by the engine's
// IceTransport) and relaying for them (protocol 11) - keeping their sealed
// mail while they are away and passing on their signals, only within its
// own chats (protocol 13). It says nothing itself; it keeps what it is told
// as any linked device does.
//
//   sgchat_node <folder> [--relay <url>] [--link <link> <six words>] [--name Node] [--ice <stun:...>]... [--for <seconds>]
//
// <folder> keeps its key, its chats and what it keeps for others (readable
// by its user only). --link once, with a "My other device" invite from the
// owner's phone. Each second it prints a line `STATE {json}`.
#include "Host.hpp"
#include "IceLive.hpp"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {
volatile std::sig_atomic_t stop = 0;
std::uint64_t now_ms() {
    return std::uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
std::string list(const std::vector<std::string>& v) {
    std::string out = "[";
    for (std::size_t i = 0; i < v.size(); ++i) out += (i ? ",\"" : "\"") + v[i] + "\"";
    return out + "]";
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: sgchat_node <folder> [--relay <url>] [--link <link> <six words>] [--name Node] [--ice <url>]... [--for <seconds>]\n");
        return 2;
    }
    std::string name = "Node", relay, link, code;
    std::vector<std::string> ice;
    double seconds = 0;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--relay") && i + 1 < argc) relay = argv[++i];
        else if (!std::strcmp(argv[i], "--link") && i + 2 < argc) link = argv[++i], code = argv[++i];
        else if (!std::strcmp(argv[i], "--name") && i + 1 < argc) name = argv[++i];
        else if (!std::strcmp(argv[i], "--ice") && i + 1 < argc) ice.push_back(argv[++i]);
        else if (!std::strcmp(argv[i], "--for") && i + 1 < argc) seconds = std::atof(argv[++i]);
    }
    std::signal(SIGINT, [](int) { stop = 1; });
    std::signal(SIGTERM, [](int) { stop = 1; });
    try {
        bot::Host host(argv[1], name, relay);
        sg::net::IceConfig c;
        c.peer = host.peer();
        c.ice_servers = ice;
        // Room for a burst taken between two rounds, as in the browser.
        c.receive_messages = 8192;
        c.receive_bytes = 64u << 20;
        bot::IceLive live(c);
        host.live(&live);
        host.set_relaying(true);
        std::vector<std::string> heard;
        host.on_notice = [&](const chat::Notice& n) {
            if (n.kind == "message" && n.type == "text") heard.push_back(std::string(n.body.begin(), n.body.end()));
        };
        if (!link.empty()) {
            const auto r = host.pair(link, code, "");
            std::printf("LINKED %s\n", r.c_str());
            std::fflush(stdout);
            if (r != "ok") return 1;
        }
        std::printf("READY %s\n", host.peer().c_str());
        std::fflush(stdout);
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::int64_t(seconds * 1000));
        std::uint64_t said = 0;
        while (!stop && (seconds <= 0 || std::chrono::steady_clock::now() < until)) {
            const auto now = now_ms();
            try {
                host.step(now);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "node: %s\n", e.what());  // the relay away: again in a moment
            }
            if (now - said >= 1000) {
                said = now;
                const auto& d = host.carrier().done;
                std::printf("STATE {\"chats\":%s,\"live\":%s,\"linked\":%s,\"kept\":%zu,\"held\":%zu,\"given\":%zu,\"passed\":%zu,\"shared\":%zu,\"hopped\":%zu,\"heard\":%s}\n",
                            list(host.app().conversations()).c_str(), list(host.app().live_peers()).c_str(), list(host.app().linked()).c_str(),
                            host.carrier().kept(), d.held, d.given, d.passed, d.shared, d.hopped, list(heard).c_str());
                std::fflush(stdout);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "node: %s\n", e.what());
        return 1;
    }
    return 0;
}
