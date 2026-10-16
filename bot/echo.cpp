// The echo bot: a native p-chat device with its own key, paired like a
// contact. In a two-sided chat it says back what it is told; in a group,
// only what follows "/echo ". It is revoked like any device (taken out of
// a group, or forgotten as a contact) and from then on reads nothing.
//
//   sgchat_echo <folder> <relay> [--pair <link> <six words>] [--name Echo] [--for <seconds>]
//
// <folder> keeps its key and what it knows (readable by its user only);
// it takes mail, so its contacts must let messages wait for them too
// ("Mailbox too") to hear its answers.
#include "Host.hpp"

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
}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: sgchat_echo <folder> <relay> [--pair <link> <six words>] [--name Echo] [--for <seconds>]\n");
        return 2;
    }
    std::string name = "Echo", link, code;
    double seconds = 0;
    for (int i = 3; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--pair") && i + 2 < argc) link = argv[++i], code = argv[++i];
        else if (!std::strcmp(argv[i], "--name") && i + 1 < argc) name = argv[++i];
        else if (!std::strcmp(argv[i], "--for") && i + 1 < argc) seconds = std::atof(argv[++i]);
    }
    std::signal(SIGINT, [](int) { stop = 1; });
    std::signal(SIGTERM, [](int) { stop = 1; });
    try {
        bot::Host host(argv[1], name, argv[2]);
        const bool trace = std::getenv("SGCHAT_ECHO_TRACE") != nullptr;
        host.on_notice = [&](const chat::Notice& n) {
            if (trace) std::fprintf(stderr, "echo notice %s %s %s %s\n", n.kind.c_str(), n.type.c_str(), n.conversation.substr(0, 8).c_str(), n.text.c_str());
            if (n.kind != "message" || n.type != "text") return;
            const std::string text(n.body.begin(), n.body.end());
            const auto kind = host.app().kind_of(n.conversation);
            if (kind == chat::Kind::Direct) host.app().post(n.conversation, "echo: " + text, now_ms());
            else if (kind == chat::Kind::Group && text.rfind("/echo ", 0) == 0) host.app().post(n.conversation, "echo: " + text.substr(6), now_ms());
        };
        if (!link.empty()) {
            const auto r = host.pair(link, code, "");
            std::printf("PAIRED %s\n", r.c_str());
            std::fflush(stdout);
            if (r != "ok") return 1;
        }
        std::printf("READY %s\n", host.peer().c_str());
        std::fflush(stdout);
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::int64_t(seconds * 1000));
        while (!stop && (seconds <= 0 || std::chrono::steady_clock::now() < until)) {
            try {
                host.step(now_ms());
            } catch (const std::exception& e) {
                std::fprintf(stderr, "echo: %s\n", e.what());  // the relay away: again in a moment
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "echo: %s\n", e.what());
        return 1;
    }
    return 0;
}
