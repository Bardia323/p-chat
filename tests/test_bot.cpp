// v1 §9: a bot is a native device. The relay (relay.py) and the echo bot
// (sgchat_echo) run as their own processes; two people are native hosts
// here, over the same WebSocket client. The bot pairs like a contact,
// answers, keeps what it knows across a restart, answers in a group only
// when asked, and once revoked from the group reads nothing more.
#include "Host.hpp"
#include "check.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <thread>

extern char** environ;
using namespace chat;
namespace fs = std::filesystem;

namespace {
// A child process whose first lines we read.
struct Process {
    pid_t pid = -1;
    int out = -1;
    std::string buffer;
    explicit Process(std::vector<std::string> args) {
        int p[2];
        if (::pipe(p) != 0) throw std::runtime_error("pipe");
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, p[1], 1);
        posix_spawn_file_actions_addclose(&fa, p[0]);
        std::vector<char*> argv;
        for (auto& a : args) argv.push_back(a.data());
        argv.push_back(nullptr);
        if (posix_spawnp(&pid, argv[0], &fa, nullptr, argv.data(), environ) != 0) throw std::runtime_error("spawn " + args[0]);
        posix_spawn_file_actions_destroy(&fa);
        ::close(p[1]);
        out = p[0];
    }
    // The next line beginning with `prefix`, within `ms`.
    std::string line(const std::string& prefix, int ms) {
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        for (;;) {
            for (auto nl = buffer.find('\n'); nl != std::string::npos; nl = buffer.find('\n')) {
                const auto l = buffer.substr(0, nl);
                buffer.erase(0, nl + 1);
                if (l.rfind(prefix, 0) == 0) return l;
            }
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now()).count();
            if (left <= 0) return {};
            pollfd pf{out, POLLIN, 0};
            if (::poll(&pf, 1, int(left)) <= 0) return {};
            char b[512];
            const auto n = ::read(out, b, sizeof b);
            if (n <= 0) return {};
            buffer.append(b, std::size_t(n));
        }
    }
    void stop() {
        if (pid > 0) {
            ::kill(pid, SIGTERM);
            ::waitpid(pid, nullptr, 0);
            pid = -1;
        }
        if (out >= 0) ::close(out), out = -1;
    }
    ~Process() { stop(); }
};

std::uint64_t now_ms() {
    return std::uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

// Steps the hosts until `done` holds or `ms` pass.
template <class F>
bool until(std::vector<bot::Host*> hosts, F done, int ms = 30000) {
    for (int waited = 0; waited < ms; waited += 300) {
        for (auto* h : hosts) h->step(now_ms());
        if (done()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    return false;
}

struct Heard {
    std::vector<Notice> notices;
    bool said(const std::string& conv, const std::string& text) const {
        for (const auto& n : notices)
            if (n.kind == "message" && n.conversation == conv && n.type == "text" && std::string(n.body.begin(), n.body.end()) == text) return true;
        return false;
    }
    bool kind(const std::string& k, const std::string& conv) const {
        for (const auto& n : notices)
            if (n.kind == k && n.conversation == conv) return true;
        return false;
    }
};
}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) return 2;
    const std::string python = argv[1], relay_py = argv[2], echo = argv[3];
    const auto dir = fs::temp_directory_path() / ("sgchat-bot-" + std::to_string(::getpid()));
    fs::create_directories(dir);

    Process relay({python, relay_py, "--port", "0"});
    const auto ready = relay.line("READY ", 15000);
    CHECK_MSG(!ready.empty(), "the relay starts");
    if (ready.empty()) return sgchat_test::finish("sgchat_bot");
    const auto url = "ws://127.0.0.1:" + ready.substr(6, ready.find(' ', 6) - 6);

    bot::Host ana((dir / "ana").string(), "Ana", url), ben((dir / "ben").string(), "Ben", url);
    Heard heard_ana, heard_ben;
    ana.on_notice = [&](const Notice& n) { heard_ana.notices.push_back(n); };
    ben.on_notice = [&](const Notice& n) { heard_ben.notices.push_back(n); };

    // 1. Ana invites the bot as a contact; the bot pairs with the six words.
    auto inv = ana.invite(InviteKind::Contact);
    const auto link = "https://p-chat.example/#" + invite_fragment(inv.invite);
    auto bot = std::make_unique<Process>(std::vector<std::string>{echo, (dir / "echo").string(), url, "--pair", link, inv.code});
    CHECK(ana.take_pairing(inv) == "ok");
    CHECK(until({&ana}, [&] { return !ana.app().conversations().empty(); }, 5000));
    CHECK(bot->line("PAIRED ", 30000) == "PAIRED ok");
    const auto bot_peer = bot->line("READY ", 10000).substr(6);
    CHECK(!bot_peer.empty());
    const auto direct = ana.app().conversations()[0];
    CHECK(ana.app().name_of(direct) == "Echo");
    // The bot takes mail only; Ana lets its answers wait for her too.
    ana.app().set_delivery(direct, DeliveryMode::Mailbox);
    ana.app().post(direct, "hello bot", now_ms());
    CHECK_MSG(until({&ana}, [&] { return heard_ana.said(direct, "echo: hello bot"); }), "the bot answers");

    // 2. Stopped and started again from its folder: the same device, the same chat.
    bot->stop();
    bot = std::make_unique<Process>(std::vector<std::string>{echo, (dir / "echo").string(), url});
    CHECK(bot->line("READY ", 10000).substr(6) == bot_peer);
    ana.app().post(direct, "still there?", now_ms());
    CHECK_MSG(until({&ana}, [&] { return heard_ana.said(direct, "echo: still there?"); }), "after a restart it still answers");

    // 3. Ben, a person, pairs with Ana; Ana makes a group of the three.
    auto inv2 = ana.invite(InviteKind::Contact);
    std::thread asker([&] { CHECK(ben.pair(invite_fragment(inv2.invite), inv2.code, "Ana") == "ok"); });
    CHECK(ana.take_pairing(inv2) == "ok");
    asker.join();
    std::string with_ben;
    for (const auto& id : ana.app().conversations())
        if (id != direct) with_ben = id;
    ana.app().set_delivery(with_ben, DeliveryMode::Mailbox);
    ben.app().set_delivery(with_ben, DeliveryMode::Mailbox);
    const auto group = ana.app().create_group("Bots and people", {direct, with_ben});
    ana.app().set_delivery(group, DeliveryMode::Mailbox);
    CHECK_MSG(until({&ana, &ben}, [&] {
        const auto ids = ben.app().conversations();
        return std::find(ids.begin(), ids.end(), group) != ids.end() && ben.app().members_of(group).size() == 3;
    }), "Ben and the bot are in the group");
    ben.app().set_delivery(group, DeliveryMode::Mailbox);
    ben.app().post(group, "hi all", now_ms());
    ben.app().post(group, "/echo in the group", now_ms());
    CHECK_MSG(until({&ana, &ben}, [&] { return heard_ana.said(group, "echo: in the group") && heard_ben.said(group, "echo: in the group"); }),
              "in a group it answers only what it is asked");
    CHECK(!heard_ana.said(group, "echo: hi all"));

    // 4. Revoked: Ana and Ben (two of three) take it out; keys turn; it hears no more.
    std::vector<Key32> bot_device;
    for (const auto& m : ana.app().members_of(group))
        if (peer_of(m.device) == bot_peer) bot_device.push_back(device_id(m.device));
    CHECK(bot_device.size() == 1);
    ana.app().remove_devices(group, bot_device);
    CHECK_MSG(until({&ana, &ben}, [&] { return ana.app().members_of(group).size() == 2 && ben.app().members_of(group).size() == 2; }),
              "the bot is out of the group, without its own say");
    ben.app().post(group, "/echo are you there", now_ms());
    CHECK(until({&ana, &ben}, [&] { return heard_ana.said(group, "/echo are you there"); }));
    CHECK_MSG(!until({&ana, &ben}, [&] { return heard_ana.said(group, "echo: are you there"); }, 8000), "a revoked bot reads nothing");

    bot->stop();
    relay.stop();
    fs::remove_all(dir);
    return sgchat_test::finish("sgchat_bot");
}
