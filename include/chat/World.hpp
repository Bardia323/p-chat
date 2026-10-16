// The inside of the world's declared arrows and edits (world/*.sg), and how
// to name what they touch. Nothing here keeps a clock, holds a key or reaches
// another state: an arrow is handed its own state, an edit the graph.
#pragma once
#include "chat/Call.hpp"
#include "sg/core/StateGraph.hpp"
#include "sg/dsl/Natives.hpp"

namespace chat {

sg::dsl::Natives natives();
// What the contact.add edit does, for whoever holds the graph before the
// engine starts (loading what was kept): ok, or why not, as the edit replies.
sg::Params make_conversation(sg::StateGraph& g, const sg::Params& contact_add);
// Makes the book (world/chat.sg) in an empty graph.
void build_world(sg::StateGraph& g);

std::string conversation_state(const ConversationId& c);  // "c_<hex>"
std::string device_element(const Key32& id);             // "d<hex>"
std::string call_state(const CallId& c);                  // "k_<hex>"
std::string game_state(const CallId& game);              // "g_<hex>": the court
std::string game_net_state(const CallId& game);          // "n_<hex>": its network
std::string game_time_state(const CallId& game);         // "t_<hex>": its time
std::string board_state(const ConversationId& c);         // "b_<hex>": a conversation's whiteboard
std::string view_state(const ConversationId& c);          // "v_<hex>": where its devices look
std::string board_time_state(const ConversationId& c);    // "u_<hex>": its time

// What a device is in an edit's arguments: "sign:agree:flags", ';'-joined.
std::string devices_arg(const std::vector<Member>& members);
std::vector<Member> devices_from(const std::string& arg);

// The arguments each port takes.
// `name` is what this device calls the other side; `introduced`, what they call themselves.
sg::Params contact_add_args(const ConversationId& c, const std::string& name, Side side, std::uint64_t generation,
                            const std::vector<Member>& pinned, const std::string& introduced = {}, int kind = 0);
sg::Params rename_args(const std::string& name);
sg::Params contact_remove_args(const ConversationId& c);
sg::Params device_args(const ConversationId& c, const Member& m, std::uint64_t generation);
sg::Params post_args(const std::string& kind, const std::string& token);
sg::Params receive_args(const Key32& device, std::uint64_t sequence, const std::string& kind, int mode = 0);
sg::Params delivery_args(int mode);
sg::Params options_args(bool recovery, std::uint32_t disappear_s);
sg::Params replace_args(const ConversationId& c, const Key32& lost, const Member& m, std::uint64_t generation);
// Calls (protocol 7): made and ended at the book; their roster and plan at their own ports.
sg::Params call_start_args(const ConversationId& c, const CallId& call, int mode, int stripes);
sg::Params call_end_args(const ConversationId& c, const CallId& call);
sg::Params call_roster_args(const ConversationId& c, const CallId& call, std::uint64_t generation, std::size_t viewers);
// A game (protocol 8): its id travels as `call`, with the conversation.
sg::Params game_args(const ConversationId& c, const CallId& game);
sg::Params board_args(const ConversationId& c, const std::vector<Member>& devices);
sg::Params call_place_args(const ConversationId& c, const CallId& call, std::uint64_t generation, std::uint64_t epoch,
                           const std::vector<std::string>& forwarders);

}  // namespace chat
