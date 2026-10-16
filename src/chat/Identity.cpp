#include "chat/Identity.hpp"
#include "chat/Crypto.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace chat {

// The lists as data, generated from data/*.txt by the build (Lists.cpp.in).
const char* word_list_text();
const char* emoji_list_text();

Key32 device_id(const Device& d) {
    return blake2b256(Bytes{}, Writer("sg.chat.v1.device").raw(d.sign).raw(d.agree).data());
}
std::string peer_of(const Device& d) { return hex(device_id(d)); }

const std::vector<std::string>& words() {
    static const std::vector<std::string> list = [] {
        std::vector<std::string> out;
        std::istringstream in(word_list_text());
        for (std::string w; in >> w;) out.push_back(w);
        if (out.size() != 2048) throw std::logic_error("chat: the word list is 2048 words");
        return out;
    }();
    return list;
}
const std::vector<std::pair<std::string, std::string>>& emoji() {
    static const std::vector<std::pair<std::string, std::string>> list = [] {
        std::vector<std::pair<std::string, std::string>> out;
        std::istringstream in(emoji_list_text());
        for (std::string line; std::getline(in, line);) {
            const auto tab = line.find('\t');
            if (tab != std::string::npos) out.emplace_back(line.substr(0, tab), line.substr(tab + 1));
        }
        if (out.size() != 256) throw std::logic_error("chat: the emoji list is 256 entries");
        return out;
    }();
    return list;
}

std::string make_code(const Bytes& r) {
    if (r.size() != 9) throw Refused("chat: a code is made from nine random bytes");
    std::string out;
    for (int i = 0; i < 6; ++i) {
        unsigned index = 0;
        for (int b = 0; b < 11; ++b) {
            const int bit = i * 11 + b;
            index = (index << 1) | ((r[std::size_t(bit / 8)] >> (7 - bit % 8)) & 1u);
        }
        if (i) out += ' ';
        out += words()[index];
    }
    return out;
}

std::string normalize_code(const std::string& typed) {
    std::vector<std::string> parts;
    std::string word;
    for (char c : typed + " ") {
        if (std::isalpha(static_cast<unsigned char>(c))) word += char(std::tolower(static_cast<unsigned char>(c)));
        else if (std::isspace(static_cast<unsigned char>(c)) || c == '-' || c == ',' || c == '.') {
            if (!word.empty()) parts.push_back(word), word.clear();
        } else throw Refused("chat: a code is six words");
    }
    if (parts.size() != 6) throw Refused("chat: a code is six words");
    std::string out;
    for (const auto& p : parts) {
        if (p.size() < 4 && std::find(words().begin(), words().end(), p) == words().end())
            throw Refused("chat: not a word of the list: " + p);
        const auto found = std::find_if(words().begin(), words().end(), [&](const std::string& w) {
            return w == p || (p.size() >= 4 && w.compare(0, p.size(), p) == 0 && p.size() <= w.size());
        });
        if (found == words().end()) throw Refused("chat: not a word of the list: " + p);
        if (!out.empty()) out += ' ';
        out += *found;
    }
    return out;
}

std::array<int, 4> fingerprint(const Key32& a, const Key32& b) {
    const bool order = std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    const auto h = blake2b256(Bytes{}, Writer("sg.chat.v1.fingerprint").raw(order ? a : b).raw(order ? b : a).data());
    return {h[0], h[1], h[2], h[3]};
}

}  // namespace chat
