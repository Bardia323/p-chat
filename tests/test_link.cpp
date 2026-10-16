// The engine's networking is linked and is the one this project expects:
// BLAKE2b-256 of nothing, and an Ed25519 signature that checks.
#include "check.hpp"
#include "sg/net/Integrity.hpp"

int main() {
    using namespace sg::net;
    CHECK(hex(hash(Bytes{})) == "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    Seed seed{};
    seed[0] = 7;
    SigningKey key(seed);
    const Bytes message{'s', 'g', 'c', 'h', 'a', 't'};
    CHECK(check_signature(key.public_key(), message, key.sign(message)));
    return sgchat_test::finish("sgchat_link");
}
