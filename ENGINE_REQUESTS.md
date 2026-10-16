# Engine requests

sgchat does not change `stategine/`. These are the engine changes it would
use. Each is worked around today, and the workaround is tested.

## 1. A signer outside the engine

**What.** `Agreement::attest`, `Agreement::endorse`, `Verify::propose` and
`Protocol` take a `const SigningKey&`: the private key in memory. Let them
take a signer instead, in two steps since a browser signs asynchronously:
the engine makes the statement and records the lock it is about to cast
(persisting it, as now), the caller returns the signature, the engine
checks it against the member's key and keeps the vote. For example
`Agreement::prepare_attestation(result, peer) -> Attestation` (unsigned,
lock persisted) and `Agreement::attested(Attestation)` (signature checked),
and the same for endorse and propose.

**Why.** A browser device's identity key is a WebCrypto `CryptoKey` with
`extractable: false`; it can sign, but its private bytes can never be
handed to `SigningKey`. Today sgchat makes each statement in Wasm, signs it
in WebCrypto, writes the vote lock as the exact
`sg.net.agreement-journal.v1` the engine persists, and has the engine read
it back with `Agreement::restore` (which verifies every lock's signature).
`sgchat_trust` holds these bytes equal to the engine's own. It works, but it
reproduces the journal's encoding outside the engine: if the engine changes
that format, sgchat breaks quietly until its test runs.

**Ontology.** Unchanged: signing is external evidence machinery (AGENTS.md,
*Networking*: "Epoch, Integrity, Verify, Agreement and Protocol are external
execution/evidence machinery"). No state, clock or graph capability is
added; locks are still persisted before a vote is exposed.

## 2. A discrete-only epoch

**What.** Let `Problem` / `Verify` / `Agreement` finalize an epoch with no
numerical system: no layout, no observations, its decision the epoch, the
inputs and the declared checkpoint alone.

**Why.** A chat history epoch has nothing to solve. Today it carries the
smallest system the engine accepts (one free coordinate observed 0 with
confidence 1, no overlaps, 0 iterations: it solves to exactly 0), so every
epoch runs a reference solve and hashes a canonical result that means
nothing. It is correct and cheap, but it is a placeholder in the model, and
every reader must be told it means nothing (docs/protocol.md does).

**Ontology.** Unchanged: discrete inputs are already ordered, signed and
validated by `Verify`'s rule; a numerical system is execution data, and an
epoch without one adds no state or clock. The checkpoint remains a pure
function of the immutable problem.

## 3. A handoff under a recovery quorum

**What.** Let a `Handoff` (`Agreement::endorse`/`resume`) be endorsed by a
declared quorum of the members that remain when one member is absent for
good - for example two thirds of the rest - with the absent member named
in the handoff and excluded from the endorsers.

**Why.** A lost phone is a member that will never sign again. Today a
handoff needs the old committee's quorum, which in a conversation of two
devices is both, so a lost device can never be replaced through it. sgchat
does recovery as a decision of its own (`chat/Recovery.hpp`): endorsements
are engine `Attestation`s over a recovery record, checked against the
committee, and after it a fresh `Agreement` is started with the decision as
its `previous`. It works, and it is tested, but it is a second, parallel
way for a committee to change, outside `verify_handoff`, and the engine
cannot see that the chain was continued deliberately rather than restarted.

**Ontology.** Unchanged: the absent member is evidence data (who is not
asked), the quorum a parameter of the decision; no state, clock or graph
capability is added. The new committee is still taken up by `graph.edit`
from a port, as today.

## 4. Messages larger than a data channel takes

**What.** Let `WebRtcTransport` (and the native ICE transport) carry a
Reliable message larger than the peer connection's SCTP maximum message
size (Chrome: 256 KiB), by framing it in pieces itself.

**Why.** `rtc.js` hands each message to `RTCDataChannel.send` whole and
throws when it is over `sctp.maxMessageSize`. sgchat's envelopes are
padded to buckets of up to 256 KiB, so a long text or a history share
could not go live; sgchat now cuts what is larger than 128 KiB into
ordered pieces in its own adapter (`LiveJoin`, `chat/Media.hpp`). Every
application on the engine meets the same limit.

**Ontology.** Unchanged: framing is transport machinery, outside the world.

