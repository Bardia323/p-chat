# The p-chat relay on Cloudflare

The relay of `relay/relay.py` as a Cloudflare Worker and one Durable Object:
the same frames, refusals and limits (docs/protocol.md, "The relay's
frames"), checked by the same tests (`tests/test_relay.py --worker`, against
`wrangler dev`). Mailboxes and pairing tokens live in the object's SQLite
storage and expire after 14 days; rooms are the WebSockets connected to it,
which sleep between frames. It logs nothing. Two differences from
relay.py: no relay-held VAPID pushes (op 48 is refused - p-chat phones push
to each other, and the relay only forwards, op 49), and no per-connection
backpressure (Cloudflare buffers what a slow reader has not taken).

    npx wrangler deploy
