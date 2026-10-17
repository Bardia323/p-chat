# Changelog

## v1.12 (2026-10-17): what you send shows at once

- What you send is in the chat the moment you press send, waiting (◷),
  then sent (✓) - before, it could show only once a push to the other
  phone had been answered, which with an unreachable push service could
  take very long. Pushes now go out beside everything else, and one that is
  not answered in 10 s is given up.
- Invite: "Whose device" is asked only after "Another device of…" or
  "Reusable device key for…", as a list of your contacts (not at all with
  one contact, or from a contact's own Devices screen).

## v1.11 (2026-10-17): nothing left unsent; a new message below; right to left

- A message sent into a link that had already dropped (a phone asleep)
  and never acknowledged is sent again when the two are linked again. With
  no relay, it used to wait forever when the other device took mail.
- Scrolled up while something new comes in: "1 new message ↓" shows at
  the bottom, and a tap goes to it. At the end, the list stays at the end,
  even while pictures load.
- The time sits at the far end of each bubble, on its last line: right for
  a message written left to right, left for one written right to left
  (Persian, Arabic, Hebrew), and always reads 07:25 PM. Their bubbles are
  as wide as what they say, as yours are.

## v1.10 (2026-10-17): a device left on (sgchat_node)

- `sgchat_node`: p-chat with no screen, for a computer left on. Link it
  from your phone (Settings → Linked devices → Link a device). It is in
  all your chats and links live with their phones and browsers. It relays
  for them: while a device is away, the node keeps that device's sealed
  messages and gives them over when it is back. Only within your own
  chats, and it opens nothing.
- A message is no longer refused with no relay when a linked device that
  relays is in the chat itself: the relaying device takes its own copy
  live and keeps the others'.

## v1.9 (2026-10-17): carried within the chat (protocol 13)

- With no relay, a message and a call's first words now go further than
  one link: through any device of the chat's own members, a few links deep
  - never through a contact who is not in the chat, nor anyone else. In a
  group, a member whose phone is on keeps the messages for one whose phone
  is off, and gives them when it comes back; members pass mail between
  them, so whichever is around has it. Once opened, it is dropped by every
  member that kept it.
- Two devices of a chat that lost their link find each other again
  through a member linked to both, or through a chain of members.
- Only messages are passed member to member, not a file's pieces.
- Both ends need this version for the new paths (protocol 13); an older
  one carries as before.

## v1.8 (2026-10-17): table tennis that answers your hand (protocol 12)

- Your paddle goes where your hand puts it, at once, and stays there: no
  more jumping back when the other phone's answer comes. Each player now
  says where its paddle is at the end of each step it has already played,
  and both courts take exactly those places (measured: within 0.0005 of the
  hand; before, it jumped by up to 0.19, most of a paddle).
- The court keeps real time: it ran at 150% on a fast link and slowed to
  half speed or less on a phone's (46% at a 130 ms round trip). Now 99% up
  to about 130 ms; slower links wait rather than race.
- A game is asked in a new way (protocol 12): both players need this
  version.
- Sending keeps the keyboard up: the send key no longer takes the focus
  from what you are writing.
- A chat that can no longer reach the other side (relays off, the link
  dropped) says so and offers "Link again" and "Turn a relay on" right
  there.

## v1.7 (2026-10-17): faster, linked, and a device that relays (protocol 11)

- Messages between devices arrive at once: a few milliseconds over a live
  link (was half a second to a second), about a round trip by the relay
  (was three seconds). The relay now says when mail is waiting instead of
  being asked every four seconds; a phone coming back checks its relay
  connection and links at once.
- Linked devices: your phone and computer as one you. Invite → "My other
  device" (or Settings → Linked devices). Every chat comes onto the other
  device with its history; new chats include both; names follow; each
  device sees the others, online or last heard. Unlink by keeping a copy to
  read, forgetting everything, or splitting the chats (both agree).
- This device relays (Settings): a computer left open keeps its contacts'
  sealed mail and helps their devices find each other, with no relay.
- Link again in person: two paired devices that lost every link make one
  from two codes.
- p-chat on a computer is a desktop app: both panes fill the window, every
  screen laid out for it.
- Fixed: a message refused after its ratchet turn broke every later one
  from that device; a handoff could stall on an old vote; two handoffs in a
  row could extend an epoch already closed; a message from a generation not
  reached yet is now kept and opened later.

## v1.6 (2026-10-16): p-chat on a computer

- A wide window (900 px and more) shows the chats in a pane of their own on
  the left, the open one marked, and the chat - or a call, a game, the
  whiteboard, Settings - on the right, the full height. Messages keep to a
  readable width. Esc goes back. A phone is as it was.

## v1.5 (2026-10-16): back, and the screens that broke

- Back works: each screen deeper is a step in the browser's history, so
  Safari's swipe and Android's key come back; the Home Screen app goes back
  with a swipe in from the left edge; every screen but Chats has ◀.
- Table tennis answers at once: the court is stepped every frame on its own
  light round, and your paddle is drawn where your hand has put it. Its
  screen in the sleeve's look: two wide keys to hold, or drag on the court.
- The whiteboard in the sleeve's look again. The chat's heading keeps its
  keys on one row.
- A chat after a game had the game's keys where its composer should be
  (and could not be written in): fixed.
- On an iPhone, a chat no longer drags the whole page: only the messages scroll.
- Pairing: "Pair this phone" is no longer stuck grey after an earlier try
  (after half a minute with no answer it asks again); a mistyped word says
  "The six words did not match" and what to do.
- Replacing a lost device: the phone asked to approve is told at once, and
  its list flags the chat.

## v1.4 (2026-10-16): calls that sound right and look like p-chat

- Call sound no longer drifts later and later: it is played a little ahead
  of now (0.12 s) and catches up when it falls behind, instead of queueing
  every late piece. Its sound starts in the tap that begins or answers the
  call (a phone kept it paused till then). Where the browser has no track
  frames (Safari), the microphone is taken by an audio worklet.
- A picture keeps its shape: a phone held upright sends an upright picture,
  shown large, never squeezed into a wide box.
- The call screen in the sleeve's look, light and dark: the chat's heading,
  the other side in the court's frame, you in its corner, keys that press
  in; calling, a disc going round the stripes' colours with rings going out.
- Table tennis: the picture may run 0.4 s ahead of what both have agreed
  (was 0.2 s), so your own paddle no longer waits on the other phone.
- The send key with nothing written records a voice note. What you send
  comes into sight. More room under the last message.
- The attach key's + and × no longer swap.
- Putting p-chat on the Home Screen: on an iPhone in Safari (which offers no
  install prompt), Chats shows the two steps; where the browser has its
  own Install, its button. Not in the installed app; gone once dismissed.

## v1.3 (2026-10-16): the keyboard stays where you put it

- A message coming in no longer raises the keyboard: the chat's messages
  are drawn again, its composer is left as it is (what was typed, the tray).
- A chat fits what can be seen: when the keyboard opens, the messages make
  room and scroll inside the chat, the newest in sight - not the whole page
  sliding up.
- The chat says how the other phone is reached now: linked, through the
  relay, or not reachable now.

## v1.2 (2026-10-16): a relay that is always there, and nothing sent that cannot arrive

- The public p-chat has a relay by default, on Cloudflare (`relay/worker`):
  the same frames as `relay/relay.py`, checked by the same tests. A chat
  made with no relay uses it, so its two phones can always find each other
  again after a reload, a locked screen or a lost link.
- Nothing is sent that cannot arrive: in a chat with no relay, sending
  waits until the two phones are linked (the box says so). Calls only where
  a relay can bring a dropped call back.
- A reload on an iPhone no longer loses the device: where a browser cannot
  keep an Ed25519/X25519 key in its storage, the key is kept wrapped under
  one it can keep. A phone that has lost its key says so plainly, names no
  one, and can start again.
- Nobody chooses a name for themselves: after pairing, each phone names the
  other, and that name never leaves it.
- A notice no longer runs off the side of the screen.
- With no relay, the joining phone's code can be copied and sent, and the
  inviting phone can paste it.
- A link lost while its peer was away is made again when the peer is next
  heard from (under an older session): the link it could not take back.

## v1.1 (2026-10-16): no middleman (protocol 10)

- A new contact needs one side only: they scan your code, or open your
  link, and tap Pair (the words are in the link). With no relay at all, the
  two phones pair side by side: theirs shows a code back, and yours scans
  it - a link of their own, the pairing going over it, checked as ever.
- Contacts carry for each other: a phone linked with two of your contacts
  passes their signals on, so two phones that lost their link find each
  other again with no relay, and keeps sealed messages for a contact who is
  away until it asks. It cannot read them; it does see who talks to whom
  among its contacts (Settings → Carry for contacts: on or off).
- Relays can be turned off altogether (Settings → Relay). Then invites are
  in person only, and no notifications are sent.
- About: four short sections, one picture each - what it does, how it stays
  private, no middleman, good to know.
- A link or code opened while p-chat is already open is taken at once.
- No decorative word at the foot of each screen; Chats keeps its bar of buttons.
- **Breaking**: an in-person invite (no relay) and messages of content
  version 10 are not read by p-chat 1.0 (protocol 9).

## v1 (2026-10-15)

- A lost phone can be replaced. Another member invites the new phone; the
  others in the chat approve after checking its four pictures in person or
  by voice; the lost phone, if it still exists, is told and has a day to
  refuse. The new phone can be given the history - all, the last 30 days or
  none - and takes only messages the chat had agreed on.
- Per chat: "No recovery" (a lost phone's history is gone with it) and
  messages that disappear after an hour, a day or a week - from every
  phone, from what waits to be sent, and from the relay.
- Notifications that say nothing: a phone that cannot be reached at once is
  woken by its contact's phone, and shows only the symbol its owner picked
  for that chat - no name, no words. The relay holds no key for it. On an
  iPhone, Settings shows how to put p-chat on the Home Screen first; p-chat
  has a Home Screen icon of its own.
- Bots: a program on a server with a key of its own, paired like a contact
  and removed like any device. The echo bot ships with p-chat.
- Calls and going live. Call a contact or a group (everyone to everyone up
  to five phones, through relays beyond); go live in a group, and its
  members watch as a swarm, each phone passing pieces on as it can. Every
  frame is checked against what its speaker signed before it plays; a new
  key whenever someone leaves.
- Play table tennis with a contact, and draw on a whiteboard together: every
  stroke a message, the others' pens moving live, and "Follow me" to bring
  everyone's view to yours.
- Updates you can check: each release of p-chat is signed by a committee
  of its owner's devices and linked to the one before; a phone takes only
  what follows the release it runs, shows "Update ready", and switches the
  next time it opens. A phone behind takes a newer release from a contact's
  phone. Two different releases signed as one version are shown to everyone.
- p-chat opens on Chats, ready for the first contact; your name is asked
  on the Invite screen. No server address to type anywhere: invites use the
  one p-chat came with (your own, if you run one, under Settings → Advanced,
  checked before it is used).
- About, in pictures and short sentences: what you can do, how it works
  (a relay is like a courier: it carries the locked box to the right door,
  but it has no key), why no server is in charge (phones talk directly; any
  relay will do; run your own), why it is safe, and what it cannot hide. It
  shows at once - also in a browser where p-chat's background worker never
  started (it waited for it before, and showed nothing).
- "Relay" everywhere, never "server". Tape tennis is now table tennis.
- An open attachment tray stays open when a message arrives.
- An update offered while p-chat's background worker is being replaced is
  asked for again instead of lost.
- Long messages now go phone to phone too, and a phone that was away when
  a chat's secret changed is still found.
- Groups and channels; photos, files, stickers and voice notes; a choice per
  contact between "live only" (the relay keeps nothing) and "mailbox too";
  used keys wiped as soon as they are spent.

## v0 (2026-10-15)

The first version of p-chat, the messenger, and sgchat, its project.

- Pair two phones with a QR code and six spoken words, in a browser tab, with
  no account. The phone that was invited chooses what to call the one who
  invited it; anyone can rename a contact on their own phone.
- Messages go phone to phone over WebRTC when both are open, else through a
  relay's mailbox that holds only ciphertext for up to 14 days.
- Every message is end-to-end encrypted under a Double Ratchet per pair of
  devices, signed by its sending device, and accepted only through the
  engine's `Integrity`: duplicates dropped, replays refused, two different
  messages under one number kept as evidence and shown.
- Each conversation's devices are an engine `Committee`. A further device
  joins, and a device is removed, only by a handoff the existing devices
  endorse; the conversation's secret changes after a removal.
- The two sides regularly agree on the exact list of messages so far
  (engine `Agreement` epochs, chained): a dropped, changed or reordered
  message shows. A message that never arrives is shown as missing.
- History is kept encrypted on the phone under a key that cannot be copied
  out of the browser.
- The app is served from a signed bundle checked by a service worker; the
  About screen shows its fingerprint. The host remains trusted on every load.
- A dark look (the black VHS sleeve), following the phone or chosen per browser;
  in the dark a pressed key's shadow is a chromatic split that closes as it goes in.
- The p-chat wordmark (its dash the tape's stripes), plain screen names, and
  motion that answers what you do: screens slide in from where they lie,
  new messages pop from their side, the send key fires, counts bump. None
  for anyone who asked their phone for less motion.
- Fingerprint pictures ship with the app: the same drawing on both phones.
- Messages and names in any language, right-to-left included.
- The relay keeps everything in memory, logs nothing, and can wake an
  Android phone with an empty push (optional).
