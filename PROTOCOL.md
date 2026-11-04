# Tonnet Messenger Protocol

**Version:** 0.5.0

This document specifies the room protocol, relay DM service, payment rules and
standalone client API. For installation and commands, see
[README.md](README.md). Software releases and wire protocol versions are
separate identifiers.

[Scope](#1-scope-roles-and-conventions),
[Identity](#2-identifiers-and-cryptographic-conventions),
[Transport and discovery](#3-transport-capabilities-and-discovery),
[Rooms](#4-rooms), [DMs](#5-direct-messages), [Payments](#6-payments),
[Client API](#7-reference-client-api), [Limits and errors](#8-limits-and-errors),
[TL schema](#9-tl-schema), [Security](#10-security-assumptions-and-exclusions)

## 1. Scope, roles and conventions

### Reading this specification

Requirements apply to the actor named in each rule: sequencer, room replica,
relay or client. [§7](#7-reference-client-api) specifies the reference-client
API contract; independent wire implementations need not use that API or Go.
Examples and explicitly non-normative notes explain the rules without adding
requirements.

The uppercase terms MUST, MUST NOT, SHOULD and MAY have the meanings defined
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html). Requirements also occur
in ordinary prescriptive prose; the absence of an uppercase keyword does not
make a rule optional.

### Roles

Version 0.5 provides persistent public rooms, verified history, moderation, TON
DNS aliases, and encrypted direct messages delivered through relays.

There is one node program. Each role is switched on or off in its configuration;
one node may hold several roles at once. A relay offers services, each switched
on in its configuration, and each service is free (tier 0) or paid
([§6](#6-payments)).

| Role | Responsibility | Authority |
| --- | --- | --- |
| Sequencer | Validate, order, sign and persist the mutations of its own rooms | Holds the room key and sequencer key of each of its rooms |
| Room replica | Replicate the verified history of a room, serve reads and forward unchanged room traffic. Never paid; carries no DMs | Holds only its own node key |
| Relay | Offer the DM service, free (tier 0) or paid under its own limits: store encrypted DMs for any recipient until ack or expiry, and push them to the recipient while it is connected. The relay role serves no room; sequencer and room replica roles carry no DMs | Holds its own node key, plus a TON Payment Network key only if it sells paid tiers |
| Client | Own a user identity, verify history, send and receive messages | Holds only its user key |

A relay's default configuration enables the free DM service (non-normative).

A room belongs to its sequencer and has exactly one. If the sequencer
disappears, the room is gone: it accepts no new events and there is no handover.
Its signed history stays verifiable wherever room replicas still hold it. Room
replicas and relays MUST NOT sequence events, rewrite history, sign room state
or self-elect. Clients only connect outbound and MUST NOT publish themselves as
room nodes. Relays are shared: one relay serves many inboxes, sets its own
limits and MAY refuse any request when full, including paid ones.

Incompatible changes to serialization, signatures, identifiers, authorization or
event semantics require a new protocol version. Changing the required room
transport after publication also requires a new version; optional transport
profiles may preserve the version only when canonical objects and verification
rules remain unchanged.

## 2. Identifiers and cryptographic conventions

### Keys and identifiers

All keys are Ed25519. Public keys and hashes are 32 bytes; signatures are 64
bytes. Textual keys and hashes use canonical unpadded base64url (43 characters).

| Identifier | Meaning |
| --- | --- |
| `room_key` / `room_id` | Permanent room identity and signing authority |
| `node_key` | Sequencer public key, pinned in genesis |
| `identity_key` | User identity, proposal author and DM endpoint |
| `seqno` | Canonical event number, starting at 1 |
| `message_id` | `seqno` for a message; zero for other events |
| `event_id` | Hash of the boxed event proposal |
| `relay_key` | A relay's node key; signs its card and receipts |
| `inbox_id` | DM inbox address of a recipient |
| `dm_id` | Hash of a boxed DM (`directMessageV3`), including its signature |

Notation: `TL(x)` is boxed TON TL serialization; `H(x) = SHA-256(x)`; `||`
concatenates bytes. The canonical declarations are in [§9](#9-tl-schema).

```text
keyid(pub)     = H(TL(pub.ed25519{key=pub}))
overlay_id     = H(TL(pub.overlay{name=room_key}))
sequencer_adnl = keyid(node_key)
identity_adnl  = keyid(identity_key)
inbox_id       = keyid(recipient_identity_key)
relays_overlay = H(TL(pub.overlay{name="tonnet-relays-v1"}))
rooms_overlay  = H(TL(pub.overlay{name="tonnet-public-rooms-v1"}))
```

### Signed room objects

Genesis fixes the room key, sequencer key, creation time, initial metadata,
write policy and initial admins. It is signed by the room key. Clients MUST pin
genesis and reject a conflicting genesis for the same room.

`genesis_hash = H(TL(roomGenesisV2))` and `commit_hash =
H(TL(committedEventV2))`, including their signatures. Creation and commit times
must be positive Unix seconds. A genesis more than 300 seconds in the future is
rejected; historical proposal timestamps are not compared with the current
clock.

Genesis, room state and commits are signed with `room_key` over `H(TL(the
corresponding .toSign object))`. Commits bind the proposal hash; room state
binds a revision sequence and hash. The first commit's previous hash is 32 zero
bytes; the initial state references the genesis hash.

### Identity lifecycle

Resetting a user identity creates a new principal: roles do not transfer and the
domain association is cleared. The reference client preserves the local display
name and public-room cache, then reconnects using the new key.

## 3. Transport, capabilities and discovery

### Room-node discovery

Every overlay-scoped query is wrapped in `overlayQueryV1` ([Connection
profile](#connection-profile)). To join a room:

1. Resolve the room alias, if supplied, through [TON DNS](#ton-dns).
2. Derive its overlay ID and discover room nodes through TON DHT.
3. Select a reachable `adnl.address.quic` endpoint.
4. Authenticate the endpoint and fetch genesis, state and canonical history.
5. Verify the history and its derived state before exposing the room.

A known node ADNL ID may be used as a discovery hint. It MUST NOT replace
verification against the room key. Ephemeral ADNL keys may be used for DHT
access; classic ADNL MUST NOT carry Messenger room traffic.

Nodes publish `overlay.nodes` under `dht.key{id=overlay_id, name="nodes",
idx=0}`, with `pub.overlay{name=room_key}` and `dht.updateRule.overlayNodes`.
Each `overlay.node` binds the node public key, overlay ID and Unix-second
version; its signature covers boxed
`overlay.node.toSign{id=keyid(node_public_key), overlay=overlay_id, version}`.
Verify these signatures and overlay IDs before resolving node addresses through
the signed ADNL `address` record. The reference implementation accepts node
versions at most ten minutes old or sixty seconds in the future.

After this seed, nodes exchange signed `overlay.node` lists with
`overlay.getRandomPeers`. An answer carries the node itself and at most seven
more peers; at most 16 advertised nodes are considered. A TON DHT value is
capped at 768 bytes, so an `overlay.nodes` record holds only about five nodes:
the DHT seeds discovery and MUST NOT be treated as the membership list.
`getRandomPeers` is overlay-scoped and wrapped in `overlayQueryV1`.

### Global overlays

Each room overlay contains its sequencer and room replicas. Two global overlays
use the same discovery process: a DHT seed followed by `getRandomPeers`.

| Overlay | Members | Content served |
| --- | --- | --- |
| `relays` | Every relay | Its own signed `tonnet.relayCardV1` |
| `public-rooms` | Sequencers | Signed `tonnet.roomCardV1` objects |

A relay card binds the relay key to its QUIC address list, services and offers;
it is signed by the relay key. A room card binds the room key to its sequencer
key, optional `.ton` alias, name and description; it is signed by the room key.
Clients MUST verify the signature, and for a card alias, that `msg_room`
resolves to the room key ([TON DNS](#ton-dns)); otherwise the alias is ignored. A
card is an advertisement, not a guarantee of service or honesty.

Card freshness and publication follow these rules:

- `version` is the Unix time at which the owner signed the card. A card is
  accepted only if `version` is at most 600 seconds old and at most 60 seconds
  in the future; otherwise it is dropped. For the same key, a higher `version`
  replaces a lower one.
- The owner (relay key for a relay card, room key for a room card) re-signs
  with a fresh `version` every 5 minutes. A card that stops being refreshed simply expires after 600 seconds.
- Publication is pull, not push. A relay joins `relays`, and a sequencer joins
  `public-rooms`: it stores
  its signed overlay node in the DHT under that overlay's key, then exchanges
  peers with `getRandomPeers`. Members answer `getRelayCardV1` with their own
  card. Sequencers answer `getRoomCardsV1` with the
  fresh cards they hold (their own and those pulled from neighbours), after
  verifying each one.

### Service bits

Relay-card `services` and capability `flags` use these bits:

| Bit | Meaning |
| --- | --- |
| 1 | Reserved; relays serve no room |
| 2 | DM service |
| 4 | Paid tiers |

Bit 1 MUST be 0 in a relay card or offer; a receiver rejects either with it
set. Nodes send bit 1 as 0 in capability `flags`; receivers ignore that bit in
`flags`. Offer masks and payment-key requirements are specified in
[Offers and tier selection](#offers-and-tier-selection).

### Capabilities

Wire protocol version and software release are separate. Every node answers
the bare `tonnet.getCapabilities` query with `version_major`, `version_minor`
and `flags`. The wire version is 0.5, represented by major 0 and minor 5;
`client.info` reports it as `"0.5.0"`. The flags use the [service
bits](#service-bits). Every node accepts `tonnet.overlayQueryV1`. A
capabilities query is never rate-limited by resetting its stream. Clients use
only peers whose version is at least 0.5 and at least the version required by
the request.

Cache the answer per peer and probe again on each new connection. Before a valid
answer arrives, version and flags are zero. A query the node cannot decode
causes a stream reset. After a reset, retry the probe once on a fresh stream. A
second reset makes the peer incompatible and unused until a probe on a later
connection succeeds; remove such a relay from the client's relay set. Resets are
not scored. A relay probe timeout or malformed answer adds 1 to its
unreliability ([Relay scoring](#relay-scoring)).

### Connection profile

| Property | Required value |
| --- | --- |
| Transport | QUIC v1, ALPN `ton` |
| Authentication | TLS 1.3 raw public keys (RFC 7250), mutual Ed25519 |
| Framing | Native TON `quic.query`, `quic.answer`, `quic.message` |
| Endpoint identity | Hash of the peer public key equals the expected ADNL ID |

TON SNI is `<first 32 hex characters>.<last 32 hex characters>.adnl`, using
the expected node ADNL ID. Each stream carries one boxed request; a query's
boxed answer uses the same stream. FIN terminates the object. A message has no
application response. There is no additional length prefix, query ID or TON
`overlay.query`/`overlay.message` envelope around the Messenger payload;
overlay selection uses `tonnet.overlayQueryV1{overlay, tier, query}` for every
overlay-scoped query, including `getRandomPeers`, room reads and submissions.
The `overlay` is its ID ([§2](#2-identifiers-and-cryptographic-conventions));
`tier` MUST be 0. The result is the inner answer or
`tonnet.overlayRejectedV1{code, message}` with code 1 or 19. Only the outer
query is wrapped: read-only subqueries inside `batchV2` remain unwrapped.
Inbox, card, capability, payment and time (`tonnet.getTime`) queries are bare,
not overlay-scoped.

An unwrapped overlay-scoped query causes a stream reset. For a wrapped query,
the node performs these checks in order:

1. If it does not serve the overlay, answer code 19. Clients then try another
   node for that overlay.
2. If `tier` is non-zero, answer code 1.
3. Process the inner query.

Code 2 denotes a definitive wrong-room proposal rejection and is not used for
this availability failure.

A generic TON node does not implement the application-specific `tonnet.*`
objects.

This is TON QUIC, not HTTP/3. There is no application-level hello or device
binding. Clients MUST reject wrong-key endpoints and MUST NOT downgrade to
classic ADNL when QUIC fails.

### TON DNS

Aliases use standard `dns_text#1eda` records:

| Category | Key | Complete record value |
| --- | --- | --- |
| `msg_room` | `H("msg_room")` | Canonical room key |
| `msg_id` | `H("msg_id")` | Canonical user identity key |

Values have no prefix or wrapper. DNS is an alias, never the canonical identity.

This refers to the text value, not its on-chain encoding: the record remains
`dns_text#1eda` followed by TL-B `Text` (chunk count and length-prefixed
chunks), not a snake string. Local inputs are trimmed and lowercased. Accepted
names end in `.ton` or `.t.me`, have nonempty labels containing only `a-z`,
`0-9` and `-`, and have no leading or trailing hyphen in a label. `.t.me` labels
also accept `_`. Signed claims must already use this normalized form. Both
namespaces use the configured TON DNS root and standard resolver delegation.
`.t.me` aliases refer to on-chain collectible usernames with DNS records, not
arbitrary Telegram accounts.

Clients, sequencers and replicas support both `.ton` and `.t.me` claims.

When a proposal includes `author_domain`, it MUST be lowercase and the sequencer
MUST resolve `msg_id` to exactly `author_key` before committing. Positive
results may be cached for five minutes. Invalid or unavailable claims are
rejected; later DNS changes do not rewrite history or transfer roles. DMs
resolve and re-check `msg_id` on both ends ([§5](#5-direct-messages)).

Domain-link helpers prepare a transaction to the domain NFT contract. Only its
owner's wallet authorizes that transaction. The client confirms the association
by resolving the published record, not by trusting a QR scan. For collectible
`.t.me` usernames, helpers check `get_telemint_auction_config` and refuse to
prepare a transaction while a sale or auction remains unsettled. This check is a
snapshot; listing state can change before wallet approval.

Resolver trust assumptions are described in [§10](#dns-resolver-trust).

## 4. Rooms

### Proposal and commit

An author signs a typed proposal containing the room, identity, optional name
and domain, random nonce, timestamp and event body:

```text
body_hash       = H(TL(body))
proposal_digest = H(TL(eventProposalV2.toSign{
                    room_id, node_key, author_key, author_name, author_domain,
                    nonce, timestamp, body_hash
                  }))
author_signature = Ed25519(identity_private_key, proposal_digest)
```

For a directly connected client, the author key MUST equal the authenticated
peer key. A verified room replica may forward the original signed proposal. A
member sends its proposal to the sequencer directly or through a room replica.
The sequencer broadcasts each commit to its room node peers and client members;
room replicas forward and retain verified commits for later readers. A client
connection becomes a member on its first room query other than `getRandomPeers`
and `getTime`, after selection of an overlay the node serves and before
processing the room query. Membership is scoped to each room; a node delivers a
room's commits only to that room's members.

On a room-only node, a member connection closes after 150 seconds without a room
query, and any other client connection closes 30 seconds after opening. On a
node also running DM service, the relay rule covers the whole connection ([Relay
connections](#relay-connections)): 150 seconds for a room member or inbox
subscriber, measured from activity of any kind, room or DM, and no idle closure
while a request is in flight. A member stays a member until its connection
closes. The client sends no keepalive: it reconnects, resumes room reads from
its cursor, and fetches and subscribes to inboxes again.

First, the sequencer MUST return the existing commit for an exact proposal
already in durable history. Current timestamp, DNS and permission checks do not
apply to this duplicate. For a new proposal, the sequencer MUST, in order:

1. Verify the room, signature, timestamp and domain claim.
2. Reject a reused author nonce within the retention window.
3. Verify authorization.
4. Allocate the next `seqno` and link the previous commit hash.
5. Sign the commit and persist its event, projection, nonce and head atomically.
6. Return and broadcast the durable commit.

Repeating the exact proposal MUST return the existing commit without consuming
another sequence number. Live timestamp checks MUST NOT be reapplied to history.

Clients and forwarding room replicas MUST compare the returned commit's proposal
ID with the submitted proposal ID before treating either `submitAcceptedV2` or
`submitDuplicateV2` as success. A valid commit for another proposal is a
protocol error, not a successful submission.

`committed_at` is the sequencer's clock. The sequencer MUST sign `committed_at =
max(now, previous committed_at)`, allowing equal timestamps. Readers require
positive commit times but MUST NOT reject a historical commit merely because its
`committed_at` is lower than its predecessor's.

### Authorization

The holder of `room_key` is the non-delegated owner.

| Event | Authorized authors |
| --- | --- |
| Message | Everyone when `anyone_can_write=true`; otherwise owner and admins |
| Metadata / write policy | Owner and admins |
| Pin / unpin | Owner, admins and moderators |
| Grant / revoke moderator | Owner and admins |
| Grant / revoke admin | Owner only |
| Ban / unban | Owner and admins; banning an admin is owner only |

Roles target identity public keys. Admins, moderators and pins MUST be unique
and canonically sorted in signed state.

The admin list is signed by the room key. A domain owner's wallet only publishes
`msg_room` on-chain, binding the alias to the room key; it does not sign
off-chain room data.

**Bans.** `tonnet.eventBanV1{subject_key}` and
`tonnet.eventUnbanV1{subject_key}` are signed, state-changing events in the hash
chain. They update the sorted `banned` list in `tonnet.roomStateV3`. Room
replicas fetch updated signed state after a ban or unban, as after other
state-changing events. Exact duplicates and nonce checks retain their stated
precedence; authorization rejects a new proposal from a banned identity with
code 6.

An admin may ban a non-admin identity; only the owner may ban an admin. An admin
banning itself therefore receives code 6. A ban removes all roles held by its
subject. Banning the owner, including self-ban, banning an already banned
identity, or unbanning an absent one receives code 8. The banned list is capped
at 256 keys; exceeding it receives code 9. For anti-abuse, a sequencer MAY
temporarily reject a source without an event (code 9); this is not a ban or
verified state.

Sequencers sign only `roomStateV3` as current room state. Clients and room
replicas accept only that constructor for current state. A peer-supplied
`roomStateV2` is malformed and produces `PROTOCOL_ERROR` at the client API.

### Durable room state

One node key and store serve all configured rooms and inboxes. Local schema
migration preserves room genesis, signed state, head, events, messages, pins,
roles, nonces and node identity. Sequencer startup also preserves its room key
and genesis; genesis pins the sequencer key.

If locally stored current state is `roomStateV2`, its sequencer re-signs it as
`roomStateV3` with the same revision and fields and an empty banned list. This
conversion is checked on every startup. It occurs in the schema-migration
transaction where possible; otherwise a later startup repairs an interruption
between migration and conversion. A room replica is not ready until it has
synced verified V3 state. Clients replace cached V2 state with verified V3 state
even at the same revision. V2 decoding is for local store migration only, not
peer state exchange.

### State ordering and event constraints

Keys are sorted lexicographically by their raw bytes; pins are sorted
numerically. Initial admins follow the same key ordering. The owner cannot
receive or lose a delegated role. Granting an existing role, revoking an absent
role or pinning an already-pinned message is rejected. Admin and moderator are
independent roles: an identity may hold both. Pins reference existing messages;
unpinning requires the message to be pinned. Room names are nonempty and contain
no control characters; descriptions cannot contain NUL. All text is valid UTF-8.

### Verification and replication

Clients and room replicas MUST verify genesis, proposal and commit signatures,
contiguous sequence numbers, previous hashes and authorized state transitions. A
valid signature alone is insufficient. Gaps MUST be repaired before later events
are accepted; submit responses and broadcasts use the same deduplication and
verification rules.

| Read | Result order |
| --- | --- |
| `getEvents(after_seqno)` | Later canonical events, ascending |
| `getMessagesRecent` | Latest messages, in display order |
| `getMessagesBefore(message_id)` | Earlier messages, in display order |
| `batch` | Read-only subqueries and their answers, in request order |

Limits are defined once in [§8](#8-limits-and-errors). A batch item exceeding
the remaining answer budget receives code 9 without invalidating earlier items.
All subsequent batch items also receive code 9. Successful items use code 0 and
contain the boxed read result; failed items contain no result data.

Room replicas MUST persist only verified canonical data. A room replica syncs
first from a healthy node peer of the room, replica or sequencer, then from the
sequencer. `ready=true` requires its signed state to cover the latest
state-changing commit. A room replica may serve verified reads while the
sequencer is unavailable; it MUST NOT invent a write result.

`RoomState` is signed; `RoomStats` is not. Presence, node role and readiness
MUST remain separate from verified state. The client's exposed `latest_seqno`
comes from its locally verified event chain.

### Broadcasts and time

Canonical events are carried in `tonnet.broadcast` wrappers with `flags=0` and
`overlay.emptyCertificate`, signed by the room key. DMs are not room broadcasts
([§5](#5-direct-messages)).

```text
broadcast_id = H(TL(tonnet.broadcast.id{
                 src=keyid(source_key), data_hash=H(data), flags
               }))
signature    = Ed25519(source_private_key,
                      TL(tonnet.broadcast.toSign{hash=broadcast_id, date}))
```

The wrapper signature and live freshness MUST be verified independently of the
inner payload. Nodes deduplicate broadcasts and forward them unchanged.

The sequencer is the only timestamp authority of its room. Each commit carries
the sequencer's time in `committed_at` ([§4](#4-rooms)). The
sequencer rejects with code 3 a proposal whose timestamp differs from its local
clock by more than 300 seconds. The time of a room replica or relay MUST NOT be
used for any room timestamp.

When the sequencer is reachable directly, the client queries `tonnet.getTime` on
a connection authenticated by the pinned genesis `node_key` and stamps the
proposal with that time. If its session peer is a room replica, it dials the
sequencer for this calibration, then submits over its session. Calibration may
be cached for five minutes, MUST be invalidated on session or identity changes,
and fails with `CLOCK_SKEW` if sequencer time differs from the local clock by
more than 300 seconds.

**Replica-only writes.** A member that reaches the sequencer only through a room
replica stamps the proposal with its own clock; the sequencer's ±300-second
check is then the only freshness bound. Writes fail with `SEQUENCER_UNAVAILABLE`
only when the sequencer cannot be reached directly or through a room replica.

Broadcast freshness uses the receiver's local clock, not proposal-time
calibration. A DM's `created_at` is checked only by the clock of the relay that
takes the deposit ([§5](#5-direct-messages)).

## 5. Direct messages

DMs are signed and end-to-end encrypted, but non-canonical: they have no
canonical sequence number or read acknowledgement. Every DM is deposited on
relays providing the DM service. They hold it in the recipient's inbox until ack
or expiry and push it to a connected recipient. Room nodes do not carry DMs
through room overlays ([Room nodes](#dm-room-nodes)).

A DM is a single-layer envelope: relays see the sender key, the recipient inbox,
sizes and times, but not the plaintext. Hiding the sender is out of scope.
Routing metadata remains visible; forward secrecy is not provided.

### Encryption

The encryption key and direction-bound AAD are independent of
any room:

```text
secret = X25519(convert(identity_private_key), convert(recipient_public_key))
key    = SHA-256("tonnet-dm-v2" || secret)
aad    = H("tonnet-dm-v3") || from_key || to_key
box    = nonce(12) || AES-256-GCM(key, plaintext, aad) || tag(16)
```

Here the GCM term denotes ciphertext without the separately shown tag. The nonce
is cryptographically random. Ed25519 identities use the TON Ed25519-to-X25519
mapping. Plaintext is valid UTF-8, at most 1400 bytes; the complete box is
28–1428 bytes. Validate plaintext before encryption and after decryption.

### Envelope

`tonnet.directMessageV3{from_key, to_key, author_name,
author_domain, created_at, expire_at, ciphertext, signature}`. The sender signs
`H(TL(directMessageV3.toSign{...}))` with its identity key. `dm_id =
H(TL(directMessageV3))`, including its signature. `author_domain` is an optional
sender alias claim; empty when absent. Only the DM constructors declared in
[§9](#9-tl-schema) are accepted.

### Sending

1. Resolve the recipient: a canonical key, or an alias through `msg_id`
   ([TON DNS](#ton-dns)). Fail closed if resolution fails.
2. Choose at most 5 DM relays ([Inbox rendezvous](#inbox-rendezvous))
   whose cards accept the size: first those listed under the inbox DHT key,
   then, only while fewer than 5 are chosen, one relay the sender already uses
   (for its own inbox), if any, with the lowest unreliability, then the next
   relays of the rendezvous ranking. After rejections the sender goes no
   further down the ranking than the 5 top-ranked relays, the ones the
   recipient tries.
3. Encrypt, then build and sign the envelope. `created_at` is the sender's
   local clock; `expire_at − created_at` MUST NOT exceed the smallest
   `retention_seconds` among the chosen relays' offers. Retention is counted
   from `created_at`.
4. Send `tonnet.inboxDepositV1{message, tier}` to each chosen relay over TON
   QUIC, with the sender's identity key as the QUIC key.

### Deposit validation and receipts

The relay MUST process a deposit in this order:

1. Parse the request (code 1 on failure).
2. Verify the signature and that `from_key` equals the authenticated peer key
   (code 5 on failure).
3. If it already holds the deposit's `dm_id`, stored or retained after deletion
   as described below, return its receipt without further checks or a new debit.
4. Require an offer for the deposit's tier in its current card (otherwise 17).
5. Check the offer's size limit, that `created_at` is within ±300 seconds of
   the relay's clock, `expire_at` against the offer's retention, the
   per-recipient quota and the per-sender rate, all defined by the relay.
6. For a non-zero tier, check the prepaid balance (17) and then the in-flight
   cap of paid deposits (16) in one admission step
   ([Paid deposits and debits](#paid-deposits-and-debits)).

A deposit is accepted when stored under `inbox_id = keyid(to_key)`; a rejection
(`inboxRejectedV1`) is not stored. The relay answers a
`tonnet.inboxReceiptV1{relay_key, dm_id, inbox_id, expire_at}` signed by the
relay key, with the envelope's `expire_at`, or `inboxRejectedV1{code, message}`.
Rejections use the [§8](#8-limits-and-errors) codes: 1 malformed; 5 invalid
signature or `from_key` not the peer key; 3 `created_at` outside ±300 seconds; 9
size or retention beyond the offer; 16 recipient quota, sender rate or relay
full; 17 tier or prepaid balance. Depositing the same envelope again returns the
stored receipt and is not debited again; this is how a client recovers a receipt
it did not receive. When the relay deletes a message (on ack or at `expire_at`),
it keeps its `dm_id` and receipt until at least `created_at` + 300 seconds,
after which a retry is rejected with code 3 anyway; a retry in that window is
answered as a duplicate and is neither stored nor pushed again.

A receipt shows that the relay accepted the message until `expire_at`; it does
not prove delivery. The client MUST check the receipt signature, that
`relay_key` is the authenticated QUIC peer key, and that `dm_id`, `inbox_id` and
`expire_at` match the envelope. The DM is `stored` at the first valid receipt;
the client aims for 3 receipts and never deposits to more than 5 relays. Without
a valid receipt the send fails ([§7](#7-reference-client-api)).

### Inbox rendezvous

```text
inbox_overlay   = H(TL(pub.overlay{name = H("tonnet-inbox" || inbox_id)}))
dht_key         = dht.key{id = inbox_overlay, name = "nodes", idx = 0}
rank(relay)     = H(inbox_id || relay_key)            (ascending)
```

While a relay holds DMs for an inbox, it stores its self-signed `overlay.node`
for `inbox_overlay` under `dht_key` with `dht.updateRule.overlayNodes`,
refreshed every 60 to 100 seconds. The update rule drops entries older than 600
seconds and keeps what fits in 768 bytes (about five nodes), so, as for any
overlay ([§3](#3-transport-capabilities-and-discovery)), the DHT value only seeds discovery:
a holder is a member of `inbox_overlay` and exchanges peers with the holders it
finds there through `getRandomPeers` wrapped in `overlayQueryV1` for
`inbox_overlay`. The sender queries `dht_key` first and tops up from the
rendezvous ranking over the `relays` overlay only as in [Sending](#sending) step 2. The
recipient queries the same key and also tries the 5 top-ranked relays, the same
bound as a deposit and as an `overlayNodes` DHT value, querying 3 at a time, and
asks each holder it reaches for `getRandomPeers` in `inbox_overlay`, considering
at most 16 advertised nodes. Every relay that accepted a deposit joins
`inbox_overlay`, so the recipient also finds DMs held by a relay the sender
chose outside the ranking, even when the DHT value dropped it. Residual risk:
ranks can be ground, so anyone can create relay keys that rank high for an inbox
and drop its DMs, or publish under its DHT key to take the five slots. Mixing in
a relay the sender already uses limits this but does not remove it; public
overlays give no Sybil resistance ([§1](#1-scope-roles-and-conventions)). Fetches are
authenticated, and an empty answer costs nothing and is not penalised. The DHT
record reveals that an inbox currently holds DMs, not who sent them.

### Fetching and acknowledgement

The recipient connects to DM relays and proves key ownership:

1. `getInboxChallengeV1{inbox_id}` → `inboxChallengeV1{nonce, expire_at}`.
2. `tonnet.inboxAuthV1{recipient_key, nonce, signature}`, where the signature
   covers `H(TL(inboxAuthV1.toSign{relay_key, inbox_id, nonce, expire_at}))`
   and `keyid(recipient_key)` MUST equal `inbox_id`. The proof stays valid
   on that QUIC connection until `expire_at`. A relay keeps at most 4
   outstanding challenges per connection, the incoming-stream limit per peer
   ([§8](#8-limits-and-errors)); beyond that it answers code 16.
3. `getInboxV1{auth, after, limit}` returns stored envelopes in deposit
   order, in pages within [§8](#8-limits-and-errors), with `has_more` and
   `last_seqno`. A relay numbers the deposits of each inbox with a local,
   increasing `seqno` that is never reused; `last_seqno` is the `seqno` of the
   page's last envelope, or `after` for an empty page; `after` is the previous
   page's `last_seqno`, or zero for the initial page. The
   client keeps one durable cursor per relay and inbox, set to
   `max(cursor, last_seqno)` after each completed page, so it never moves
   back. Pushes do not move it (push step 4).
   Deleting acked messages does not invalidate the cursor.
4. `inboxAckV1{auth, ids}` after the messages are durably stored locally or
   dropped by the recipient checks (below), with at most 256 `ids`, the query
   page maximum.

The relay deletes a message on ack or at `expire_at`, whichever comes first.
Challenge, fetch and ack failures are answered with `inboxChallengeRejectedV1`,
`inboxPageRejectedV1` or `inboxAckRejectedV1{code, message}`: 18 for a failed or
expired proof, 1 malformed, 16 rate.

<a id="dm-push"></a>

### Real-time delivery

A relay pushes new deposits to
the connected recipient as one-way `quic.message` objects on its bounded
outbound queue. Push reuses fetch authentication and adds no query:

1. A valid `getInboxV1` answered with `has_more = false` subscribes its QUIC
   connection to that inbox until the proof's `expire_at` or until the
   connection closes. A connection holds at most one subscription; any later
   page with `has_more = false`, for the same or another inbox, replaces it.
2. For each later deposit to the subscribed inbox, the relay sends
   `tonnet.inboxPushV1{seqno, message}` as a `quic.message` on that
   connection, in `seqno` order, where `seqno` is the deposit's relay-local
   number and every pushed `seqno` is above that page's `last_seqno`. The
   relay assigns the number and queues the push atomically with the deposit,
   so a deposit is either in the page or pushed. A push has no answer and
   fits the QUIC message payload limit ([§8](#8-limits-and-errors)).
3. Pushes share the connection's single outbound queue of 32 slots with every
   other message sent on it, such as room broadcasts when the node also serves
   rooms. When the queue is full, the relay closes the connection; the
   deposits stay stored.
4. A push does not delete or mark anything: the message stays until ack or
   `expire_at`, exactly as if fetched. The client accepts an `inboxPushV1`
   only on a connection where it holds a subscription or has a `getInboxV1`
   for that inbox outstanding, since the push's stream may complete before
   the answer of the page that subscribed it (below); it applies the recipient
   checks below and the same `dm_id` deduplication, and acks with `inboxAckV1`
   once it has stored or dropped the message. It does not move its fetch cursor:
   each push is its own QUIC stream and receiving streams are served
   concurrently, so
   pushes may complete out of order and a later `seqno` does not prove that
   earlier ones arrived. Pushes are not debited from a prepaid balance.
5. A running client subscribes on every relay it fetches from (the 5
   top-ranked relays and the holders found under its `dht_key` or through
   `getRandomPeers` in `inbox_overlay`) and renews a
   subscription before `expire_at` with a new challenge and a `getInboxV1`
   from its cursor. Pushes are only a fast path: after a reconnect, a closed
   connection or an expired subscription, the client fetches with
   `getInboxV1` from its cursor for that relay, so nothing is missed; messages
   already received by push are deduplicated, or already acked and deleted. A
   relay that holds DMs outside the ranking is reached once the recipient
   learns it from the DHT or from another holder.

<a id="dm-room-nodes"></a>

### Room nodes

Only the DM service handles DMs,
through bare inbox queries. Sequencers and room replicas MUST NOT accept,
store, forward or push DMs on room overlays. A `tonnet.broadcast` is dropped
without forwarding if its source is not a served room key or its data is not
an accepted canonical room event. Closed types reject unknown constructors
([§9](#9-tl-schema)). Dropping such a message is not scored; only an invalid
outer wrapper signature penalises the sending peer. A node with both room
and DM roles handles DMs only through its DM service.

### Recipient checks

For each envelope, fetched or pushed, the client MUST
verify the sender signature and that `to_key` is its own key, deduplicate by
`dm_id` across relays, decrypt and validate the plaintext. An envelope that
fails any of these checks is dropped without being stored or shown and is acked
like a stored one, and the client goes on with the next envelope and page: the
relay holds it until ack or `expire_at`, so leaving it unacked would keep it in
the recipient's inbox quota (code 16) and return it on every fetch. If
`author_domain` is set, it resolves `msg_id` and shows the alias only if it
resolves to `from_key`; a failed check drops the claim, not the message. The
recipient applies no ±300-second timestamp check: `created_at` is shown as
claimed by the sender. It drops without showing, and acks, an envelope whose
`expire_at` plus 300 seconds is not after its clock, so a relay that keeps a
copy past `expire_at` cannot have it shown again once deduplication forgets it.
The ack is sent to every relay that returned the message. The client remembers
each accepted `dm_id` until its `expire_at` plus 300 seconds (the deposit
`created_at` skew); a copy returned later by another relay is not shown again
but is acked to that relay.

### Relay connections

A relay closes a client connection after 30 seconds
without an answered request on it, and a connection that holds an inbox push
subscription ([Real-time delivery](#dm-push)) after 150 seconds without one.
Both are measured from the last activity, an answered request or, on a
subscribed connection, a push sent, or if none from the connection's opening,
and a connection is never closed for idleness while a request on it is in
flight. Every request the relay answers counts, including a rejection: inbox
deposit, challenge, fetch and ack, card, capability, payment and time queries,
and `getRandomPeers` in the `relays` and inbox overlays. A paid deposit is debited
when stored and is not refunded if the connection closes before its receipt
is delivered; the client sends it again on a new connection and gets the
stored receipt without a new debit ([Paid deposits and debits](#paid-deposits-and-debits)).

### Relay scoring

A client scores the relays it
uses locally:

| Observation | Effect |
| --- | --- |
| Capabilities probe reset twice | Not scored; drop it from the relay set |
| Quota exceeded or prepaid balance insufficient (codes 16, 17) | Not scored; ask another |
| Malformed request (code 1) | Not scored: a client bug, such as a non-zero tier on a free query |
| Timeout or no answer | Unreliability +1 |
| Successful answer | Unreliability −1, not below zero |
| Malformed answer | Unreliability +1 |
| Invalid signature, such as on a receipt | Local ban of that relay key (see below) |

A relay is picked at random with weight `2^(F − (u − u_min))`, excluding relays
whose `u − u_min > F`, with `F = 10`. When the relay set is full, the most
unreliable relay is dropped if its `u > 5`; otherwise a random one is replaced.
Scores are local, unsigned and never shared. An empty inbox page is a successful
answer.

Each relay key has a ban duration `d`, starting at 60 seconds. An offence bans
the relay until `now + d`, then sets `d = min(3600, 1.5 * d)`. Every valid answer
sets `d = max(60, d / 1.5)`. `d` is kept after a ban expires, so a relay that
offends again soon is banned longer. The table is bounded at 4096 entries. When
it is full, the entry with the lowest `d` is evicted, and among equal `d` the
least recently updated one.

## 6. Payments

### Offers and tier selection

Each relay advertises one or more offers in its card. An offer states its tier,
the services it covers, the maximum object size, retention, request rate,
per-recipient inbox quota, and the price `price_nanoton` of one unit of
`unit_bytes` paid bytes (below). All values are defined by each relay; tier 0 is
free, needs no prepaid balance and ignores `price_nanoton` and `unit_bytes`.
Payment does not mean unlimited: a paid tier has finite limits and a relay MAY
refuse a paid request when full.

An offer's `services` is non-zero, a subset of the card's service bits, and
never contains bit 4 ([Service bits](#service-bits)). In 0.5.0 its value is
therefore 2. An offer of a non-zero tier has positive `price_nanoton` and
`unit_bytes`. A card has at most one offer per tier. A card without bit 4 MUST
NOT carry an offer of a non-zero tier, and MUST have a `payment_key` of 32
zero bytes. A card with bit 4 MUST have a non-zero `payment_key` and at least
one offer of a non-zero tier. A card that breaks any of these rules is
rejected. Its address list is also subject to the bound in
[§8](#8-limits-and-errors).

Only one request is tier-checked: a deposit (`inboxDepositV1`), which uses the
DM service and names a `tier`. The DM service is free at a relay if and only if
its tier-0 offer covers it. A deposit of tier T is accepted only when the card
has a tier-T offer, and for T ≠ 0 only within the client's prepaid balance for
tier T (below); otherwise it is rejected with code 17. Every other request is
free and not tier-checked: every query to a sequencer or a room replica (rooms
are never paid), `getRandomPeers` in any overlay, queries in the global `relays`
and `public-rooms` overlays, and inbox challenge, fetch and ack, card,
capability, payment and time queries. Of these, only `overlayQueryV1` carries a
`tier`, which MUST be 0; a non-zero tier is answered with code 1 (malformed
request).

The [deposit validation order](#deposit-validation-and-receipts) applies to
free and paid deposits.

Paid tiers use the TON Payment Network (TPN). Channel opening, routing and
on-chain disputes follow TPN and are not specified here. The TPN state,
conditional and status names below describe the required payment integration.

### Prepaid balances

A relay keeps a durable prepaid balance per authenticated
client key and paid tier. Payments credit it; stored paid deposits debit it. The
record contains:

- `balance_bytes`: a signed 64-bit count of paid bytes, allowing the bounded
  overdraft defined under [Paid deposits and debits](#paid-deposits-and-debits);
- `remainder_nanoton`: paid nanoton not yet converted into units.

The paid bytes of a deposit are the serialized boxed TL bytes of
`inboxDepositV1` plus its boxed receipt, without QUIC framing. The client key is
the authenticated QUIC peer key for both `relayPaymentV1` and deposits. Balances
do not expire and survive restarts. Their funds are secured by settlement
independently of whether the balance has been spent.

### Client payment procedure

1. Generate a fresh Ed25519 channel key for each virtual channel. Open a send
   conditional to the relay's `payment_key` with `CreateSendConditional` and
   wait until `GetVirtualChannelMeta` reports `Active`. The channel MUST be
   opened without a final state (`withFinalState = false`). A channel opened
   with one is rejected with code 17 and credited nothing, even if TPN later
   collects it; this loss is accepted by the client. Capacity is at least the
   tier's `price_nanoton`. The relay accepts new states only with at least
   300 seconds remaining before the safe deadline. A channel pays one tier
   for one client key.
2. To top up, sign a TPN `VirtualChannelState{Signature, Amount}` whose
   cumulative `Amount` is k × `price_nanoton` above the previous state, for
   k ≥ 1 units. Save it on the client's own TPN node with
   `AddConditionalResolve`, then send
   `tonnet.relayPaymentV1{tier, channel_key, state, final}`. The `state` is the
   BoC of the signed state. Set `final` when remaining capacity cannot buy
   another unit.
3. After a timeout or reset, retry with the same state. The relay returns the
   current balance without crediting twice.
4. Track the last received `balance_bytes` minus the paid bytes of later paid
   deposits answered with receipts, excluding duplicates. Top up before this
   balance falls below the next paid deposit's bytes. If this count is lost,
   or code 17 is received, resend the last state to obtain the current balance
   at no charge, or pay again. There is no separate balance query.

### Relay credit procedure

On `relayPaymentV1` the relay MUST perform these steps in order:

1. Parse `state` (code 1 on failure), require `Amount > 0` and verify the
   signature with `channel_key`; otherwise answer 17.
2. Under a lock per `channel_key`, read `last_credited_amount` and the client
   key and tier bound by the first credit. Resolve any pending record first
   ([Pending recovery](#pending-payment-recovery)) and use the updated record. If the channel was credited
   to another client key or tier, answer 17. If
   `Amount ≤ last_credited_amount`, return the current balance and stop,
   before checking the current offer or channel status. This retry remains
   valid after channel closure.
3. Require a non-zero `tier` offered in the relay's current card. Read
   `GetVirtualChannelMeta(channel_key)` and require `meta.Incoming` set,
   `meta.Outgoing` unset and status `Active`. Parse
   `meta.Incoming.Conditional` as a `ConditionalVirtualChannel` and require
   `Capacity ≥ price_nanoton`. Require
   `GetAction().GetAffectedCoins()[0].BalanceID == GetTONBalanceID()`: prices
   are in nanoton. Require
   `GetActiveChannel(meta.Incoming.ChannelAddress)` to succeed and
   `FindConditional` to find the incoming conditional, by hash, in the base
   channel's `Their.Data.Conditionals`. Virtual-channel status alone is
   insufficient: it may remain `Active` after the base channel closes.
   Finally require `meta.LastKnownResolve` to be nil or its `Amount` to be at
   most `last_credited_amount`. Otherwise answer 17. This refuses channels
   opened with a final state, for which collateral is not established by the
   opening checks.
4. Require `meta.Incoming.SafeDeadline − now ≥ 300` seconds; otherwise 17.
5. A relay key MUST NOT share its `payment_key` with another relay key. One
   node key and store cover every state paid to that payment key, preventing
   separate credit tables from crediting the same state. The durable
   `last_credited_amount` is zero only for a channel never credited. Require
   `Amount ≤ Capacity`; otherwise 17. Set
   `delta = Amount − last_credited_amount`, which is positive by step 2.
6. Durably record a pending entry containing `channel_key`, client key, tier,
   `Amount`, `final`, and the current tier's `price_nanoton` and `unit_bytes`.
   Call `AddConditionalResolve(channel_key, state)`. Reread the channel and
   require `LastKnownResolve.Amount` to be at least the submitted `Amount`.
   On new reads after that call, repeat step 3's `Active` status,
   `GetActiveChannel` and `FindConditional` checks, and step 4. If all pass,
   proceed to step 7 using the held `LastKnownResolve.Amount`. Otherwise
   answer 17. Clear the pending record only if `LastKnownResolve` is nil or
   its amount is at most `last_credited_amount`; otherwise retain it for
   recovery and settlement. A successful SDK call alone is insufficient:
   `AddConditionalResolve` may return success without storing a state.
7. In one atomic durable write, use the pending record's client key, tier,
   `final`, price and unit size, and the held `Amount` from step 6 or recovery.
   Set `delta = Amount − last_credited_amount` and:
   - store `last_credited_amount = Amount`, binding client key and tier on the
     first credit, and store `final`;
   - compute `total = delta + remainder_nanoton`, then add
     `floor(total / price_nanoton) × unit_bytes` to `balance_bytes`, repaying
     any overdraft first; use arbitrary precision and saturate at 2⁶³ − 1;
   - store `remainder_nanoton = total mod price_nanoton` and clear pending.
   Return `tonnet.relayBalanceV1{tier, balance_bytes}`. Serialize this write
   with all debits and credits to the same balance, including other channels.
   Amounts and deltas use arbitrary precision: a TPN `Amount` is a TL-B
   `VarUInteger 16` of up to 15 bytes. The remainder fits in signed 64 bits
   because it is below the positive `price_nanoton`.

### Collectibility

Credit is permitted only on one of these facts, read after TPN
stored the state:

- *Held while open:* virtual channel `Active`, base channel accepted by
  `GetActiveChannel`, incoming conditional present in
  `Their.Data.Conditionals`, and safe-deadline margin at least 300 seconds.
  TPN collects `LastKnownResolve` off-chain on `CloseConditional`, or through
  on-chain settlement if the payer closes the base channel. The safe deadline
  precedes the conditional deadline by the on-chain close period plus TPN's
  minimum safe virtual-channel timeout. An older payer state is challenged
  using the latest one; the payer cannot remove the unexpired conditional
  without the relay's signature, and cooperative closure is refused while
  an unexpired conditional remains. Collateral relies on the channel having
  been opened without a final state, as required above.
- *Executed off-chain:* virtual-channel status `Closed`. TPN records this in
  the transaction saving the mutually signed base-channel state that executes
  the conditional, using the `LastKnownResolve` read when closure set
  `WantClose`. Concurrent resolve and close calls could overwrite that
  metadata, so the relay MUST serialize its own calls with the channel lock.
  Received channels opened with a final state are refused before any call;
  TPN's other autonomous received-channel close path operates after the base
  channel leaves `Active`, which the relay's checks detect.

No other TPN status proves collectibility. TPN exposes no per-conditional
on-chain execution outcome, and `CloseConditional` may return success when the
conditional is gone without collecting it. The relay calls both
`AddConditionalResolve` and `CloseConditional` only under the channel's lock.

### Pending payment recovery

Resolve pending records under the channel lock at startup before
the settlement scan, and before processing a later payment for that channel.
Read `GetVirtualChannelMeta`. If `LastKnownResolve.Amount` is at least the
recorded pending amount and a [collectibility](#collectibility) fact holds on current reads, run
step 7 with the recorded client key, tier, final flag, price and unit size, and
the held amount. Do not reapply steps 3–5: later price or offer changes cannot
undo the recorded payment. TPN may hold a higher state, up to capacity;
crediting that held amount covers the difference.

If `LastKnownResolve` is nil or its amount is at most the credited amount, clear
pending without credit. In every other case, including unreadable channel
metadata, retain pending and credit nothing. A channel may still become `Closed`
after the base channel leaves `Active`, so that transition does not justify
discarding pending. While retained, the unexpected held state prevents a new
state from passing step 3. Recovery credits at most once after a crash between
steps 6 and 7, and credits once a permitted fact becomes provable. A retry then
returns the current balance through step 2.

**Accepted loss:** if the base channel leaves `Active` before credit and the
virtual channel never becomes `Closed`, the client is not credited even if TPN
collects on-chain. TPN provides no corresponding execution outcome to
distinguish this case from non-collection. This loss, and the loss from opening
with a final state, are accepted by the client; the relay never credits money
whose collectibility is unproven.

Rejections use `tonnet.relayPaymentRejectedV1` with code 1, 16 (relay full) or
17. Balance answers are unsigned and are used by the client only to decide
when to top up.

### Paid deposits and debits

At the paid-admission step, a deposit of tier T ≠ 0 requires the
authenticated client's tier-T balance to cover the deposit's paid bytes
(otherwise 17) and fewer than four admitted, not-yet-answered paid deposits for
that client key (otherwise 16). Checking the balance and taking a slot is one
atomic step per key, serialized with credits and debits. Slots are counted
across connections and held until storage, a duplicate answer or rejection, even
if the carrying connection is replaced.

The actual paid bytes are debited in the same durable transaction as the
duplicate check, envelope and receipt. Concurrent identical deposits produce one
stored envelope and one debit. Rejected deposits are neither stored nor debited.
Stored deposits are never refunded, including when a receipt is lost: the
identical retry returns the stored receipt without another debit.

Deposits already in flight may take a balance below zero. The four per-key slots
apply even when handlers from a replaced connection are still running. Each
request is at most 64 KiB and the boxed receipt is 176 bytes, so the balance
stays above −4 × (64 KiB + 176 bytes). A balance below the next deposit's bytes
admits no new paid deposit; a later credit repays the debt. Pushes are not
charged. A balance is spent only at the relay that credited it.

### Settlement

Keep credited and pending channels durable across restarts. Call
`CloseConditional(channel_key)` under the channel lock and retry failures. Its
result is handled as follows:

- `ErrNoResolveExists` or virtual channel not existing: drop that channel's
  records because no state remains to settle. Credited states retain their
  `LastKnownResolve` in TPN, so this cleanup cannot credit one twice; a state
  replayed after metadata removal fails the new-channel checks.
- An error wrapping `ErrNotActive`: stop close attempts and retain records;
  TPN handles settlement after the base channel leaves `Active`.
- Other failures remain eligible for retry. A successful call alone is not
  proof of collection.

Settlement is triggered when:

- a credited state has `final = true`;
- remaining capacity is below the current tier's `price_nanoton`, or that
  tier is no longer offered, for a credited channel;
- a periodic sweep finds fewer than 300 seconds before the safe deadline
  for a credited or pending channel;
- a startup scan of stored credited and pending channels finds any of these
  conditions, including stored final flags.

## 7. Reference-client API

The standalone client owns keys, networking, discovery, verification and cache.
Applications integrating the reference client should use that boundary rather
than duplicate its cryptography. Independent wire-protocol implementations are
allowed; this API describes the reference engine, not a mandatory Go dependency.
The terminal UI and command-line interface use the same client engine.

### JSON-RPC transport

`tonnet-messenger run --stdio` exposes newline-delimited JSON-RPC 2.0:

- stdin/stdout contain one UTF-8 JSON message per line; stderr contains logs.
- EOF, interruption and broken stdio terminate the session cleanly.
- Keys/hashes are base64url; sequence numbers and message IDs are decimal strings.
- Timestamps are Unix-second JSON numbers.
- Private keys and raw TL, DHT or QUIC operations are never exposed.

```json
{"jsonrpc":"2.0","id":1,"method":"room.join","params":{"reference":"community.ton"}}
```

### Methods

Optional parameters are marked `?`; no-argument methods accept an empty object.

| Method | Parameters | Result |
| --- | --- | --- |
| `client.info` | — | Version, protocol, transports, identity |
| `identity.get` | — | Identity |
| `identity.setName` | `name` | Identity |
| `identity.prepareDomainLink` | `domain` | `Domain, Category, Key, Owner, TxURL` |
| `identity.confirmDomainLink` | `domain` | Verified identity |
| `identity.clearDomain` | — | Identity |
| `identity.reset` | `expected_key` | New identity |
| `room.resolve` | `reference` | `room` |
| `room.list` | — | `rooms` |
| `room.join` | `reference, bootstrap?` | `room, state, connection, presence, timeline` |
| `room.leave` | `reference` | `left` |
| `room.getState` | `room` | Verified state |
| `room.getPending` | `room` | `pending` (operation or `null`) |
| `room.retryPending` | `room, event_id` | Original committed event |
| `room.discardPending` | `room, event_id` | `discarded` |
| `room.getTimeline` | `room, before_seqno?, limit?` | `items, has_more` |
| `room.sendMessage` | `room, text` | Committed event |
| `room.setMetadata` | `room, name, description` | Committed event |
| `room.setWritePolicy` | `room, policy` (`everyone` or `admins`) | Committed event |
| `room.pin` / `room.unpin` | `room, message_id` | Committed event |
| `room.grantModerator` / `room.revokeModerator` | `room, identity_key` | Committed event |
| `room.ban` / `room.unban` | `room, identity_key` | Committed event |
| `dm.send` | `recipient, text` | DM with `status` and `receipts` |

`reference` accepts a canonical room key or a `.ton` / `.t.me` alias; `room` is
the canonical key. `recipient` accepts an identity key or alias. `bootstrap` is
an optional node ADNL ID, not a replacement for the room key. Admin grants
remain operator-only and are not part of the client API.

`client.info` reports the software release in `version`, plus `protocol:
"0.5.0"`, `transport: "stdio-jsonrpc"` and `room_transport: "ton-quic"`.

The client fetches its inboxes and keeps their push subscriptions while running,
and reports received DMs with `dm.message`, which has no `room`.

### Shared JSON objects

All fields below are required unless marked `?`. Numbers in sequence/ID fields
remain decimal strings; timestamps are Unix-second numbers.

| Object | Fields |
| --- | --- |
| Identity | `key, name, domain?` |
| State | `room, name, description, write_policy, admins[], moderators[], pinned_messages[], revision_seqno, latest_seqno`, plus `banned[]` from `roomStateV3` |
| Connection | `node_role` (`sequencer` or `relay`, derived from the authenticated key; `relay` denotes a room replica here) |
| Presence | `room, online_users` |
| Timeline | `items[]` (events), `has_more` |
| Room list entry | `room, reference, name, connected` |
| Event | `room, event_id, seqno, message_id, committed_at, actor, kind`, plus the fields below |
| DM | `id, peer_key, text, timestamp, direction, author_name, domain?`, plus `status, receipts` for a sent DM |
| Pending operation | `room, event_id, status` (`uncertain` or `committed`), `timestamp, event` (proposal preview, not a committed event) |

Event `actor` contains `key, name, domain` (empty when absent). Message events
add `text`; pin/unpin add `target_message_id`; metadata adds `name,
description`; write-policy adds `write_policy`; role and ban events add
`subject_key`. Role kinds are `admin-grant`, `admin-revoke`, `moderator-grant`,
`moderator-revoke`; ban kinds are `ban` and `unban`. Pending previews contain
`actor, kind` and the corresponding event fields, but no sequence numbers,
commit time, room or event ID (the latter two are on the pending object). They
do not prove that a message was committed.

### Notifications and state

| Notification | Data |
| --- | --- |
| `client.ready` | `identity` |
| `identity.changed` | Identity: `key, name, domain?` |
| `room.connection` | `room, status`; connected state/connection/presence, reconnect attempt or error details |
| `room.state` | Verified state, including locally verified `latest_seqno` |
| `room.presence` | `room, online_users` (unsigned, node-local) |
| `room.event` | `room, event_id, seqno, message_id, committed_at, actor, kind` and event fields |
| `dm.message` | `id, peer_key, text, timestamp, direction, author_name, domain?` |

`direction` is `sent` or `received`. JSON `connection.node_role` is `sequencer`
or `relay`; the TL role values are 1 and 2 respectively.

A `sent` DM was deposited on relays; that is not delivery to the recipient.
`dm.send` returns `status: "stored"` once at least one relay receipt is
verified; this is still not delivery. `receipts` lists the relay keys of
verified receipts. Without one it fails with the first rejection, the one from
the earliest relay in the order of [Sending](#sending) step 2, mapped like any wire code
([Pending operations](#pending-operations)): numeric `-32010 − code` and its
symbolic class. For example code 3 gives -32013 `ROOM_REJECTED`, and codes 9, 16
and 17 give `LIMIT_EXCEEDED`. When no relay was reachable it fails with
`ROOM_UNAVAILABLE` (-32003). An outgoing DM's optional domain is the recipient
alias used for resolution. An incoming DM's domain is its signed
`author_domain`, shown only after the `msg_id` check in
[§5](#5-direct-messages).

Each state directory contains one private `identity.key` and a versioned SQLite
cache. Running sessions reconnect saved rooms and persist verified events before
notifying consumers. Consumers MUST keep reading notifications while operations
are in progress. `room.leave` removes membership and its cached history;
navigating an application's screens need not leave a room.

### Pending operations

Error codes and wire-to-API mappings are defined in
[§8](#reference-client-api-errors).

The client durably journals each canonical proposal before transmission, with
its identity and pinned genesis. There is at most one unacknowledged operation
per room. This canonical-operation journal is not a DM sending queue; DMs use
relay inboxes and the retry/accounting rules in
[§6](#6-payments) and [§5](#5-direct-messages).

A timeout, broken connection or untrustworthy reply leaves the result unknown.
Relayed rejections are not signed by the sequencer. A rejection can be treated
as definitive only on the first attempt directly against the authenticated
sequencer, excluding ambiguous persistence, availability and canonical-state
errors. Once an attempt is uncertain, a later rejection does not prove the
absence of an earlier commit. Unknown rejection codes are protocol errors.

A node that rejects the `overlayQueryV1` wrapper of a submission answers
`overlayRejectedV1` with code 1 (non-zero tier) or 19 (overlay not served)
instead of a `SubmitResult` ([Connection profile](#connection-profile)). The
same definitiveness rule as for `submitRejectedV2` applies: it is definitive,
and the client clears the journal and returns the mapped error, only on the
first attempt directly against the authenticated sequencer. From a room replica,
or on a later attempt, it is uncertain (`SEND_UNCERTAIN`) and the journal is
kept, since a replica could forward the proposal and still answer 1 or 19.

Retries use the exact original proposal, nonce, timestamp and signature.
Submitting the same event body while it is pending retries that proposal;
another body is blocked. Reconnection only reconciles verified history and never
retransmits automatically. A verified matching commit atomically records a
`committed` receipt in the journal, retained until the caller retrieves the
successful result or explicitly discards tracking.

`retryPending` requires a connected room and the current pending event ID. An
expired timestamp is never refreshed: the sequencer may still return the durable
duplicate, otherwise the operation remains uncertain. `discardPending` requires
the matching ID and does not cancel any possible commit. Room leave and identity
reset require resolving or explicitly discarding pending tracking first.
Successful calls acknowledge the journal; this is not an exactly-once delivery
guarantee for consumers that lose a successful JSON-RPC response.

### Timeline pagination

Timeline pages are in ascending display order. To load older events, pass the
first item's `seqno` as `before_seqno`. Join/timeline responses may return fewer
items to satisfy the line limit; they then set `has_more=true`. Pagination MUST
remain gap-free and duplicate-free.

## 8. Limits and errors

### Protocol limits

| Item | Limit |
| --- | ---: |
| Room / author name | 64 UTF-8 bytes |
| Description | 512 UTF-8 bytes |
| Author domain | 126 bytes |
| Public message / DM plaintext | 2048 / 1400 UTF-8 bytes |
| Initial admins / admins / moderators / pins | 32 / 64 / 256 / 100 |
| Banned identities | 256 |
| Query page | 1–256 items; zero selects 100 |
| Batch | 16 queries / 8064 bytes |
| QUIC request or message payload | 64 KiB |
| QUIC answer object, including framing | 4 MiB |
| Incoming QUIC streams per peer | 4 |
| JSON-RPC line, including newline | 64 KiB |
| Complete boxed broadcast wrapper / freshness | 4096 bytes / ±60 seconds |
| Live proposal timestamp and DM deposit `created_at` skew | ±300 seconds |
| Author nonce retention | 24 hours |
| Relays per DM | At most 5 (target 3) |
| DM size, retention, rate, per-recipient quota | Defined by each relay, within the protocol maxima above |
| Paid tier limits and prices | Defined by each relay |
| Paid deposits in flight per client key / overdraft per prepaid balance | 4 / below 4 × (64 KiB + 176 bytes) |
| Paid channel: safe-deadline margin for a new state and for the settlement sweep | 300 seconds |
| Room cards per answer / inbox ack IDs | 1–256, zero selects 100 / at most 256 |
| Relay card address list | 128 serialized bytes |
| Outstanding inbox challenges per connection | 4 |
| Inbox push subscriptions / outbound queue (pushes and broadcasts) per connection | 1 / 32 slots |
| Local relay ban | 60–3600 seconds, ×1.5 per offence, ÷1.5 per valid answer; 4096 entries |

Rate limits are implementation policy, not exemptions from validation.
Relay-defined limits are advertised in relay cards and never exceed the protocol
maxima in this table.

### Wire rejection codes

| Wire rejection code | Meaning |
| --- | --- |
| 1 | Malformed request |
| 2 | Wrong room |
| 3 | Timestamp outside the live window |
| 4 | Reused nonce |
| 5 | Invalid author signature |
| 6 | Permission denied |
| 7 | Unknown message |
| 8 | Role conflict |
| 9 | Limit exceeded |
| 10 | Persistence failure |
| 11 | Unsupported event |
| 12 | Sequencer unavailable |
| 13 | Replica not ready |
| 14 | Invalid canonical state |
| 15 | Invalid or unverifiable identity domain |
| 16 | Relay full or quota exceeded |
| 17 | Insufficient prepaid balance, service not covered by the tier, or payment not verified |
| 18 | Inbox authentication failed |
| 19 | Overlay not served by this node |

Unknown rejection codes are protocol errors.

### Reference-client API errors

JSON-RPC errors use `error.code`, `error.message` and symbolic
`error.data.code`. Wire rejection codes are a separate namespace. Clients
MUST distinguish a confirmed rejection from an uncertain send outcome; a timeout
is not proof that nothing was committed.

Operation errors include `data.room`, `data.event_id` and `data.outcome`
(`unknown`, or `committed` when a confirmed receipt blocks a new operation):
`SEND_UNCERTAIN` (-32032), `PENDING_OPERATION` (-32033) and `PROTOCOL_ERROR`
(-32034). A protocol error without an associated submission has no operation
metadata. Other symbolic errors include `INVALID_ARGUMENT`, `NOT_CONNECTED`,
`ROOM_UNAVAILABLE`, `TIMEOUT`, `SEQUENCER_UNAVAILABLE`, `CLOCK_SKEW`,
`PERMISSION_DENIED`, `INVALID_IDENTITY_DOMAIN`, `UNKNOWN_MESSAGE`,
`ROLE_CONFLICT`, `LIMIT_EXCEEDED` and `ROOM_REJECTED`; unclassified local
failures use `OPERATION_FAILED`.

Wire codes 1–19 map to numeric `-32010 − code` (-32011 through -32029). Their
symbolic classes are:

| Wire code | Symbolic class |
| --- | --- |
| 6, 18 | `PERMISSION_DENIED` |
| 7 | `UNKNOWN_MESSAGE` |
| 8 | `ROLE_CONFLICT` |
| 9, 16, 17 | `LIMIT_EXCEEDED` |
| 12 | `SEQUENCER_UNAVAILABLE` |
| 15 | `INVALID_IDENTITY_DOMAIN` |
| 19 | `ROOM_UNAVAILABLE` |
| Other known wire codes | `ROOM_REJECTED` |

The numeric code identifies the wire rejection; the symbol is a class. For
example `SEQUENCER_UNAVAILABLE` is -32022 for wire code 12 and -32030 for the
local failure. Unknown wire codes, including those above 19, are
`PROTOCOL_ERROR`.

## 9. TL schema

Objects are boxed TON TL. Integers, bytes and vectors use their declared TL
representation. Closed types MUST reject unknown constructors; decoders MUST
reject trailing bytes. Constructor suffixes such as V1, V2 and V3 are part of
their declared names; they are not the negotiated wire protocol version.

### Room objects and queries

```tl
tonnet.roomWritePolicyV1 anyone_can_write:Bool = tonnet.RoomWritePolicy;

tonnet.roomGenesisV2 room_key:int256 node_key:int256 created_at:long
    name:string description:string write_policy:tonnet.RoomWritePolicy
    initial_admins:(vector int256) signature:bytes = tonnet.RoomGenesis;
tonnet.roomGenesisV2.toSign room_key:int256 node_key:int256 created_at:long
    name:string description:string write_policy:tonnet.RoomWritePolicy
    initial_admins:(vector int256) = tonnet.RoomGenesisToSign;

tonnet.roomStateV2 room_id:int256 revision_seqno:long revision_hash:int256
    name:string description:string write_policy:tonnet.RoomWritePolicy
    admins:(vector int256) moderators:(vector int256)
    pinned_messages:(vector long) signature:bytes = tonnet.RoomState;
tonnet.roomStateV2.toSign room_id:int256 revision_seqno:long
    revision_hash:int256 name:string description:string
    write_policy:tonnet.RoomWritePolicy admins:(vector int256)
    moderators:(vector int256) pinned_messages:(vector long)
    = tonnet.RoomStateToSign;
tonnet.roomStatsV2 online_users:int replica_seqno:long replica_hash:int256
    node_role:int ready:Bool = tonnet.RoomStats;
tonnet.roomStateResultV2 state:tonnet.RoomState stats:tonnet.RoomStats
    = tonnet.RoomStateResult;

tonnet.eventMessageV2 text:string = tonnet.EventBody;
tonnet.eventPinV2 message_id:long = tonnet.EventBody;
tonnet.eventUnpinV2 message_id:long = tonnet.EventBody;
tonnet.eventMetadataV2 name:string description:string = tonnet.EventBody;
tonnet.eventAdminGrantV2 subject_key:int256 = tonnet.EventBody;
tonnet.eventAdminRevokeV2 subject_key:int256 = tonnet.EventBody;
tonnet.eventModeratorGrantV2 subject_key:int256 = tonnet.EventBody;
tonnet.eventModeratorRevokeV2 subject_key:int256 = tonnet.EventBody;
tonnet.eventWritePolicyV2 anyone_can_write:Bool = tonnet.EventBody;

tonnet.eventProposalV2 room_id:int256 author_key:int256 author_name:string
    author_domain:string nonce:int256 timestamp:long body:tonnet.EventBody
    signature:bytes = tonnet.EventProposal;
tonnet.eventProposalV2.toSign room_id:int256 node_key:int256
    author_key:int256 author_name:string author_domain:string nonce:int256
    timestamp:long body_hash:int256 = tonnet.EventProposalToSign;

tonnet.committedEventV2 seqno:long message_id:long previous_hash:int256
    proposal:tonnet.EventProposal committed_at:long signature:bytes
    = tonnet.CommittedEvent;
tonnet.committedEventV2.toSign seqno:long message_id:long
    previous_hash:int256 proposal_hash:int256 committed_at:long
    = tonnet.CommittedEventToSign;

tonnet.submitEventV2 proposal:tonnet.EventProposal = tonnet.SubmitResult;
tonnet.submitAcceptedV2 event:tonnet.CommittedEvent = tonnet.SubmitResult;
tonnet.submitDuplicateV2 event:tonnet.CommittedEvent = tonnet.SubmitResult;
tonnet.submitRejectedV2 code:int message:string = tonnet.SubmitResult;

tonnet.getRoomGenesisV2 = tonnet.RoomGenesis;
tonnet.getRoomStateV2 = tonnet.RoomStateResult;
tonnet.getEventsV2 after_seqno:long limit:int = tonnet.EventList;
tonnet.eventListV2 events:(vector tonnet.CommittedEvent) has_more:Bool
    = tonnet.EventList;
tonnet.getMessagesRecentV2 limit:int = tonnet.MessageList;
tonnet.getMessagesBeforeV2 message_id:long limit:int = tonnet.MessageList;
tonnet.messageListV2 messages:(vector tonnet.CommittedEvent) has_more:Bool
    = tonnet.MessageList;

tonnet.batchV2 queries:(vector bytes) = tonnet.BatchResult;
tonnet.batchItemV2 code:int data:bytes = tonnet.BatchItem;
tonnet.batchResultV2 items:(vector tonnet.BatchItem) = tonnet.BatchResult;
```

### Broadcast wrapper and time query

`PublicKey` and `overlay.Certificate` use the standard TON declarations.

```tl
tonnet.broadcast src:PublicKey certificate:overlay.Certificate flags:int
    data:bytes date:int signature:bytes = tonnet.Broadcast;
tonnet.broadcast.id src:int256 data_hash:int256 flags:int = tonnet.broadcast.Id;
tonnet.broadcast.toSign hash:int256 date:int = tonnet.broadcast.ToSign;
tonnet.getTime = tonnet.Time;
tonnet.time now:int = tonnet.Time;
```

### Relay, inbox and state objects

Each signed object's `.toSign` is declared below; its signature is
`Ed25519(signer, H(TL(X.toSign)))`. `adnl.addressList` uses the standard TON
declaration.

```tl
tonnet.relayOfferV1 tier:int services:int max_object_bytes:int
    retention_seconds:int requests_per_minute:int inbox_quota_bytes:long
    price_nanoton:long unit_bytes:long = tonnet.RelayOffer;
tonnet.relayCardV1 relay_key:int256 addrs:adnl.addressList services:int
    payment_key:int256 offers:(vector tonnet.RelayOffer) version:int
    signature:bytes = tonnet.RelayCard;
tonnet.relayCardV1.toSign relay_key:int256 addrs:adnl.addressList
    services:int payment_key:int256 offers:(vector tonnet.RelayOffer)
    version:int = tonnet.RelayCardToSign;
tonnet.roomCardV1 room_key:int256 node_key:int256 alias:string name:string
    description:string version:int signature:bytes = tonnet.RoomCard;
tonnet.roomCardV1.toSign room_key:int256 node_key:int256 alias:string
    name:string description:string version:int = tonnet.RoomCardToSign;
tonnet.relayPaymentV1 tier:int channel_key:int256 state:bytes final:Bool
    = tonnet.RelayPaymentResult;
tonnet.relayBalanceV1 tier:int balance_bytes:long = tonnet.RelayPaymentResult;
tonnet.relayPaymentRejectedV1 code:int message:string
    = tonnet.RelayPaymentResult;

tonnet.getRelayCardV1 = tonnet.RelayCard;
tonnet.getRoomCardsV1 limit:int = tonnet.RoomCardList;
tonnet.roomCardListV1 cards:(vector tonnet.RoomCard) = tonnet.RoomCardList;

tonnet.overlayQueryV1 overlay:int256 tier:int query:bytes = Object;
tonnet.overlayRejectedV1 code:int message:string = Object;

tonnet.getCapabilities = tonnet.Capabilities;
tonnet.capabilities version_major:int version_minor:int flags:int
    = tonnet.Capabilities;

tonnet.eventBanV1 subject_key:int256 = tonnet.EventBody;
tonnet.eventUnbanV1 subject_key:int256 = tonnet.EventBody;
tonnet.roomStateV3 room_id:int256 revision_seqno:long revision_hash:int256
    name:string description:string write_policy:tonnet.RoomWritePolicy
    admins:(vector int256) moderators:(vector int256)
    pinned_messages:(vector long) banned:(vector int256) signature:bytes
    = tonnet.RoomState;
tonnet.roomStateV3.toSign room_id:int256 revision_seqno:long
    revision_hash:int256 name:string description:string
    write_policy:tonnet.RoomWritePolicy admins:(vector int256)
    moderators:(vector int256) pinned_messages:(vector long)
    banned:(vector int256) = tonnet.RoomStateToSign;

tonnet.directMessageV3 from_key:int256 to_key:int256 author_name:string
    author_domain:string created_at:long expire_at:long ciphertext:bytes
    signature:bytes = tonnet.DirectMessage;
tonnet.directMessageV3.toSign from_key:int256 to_key:int256
    author_name:string author_domain:string created_at:long expire_at:long
    ciphertext:bytes = tonnet.DirectMessageToSign;
tonnet.inboxDepositV1 message:tonnet.DirectMessage tier:int
    = tonnet.DepositResult;
tonnet.inboxReceiptV1 relay_key:int256 dm_id:int256 inbox_id:int256
    expire_at:long signature:bytes = tonnet.DepositResult;
tonnet.inboxReceiptV1.toSign relay_key:int256 dm_id:int256 inbox_id:int256
    expire_at:long = tonnet.InboxReceiptToSign;
tonnet.inboxRejectedV1 code:int message:string = tonnet.DepositResult;

tonnet.getInboxChallengeV1 inbox_id:int256 = tonnet.InboxChallenge;
tonnet.inboxChallengeV1 nonce:int256 expire_at:long = tonnet.InboxChallenge;
tonnet.inboxChallengeRejectedV1 code:int message:string
    = tonnet.InboxChallenge;
tonnet.inboxAuthV1 recipient_key:int256 nonce:int256 signature:bytes
    = tonnet.InboxAuth;
tonnet.inboxAuthV1.toSign relay_key:int256 inbox_id:int256 nonce:int256
    expire_at:long = tonnet.InboxAuthToSign;
tonnet.getInboxV1 auth:tonnet.InboxAuth after:long limit:int
    = tonnet.InboxPage;
tonnet.inboxPageV1 messages:(vector tonnet.DirectMessage) has_more:Bool
    last_seqno:long = tonnet.InboxPage;
tonnet.inboxPageRejectedV1 code:int message:string = tonnet.InboxPage;
tonnet.inboxAckV1 auth:tonnet.InboxAuth ids:(vector int256)
    = tonnet.InboxAck;
tonnet.inboxAckedV1 deleted:int = tonnet.InboxAck;
tonnet.inboxAckRejectedV1 code:int message:string = tonnet.InboxAck;
tonnet.inboxPushV1 seqno:long message:tonnet.DirectMessage
    = tonnet.InboxPush;
```

Service-bit meanings are defined in [§3](#service-bits); offer masks,
payment-key constraints, tier selection and payment results in
[§6](#6-payments). `getRoomCardsV1.limit` follows the query-page rule; card
address lists and `inboxAckV1.ids` follow their bounds in
[§8](#8-limits-and-errors). Inbox `after`, `last_seqno` and
`inboxPushV1.seqno` use the relay-local deposit sequence described in
[Fetching and acknowledgement](#fetching-and-acknowledgement). `inboxPushV1`
is a one-way `quic.message` on a subscribed connection ([Real-time
delivery](#dm-push)).

## 10. Security assumptions and exclusions

### Verification guarantees and key custody

Messages are off-chain; TON provides discovery and DNS names, not message
consensus. Verification proves the signatures and consistency of the observed
chain. It does not prove global freshness, prevent censorship or stop a
sequencer from signing different branches for different clients. A self-signed
relay announcement authenticates its node key, not its honesty. Public overlays
provide no Sybil-resistance guarantee.

Any invalid signature, identity, sequence link or canonical-state transition
MUST fail closed. A room private key MUST remain on its authoritative
sequencer and MUST NOT reach clients, room replicas or relays.

### DNS resolver trust

The reference client and server use the configured TON liteservers. The SDK's
default proof policy checks account-state proofs but does not anchor the
complete masterchain proof chain, and the DNS getter result is computed
remotely rather than verified by local TVM execution. A resolved alias
therefore depends on these liteservers and the selected configuration.
Messenger signatures authenticate the resulting key, not the user's intended
name independently of that resolver. Historical domain claims attest what the
sequencer accepted then; they are not fresh proofs of domain ownership.

### Exclusions

**Not provided:** consensus, sequencer election, handover or key rotation,
private rooms, media, editing/deletion, forward secrecy, multi-device identity
or an identity-backup protocol.

Volatile rooms, name-derived overlays, V1 community objects, wallet attribution,
device binding and session challenges are not accepted. There is no automatic
migration from volatile rooms.

- Post-quantum cryptography.
- Hiding the sender of a DM from relays.
- Stolen sequencer key, malicious sequencer, equivocation (different signed
  branches for different readers) and sequencer handover.
- Rooms without a sequencer and multi-hop tunnels.
