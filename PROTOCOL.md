# Tonnet Messenger Protocol

**Version:** 0.4.0
**Status:** Stable

This is the single specification for the room protocol and standalone client API.
For installation and commands, see [README.md](README.md).

[Scope](#1-scope-and-roles) · [Identity](#2-keys-and-identifiers) ·
[Transport](#3-discovery-and-transport) · [Events](#4-canonical-history) ·
[DNS](#5-ton-dns) · [DMs](#6-direct-messages) ·
[Client API](#7-client-api) · [Limits](#8-limits-and-errors) · [TL schema](#9-tl-schema)

## 1. Scope and roles

Version 0.4 provides persistent public rooms, verified history, moderation,
TON DNS aliases and online encrypted direct messages.

| Role | Responsibility | Authority |
| --- | --- | --- |
| Sequencer | Validate, order, sign and persist room mutations | Holds the room and sequencer keys |
| Relay | Replicate verified history, serve reads and forward unchanged traffic | Holds only its own node key |
| Client | Own a user identity, verify history, send and receive messages | Holds only its user key |

A room has exactly one sequencer. Relays MUST NOT sequence events, rewrite
history, sign room state or self-elect. Clients are outbound leaves and MUST
NOT publish themselves as room nodes.

**Not provided:** consensus, sequencer election or key rotation, private rooms,
media, editing/deletion, offline DM delivery, forward secrecy, multi-device
identity or an identity-backup protocol.

Legacy volatile rooms, name-derived overlays, V1 community objects, wallet
attribution, device binding and session challenges are not accepted.
There is no automatic migration from legacy rooms.

Messages are off-chain; TON provides discovery and DNS names, not message
consensus. Verification proves the signatures and consistency of the observed
chain. It does not prove global freshness, prevent censorship or stop a
sequencer from signing different branches for different clients. A self-signed
relay announcement authenticates its node key, not its honesty or approval by
the room owner. Public overlays provide no Sybil-resistance guarantee.

Incompatible changes to serialization, signatures, identifiers, authorization
or event semantics require a new protocol version. Changing the required room
transport after publication also requires a new version; optional transport
profiles may preserve the version only when canonical objects and verification
rules remain unchanged.

## 2. Keys and identifiers

All keys are Ed25519. Public keys and hashes are 32 bytes; signatures are
64 bytes. Textual keys and hashes use canonical unpadded base64url (43 characters).

| Identifier | Meaning |
| --- | --- |
| `room_key` / `room_id` | Permanent room identity and signing authority |
| `node_key` | Sequencer public key, pinned in genesis |
| `identity_key` | User identity, proposal author and DM endpoint |
| `seqno` | Canonical event number, starting at 1 |
| `message_id` | `seqno` for a message; zero for other events |
| `event_id` | Hash of the boxed event proposal |

Notation: `TL(x)` is boxed TON TL serialization; `H(x) = SHA-256(x)`;
`||` concatenates bytes. The canonical declarations are in [§9](#9-tl-schema).

```text
keyid(pub)     = H(TL(pub.ed25519{key=pub}))
overlay_id     = H(TL(pub.overlay{name=room_key}))
sequencer_adnl = keyid(node_key)
identity_adnl  = keyid(identity_key)
```

Genesis fixes the room key, sequencer key, creation time, initial metadata,
write policy and initial admins. It is signed by the room key. Clients MUST pin
genesis and reject a conflicting genesis for the same room.

`genesis_hash = H(TL(roomGenesisV2))` and
`commit_hash = H(TL(committedEventV2))`, including their signatures.
Creation and commit times must be positive Unix seconds. A genesis more than
300 seconds in the future is rejected; historical proposal timestamps are not
compared with the current clock.

Resetting a user identity creates a new principal: roles do not transfer and
the domain association is cleared. The reference client preserves the local
display name and public-room cache, then reconnects using the new key.

## 3. Discovery and transport

Joining a room follows this sequence:

1. Resolve the room alias, if supplied, through [TON DNS](#5-ton-dns).
2. Derive its overlay ID and discover room nodes through TON DHT.
3. Select a reachable `adnl.address.quic` endpoint.
4. Authenticate the endpoint and fetch genesis, state and canonical history.
5. Verify the history and its derived state before exposing the room.

A known node ADNL ID may be used as a discovery hint. It MUST NOT replace
verification against the room key. Ephemeral ADNL keys may be used for DHT
access; classic ADNL MUST NOT carry Messenger room traffic.

Nodes publish `overlay.nodes` under
`dht.key{id=overlay_id, name="nodes", idx=0}`, with `pub.overlay{name=room_key}`
and `dht.updateRule.overlayNodes`. Each `overlay.node` binds the node public key,
overlay ID and Unix-second version; its signature covers boxed
`overlay.node.toSign{id=keyid(node_public_key), overlay=overlay_id, version}`.
Verify these signatures and overlay IDs before resolving node addresses through
the signed ADNL `address` record. The reference implementation accepts node
versions at most ten minutes old or sixty seconds in the future.

### Connection profile

| Property | Required value |
| --- | --- |
| Transport | QUIC v1, ALPN `ton` |
| Authentication | TLS 1.3 raw public keys (RFC 7250), mutual Ed25519 |
| Framing | Native TON `quic.query`, `quic.answer`, `quic.message` |
| Endpoint identity | Hash of the peer public key equals the expected ADNL ID |

TON SNI is `<first 32 hex characters>.<last 32 hex characters>.adnl`, using
the expected node ADNL ID. Each stream carries one boxed request; a query's
boxed answer uses the same stream. FIN terminates the object. A message has
no application response. There is no additional length prefix, query ID or
`overlay.query`/`overlay.message` envelope around the Messenger payload.
The endpoint serves one room, so read queries have no room selector. A generic
TON node does not implement the application-specific `tonnet.*` objects.

This is TON QUIC, not HTTP/3. There is no application-level hello or device
binding. Clients MUST reject wrong-key endpoints and MUST NOT downgrade to
classic ADNL when QUIC fails.

### Broadcasts and time

Canonical events and DMs are carried in signed `tonnet.broadcast` wrappers
with `flags=0` and `overlay.emptyCertificate`. Canonical broadcasts are signed
by the room key; DM broadcasts by the sender identity.

```text
broadcast_id = H(TL(tonnet.broadcast.id{
                 src=keyid(source_key), data_hash=H(data), flags
               }))
signature    = Ed25519(source_private_key,
                      TL(tonnet.broadcast.toSign{hash=broadcast_id, date}))
```

The wrapper signature and live freshness MUST be verified independently of the
inner payload. Nodes deduplicate broadcasts and forward them unchanged.

Canonical-write time MUST come from an authenticated connection whose peer key
equals the pinned genesis `node_key`, using `tonnet.getTime`. Relay time MUST
NOT set proposal timestamps. Calibration may be cached for five minutes and
MUST be invalidated on session or identity changes. If the sequencer cannot be
reached, reads may remain available but writes fail with `SEQUENCER_UNAVAILABLE`.

Calibration fails with `CLOCK_SKEW` if sequencer time differs from the local
clock by more than 300 seconds. Broadcast freshness and DM timestamps use the
receiver's local clock, not this proposal-time calibration.

## 4. Canonical history

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

For a direct leaf, the author key MUST equal the authenticated peer key.
A verified relay may forward the original signed proposal.

First, the sequencer MUST return the existing commit for an exact proposal
already in durable history. Current timestamp, DNS and permission checks do
not apply to this duplicate. For a new proposal, the sequencer MUST, in order:

1. Verify the room, signature, timestamp, domain claim and authorization.
2. Reject a reused author nonce within the retention window.
3. Allocate the next `seqno` and link the previous commit hash.
4. Sign the commit and persist its event, projection, nonce and head atomically.
5. Return and broadcast the durable commit.

Repeating the exact proposal MUST return the existing commit without consuming
another sequence number. Live timestamp checks MUST NOT be reapplied to history.

Clients and forwarding relays MUST compare the returned commit's proposal ID
with the submitted proposal ID before treating either `submitAcceptedV2` or
`submitDuplicateV2` as success. A valid commit for another proposal is a protocol
error, not a successful submission.

Genesis, room state and commits are signed with `room_key` over
`H(TL(the corresponding .toSign object))`. Commits bind the proposal hash;
room state binds a revision sequence and hash. The first commit's previous
hash is 32 zero bytes; the initial state references the genesis hash.

### Authorization

The holder of `room_key` is the non-delegated owner.

| Event | Authorized authors |
| --- | --- |
| Message | Everyone when `anyone_can_write=true`; otherwise owner and admins |
| Metadata / write policy | Owner and admins |
| Pin / unpin | Owner, admins and moderators |
| Grant / revoke moderator | Owner and admins |
| Grant / revoke admin | Owner only |

Roles target identity public keys. Admins, moderators and pins MUST be unique
and canonically sorted in signed state.

Keys are sorted lexicographically by their raw bytes; pins are sorted
numerically. Initial admins follow the same key ordering. The owner cannot
receive or lose a delegated role. Granting an existing role, revoking an absent
role or pinning an already-pinned message is rejected. Admin and moderator are
independent roles: an identity may hold both. Pins reference existing messages;
unpinning requires the message to be pinned. Room names are nonempty and contain
no control characters; descriptions cannot contain NUL. All text is valid UTF-8.

### Verification and replication

Clients and relays MUST verify genesis, proposal and commit signatures,
contiguous sequence numbers, previous hashes and authorized state transitions.
A valid signature alone is insufficient. Gaps MUST be repaired before later
events are accepted; submit responses and broadcasts use the same deduplication
and verification rules.

| Read | Result order |
| --- | --- |
| `getEvents(after_seqno)` | Later canonical events, ascending |
| `getMessagesRecent` | Latest messages, in display order |
| `getMessagesBefore(message_id)` | Earlier messages, in display order |
| `batch` | Read-only subqueries and their answers, in request order |

Limits are defined once in [§8](#8-limits-and-errors). A batch item exceeding the
remaining answer budget receives code 9 without invalidating earlier items.
All subsequent batch items also receive code 9. Successful items use code 0
and contain the boxed read result; failed items contain no result data.

Relays MUST persist only verified canonical data and periodically reconcile
with the sequencer. `ready=true` requires their signed state to cover the
latest state-changing commit. A relay may serve verified reads while the
sequencer is unavailable; it MUST NOT invent a write result.

`RoomState` is signed; `RoomStats` is not. Presence, node role and readiness
MUST remain separate from verified state. The client's exposed `latest_seqno`
comes from its locally verified event chain.

## 5. TON DNS

Aliases use standard `dns_text#1eda` records:

| Category | Key | Complete record value |
| --- | --- | --- |
| `msg_room` | `H("msg_room")` | Canonical room key |
| `msg_id` | `H("msg_id")` | Canonical user identity key |

Values have no prefix or wrapper. DNS is an alias, never the canonical identity.

This refers to the text value, not its on-chain encoding: the record remains
`dns_text#1eda` followed by TL-B `Text` (chunk count and length-prefixed chunks),
not a snake string. Local inputs are trimmed and lowercased. Accepted names end
in `.ton` or `.t.me`, have nonempty labels containing only `a-z`, `0-9` and `-`,
and have no leading or trailing hyphen in a label. `.t.me` labels also accept
`_`. Signed claims must already use this normalized form. Both namespaces use
the configured TON DNS root and standard resolver delegation.
`.t.me` aliases refer to on-chain collectible usernames with DNS records, not
arbitrary Telegram accounts.

Clients, sequencers and replicas must support `.t.me` claims before using them
in a room; the original v0.4.0 implementation only accepts `.ton` claims.

When a proposal includes `author_domain`, it MUST be lowercase and the
sequencer MUST resolve `msg_id` to exactly `author_key` before committing.
Positive results may be cached for five minutes. Invalid or unavailable claims
are rejected; later DNS changes do not rewrite history or transfer roles.

Domain-link helpers prepare a transaction to the domain NFT contract.
Only its owner's wallet authorizes that transaction. The client confirms the
association by resolving the published record, not by trusting a QR scan.
For collectible `.t.me` usernames, helpers check `get_telemint_auction_config`
and refuse to prepare a transaction while a sale or auction remains unsettled.
This check is a snapshot; listing state can change before wallet approval.

**Resolver trust:** the reference client and server use the configured TON
liteservers. The SDK's default proof policy checks account-state proofs but
does not anchor the complete masterchain proof chain, and the DNS getter result
is computed remotely rather than verified by local TVM execution. A resolved
alias therefore depends on these liteservers and the selected configuration.
Messenger signatures authenticate the resulting key, not the user's intended
name independently of that resolver. Historical domain claims attest what the
sequencer accepted then; they are not fresh proofs of domain ownership.

## 6. Direct messages

DMs are signed and end-to-end encrypted, but non-canonical: no `seqno`,
server history, delivery/read acknowledgement or offline mailbox.
Both identities MUST be online in the same room overlay.

```text
secret = X25519(convert(identity_private_key), convert(recipient_public_key))
key    = SHA-256("tonnet-dm-v2" || secret)
aad    = room_id || from_key || to_key
box    = nonce(12) || AES-256-GCM(key, plaintext, aad) || tag(16)
```

Here the GCM term denotes ciphertext without the separately shown tag.
The nonce is cryptographically random. Plaintext is valid UTF-8, at most 1400
bytes; the complete box is 28–1428 bytes. Validate plaintext before encryption
and after decryption. `dm_id = H(TL(directMessageV2))`, including its signature.

Ed25519 identities use the TON Ed25519-to-X25519 mapping. The sender signs
`H(TL(directMessageV2.toSign{room_id, from_key, to_key, author_name,
timestamp, ciphertext}))`. The outer broadcast source and signature MUST match
`from_key`; both the wrapper and DM timestamps are checked on live delivery.

Nodes route valid DMs to the online recipient and verified node peers.
Routing metadata remains visible; plaintext does not. Forward secrecy is not
provided.

## 7. Client API

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
| `dm.send` | `room, recipient, text` | Direct message |

`reference` accepts a canonical room key or a `.ton` / `.t.me` alias; `room` is the
canonical key. `recipient` accepts an identity key or alias. `bootstrap` is an
optional node ADNL ID, not a replacement for the room key. Admin grants remain
operator-only and are not part of the client API.

`client.info` reports `protocol: "0.4.0"`, `transport: "stdio-jsonrpc"`
and `room_transport: "ton-quic"`.

### Shared JSON objects

All fields below are required unless marked `?`. Numbers in sequence/ID fields
remain decimal strings; timestamps are Unix-second numbers.

| Object | Fields |
| --- | --- |
| Identity | `key, name, domain?` |
| State | `room, name, description, write_policy, admins[], moderators[], pinned_messages[], revision_seqno, latest_seqno` |
| Connection | `node_role` (`sequencer` or `relay`, derived from the authenticated key) |
| Presence | `room, online_users` |
| Timeline | `items[]` (events), `has_more` |
| Room list entry | `room, reference, name, connected` |
| Event | `room, event_id, seqno, message_id, committed_at, actor, kind`, plus the fields below |
| DM | `room, id, peer_key, text, timestamp, direction, author_name, domain?` |
| Pending operation | `room, event_id, status` (`uncertain` or `committed`), `timestamp, event` (proposal preview, not a committed event) |

Event `actor` contains `key, name, domain` (empty when absent). Message events
add `text`; pin/unpin add `target_message_id`; metadata adds `name, description`;
write-policy adds `write_policy`; role events add `subject_key`. Role kinds are
`admin-grant`, `admin-revoke`, `moderator-grant`, `moderator-revoke`.
Pending previews contain `actor, kind` and the corresponding event fields, but
no sequence numbers, commit time, room or event ID (the latter two are on the
pending object). They do not prove that a message was committed.

### Notifications and state

| Notification | Data |
| --- | --- |
| `client.ready` | `identity` |
| `identity.changed` | Identity: `key, name, domain?` |
| `room.connection` | `room, status`; connected state/connection/presence, reconnect attempt or error details |
| `room.state` | Verified state, including locally verified `latest_seqno` |
| `room.presence` | `room, online_users` (unsigned, node-local) |
| `room.event` | `room, event_id, seqno, message_id, committed_at, actor, kind` and event fields |
| `dm.message` | `room, id, peer_key, text, timestamp, direction, author_name, domain?` |

`direction` is `sent` or `received`. JSON `connection.node_role` is
`sequencer` or `relay`; the TL role values are 1 and 2 respectively.

DM `sent` means submitted to the connected node, not delivered to the recipient.
An outgoing DM's optional domain is the recipient alias used for resolution.
An incoming DM's optional domain is learned from historical public messages,
not freshly resolved or contained in the signed DM.

Each state directory contains one private `identity.key` and a versioned
SQLite cache. Running sessions reconnect saved rooms and persist verified
events before notifying consumers. Consumers MUST keep reading notifications
while operations are in progress. `room.leave` removes membership and its
cached history; navigating an application's screens need not leave a room.

### Pending operations

The client durably journals each canonical proposal before transmission, with
its identity and pinned genesis. There is at most one unacknowledged operation
per room; DMs are not journaled. The journal is not an offline sending queue.

A timeout, broken connection or untrustworthy reply leaves the result unknown.
Relayed rejections are not signed by the sequencer. A rejection can be treated
as definitive only on the first attempt directly against the authenticated
sequencer, excluding ambiguous persistence, availability and canonical-state
errors. Once an attempt is uncertain, a later rejection does not prove the
absence of an earlier commit. Unknown rejection codes are protocol errors.

Retries use the exact original proposal, nonce, timestamp and signature.
Submitting the same event body while it is pending retries that proposal;
another body is blocked. Reconnection only reconciles verified history and
never retransmits automatically. A verified matching commit atomically records
a `committed` receipt in the journal, retained until the caller retrieves the
successful result or explicitly discards tracking.

`retryPending` requires a connected room and the current pending event ID.
An expired timestamp is never refreshed: the sequencer may still return the
durable duplicate, otherwise the operation remains uncertain. `discardPending`
requires the matching ID and does not cancel any possible commit. Room leave
and identity reset require resolving or explicitly discarding pending tracking
first. Successful calls acknowledge the journal; this is not an exactly-once
delivery guarantee for consumers that lose a successful JSON-RPC response.

Timeline pages are in ascending display order. To load older events, pass the
first item's `seqno` as `before_seqno`. Join/timeline responses may return
fewer items to satisfy the line limit; they then set `has_more=true`.
Pagination MUST remain gap-free and duplicate-free.

JSON-RPC errors use `error.code`, `error.message` and symbolic
`error.data.code`. Wire rejection codes below are a separate namespace.
Clients MUST distinguish a confirmed rejection from an uncertain send outcome;
a timeout is not proof that nothing was committed.

Operation errors include `data.room`, `data.event_id` and `data.outcome`
(`unknown`, or `committed` when a confirmed receipt blocks a new operation):
`SEND_UNCERTAIN` (-32032), `PENDING_OPERATION`
(-32033) and `PROTOCOL_ERROR` (-32034). A protocol error without an associated
submission has no operation metadata. Other symbolic errors include
`INVALID_ARGUMENT`, `NOT_CONNECTED`, `ROOM_UNAVAILABLE`, `TIMEOUT`,
`SEQUENCER_UNAVAILABLE`, `CLOCK_SKEW`, `PERMISSION_DENIED`,
`INVALID_IDENTITY_DOMAIN`, `UNKNOWN_MESSAGE`, `ROLE_CONFLICT`, `LIMIT_EXCEEDED`
and `ROOM_REJECTED`; unclassified local failures use `OPERATION_FAILED`.

## 8. Limits and errors

| Item | Limit |
| --- | ---: |
| Room / author name | 64 UTF-8 bytes |
| Description | 512 UTF-8 bytes |
| Author domain | 126 bytes |
| Public message / DM plaintext | 2048 / 1400 UTF-8 bytes |
| Initial admins / admins / moderators / pins | 32 / 64 / 256 / 100 |
| Query page | 1–256 items; zero selects 100 |
| Batch | 16 queries / 8064 bytes |
| QUIC request or message payload | 64 KiB |
| QUIC answer object, including framing | 4 MiB |
| Incoming QUIC streams per peer | 4 |
| JSON-RPC line, including newline | 64 KiB |
| Complete boxed broadcast wrapper / freshness | 4096 bytes / ±60 seconds |
| Live proposal and DM timestamp skew | ±300 seconds |
| Author nonce retention | 24 hours |

Rate limits are implementation policy, not exemptions from validation.

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

Unknown rejection codes are protocol errors. Any invalid signature, identity,
sequence link or canonical-state transition MUST fail closed. A room private
key MUST remain on its authoritative sequencer and MUST NOT reach clients or relays.

## 9. TL schema

Objects are boxed TON TL. Integers, bytes and vectors use their declared TL
representation. Closed types MUST reject unknown constructors; decoders MUST
reject trailing bytes. Constructors below match the implementation; the
`roomWritePolicyV1` name is intentionally retained within the V2 room protocol.

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

tonnet.directMessageV2 room_id:int256 from_key:int256 to_key:int256
    author_name:string timestamp:long ciphertext:bytes signature:bytes
    = tonnet.DirectMessage;
tonnet.directMessageV2.toSign room_id:int256 from_key:int256 to_key:int256
    author_name:string timestamp:long ciphertext:bytes
    = tonnet.DirectMessageToSign;
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
