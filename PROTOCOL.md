# Tonnet Messenger Protocol

- **Version:** 0.4.0
- **Status:** Draft
- **Compatibility:** Not compatible with earlier versions or pre-release 0.4 rooms

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only
when, they appear in all capitals.

## 1. Scope

Tonnet Messenger provides persistent public rooms over TON DHT and overlays,
using TON QUIC as the room transport.

The protocol defines:

- canonical room history;
- signed user actions;
- room administration and write policy;
- verified replication;
- TON DNS aliases;
- online, end-to-end encrypted direct messages;
- a standalone client interface for applications.

Private rooms, media, message editing, message deletion, offline direct
messages and multi-device identity are outside version 0.4.

## 2. Network roles

| Role      | Responsibility                                                                             |
| --------- | ------------------------------------------------------------------------------------------ |
| Sequencer | Owns the room key, validates proposals, assigns `seqno`, signs and stores canonical events |
| Relay     | Replicates verified history, serves reads and forwards data unchanged                      |
| Client    | Owns one user identity, joins rooms and verifies all canonical data                        |

A room has one authoritative sequencer. Version 0.4 has no consensus,
sequencer election or key rotation.

A relay MUST NOT own the room key, assign `seqno`, alter proposals, rewrite
history or self-elect as sequencer. A client is an outbound leaf and MUST NOT
publish itself as a room node.

## 3. Keys and identifiers

All protocol keys use Ed25519.

| Identifier     | Meaning                                                       |
| -------------- | ------------------------------------------------------------- |
| `room_key`     | Permanent room identity and canonical signing authority       |
| `node_key`     | Sequencer Ed25519 key; its key ID is the sequencer ADNL ID    |
| `identity_key` | User Ed25519 key; its key ID is the client ADNL ID            |
| `room_id`      | The raw `room_key`                                            |
| `seqno`        | Monotonic canonical event number, starting at 1               |
| `message_id`   | Equal to `seqno` for messages; zero for non-message events    |
| `event_id`     | SHA-256 hash of the boxed event proposal                      |

Public keys and hashes are 32 bytes. Signatures are 64 bytes. Textual public
keys use unpadded base64url and are exactly 43 characters.

```text
H(x)           = SHA-256(x)
keyid(pub)     = H(TL(pub.ed25519{key=pub}))
overlay_id     = H(TL(pub.overlay{name=room_key}))
sequencer_adnl = keyid(node_key)
identity_adnl  = keyid(identity_key)
```

Resetting an identity creates a new principal. Names, domains and room roles
do not transfer automatically.

## 4. Discovery and connection

A client joins a room as follows:

1. Resolve a `.ton` alias to a `room_key`, when an alias was supplied.
2. Derive the room overlay from the `room_key`.
3. Find published room nodes and their QUIC addresses through the TON DHT.
4. Connect to a compatible room endpoint over TON QUIC.
5. Fetch genesis, room state and canonical events.
6. Verify all signatures, hashes and sequence links before exposing the room.

A known node ID MAY be supplied as a diagnostic discovery hint. It is not part
of room identity and MUST NOT replace verification against `room_key`.

For canonical writes, a client MUST calibrate time only over an authenticated
QUIC connection whose remote public key equals the pinned `genesis.node_key`.
A relay clock MUST NOT set proposal timestamps. Calibration MAY be cached for
at most five minutes and MUST be invalidated when the session or identity
changes. If the sequencer is unavailable, relay reads remain available but
writes fail with `SEQUENCER_UNAVAILABLE`.

Classic ADNL MAY be used to access the TON DHT during bootstrap and discovery.
It MUST NOT carry Messenger room queries, events or direct messages. There is
no application-level hello, session challenge or device binding.

### 4.1 TON QUIC transport

Every Messenger room node MUST advertise a reachable `adnl.address.quic`
endpoint. A node without one is incompatible and MUST NOT be selected.

TON QUIC connections MUST use:

- QUIC v1;
- ALPN `ton`;
- TLS 1.3 with RFC 7250 raw public keys;
- mutual Ed25519 authentication;
- the TON `quic.query`, `quic.answer` and `quic.message` TL framing.

The hash of the remote QUIC public key MUST equal the expected ADNL ID. A
client MUST reject an endpoint that presents a different key, even if the
address came from a valid DHT response.

Clients MUST use TON QUIC for all room traffic and MUST NOT silently downgrade
to classic ADNL. If no authenticated QUIC endpoint is reachable, the room is
unavailable. A transport failure MUST NOT bypass room, author, signature or
canonical-history validation.

TON QUIC carries the same boxed Tonnet Messenger payloads. It does not change
`room_key`, `node_key`, `overlay_id`, event hashes, signatures or authorization.
It is the native TON QUIC protocol, not HTTP/3.

## 5. Wire format

Network objects use boxed TON TL serialization. Integers, byte strings and
vectors MUST use their declared TL representation. Decoders MUST reject
unknown constructors where a closed type is required and MUST reject trailing
bytes.

The canonical TL declarations are maintained in
[`spec/SPECS-4-0-0.md`](spec/SPECS-4-0-0.md#appendix-a--canonical-tl-schema).
Implementations MUST use those declarations byte-for-byte.

## 6. Canonical events

Every room mutation starts as an identity-signed proposal containing:

- room and author keys;
- optional author name and verified domain;
- a random 32-byte nonce;
- a Unix timestamp;
- one typed event body;
- the author signature.

The author signs a digest that also includes the sequencer `node_key` and the
hash of the boxed event body:

```text
body_hash = H(TL(body))
digest    = H(TL(eventProposalV2.toSign{
              room_id, node_key, author_key, author_name, author_domain,
              nonce, timestamp, body_hash
            }))
signature = Ed25519(identity_private_key, digest)
```

For a direct client, `author_key` MUST match the authenticated TON QUIC peer
key. A verified relay MAY forward the original proposal unchanged.

The sequencer MUST:

1. validate the proposal, signature and authorization;
2. reject a timestamp more than 300 seconds from its current time;
3. reject a nonce already used by that author during the previous 24 hours;
4. allocate the next `seqno`;
5. link the previous committed-event hash;
6. sign the commit with `room_key`;
7. persist the commit atomically before responding or broadcasting it.

Submitting the exact same proposal again MUST return the existing commit and
MUST NOT allocate another `seqno`.

## 7. Event types and authorization

The room owner is the holder of `room_key` and is not a delegated role.

| Event | Authorized identities |
|---|---|
| Message | Everyone when `anyone_can_write=true`; otherwise owner and admins |
| Metadata | Owner and admins |
| Write policy | Owner and admins |
| Pin or unpin | Owner, admins and moderators |
| Grant or revoke moderator | Owner and admins |
| Grant or revoke admin | Owner only |

Role targets are identity public keys. Admins, moderators and pinned message
IDs MUST be unique and canonically sorted in signed room state.

## 8. History and synchronization

Canonical commits form a hash-linked sequence ordered by `seqno`.

- `getEvents(after_seqno)` returns later commits in ascending order.
- Recent and before queries return messages in display order.
- Page size is `1..256`; zero selects the default of 100.
- A batch contains at most 16 read-only queries and 8064 bytes.

Clients and relays MUST verify genesis, room state, proposal signatures, commit
signatures, contiguous `seqno` and previous-hash links. Gaps MUST be repaired
before later events are accepted.

A relay persists and serves only verified canonical data. It MAY serve reads
while the sequencer is unavailable, but writes remain unavailable.

`roomStateResultV2` keeps signed `RoomState` and unsigned `RoomStats` separate
on the wire. Client APIs MUST NOT merge `online_users`, `node_role` or `ready`
into verified room state. Exposed `latest_seqno` MUST come from the client's
locally verified event chain.

## 9. TON DNS

Aliases use standard `dns_text#1eda` records.

```text
H("msg_room") -> <room_key>
H("msg_id")   -> <identity_key>
```

The record value is the canonical 43-character key with no prefix or wrapper.
DNS is an alias only; it never becomes canonical room or user identity.

When `author_domain` is present, the sequencer MUST resolve `msg_id` and verify
that it equals `author_key` before committing the event. Positive results MAY
be cached for five minutes. DNS changes MUST NOT rewrite history or transfer
roles.

## 10. Direct messages

Direct messages are signed and end-to-end encrypted, but are not canonical.
They have no `seqno`, server history, acknowledgement or offline mailbox.

```text
secret = X25519(identity_private_key, recipient_identity_key)
key    = SHA-256("tonnet-dm-v2" || secret)
aad    = room_id || from_key || to_key
box    = nonce(12) || AES-256-GCM(key, plaintext, aad) || tag(16)
```

The Ed25519 identities use the defined X25519 mapping. Both users MUST share
the room overlay and be online. Nodes may observe routing metadata but not DM
plaintext. Version 0.4 does not provide forward secrecy.

## 11. Standalone client boundary

`tonnet-messenger` owns identity keys, networking, discovery, verification and
the local cache. Applications MUST consume the client API rather than
reimplementing protocol cryptography.

`tonnet-messenger run --stdio` exposes newline-delimited JSON-RPC 2.0:

- stdin and stdout carry one UTF-8 JSON message per line;
- stderr carries logs only;
- each line is limited to 64 KiB;
- EOF shuts down the client;
- private keys and raw TL, DHT or QUIC operations are never exposed.

The API covers client information, identity management, room resolution and
membership, history, messages, moderation and direct messages.

`room.join` returns separate `state`, `connection`, `presence` and `timeline`
objects. `room.getState` and `room.state` expose only verified room data.
`connection` contains the authenticated node role. `room.presence` contains
`room` and unsigned node-local `online_users`; consumers MUST treat it as an
informational snapshot.

Required notifications are `client.ready`, `identity.changed`,
`room.connection`, `room.state`, `room.presence`, `room.event` and `dm.message`.

`client.info` MUST report `room_transport: "ton-quic"`.

The client MUST persist verified events before notifying its consumer.

## 12. Protocol limits

| Item | Limit |
|---|---:|
| Room or author name | 64 UTF-8 bytes |
| Room description | 512 UTF-8 bytes |
| Author domain | 126 bytes |
| Public message | 2048 UTF-8 bytes |
| DM plaintext | 1400 UTF-8 bytes |
| Admins / moderators / pins | 64 / 256 / 100 |
| Page / batch count / batch bytes | 256 / 16 / 8064 |
| QUIC request or message payload / answer object | 64 KiB / 4 MiB including framing |
| Concurrent incoming QUIC streams per peer | 4 |
| Live timestamp skew | 300 seconds |
| Nonce retention | 24 hours |

Rate limits are implementation policy and MUST NOT weaken signature,
authorization or canonical-state validation.

## 13. Rejection codes

| Code | Meaning |
|---:|---|
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

Unknown rejection codes MUST be treated as protocol errors.

## 14. Security requirements

Implementations MUST fail closed when any signature, room identity, sequence
link, authorization rule or canonical-state check fails.

Private keys MUST remain in their owning process and state directory. A room
private key MUST exist only on its authoritative sequencer. Relays and clients
MUST never receive it.

Clients MUST treat DHT records, relays, DNS aliases, presence counts and display
names as untrusted until validated by the corresponding protocol rule.

## 15. Versioning

Version 0.4 accepts only V2 room objects and queries. Legacy volatile rooms, V1
community objects, wallet attribution, device binding, session challenges and
name-derived overlays MUST be rejected.

Any incompatible change to serialization, signatures, identifiers, event
semantics or authorization requires a new protocol version.

An optional transport profile MAY be added without a new protocol version when
canonical TL objects, identities and verification rules remain unchanged.
Changing the required room transport after publication requires a new protocol
version.
