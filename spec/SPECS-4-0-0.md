# Tonnet Messenger Protocol 0.4.0

- **Status:** development specification
- **Compatibility:** incompatible with every earlier version and pre-release 0.4 build

## 1. Protocol overview

Version 0.4 defines persistent public rooms over TON overlays and a standalone
leaf client.

| Component | Responsibility |
|---|---|
| `tonnet-messenger-server` | Create, sequence and store one room, or run as a verified relay |
| `tonnet-messenger` | Own one identity, join rooms and expose a local API to any UI |
| Sequencer | Allocate canonical `seqno` and sign room state and commits |
| Relay | Replicate verified history and forward unchanged proposals and commits |
| Client leaf | Read, submit and receive events without serving a room |

All reads are public. Posting is allowed either to everyone or only to the room
owner and administrators.

## 2. Keys and encodings

| Name | Meaning |
|---|---|
| `room_key` | Permanent room identity and commit authority |
| `node_key` | ADNL identity of the sequencer |
| `identity_key` | Permanent client identity, ADNL key, author and DM endpoint |
| `room_id` | Raw `room_key` |
| `seqno` | Monotonic canonical event number |
| `message_id` | Equal to `seqno` for messages, zero for other events |

All keys are Ed25519. Public keys and hashes are 32 bytes; signatures are 64
bytes. Textual room and identity keys are canonical unpadded base64url of
exactly 43 characters.

```text
H(x)           = SHA-256(x)
keyid(pub)     = H(TL(pub.ed25519{key=pub}))
overlay_id     = H(TL(pub.overlay{name=room_key}))
sequencer_adnl = keyid(node_key)
identity_adnl  = keyid(identity_key)
```

The client MAY use ephemeral ADNL keys for DHT discovery but MUST NOT publish
its identity as a room node.

## 3. Canonical events

Genesis and room state are signed by `room_key` over the digest of their boxed
`toSign` object. Admins, moderators and pins MUST be unique and canonically
sorted.

Every mutation is an identity-signed proposal:

```text
body_hash = H(TL(body))
digest    = H(TL(eventProposalV2.toSign{
              room_id, node_key, author_key, author_name, author_domain,
              nonce, timestamp, body_hash
            }))
signature = Ed25519(identity_private_key, digest)
event_id  = H(TL(proposal))
```

`nonce` is random, 32 bytes and unique per author during 24 hours. New
proposals MUST be within 300 seconds of calibrated sequencer time. Historical
verification does not reapply this time window.

For a direct leaf, `author_key` MUST equal the authenticated ADNL peer public
key. A verified relay MAY forward the unchanged signed proposal.

The sequencer verifies the proposal and authorization, assigns the next
`seqno`, links the previous commit hash, signs with `room_key`, persists the
commit atomically, then answers and broadcasts. Repeating the exact proposal
returns the existing commit without allocating another `seqno`.

## 4. Authorization

The non-delegated owner is `room_key`.

| Event | Authorized authors |
|---|---|
| Message | Everyone when `anyone_can_write=true`; otherwise owner and admins |
| Metadata or write policy | Owner and admins |
| Pin or unpin | Owner, admins and moderators |
| Grant or revoke moderator | Owner and admins |
| Grant or revoke admin | Owner only |

Roles target identity public keys. Resetting an identity creates a new
principal and transfers no role.

## 5. Synchronization and relays

Reads require only an authenticated ADNL connection; there is no application
hello, challenge or binding.

- `getEvents` returns commits after `after_seqno`, ascending.
- Recent and before queries return messages in display order.
- Page limits are `1..256`; zero selects 100.
- A batch is read-only, ordered, limited to 16 queries and 8064 bytes.

Clients verify genesis, state, proposal signatures, commit signatures, hash
links and contiguous `seqno`. Submit responses, broadcasts and gap recovery use
the same verification and deduplication path.

A relay persists only verified data. It never possesses `room.key`, allocates a
`seqno`, changes history, signs room state or self-elects. It may serve verified
reads while the sequencer is unavailable.

`online_users` is unsigned node-local data counting connected leaf identities;
it is not canonical room state.

## 6. TON DNS

Aliases use standard `dns_text#1eda` records:

```text
H("msg_room") -> <room_key>
H("msg_id")   -> <identity_key>
```

The record value is only the canonical 43-character key. DNS is an alias, never
the canonical identity.

`author_domain` is optional and normalized lowercase. When present, the
sequencer MUST resolve `msg_id` to the exact `author_key` before committing. A
positive result MAY be cached for at most five minutes. A false or unavailable
claim is rejected and never rewritten. Later DNS changes do not rewrite history
or transfer roles.

## 7. Direct messages

DMs are signed but non-canonical: no `seqno`, server history, acknowledgement or
offline mailbox.

```text
secret = X25519(identity_private_key, recipient_identity_key)
key    = SHA-256("tonnet-dm-v2" || secret)
aad    = room_id || from_key || to_key
box    = nonce(12) || AES-256-GCM(key, plaintext, aad) || tag(16)
```

Ed25519 keys use the existing X25519 mapping. The outer `tonnet.broadcast`
source and signature MUST match `from_key`. Nodes route valid DMs to the online
recipient identity and verified node peers. Both users must share the room
overlay. Routing metadata is visible; forward secrecy and multi-device delivery
are not provided.

## 8. Standalone client interface

`tonnet-messenger run --stdio` exposes JSON-RPC 2.0 as newline-delimited UTF-8.
stdin/stdout carry protocol messages only, stderr carries logs, EOF shuts down,
and each line is limited to 64 KiB.

Keys use base64url; `seqno` and message IDs use decimal strings; timestamps are
Unix-second JSON numbers. Raw TL, ADNL operations and private keys are never
exposed.

| Area | Required methods |
|---|---|
| Client | `client.info` |
| Identity | `identity.get`, `identity.setName`, `identity.prepareDomainLink`, `identity.confirmDomainLink`, `identity.clearDomain`, `identity.reset` |
| Rooms | `room.resolve`, `room.list`, `room.join`, `room.leave`, `room.getState`, `room.getTimeline`, `room.sendMessage` |
| Moderation | `room.setMetadata`, `room.setWritePolicy`, `room.pin`, `room.unpin`, `room.grantModerator`, `room.revokeModerator` |
| Direct messages | `dm.send` |

Required notifications are `client.ready`, `identity.changed`,
`room.connection`, `room.state`, `room.event` and `dm.message`. They contain
typed application data, never localized display text.

Each state directory contains one private `identity.key` and a versioned SQLite
cache. The client reconnects saved rooms, repairs gaps and persists verified
events before notifying the UI. `room.leave` removes the room and cache.
`identity.reset` preserves public rooms and history, clears the domain and
reconnects with a new identity. Backup and multi-device use are outside 0.4.

## 9. Limits and errors

| Item | Limit |
|---|---:|
| Room name / author name | 64 UTF-8 bytes |
| Description | 512 UTF-8 bytes |
| Author domain | 126 bytes |
| Public message | 2048 UTF-8 bytes |
| DM plaintext | 1400 UTF-8 bytes |
| Admins / moderators / pins | 64 / 256 / 100 |
| Query page / batch count / batch bytes | 256 / 16 / 8064 |
| Live timestamp skew / nonce retention | 300 seconds / 24 hours |

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

## 10. Non-goals and compatibility

Version 0.4 has no consensus, sequencer rotation, private rooms, media, uploads,
editing, deletion, offline DM mailbox, identity backup or state migration.

Only V2 room objects and queries are accepted. Legacy volatile rooms, V1
community objects, wallet attribution, device binding, session challenges and
name-derived overlays MUST be rejected.

## Appendix A — Canonical TL schema

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
