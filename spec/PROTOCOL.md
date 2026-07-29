# Tonnet chat protocol

**Spec version:** 0.3.1
**Status:** implemented in the v0.3.1 working tree, not yet released. This
document is normative; the Go and TypeScript implementations MUST conform to
it. Cross-language fixtures in
`internal/broadcast/testdata/vectors.json`,
`internal/tonproof/testdata/vectors.json`, and `internal/dm/testdata/vectors.json`
cover the wire broadcast envelope, TON proof attribution, and DM crypto.

**Product scope:** the stable product is open rooms plus direct messages, on a
blockchain-agnostic core: authorship is a device ed25519 key, and a TON wallet is
optional attribution. Gated rooms (owner-certificate posting) are experimental,
disabled by default in nodes and clients, and are not a stable product feature;
see sections 9 and 19.

**Reference model:** TON `v2026.06`, commit
`bbc3bc6e54d46d049173b7940183eb517b07b44c`: the overlay implementation under
`ton/overlay/`, ADNL/DHT under `ton/`, and
`tl/generate/scheme/ton_api.tl`. Appendix A maps each adopted mechanism to the
reference source. Tonnet reuses TON primitives without claiming wire
compatibility with native TON overlay broadcasts.

Notation: `‖` is concatenation. `u32be(n)` and `u64be(n)` are big-endian
integers, `u64le` little-endian. `sha256(x)` is the 32-byte SHA-256 digest.
`TL(x)` is the boxed TL serialization of `x` (4-byte constructor id prefix).
`keyid(k) = sha256(TL(pub.ed25519{key=k}))` is the standard TON key id of an
ed25519 public key. RFC 2119 keywords (MUST, SHOULD, MAY) apply. Hex fields are
lowercase.

---

## 1. Roles and objects

- **Room**: a chat named `tonnet:<group>` (for example `tonnet:groupchat`). The
  name is the only convention; everything else derives from it.
- **Overlay**: the TON overlay the room lives on. `overlay_id` derives from the
  room name (section 3).
- **Node**: an overlay peer that meshes, relays, and holds room state, run with
  `tonnet serve`. Hosting and relaying are the same role: the first node of a
  room hosts it, further nodes relay it.
- **Leaf (client)**: an end-user client such as Tonnet Browser. Behind NAT it
  cannot be dialed, so it connects out to a reachable node and rides that node's
  flood. It never relays.
- **Device key**: a per-install ed25519 keypair. It signs every message and is
  the sole authenticator of authorship.
- **Wallet**: the user's TON wallet (v5r1). It never signs messages directly; it
  may sign one delegation (section 8) that endorses the device key. Optional.

Identity is intentionally permissionless. A user MAY keep a device key, rotate
it, or create a new one at any time. Rotation creates a new protocol identity;
there is no global account, continuity proof, recovery authority, or uniqueness
claim. A wallet proof attributes one current device key but is not an admission
token or Sybil-resistance mechanism.

---

## 2. Design rationale

The protocol floods signed messages over a TON overlay and lets each node dedup
by signed broadcast id, rather than using the library's FEC broadcasts (which
hand the receiver a decoded payload without the signed wire parts, so
re-gossiping would re-originate under the relayer's key and defeat dedup). The
signed-broadcast model closes the gaps of an earlier unsigned-flood draft:

| Concern | Mechanism | Section |
|---|---|---|
| Bounded replay | signed `date`, +/-60 s freshness, dedup set larger than the window | 5 |
| Authorship without a blockchain | device ed25519 signature over content | 7 |
| Optional wallet attribution | ton_proof inside the device-signed envelope, never required | 8 |
| DM confidentiality and delivery | x25519 + AES-256-GCM, routed to the recipient's node | 11 |
| Explicit wire version | TL constructor per format | 17 |
| Cross-room injection | node enforces `envelope.room == room` | 12 |

Forward secrecy, sealed sender, authenticated history, and multi-admin rooms are
deferred (section 19).

---

## 3. Overlay id and discovery

**Overlay id**, from the room name string:

```
overlay_id = tl.Hash( pub.overlay{ name = utf8(room) } )     // sha256 of the boxed TL object
```

(`internal/overlay/id.go`.)

**Publishing.** A node republishes two DHT records every 5 min, each with a 30
min TTL (`internal/dht/publish.go`): its ADNL address list (`StoreAddress`), and
a signed `overlay.nodes` list containing its own `overlay.node`
(`StoreOverlayNodes`), stored under `pub.overlay{name=room}` with attribute
`"nodes"`, that is, under `overlay_id`. Each `overlay.node` carries the node's
ADNL pubkey, the `overlay_id`, a unix-seconds `Version`, and a signature; peers
reject nodes whose signature or overlay id does not check out.

**Finding nodes.** A client passes `utf8(room)` to the verified
`FindOverlayNodes` operation. It MUST keep only signed ed25519 `overlay.node`
records whose `Overlay` equals `overlay_id`, whose `Version` is at most 60 s in
the future and at most 600 s old. The returned ADNL id is
`keyid(node.ID)`. The client resolves each ADNL id with `FindAddresses`, tries
multiple public addresses, and accepts a connection only after ADNL liveness
succeeds. An explicit bootstrap node is tried first; DHT discovery supplies
fallbacks if it fails. Clients deduplicate, randomize DHT candidates, and try
at most 8.

Gated and open rooms are discovered identically; the DHT layer is mode-agnostic.
Relaying is open in both modes: authorization gates posting, not meshing.

---

## 4. Transport: the signed broadcast

The flood unit is a signed broadcast wrapper modeled on `overlay.broadcast`
(ton_api.tl:243). Tonnet constructors are used instead of the `overlay.*` ones so
the library's internal overlay handling cannot intercept them; the shape, the
signing scheme, and the `overlay.Certificate` field type are the native ones.

```
tonnet.broadcast src:PublicKey certificate:overlay.Certificate flags:int
                 data:bytes date:int signature:bytes = tonnet.Broadcast;

tonnet.broadcast.id src:int256 data_hash:int256 flags:int = tonnet.broadcast.Id;
tonnet.broadcast.toSign hash:int256 date:int = tonnet.broadcast.ToSign;
```

Fields:

- `src`: the sender's device public key, boxed as `pub.ed25519`. It MUST equal
  the `key` field of the enclosed envelope (section 12, step 6).
- `certificate`: `overlay.certificate` in gated rooms, `overlay.emptyCertificate`
  otherwise (any certificate in an open room is ignored).
- `flags`: MUST be `0`. Receivers MUST drop broadcasts with unknown flag bits.
  Reserved as the capability space.
- `data`: the boxed TL envelope `tonnet.envelopeV4` (section 6).
- `date`: unix seconds at origination, set by the sender.
- `signature`: by the device key over the id and date:

```
broadcast_id = sha256( TL( tonnet.broadcast.id{
                   src       = keyid(devicePub),
                   data_hash = sha256(data),
                   flags     = flags } ) )

signature    = ed25519_sign( deviceKey,
                   TL( tonnet.broadcast.toSign{ hash = broadcast_id, date = date } ) )
```

Because `date` is signed with the broadcast id, a third party cannot re-wrap an
old envelope with a fresh date; only the original author can re-flood their own
envelope, which is a resend. The wrapper is carried as an ADNL overlay custom
message. The transport library MAY first parse a TL object under its bounded
8320-byte ADNL custom-message ceiling. The application MUST immediately
reserialize `tonnet.broadcast`, reject anything over 4096 bytes, and perform no
signature or envelope cryptography before that application size check.

---

## 5. Freshness and dedup

**Freshness.** A node MUST reject a live broadcast whose `date` is more than 60 s in
the past or future of its local clock. (The reference uses +/-20 s,
overlay.cpp:564; +/-60 s accommodates browser leaves behind a WS bridge and
unsynchronized clocks.) With dedup this bounds replay to about 120 s. Leaves
SHOULD calibrate their clock against their node via `tonnet.getTime` (section 16)
and apply the offset to `date`. Leaves MUST reject every received wrapper,
including history, when its signed `date` lies before calibrated receive time
minus 6 h 5 min or after calibrated receive time plus 5 min. Thus an honest
node's live replay window remains about 120 s, while even a malicious node
cannot make arbitrarily old captured history appear current.

**Dedup.** A node keeps a delivered set of the last 8192 `broadcast_id`s and MUST
drop any broadcast already present. Verification is guarded by an atomic
reservation: a node reserves a fresh id before expensive cryptography, releases it
if validation fails, and commits it only after acceptance (section 12, step 11).
This prevents concurrent duplicate acceptance while preserving the rule that a
rejected copy cannot permanently poison the id of a valid broadcast. Design
invariant: the dedup memory MUST cover more traffic than can arrive within the
freshness window. At the global message ceiling, one burst plus 120 s of refill
is `64 + 32*120 = 3904`, below 8192.

`broadcast_id` covers `(src, data_hash, flags)` but not `date`, so a resend with
a bumped date dedups naturally while the id is remembered. Nodes SHOULD also
retain the last 128 full wrappers to answer pull-repair queries (section 16).

---

## 6. The envelope

The envelope is a boxed TL object carried in `tonnet.broadcast.data`:

```
tonnet.envelopeV4 type:string nick:string text:string ts:long
                 room:string to:string key:int256
                 wkey:int256 wsig:bytes wts:long wexp:long
                 sig:bytes = tonnet.Envelope;

tonnet.envelopeV4.toSign type:string nick:string text:string ts:long
                        room:string to:string key:int256
                        wkey:int256 wsig:bytes wts:long wexp:long
                        = tonnet.EnvelopeToSign;
```

Fields:

- `type`: `msg`, `hello`, `dm`, `cert-req`, `cert-grant`, or empty
  (empty is treated as `msg`).
- `nick`: advisory display name (section 15).
- `text`: body, or base64(box) for a dm (section 11).
- `ts`: client timestamp in milliseconds, advisory.
- `room`: full room name, required and byte-equal to the node's room.
- `to`: REQUIRED as lowercase 32-byte hex for `dm` and `cert-grant`; MUST be
  empty for `msg`, empty type, `hello`, and `cert-req`.
- `key`: sender device ed25519 public key, raw 32 bytes.
- `sig`: ed25519 signature, 64 bytes, over section 7's digest.
- `wkey/wsig/wts/wexp`: optional wallet attribution proof (section 8). On the TL
  wire, absence is encoded as `wkey = 32 zero bytes`, `wsig = empty bytes`,
  `wts = 0`, `wexp = 0`.

Field groups:

- Device signature (`key`, `sig`): present on every message.
- Wallet proof (`wkey`, `wsig`, `wts`, `wexp`): optional attribution (section 8).
  All four present together or all absent; any partial set is malformed.
- Routing (`room`, `to`): `room` is mandatory; type-specific `to` presence is
  mandatory as defined above.

Strict byte limits before signature verification:

| Field | Limit |
|---|---:|
| `type` | 16 B |
| `nick` | 64 B |
| `text` | 2048 B |
| `room` | 256 B, visible ASCII |
| `to` | 64 B |

JSON envelopes and envelope v1/v2/v3 are obsolete and MUST be rejected on the
wire. The `room` field MUST equal the node's full room name exactly.

---

## 7. Device signature

The device key signs the SHA-256 of the boxed TL `tonnet.envelopeV4.toSign`
object:

```
digest = sha256( TL( tonnet.envelopeV4.toSign{
  type, nick, text, ts, room, to, key, wkey, wsig, wts, wexp
} ) )

sig = ed25519_sign(deviceKey, digest)
```

The constructor id is the domain separator. `room` closes cross-room replay; `to`
binds a dm to its recipient; `wkey/wsig/wts/wexp` are inside the device digest so
wallet proofs cannot be grafted onto or stripped from an authored message.

**Integrity invariant (C1).** Every consumer of a wire frame MUST use the common
frame verifier: wrapper signature, `src == envelope.key`, envelope signature, and
room match must all pass before wallet fields are used for attribution. A bare
`envelope.Verify()` is now safe against wallet-proof grafting, but it is not a
network-liveness proof and does not replace wrapper verification.

---

## 8. Wallet endorsement (ton_proof), optional

Authorship is a device key; a TON wallet endorsement is optional attribution,
never a protocol requirement. A device-signed message with no wallet proof is a
first-class message. When present and valid it lets a client attribute the
message to a wallet, and, if the signed `nick` is an owned `.ton`, to a verified
name (section 15).

The wire shape and the attribution result are separate checks:

| Wallet fields | Envelope result | Display result |
|---|---|---|
| canonically absent: zero `wkey`, empty `wsig`, zero `wts/wexp` | valid | device tier |
| partial, wrong-sized, non-canonical, or with non-positive required values | malformed; drop before relay/history | none |
| structurally complete but expired, future-dated, over-long, or cryptographically invalid | valid device-authored envelope | device tier |
| structurally complete and cryptographically valid | valid | wallet tier, optionally domain tier |

Thus “invalid proof degrades” means a structurally complete attribution that
fails client-side TON proof verification. It does not make a malformed TL
envelope acceptable.

The wallet signs once a delegation endorsing the device key, reusing the TON
Connect `ton_proof` construction with domain `tonnet.chat`
(`internal/tonproof/tonproof.go`):

```
payload = "tonnet-chat-device:v1:" ‖ deviceKeyHex ‖ ":" ‖ dec(wexp)

inner   = sha256( "ton-proof-item-v2/"
            ‖ u32be(workchain) ‖ address.data(32)
            ‖ u32le(len("tonnet.chat")) ‖ "tonnet.chat"
            ‖ u64le(wts) ‖ payload )

digest  = sha256( 0xFF 0xFF ‖ "ton-connect" ‖ inner )
wsig    = ed25519_sign(walletKey, digest)
```

The mixed endianness (workchain big-endian, domain length and `wts`
little-endian) follows the TON Connect spec verbatim and must not be "corrected".
The wallet address is derived offline from `wkey` with no blockchain read: wallet
v5r1 (`ConfigV5R1Final`, network global id -239, workchain 0, subwallet 0).

Verification (`tonproof.Verify`): `wkey` is 32 bytes and `wsig` 64 bytes;
`wts, wexp > 0`; `wts <= now + 300 s`, `wexp > now`, `wexp > wts`, and
`wexp - wts <= 604800 s`; the address derived from `wkey` recomputes a `digest`
that `wsig` verifies. The `payload` binds the proof
to `deviceKeyHex`, so a proof only ever attributes the exact device key it
endorses; it cannot be transferred to another key.

The node does not verify ton_proof and does not require it (section 12).
Attribution is computed by clients. Clients MUST fully reverify cached proofs,
including signature and lifetime, before reuse. Layers: authorship is the
device ed25519 signature (no blockchain); attribution is ton_proof plus an
on-chain `.ton` check (optional, blockchain).

---

## 9. Gated rooms (experimental, disabled by default)

A room name MAY carry an owner suffix, `tonnet:<group>#o=<64 hex owner ed25519
pubkey>`, which makes the overlay id commit to an owner key so that posting can
require an owner-signed member certificate (native `overlay.certificate`,
ton_api.tl:235, one-level PKI with a single pinned root). The node implements
this experimental capability: `internal/room/name.go` parses the suffix,
`internal/room/cert.go` issues and verifies certificates against the pinned
owner, and the pipeline (section 12) and rate limits (section 13) enforce it when
the experimental mode is explicitly enabled.

Nodes MUST refuse a gated room unless started with
`--experimental-gated-rooms`. Tonnet Browser MUST refuse joining or creating one
unless `TONNET_EXPERIMENTAL_GATED_ROOMS=1`. Current in-band enrollment is an
experimental protocol exercise, not a privacy or authorization guarantee for
the stable product. The remainder of this document describes open rooms.

---

## 10. Message types

| type | envelope | stored | addressed | notes |
|---|---|---|---|---|
| `msg` / `""` | v4 | yes | no | room message |
| `hello` | v4 | no | no | presence; carries connection challenge; triggers history replay |
| `dm` | v4 | yes (ciphertext) | yes | E2E box (section 11) |

Addressed types carry `to` and follow the routing rule of section 11; all other
types flood. The `nick` field is advisory; verifiers never trust it for identity,
only for the optional `.ton` display upgrade (section 15). Experimental gated
rooms also define `cert-req` / `cert-grant` per section 9.

---

## 11. Direct messages

A dm rides the same room overlay (leaves are NAT-bound and cannot open a direct
channel). It is a v4 envelope with `type="dm"`, `to` = the recipient's device
public key, `text` = base64 of the sealed box, signed like any message.

Encryption (`internal/dm/dm.go`):

```
secret = ECDH_x25519(myDevicePriv, peerDevicePub)   // ed25519 keys mapped to X25519, RFC 7748
shared = sha256("tonnet-dm-v1" ‖ secret)            // AES-256 key
box    = nonce(12) ‖ AES-256-GCM(shared, plaintext, aad) ‖ tag(16)
aad    = senderDevicePub(32) ‖ recipientDevicePub(32)
```

The direction-bound `aad` prevents a box sealed A to B from being replayed as
B to A. The recipient decrypts only when `to` equals its own device key. DM
identity is the device key, so DMs work without a wallet.

**Routing.** Transporting a signed frame does not prove that a leaf owns its
author key: a relay can copy somebody else's frame. Device routing therefore
uses an explicit connection challenge (section 16). After joining, a leaf
requests a random 32-byte nonce from that exact overlay connection and includes
its lowercase hex value in the device-signed `text` of its first `hello`
(`cert-req` in experimental gated mode). The node accepts the binding only when
the unexpired nonce matches that connection. Later accepted frames from the
same key refresh it; one connection cannot switch device keys.

A node maintains authenticated `deviceKey -> leafPeer[]` bindings with a 90 s
TTL, at most 4 peers per device key and 4096 bindings total. Clients refresh
presence every 60 s. For an accepted addressed broadcast the node delivers to
every healthy local leaf whose authenticated bound device key equals `to`,
relays to healthy node-peers (bounded fanout, section 12 step 12), and MUST NOT
deliver to any other leaf. A replayed victim frame cannot create a binding
because it does not carry the current connection nonce. Other nodes apply the
same rule. If the recipient is offline, dm history (ciphertext, section 14) is
the best-effort delivery path on rejoin. History replay to a joining leaf is
filtered per-leaf and MUST skip stored `dm` items whose `to` is neither that
authenticated key nor authored by it.

Not provided: metadata privacy (`to` and sender identity are visible to relaying
nodes, though no longer to unrelated leaves) and forward secrecy (static ECDH per
device-key pair). Both are deferred (section 19).

---

## 12. Node pipeline (normative)

On receiving an overlay custom message a node processes strictly in this order,
cheap checks before cryptography:

1. **Per-peer rate limit**: pending/member leaves use burst 4, refill 2/s;
   authenticated node-peers that aggregate room traffic use burst 32, refill
   16/s. Excess is dropped and adds a small bad-peer score.
2. **Parse and flags**: accept `tonnet.broadcast` with `flags == 0` only.
3. **Application size**: reserialize the object and require <= 4096 bytes.
4. **Freshness**: require `|now - date| <= 60 s`.
5. **Cheap id and dedup reservation**: compute `broadcast_id`; drop an id already
   delivered or pending. Otherwise reserve it. Any later failure releases the
   reservation.
6. **Global ingress**: atomically charge one message and its serialized bytes
   against the node-wide dual bucket (section 13).
7. **Frame verification**: use the common frame verifier:
   `tonnet.broadcast.toSign{broadcast_id, date}` signature by `src`, parse boxed
   TL `tonnet.envelopeV4`, require `envelope.key == src`, verify the envelope
   device signature, and require `envelope.room ==` this node's full room name.
   Wrapper signature/source mismatch and inner envelope signature failures apply
   the signature penalty (section 13).
8. **Envelope policy**: field limits, type-specific `to`, and malformed partial
   wallet proofs fail inside frame verification. JSON and legacy framing drop.
9. **Attribution**: none. The node does not verify ton_proof (section 8).
10. **Authorization (gated rooms only)**: `cert-req` is accepted uncertified
   within the uncertified budget (section 13) and only if <= 2048 bytes; anything
   else MUST carry a certificate valid per section 9, with `keyid(src)` as
   subject. Fail drops. Open rooms skip this step.
11. **Per-source rate limit**: charge the device key's budget (section 13); over
    budget drops.
12. **Observe**: commit `broadcast_id`, mark presence, add storable types to
    history as their accepted wrapper, and create or refresh a device binding
    only after the connection-challenge rule in section 11 succeeds.
13. **Relay**: enqueue the original wrapper. Flood types go to healthy member
    leaves and at most 5 healthy node-peers; addressed types follow section 11.
    `hello` goes to node-peers only. Each peer has one writer, a 32-job queue,
    and an 8 s send deadline. A full queue closes the slow peer.
14. **Replay-on-bind**: after the first accepted `hello`/`cert-req` that proves
    the current connection challenge, enqueue at most one history batch to that
    leaf, filtered per section 11 and excluding the triggering frame. An
    unauthenticated transported frame MUST NOT select DM history. Later frames
    on the same connection MUST NOT trigger another replay.

Relaying the accepted signed wrapper is what makes multi-hop dedup work: every hop
sees the same `broadcast_id` because the origin data, signature, source, and date
are preserved. This resolves the re-origination problem that ruled out the
library's FEC path.

---

## 13. Rate limits and abuse controls

| Limiter | Key | Budget |
|---|---|---|
| leaf transport floor | peer | burst 4, refill 2/s |
| authenticated node transport | node peer | burst 32, refill 16/s |
| accepted ingress | node | atomic messages burst 64/refill 32/s plus bytes burst 256 KiB/refill 128 KiB/s |
| per-source | `keyid(device key)` | 30 msgs and 64 KiB per 60 s, LRU 4096 |
| auxiliary queries | node | burst 128, refill 64/s |
| uncertified (gated only) | one bucket per node | burst 8, refill 4/min, `cert-req` only, <= 2048 B |
| cert verification (gated only) | issuer | LRU 128 result cache, misses <= 60/60 s |

**Authenticated-frame penalty.** A peer delivering a broadcast that fails
signature verification (step 6), binds different authenticated layers, or is
validly signed for another room MUST have all its traffic ignored for 5 s.
Nodes SHOULD keep a per-peer error counter and MAY disconnect peers that
repeatedly trip it.
Per-source keying (device key) is a deliberate deviation from the reference's
issuer keying: with a single owner per room, issuer keying would collapse all
members into one bucket.

**Peer hygiene.** New protocol peers begin in quarantine. Because the shared
ADNL gateway reports locally dialed DHT connections through the same callback
as accepted connections, an unknown transport peer enters Tonnet's pending
table only when it sends correctly overlay-wrapped Tonnet custom or auxiliary
query traffic. A node tracks at most
100 such pending peers for 30 s; invalid traffic does not extend this deadline.
A leaf leaves quarantine only
after a broadcast is accepted; invalid or stale first traffic MUST NOT create
membership or trigger history replay. A node leaves quarantine only after a
successful overlay liveness exchange, such as `getRandomPeers`, or after it
delivers an accepted broadcast. Quarantined nodes are not relay targets and are
not advertised to other peers.

Nodes keep at most 16 live node-peers and 256 known node ids. The signature
penalty table is expiry-swept and capped at 4096 entries. Nodes maintain a
per-peer bad score. Signature/source failures add a high score;
rate-limit abuse adds a low score; repeated relay, overlay probe, answer, or
healthy-node keepalive failures count as liveness failures. At the eviction
threshold the peer is removed and the connection is closed. Non-member leaves
that remain in quarantine past the quarantine TTL are also closed. Member
leaves are closed after 150 s without an accepted Tonnet frame; transport
traffic and invalid frames do not refresh that application idle timer. Healthy
node-peers are periodically probed with ADNL keepalive so dead connections stop
consuming relay slots; quarantined nodes must first pass an overlay liveness
exchange before they are eligible for keepalive, relay, or advertisement.

---

## 14. History and presence

Storable types (`msg`, `dm`) enter an in-memory ring, capped at
`min(200 items, 6 hours, process uptime)` (`internal/room/history.go`); `hello`
is not stored. History stores the
accepted wrapper so replayed items stay fully verifiable. After the first
connection-challenge-authenticated frame on a leaf connection, the node replays
the recent buffer once to that leaf only, excluding the triggering frame and filtering addressed types
(section 11). Replay recipients do not apply the node's +/-60 s live-freshness
rule, but they MUST apply the client replay bound from section 5; all other
verifications apply.

Presence marks only accepted messages, so only signed identities appear, TTL-
swept (90 s). History is in memory (a restart wipes it) and is not authenticated
for completeness or ordering: a node can withhold or reorder, and absence from a
roster is not proof of absence.

Replay is an opportunistic cache, not synchronization: it offers no delivery,
completeness, total-order, persistence, or availability guarantee. Clients
preserve receive order and MUST NOT reorder by the untrusted envelope `ts`. A
client MAY display `ts` only when it lies between receive time minus 6 h 5 min
and receive time plus 5 min; otherwise it uses receive time. A local “sent”
state means only that the local Bridge accepted the send.

---

## 15. Client display policy

A message is displayed if its device signature and the wrapper verify; it is
never dropped for lacking a wallet. Wallet attribution is an optional upgrade
shown as a tier (precedence `domain` > `wallet` > `device`):

- **device**: valid device signature, no valid ton_proof. The floor. Show a
  stable pseudonym from the device key (the signed `nick`, else a fingerprint
  like `#a1b2c3d4`). No verified check.
- **wallet**: additionally a valid ton_proof. Show the short wallet address;
  muted check.
- **domain**: additionally, the signed `nick` is an owned `.ton` that on-chain
  resolves to the proof wallet. Show the `.ton`; primary check.

A structurally complete but cryptographically invalid or expired proof degrades
to device, never drops. A partial or structurally malformed proof is an envelope
policy failure and drops before attribution, as defined in sections 6, 8, and
12. Clients MUST run the common frame verifier (broadcast signature,
`src == envelope.key`, TL envelope signature, room match, and structural
envelope policy) before reading any wallet field (invariant C1, section 7).
Clients treat `date` as informational and trust their node for liveness only,
never for authenticity or authorization.

---

## 16. Auxiliary queries

```
tonnet.getTime = tonnet.Time;
tonnet.time now:int = tonnet.Time;
tonnet.getChallenge = tonnet.Challenge;
tonnet.challenge nonce:int256 expires:int = tonnet.Challenge;
tonnet.getBroadcast hash:int256 = tonnet.Broadcast;
tonnet.broadcastNotFound = tonnet.Broadcast;
```

- `getTime`: after the overlay transport connects, but before the challenge-
  authenticated `hello`/`cert-req`, leaves MUST query it with a 3 s timeout, compute the
  offset against the request midpoint, reject nodes outside +/-300 s, and use
  the offset only for wrapper `date`, never display or authorization.
- `getChallenge`: after time calibration, leaves MUST request it with a 3 s
  timeout. The node returns a cryptographically random 32-byte nonce bound to
  that peer and expiring after 60 s. Leaves reject an already expired response
  or one more than 120 s in the future, then sign its lowercase hex value inside
  the first `hello`/`cert-req` as specified in section 11.
- `getBroadcast`: pull-repair; any peer MAY request a recently seen broadcast by
  id, answered from the wrapper store (last 128) or `broadcastNotFound`. Nodes
  SHOULD answer; requesting is OPTIONAL.

---

## 17. Versioning and migration

Versioning is by TL constructor: a new wire format is a new constructor, and
receivers dispatch on the constructor id. `flags` (always 0) is the
intra-constructor capability space; the envelope version is the constructor
`tonnet.envelopeV4`. Nodes speak only `tonnet.broadcast` carrying
`tonnet.envelopeV4` and reject JSON or legacy envelope framing. Clients upgrade
together with their node. A future wire format will be announced as deprecated one
revision before removal.

---

## 18. Constants

| Constant | Value |
|---|---|
| max broadcast size | 4096 B |
| envelope wire format | boxed TL `tonnet.envelopeV4` |
| envelope field limits | `type` 16 B; `nick` 64 B; `text` 2048 B; `room` 256 B; `to` 64 B |
| node live freshness / client replay bound | +/-60 s / past 6 h 5 min, future 5 min |
| delivered set (dedup) | 8192 broadcast ids |
| wrapper store (pull-repair) | 128 |
| node relay fanout (node-peers) | 5 random |
| leaf rate limit | burst 4, refill 2/s |
| node-peer rate limit | burst 32, refill 16/s |
| global ingress | messages burst 64/refill 32/s; bytes burst 256 KiB/refill 128 KiB/s |
| global query limiter | burst 128, refill 64/s |
| per-source rate limit | 30 msgs and 64 KiB per 60 s, LRU 4096 |
| signature penalty | ignore peer 5 s |
| peer hygiene | pending cap 100; quarantine TTL 30 s; bad score eviction 8; failed liveness eviction 3 |
| peer keepalive | maintenance 30 s; healthy idle probe 45 s; probe timeout 5 s |
| device-key binding TTL | 90 s |
| device-key bindings | 4 peers/key; 4096 total |
| connection challenge / presence refresh | 60 s / 60 s |
| history / presence | 200 msgs / 6 h; presence TTL 90 s |
| DHT publish / TTL | 5 min / 30 min |
| max leaves per node | default 256; CLI range 1..2048 |
| max live node-peers / known ids | 16 / 256 |
| outbound relay | 32 jobs/peer; one writer; 8 s send timeout |
| proof clock skew / lifetime | 300 s / max 604800 s |
| wallet | v5r1, global id -239, workchain 0, subwallet 0 |
| certificate (gated, experimental) | `max_size` 4096 B, TTL 30 days, cert cache LRU 128 |

---

## 19. Non-goals and deferred work

- **Gated rooms**: experimental and disabled by default (section 9).
- **Forward secrecy for DMs**: static ECDH; candidates are Signal X3DH plus
  Double Ratchet or a Noise session.
- **Sealed sender / DM metadata privacy**: `to` and sender identity stay visible
  to relaying nodes.
- **Authenticated or persistent history**: replay is best-effort and
  unauthenticated for completeness and ordering.
- **Certificate revocation**: expiry only.
- **Multi-admin rooms**: one owner key per room.
- **Wallet-proof spam cost**: a wallet is approximately free; ton_proof is
  attribution, not protection.
- **Identity continuity**: rotation is allowed and creates a new identity; there
  is no multi-device linking, account recovery, uniqueness, or continuity proof.
- **Sybil resistance and account bans**: device and wallet creation are cheap by
  design. Rate limits protect node resources, not social identity.

---

## Appendix A. Correspondence to the TON reference

| Mechanism | Reference |
|---|---|
| broadcast wrapper shape | `overlay.broadcast`, ton_api.tl:243 (own constructors, same fields) |
| broadcast id | `overlay.broadcast_id`, broadcast-simple.cpp:37 (src as keyid) |
| date in signature | `overlay.broadcast.toSign`, ton_api.tl:230 |
| freshness window | `check_date` +/-20 s, overlay.cpp:564 (widened to +/-60 s) |
| dedup > freshness invariant | delivered set plus GC windows, overlay.hpp:329 (sized 8192) |
| re-flood of original bytes | broadcast-simple.cpp:125 (tonutils-go lacks this path) |
| fanout bound | `propagate_broadcast_to_ = 5`, overlays.h:296 |
| certificate and CertificateId | ton_api.tl:235, tonutils-go types.go:54 (via room/cert.go) |
| one-root eligibility | `check_source_eligible`, overlay.cpp:575 |
| cert-check cache and limiter | overlay.cpp:588, overlay.hpp:191 |
| uncertified shared bucket | `unauthorized_broadcasts_limiter_`, overlay.cpp:849 |
| per-source count and size windows | `BroadcastsLimiter`, overlay.cpp:887 (keyed by source, deviation) |
| signature ban | `reject_signatures_from_` 5 s, overlay.hpp:538 |
| pull-repair | `overlay.getBroadcast`, ton_api.tl:263 |
