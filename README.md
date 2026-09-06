# tonnet-messenger

[![ci](https://github.com/TONresistor/tonnet-messenger/actions/workflows/ci.yml/badge.svg)](https://github.com/TONresistor/tonnet-messenger/actions/workflows/ci.yml)

Persistent public rooms and an independent client over TON QUIC, DHT and
overlays.

Protocol 0.4 provides two binaries:

- `tonnet-messenger-server`: authoritative room sequencer or verified relay;
- `tonnet-messenger`: standalone leaf client with a JSON-RPC stdio interface.

The normative protocol and client contract are defined in
[spec/SPECS-4-0-0.md](spec/SPECS-4-0-0.md).

## Build

```bash
go build ./cmd/tonnet-messenger
go build ./cmd/tonnet-messenger-server
```

## Server

```bash
tonnet-messenger-server room create \
  --state /var/lib/tonnet-messenger \
  --name "My community"

tonnet-messenger-server serve \
  --state /var/lib/tonnet-messenger \
  --advertise PUBLIC_IP:17400
```

Room creation is an operator action and is never available to clients.
The advertised UDP port carries mandatory TON QUIC room traffic and must be
publicly reachable. The node publishes it as `adnl.address.quic` through DHT.
Sequencers, relays and clients must be upgraded together; legacy ADNL room
endpoints are not compatible.

```bash
tonnet-messenger-server room admin grant \
  --state /var/lib/tonnet-messenger \
  IDENTITY_KEY

tonnet-messenger-server room write-policy set \
  --state /var/lib/tonnet-messenger \
  admins
```

TON DNS room aliases use `dns_text` category `msg_room` with the canonical room
key as their complete value.

## Client

The client owns one Ed25519 identity and joins rooms through mutually
authenticated TON QUIC. Classic ADNL is used only for DHT discovery. The client
does not create rooms, sequence events or publish room-node records.

Run the client without a command in a terminal to open the interactive menu:

```bash
tonnet-messenger
```

The menu provides **My rooms**, **Join a room**, **Direct messages** and
**My identity**. Use arrow keys and Enter to select, Escape to go back, and
Ctrl+C to quit. Rooms keep receiving messages while you browse other screens.
The identity screen shows your public key, lets you change your name, and
prepares/verifies a domain link without submitting a DNS transaction.
Linking a domain displays a QR code for the prepared wallet transaction. Scan it
with the wallet owning the domain, approve it there, then select **Verify DNS
record**. Both the QR and the transaction link are always included. Use
PgUp/PgDown to scroll when the content extends beyond the screen.

In a conversation, Enter sends the current draft; pasting never sends it.
PgUp/PgDown scroll the displayed history. For public rooms, Ctrl+O loads an
older page, Ctrl+N returns to a newer page, Ctrl+L returns to the latest messages,
Ctrl+D opens room details, and Ctrl+R retries a connection. Reading an older
page keeps it in place while new events arrive. Leaving a room requires an
explicit confirmation in its details screen and removes that room's local cache.

Drafts and direct conversations survive menu navigation during the session.
DM conversations are scoped to a room and recipient, retain the latest 500
messages in memory, and are not archived to disk. Both recipients must be
online. A successful send is not a read receipt; failed sends are never retried
automatically.

The default client profile is `~/.tonnet-messenger/client`; use `--state PATH`
for another profile and `--config URL` for another TON configuration. A profile
can only be opened by one process at a time. The menu does not import the
Browser profile. `NO_COLOR` disables colors. Without a terminal, invoking the
client without a command prints help and does not open a profile.

Explicit commands remain available for scripts and print JSON results:

```bash
tonnet-messenger identity show
tonnet-messenger room join community.ton
tonnet-messenger room send community.ton "hello"
```

Any interface can embed the client through newline-delimited JSON-RPC 2.0:

```bash
tonnet-messenger run --stdio
```

```json
{"jsonrpc":"2.0","id":1,"method":"identity.get","params":{}}
{"jsonrpc":"2.0","id":2,"method":"room.join","params":{"reference":"community.ton"}}
```

Timeline responses stay within the 64 KiB line contract by returning a shorter
page with `has_more=true`. `SIGINT`, `SIGTERM`, EOF and broken stdio shut the
client down cleanly.

User identity domains use `dns_text` category `msg_id` with the canonical
identity key as their complete value.

## License

[MIT](LICENSE) © Digital Resistance
