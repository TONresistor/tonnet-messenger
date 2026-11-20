# Tonnet Messenger

[![The Open Network](https://img.shields.io/badge/The_Open_Network-0098EA?logo=ton&logoColor=white)](https://ton.org)

Persistent public rooms and encrypted direct messages over TON QUIC.

| Binary | Use |
| --- | --- |
| `tonnet-messenger` | Interactive terminal client, CLI commands and JSON-RPC API |
| `tonnet-messenger-server` | Room sequencer, verified room replica and DM relay |

Protocol and API: [PROTOCOL.md](PROTOCOL.md).

## Build

Requires **Go 1.26.7 or newer**. From the repository root:

```sh
go build -o tonnet-messenger ./cmd/tonnet-messenger
go build -o tonnet-messenger-server ./cmd/tonnet-messenger-server
```

## Client

Open the interactive client:

```sh
./tonnet-messenger
```

Join rooms, send messages and manage your identity from the menu.
To link a `.ton` or `.t.me` domain, scan the QR code and approve the transaction in the wallet that owns it.

Room history and received DMs are saved locally in `~/.tonnet-messenger/client`.
DMs do not require joining a room or both users being online. Relays retain
encrypted messages until acknowledgement or expiry; the running client fetches
its inboxes and subscribes for live delivery. A relay receipt confirms storage,
not delivery to the recipient.

If an operation's result is unknown, review it in **Room details → Pending operation**.
Retry reuses the original proposal. Discarding its tracking does not cancel a possible commit.

You can also use commands directly:

```sh
./tonnet-messenger identity set-name "Alice"
./tonnet-messenger room join community.ton
./tonnet-messenger room send community.ton "Hello"
./tonnet-messenger room history community.ton
./tonnet-messenger room pending community.ton
./tonnet-messenger room retry community.ton EVENT_ID
./tonnet-messenger dm send RECIPIENT_KEY "Hi"
```

Rooms and DM recipients accept canonical public keys or `.ton` / `.t.me` aliases.

Applications can connect to the client through JSON-RPC:

```sh
./tonnet-messenger run --stdio
```

## Server

One node can sequence its own rooms, replicate other rooms and relay DMs under
one node identity and database. Each room has one authoritative sequencer;
replicas verify its history and cannot take over sequencing.

Create a room in a new state directory, then start it. Replace `ROOM_KEY` with
the canonical key printed by `room create`:

```sh
./tonnet-messenger-server room create --state ./node --name "My community"
./tonnet-messenger-server serve --state ./node --sequencer ROOM_KEY --advertise PUBLIC_IP:17400
```

Replace `PUBLIC_IP` with the server's public IP and open UDP port 17400.
Keep the node's state directory for subsequent runs.

To add another owned room to the same state:

```sh
./tonnet-messenger-server room add --state ./node --name "Another community"
```

Repeat `--sequencer ROOM_KEY` for each owned room to serve. Add `--dm` to enable
the free DM relay alongside those rooms.

To link a `.ton` or `.t.me` domain to the room:

```sh
./tonnet-messenger-server room link-domain community.ton --state ./node --room ROOM_KEY
```

### Room replicas

Obtain a room's public `genesis.boc` from its sequencer. Retain that verified
artifact in an existing node state, then select the room as a replica:

```sh
./tonnet-messenger-server room retain --state ./node --genesis ./replica-genesis.boc
./tonnet-messenger-server serve --state ./node --replica REPLICA_ROOM_KEY --advertise PUBLIC_IP:17400
```

Replace `REPLICA_ROOM_KEY` with the key printed by `room retain`. Combine or
repeat `--sequencer` and `--replica` to serve multiple rooms. Only selected
rooms are served. The room's private authority key stays on its sequencer.

### DM relays

Run a standalone free DM relay without serving rooms:

```sh
./tonnet-messenger-server relay --state ./relay --advertise PUBLIC_IP:17400
```

Relay size, retention, rate and inbox quotas are configurable with the `--dm-*`
flags. This service stores encrypted DMs independently of room membership.

Paid tiers are optional. A relay uses `--tpn-config CONFIG` with
`--dm-paid-offer TIER:PRICE_NANOTON:UNIT_BYTES`; a client opts in with
`--tpn-config CONFIG`. The existing TPN setup must have usable funded channels,
and the client config must include `TonnetPayer` settings. Payment and recovery
rules are in [PROTOCOL.md](PROTOCOL.md#6-payments).

### Direct local connections

For isolated testing, use `--local --listen 127.0.0.1:17400` on the server and
`--direct 127.0.0.1:17400 --direct-key NODE_PUBLIC_KEY` on the client. `--local`
disables DHT publication. A room's JSON output includes `node_key`:

```sh
./tonnet-messenger-server room show --state ./node --room ROOM_KEY --json
./tonnet-messenger --direct 127.0.0.1:17400 --direct-key NODE_PUBLIC_KEY
```

Use `--help` on any command for its options.

## License

[MIT](LICENSE) © Digital Resistance
