# Tonnet Messenger

[![The Open Network](https://img.shields.io/badge/The_Open_Network-0098EA?logo=ton&logoColor=white)](https://ton.org)

Persistent public rooms and encrypted direct messages over TON QUIC.

| Binary                    | Use                                                        |
| ------------------------- | ---------------------------------------------------------- |
| `tonnet-messenger`        | Interactive terminal client, CLI commands and JSON-RPC API |
| `tonnet-messenger-server` | Authoritative room sequencer or verified relay             |

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
To link a `.ton` domain, scan the QR code and approve the transaction in the wallet that owns it.

Public history is saved locally. Direct messages require both users online and are kept only for the current session.
The client stores its data in `~/.tonnet-messenger/client`.

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
./tonnet-messenger dm send community.ton RECIPIENT_KEY "Hi"
```

Applications can connect to the client through JSON-RPC:

```sh
./tonnet-messenger run --stdio
```

For an isolated local test, start the server with `--local` and connect the
client with `--direct IP:PORT --direct-key NODE_PUBLIC_KEY`. The room's JSON
output includes `node_key`.

## Server

Create a room, then start its server. The state directory must not already exist when creating the room.

```sh
./tonnet-messenger-server room create --state ./room --name "My community"
./tonnet-messenger-server serve --state ./room --advertise PUBLIC_IP:17400
```

Replace `PUBLIC_IP` with the server's public IP and open UDP port 17400.

To link a `.ton` domain to the room:

```sh
./tonnet-messenger-server room link-domain community.ton --state ./room
```

A relay serves a verified copy of an existing room's history. To run one on another host:

```sh
./tonnet-messenger-server relay --state ./relay --room ROOM_KEY --advertise PUBLIC_IP:17400
```

Use `--help` on any command for its options.

## License

[MIT](LICENSE) © Digital Resistance
