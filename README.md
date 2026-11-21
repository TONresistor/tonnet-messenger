# Tonnet Messenger

Tonnet Messenger is a messaging protocol over TON QUIC. You can host public rooms with a signed history that anyone can verify, and send end-to-end encrypted direct messages that recipients can pick up when they come online.

## Build

Go 1.26.7+

```sh
go build -o tonnet-messenger ./cmd/tonnet-messenger
go build -o tonnet-messenger-server ./cmd/tonnet-messenger-server
```

## Client

The client keeps your identity, room history and received messages on your machine. Use a public key or a linked `.ton` or `.t.me` name to join a room or address a direct message.

Run `./tonnet-messenger` for the terminal interface, or use individual commands from the shell.

```sh
./tonnet-messenger identity show
./tonnet-messenger room join ROOM_KEY
./tonnet-messenger room send ROOM_KEY "Hello"
./tonnet-messenger dm send RECIPIENT_KEY "Hi"
```

`identity show` prints the public key others can use to message you. For application integration, `./tonnet-messenger run --stdio` exposes JSON-RPC.

## Server

One node can sequence several rooms, serve replicas of other rooms, and run a DM relay under the same node identity.

Create a room in a new state directory. Use the printed room key for `ROOM_KEY` and the host’s public IP for `PUBLIC_IP`. Allow inbound UDP on port 17400.

```sh
./tonnet-messenger-server room create --state ./node --name "My room"
./tonnet-messenger-server serve --state ./node --sequencer ROOM_KEY \
  --advertise PUBLIC_IP:17400
```

Add `--dm` to `serve` to run a relay alongside the room. Run a standalone relay with its own state directory.

```sh
./tonnet-messenger-server relay --state ./relay --advertise PUBLIC_IP:17400
```

To replicate a room, import its public genesis into an existing node state with `room retain`, then select it with `serve --replica ROOM_KEY`. See `--help` for command options.

[Protocol and API](PROTOCOL.md) | [MIT license](LICENSE)
