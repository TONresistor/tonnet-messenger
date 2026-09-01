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

User identity domains use `dns_text` category `msg_id` with the canonical
identity key as their complete value.

## License

[MIT](LICENSE) © Digital Resistance
