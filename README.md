# tonnet-messenger

[![ci](https://github.com/TONresistor/tonnet-messenger/actions/workflows/ci.yml/badge.svg)](https://github.com/TONresistor/tonnet-messenger/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TON](https://img.shields.io/badge/TON-Blockchain-0098EA?logo=ton&logoColor=white)](https://ton.org)

**Serverless group chat on the TON network layer.**

Every chat room is a peer-to-peer overlay mesh. Nodes find each other through the TON DHT, flood messages between them, and clients join through any node. No hub, no database, no accounts: authenticity comes from signed device keys, with optional TON wallet attribution.

> [!WARNING]
> **Experimental, for testing only.** This is a research prototype, not a
> production messenger. The cryptography has not been audited by an external
> party and the wire protocol may still change. All code is open source and
> open to review.
>
> To try it end to end, build the desktop client from source from the
> [`dev` branch of Tonnet Browser](https://github.com/TONresistor/Tonnet-Browser/tree/dev).

## Features

- **No server.** A room is a self-healing mesh: any node can die, the room survives, clients reconnect to another node.
- **One binary, one command.** Hosting a room and relaying it are the same thing: `tonnet serve --room NAME`.
- **Signed messages.** Every message is signed by an ed25519 device key; clients can add a TON Connect ton_proof to attribute that device to a wallet without making the mesh blockchain-dependent.
- **Native TON stack.** ADNL transport, DHT discovery, overlay broadcast flooding. Point a `.ton` record at a node's ADNL id to name it.
- **Free identity.** A device key may be kept or rotated at any time. Wallet proof is optional display attribution, not an account, admission token, or Sybil defense.

## Install

```bash
go install github.com/TONresistor/tonnet-messenger/cmd/tonnet@latest
```

Or grab a prebuilt binary from [Releases](https://github.com/TONresistor/tonnet-messenger/releases), or build from source with `go build -o tonnet ./cmd/tonnet`.

## Quick start

Run a node on a host with a public IP and an open UDP port:

```bash
tonnet serve --room tonnet:myroom
```

The first run creates the identity key and prints a checklist:

```
✓ identity   ~/.tonnet/node.key   (ADNL k6Jgg2Xh…I=)
✓ listening  0.0.0.0:17400        (public 203.0.113.10:17400)
✓ room       "tonnet:myroom"      (overlay 7ESd…P6Y=)
→ point a .ton site record at k6Jgg2Xh… to name it
node live · ctrl-C to stop · introspect: tonnet status
```

Run the same command on another host and the two nodes mesh automatically. Check who is hosting a room from anywhere:

```bash
tonnet room find tonnet:myroom
```

## Commands

```
tonnet serve --room NAME     run a node (host or relay)
tonnet status                inspect the running node
tonnet id                    print this node's ADNL id
tonnet room id <name>        overlay id for a room name
tonnet room find <name>      find the nodes hosting a room (DHT)
tonnet probe <name>          headless leaf client: join a room, listen
tonnet keygen                create a node identity key
```

`tonnet <command> --help` for flags.

| `serve` flag | Default | Meaning |
|---|---|---|
| `--room` | `tonnet:groupchat:v1` | room name, derives the overlay id |
| `--listen` | `0.0.0.0:17400` | UDP bind address |
| `--advertise` | autodetect | public `ip:port` published to the DHT |
| `--key` | `~/.tonnet/node.key` | ed25519 seed, defines the ADNL id (back it up) |
| `--socket` | `~/.tonnet/node.sock` | control socket for `tonnet status` |
| `--max-leaves` | `256` | accepted leaves, configurable from 1 to 2048 |
| `--experimental-gated-rooms` | off | enable the unstable owner-certificate room mode |

## How it works

**Mesh.** Each node publishes itself to the TON DHT under the room's overlay id, looks up verified fresh node records, and peers with live addresses over ADNL. A message seen for the first time is relayed through bounded per-peer queues. The in-memory history is only an opportunistic cache: no delivery, completeness, ordering, persistence, or availability guarantee.

**Identity.** Messages always carry two device-level checks that every node verifies offline: the ADNL overlay broadcast signature and an ed25519 device-key signature over the TL envelope. A TON Connect ton_proof can additionally bind that device key to the sender's wallet for display attribution. Anything unsigned, forged, cross-room, or malformed is dropped: never relayed, never stored. Rooms are public and readable by design; signatures provide authenticity, not secrecy.

## Deploy

Cross-compile a static binary, ship it, then install the systemd unit from [`deploy/systemd/overlay-node.service`](deploy/systemd/overlay-node.service):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o tonnet ./cmd/tonnet
scp tonnet SERVER:/tmp/tonnet
ssh SERVER sudo install -m 0755 /tmp/tonnet /usr/local/bin/tonnet
```

See [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for the environment file,
firewall, observability, backup, and GTON plus two-client smoke-test procedure.

## Clients

[**Tonnet Browser**](https://github.com/TONresistor/Tonnet-Browser) is the end-user client: chat lives at `ton://chat`, the TON wallet links silently, and a `.ton` domain owned by the wallet becomes the username. `tonnet probe` is a headless client for testing nodes from the terminal.

## License

[MIT](LICENSE) © Digital Resistance
