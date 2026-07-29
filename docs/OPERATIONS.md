# Tonnet node operations

This runbook targets the experimental v0.3.1 node. It does not turn Tonnet into
a guaranteed-delivery service: history and presence remain volatile caches.

## Install

Install the binary as `/usr/local/bin/tonnet`, then install the unit and its
required environment file:

```bash
sudo install -d -m 0755 /etc/tonnet
sudo install -m 0644 deploy/systemd/overlay-node.service /etc/systemd/system/tonnet.service
sudo install -m 0600 deploy/systemd/tonnet.env.example /etc/tonnet/tonnet.env
```

Set `TONNET_ADVERTISE` to the server's public UDP endpoint. Keep the room string
byte-identical across nodes. Do not enable the gated-room flag for stable open
rooms.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tonnet
sudo systemctl status tonnet
```

Open the advertised UDP port in both host and cloud firewalls. The control
socket is local Unix-only; no TCP management port is required.

## Identity and backup

`/var/lib/tonnet/node.key` is the node's persistent ADNL identity. Back it up
offline with mode `0600`. Losing it creates a different node id and invalidates
DNS or bootstrap references to the old id. Never copy the same node key onto
two simultaneously running hosts.

## Health and observability

```bash
tonnet status --socket /run/tonnet/node.sock --json
journalctl -u tonnet --since "15 minutes ago"
```

With `DynamicUser=yes`, the numeric service uid is allocated by systemd; use
`systemctl show tonnet -p User` if direct socket access is needed. A healthy
status reports a growing uptime and bounded `limits`. Watch `stats` deltas:

- `invalid_drops`, `duplicate_drops`, and rate drops describe rejected ingress;
- `slow_peer_disconnects` means a peer filled its 32-job outbound queue;
- `replayed_items` counts best-effort cache items queued to joining leaves.

Members, neighbours, and presence can legitimately be zero. They are not SLA or
delivery proofs.

## Upgrade and rollback

Stop the unit, atomically replace only `/usr/local/bin/tonnet`, then start and
inspect status and logs. Keep the previous binary until the GTON plus two-client
smoke test passes. Do not delete the state directory during an upgrade.

## Current acceptance: one server and two clients

The current production topology uses one Messenger server on GTON. PC A and PC
B run Browser plus Bridge only; they do not run Messenger.

1. Confirm GTON publishes the exact room and its public UDP endpoint.
2. Join from both Browsers through DHT discovery without a pasted node id.
3. Send public messages and DMs in both directions.
4. Disconnect one Browser while GTON remains running, then reconnect and verify
   bounded replay without duplicates.
5. Keep both clients connected for more than 90 seconds and repeat the sends.
6. Restart GTON only with explicit approval and rollback ready. Reconnection is
   required; replay across restart is not, because history is volatile.

Use `docs/TWO-PC-VALIDATION.md` as the normative checklist and retain hashes,
status JSON, timestamps, and sanitized logs.

## Optional two-server mesh

Mesh/failover validation requires a second public Messenger server with a
distinct persistent node key and the same byte-exact room:

1. Confirm both public UDP endpoints and fresh signed DHT records.
2. Confirm each node reports the other as a healthy neighbour.
3. Stop one node and verify clients rediscover the surviving node.
4. Restart it and verify the mesh reforms.

This optional scenario is not part of the current two-PC acceptance and must not
install Messenger on either client PC.
