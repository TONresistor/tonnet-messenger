# Tonnet v0.3.1: GTON and two-client validation

This is the final acceptance run for the coordinated, unreleased candidates:
Messenger v0.3.1, WS Bridge v0.4.1, and Tonnet Browser v2.4.1.

The topology is fixed:

- **GTON:** the only Messenger server, `tonnet-groupchat.service`, room
  `tonnet:groupchat`, public UDP port `17400`;
- **PC A:** Browser plus its local Bridge;
- **PC B:** Browser plus its local Bridge.

Do not build, install, or run Messenger on either PC. Do not publish, tag, or
release before this run passes. The Browser Bridge pin remains on the last
release; place the locally built v0.4.1 binary in the Browser's ignored
`resources/bin/<platform>/` directory for this test.

## Record before starting

- HEAD, dirty status, untracked-file list, and source-tree SHA-256 for all three
  worktrees;
- OS and architecture of PC A and PC B;
- SHA-256 of the GTON Messenger candidate and both Browser/Bridge candidates;
- GTON service definition, node id, persistent key path, advertised endpoint,
  control socket, start time, and initial `tonnet status --json`;
- an explicit backup and rollback path for the current GTON binary.

Building or replacing the GTON binary and restarting the service require the
operator's explicit approval during the joint test session.

## Acceptance sequence

1. **Server preflight:** confirm the GTON service is active, UDP `17400` is
   listening and advertised, the control socket responds, the room is exact,
   and the node publishes a fresh signed DHT record.
2. **Client discovery:** start Browser plus Bridge on PC A and PC B. Join
   `tonnet:groupchat` without a pasted bootstrap id. Both clients must reach
   `connected` through DHT discovery, ADNL, time calibration, and the connection
   challenge.
3. **Public traffic:** send A to B, B to A, then an alternating sequence.
   Receive order must be preserved and each canonical broadcast id must appear
   exactly once, including the sender's own message.
4. **Direct messages:** send one DM in each direction. No unrelated client may
   receive or decrypt it.
5. **Binding lifetime:** leave both Browsers connected for more than 90 seconds,
   then repeat public and direct sends. Challenge refresh, binding, and routing
   must remain active.
6. **Controlled replay:** disconnect Browser B only; keep GTON running. Send a
   public message and a DM from A, reconnect B within the replay window, and
   confirm bounded best-effort replay with no duplicate. Search covers only the
   retained 500-message client window.
7. **Identity policy:** verify device-only use, valid wallet attribution,
   `.ton` display only after ownership verification, and free identity reset.
   An absent proof stays at device tier. A structurally complete but expired or
   cryptographically invalid proof degrades to device tier. A partial or
   malformed proof is rejected as a malformed envelope.
8. **Client recovery:** stop or disconnect Bridge B without stopping GTON.
   Browser B must show `reconnecting`, recover, and keep already displayed
   messages deduplicated.
9. **Optional server restart:** only after explicit approval, restart the GTON
   service and verify client reconnection. Do not expect replay across the
   restart because server history is in memory.
10. **Evidence:** capture final status JSON, bounded counters, sanitized logs,
    timestamps, and all artifact hashes. Deliberately invalid frames must be
    identifiable without logging message content or identity material.

## Pass boundary

Unit, race, static, build, vulnerability, and bundle checks are prerequisites,
not proof of network correctness. v0.3.1 is accepted only after this complete
GTON plus two-client sequence passes and its evidence is retained.

A two-Messenger-server mesh/failover test is a separate optional scenario. It
requires a second public server and is not simulated by PC A or PC B.
