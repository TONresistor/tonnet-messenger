package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

type freshnessTestServer struct {
	mu         sync.Mutex
	events     []community.CommittedEvent
	role       int32
	headLimit  int64
	stateError bool
	eventDelay time.Duration
	onEvents   chan struct{}
}

func (server *freshnessTestServer) setEvents(events ...community.CommittedEvent) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.events = append([]community.CommittedEvent(nil), events...)
}

func freshnessTestEndpoint(t *testing.T, key ed25519.PrivateKey, genesis community.Genesis, state community.RoomState, server *freshnessTestServer) string {
	t.Helper()
	gateway, err := roomnet.NewGateway(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gateway.Close() })
	gateway.SetConnectionHandler(func(raw *quic.Peer) error {
		roomnet.Wrap(raw).SetQueryHandler(func(query *roomnet.Query) error {
			server.mu.Lock()
			defer server.mu.Unlock()
			switch req := query.Data.(type) {
			case community.GetRoomGenesis:
				return query.Answer(genesis)
			case community.GetRoomState:
				if server.stateError {
					return errors.New("state unavailable after commits")
				}
				seqno, hash := int64(0), community.Zero256()
				for _, event := range server.events {
					if server.headLimit > 0 && event.Seqno > server.headLimit {
						break
					}
					seqno = event.Seqno
					hash, _ = event.Hash()
				}
				return query.Answer(community.RoomStateResult{State: state, Stats: community.RoomStats{
					NodeRole: server.role, Ready: true, ReplicaSeqno: seqno, ReplicaHash: hash,
				}})
			case community.GetEvents:
				select {
				case server.onEvents <- struct{}{}:
				default:
				}
				if server.eventDelay > 0 {
					time.Sleep(server.eventDelay)
				}
				var events []community.CommittedEvent
				for _, event := range server.events {
					if event.Seqno > req.AfterSeqno {
						events = append(events, event)
					}
				}
				limit := int(req.Limit)
				if limit == 0 {
					limit = community.DefaultPageLimit
				}
				more := len(events) > limit
				if more {
					events = events[:limit]
				}
				return query.Answer(community.EventList{Events: events, HasMore: more})
			default:
				return roomnet.ErrNoAnswer
			}
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	go gateway.Serve(packet)
	return packet.LocalAddr().String()
}

func freshnessTestRoom(t *testing.T) (*Client, *roomHandle, *freshnessTestServer, *freshnessTestServer, []community.CommittedEvent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	room, sequencer, relay := clientTestPrivateKey(t), clientTestPrivateKey(t), clientTestPrivateKey(t)
	genesis, err := community.NewGenesis(room, sequencer, time.Now(), "Freshness", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := community.NewProjection(genesis)
	if err != nil {
		t.Fatal(err)
	}
	state, err := community.SignRoomState(room, projection.State())
	if err != nil {
		t.Fatal(err)
	}
	var events []community.CommittedEvent
	previous := community.Zero256()
	for seqno := int64(1); seqno <= 3; seqno++ {
		nonce := make([]byte, 32)
		nonce[0] = byte(seqno)
		proposal, err := community.SignProposal(room, genesis.NodeKey, community.EventProposal{
			RoomID: genesis.RoomKey, Nonce: nonce, Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "new commit"},
		})
		if err != nil {
			t.Fatal(err)
		}
		event, err := community.SignCommit(room, proposal, seqno, previous, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
		previous, _ = event.Hash()
	}
	authority := &freshnessTestServer{role: community.NodeRoleSequencer}
	withholder := &freshnessTestServer{role: community.NodeRoleRelay}
	authorityAddress := freshnessTestEndpoint(t, sequencer, genesis, state, authority)
	relayAddress := freshnessTestEndpoint(t, relay, genesis, state, withholder)
	instance, err := Open(ctx, Config{StateDir: t.TempDir(), DirectAddress: relayAddress, DirectPublic: relay.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err := instance.store.addRoom(ctx, genesis.RoomKey, "room", nil); err != nil {
		t.Fatal(err)
	}
	session, err := replica.DialRoom(ctx, replica.Config{RoomID: genesis.RoomKey, NodeKey: instance.key,
		DirectAddress: relayAddress, DirectPublic: relay.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	roomCtx, roomCancel := context.WithCancel(instance.ctx)
	handle := &roomHandle{client: instance, key: genesis.RoomKey, ctx: roomCtx, cancel: roomCancel, session: session, sessionEpoch: 1}
	instance.rooms[keyText(genesis.RoomKey)] = handle
	handle.dialSequencer = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		if len(cfg.NodeKey) != ed25519.PrivateKeySize || bytes.Equal(cfg.NodeKey.Public().(ed25519.PublicKey), instance.key.Public().(ed25519.PublicKey)) {
			t.Error("authority read reused the user identity")
		}
		expected, _ := community.KeyID(genesis.NodeKey)
		if !bytes.Equal(cfg.BootstrapADNL, expected) {
			t.Error("freshness query did not target the pinned sequencer")
		}
		cfg.DirectAddress, cfg.DirectPublic = authorityAddress, sequencer.Public().(ed25519.PublicKey)
		return replica.DialSequencer(ctx, cfg)
	}
	if err := handle.syncSessionLocked(ctx, session, 1); err != nil {
		t.Fatal(err)
	}
	return instance, handle, authority, withholder, events
}

func TestRelayFreshnessDetectsWithholdingWithoutMovingTheDeadline(t *testing.T) {
	_, handle, authority, _, events := freshnessTestRoom(t)
	session := handle.session
	now := time.Now()
	for index := 0; index < len(events); index++ {
		authority.setEvents(events[:index+1]...)
		when := now.Add(time.Duration(index) * relayFreshnessGrace / 2)
		if err := handle.checkFreshness(handle.ctx, session, 1, when); err != nil {
			t.Fatal(err)
		}
		if index < 2 && !handle.isCurrentSession(session, 1) {
			t.Fatal("relay was abandoned within the grace period")
		}
	}
	if !handle.isCurrentSession(session, 1) || handle.freshness.status != "stale" {
		t.Fatal("last withholding relay was not marked stale and retained for reads")
	}
	keys := handle.excludedRelayKeys(now.Add(relayFreshnessGrace))
	if len(keys) != 1 || !bytes.Equal(keys[0], session.Peer.GetPubKey()) {
		t.Fatal("withholding relay identity was not excluded")
	}
	_, err := replica.DialRoom(handle.ctx, replica.Config{RoomID: handle.key, NodeKey: handle.client.key,
		DirectAddress: "127.0.0.1:1", DirectPublic: session.Peer.GetPubKey(), ExcludedPublicKeys: keys})
	if err == nil {
		t.Fatal("excluded target remained dialable")
	}
	if len(handle.excludedRelayKeys(now.Add(relayFreshnessGrace+relayExclusionTTL))) != 0 {
		t.Fatal("relay exclusion did not expire")
	}
}

func TestRelayFreshnessAllowsGraceAndRepairsAnHonestRelay(t *testing.T) {
	instance, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	session, now := handle.session, time.Now()
	for _, when := range []time.Time{now, now.Add(relayFreshnessGrace - time.Second)} {
		if err := handle.checkFreshness(handle.ctx, session, 1, when); err != nil {
			t.Fatal(err)
		}
		if !handle.isCurrentSession(session, 1) {
			t.Fatal("honest lagging relay abandoned within grace")
		}
	}
	relay.setEvents(events[0])
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(relayFreshnessGrace)); err != nil {
		t.Fatal(err)
	}
	if !handle.isCurrentSession(session, 1) || handle.freshness.status != "verified" {
		t.Fatal("missed broadcast was not repaired through the honest relay")
	}
	state, err := instance.RoomState(keyText(handle.key))
	if err != nil || state["freshness"].(map[string]any)["status"] != "verified" {
		t.Fatalf("freshness missing from existing API: %#v %v", state, err)
	}
}

func TestRelayFreshnessKeepsReadsWhenAuthorityIsUnreachable(t *testing.T) {
	instance, handle, _, _, _ := freshnessTestRoom(t)
	session, now := handle.session, time.Now()
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.status != "verified" {
		t.Fatal("authenticated empty head was not verified")
	}
	handle.dialSequencer = func(context.Context, replica.Config) (*replica.Session, error) {
		return nil, errors.New("sequencer unreachable")
	}
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	state, err := instance.RoomState(keyText(handle.key))
	if err != nil || !handle.isCurrentSession(session, 1) {
		t.Fatalf("unreachable authority blocked relay reads: %v", err)
	}
	freshness := state["freshness"].(map[string]any)
	if freshness["status"] != "unverified" || freshness["last_verified_at"] != now.Unix() {
		t.Fatalf("unexpected freshness state: %#v", freshness)
	}
	if _, _, err := instance.Timeline(handle.ctx, handle.key, 0, 10); err != nil {
		t.Fatalf("cached history became unreadable: %v", err)
	}
	if delay := handle.nextFreshnessCheck(); delay < time.Minute || delay >= 90*time.Second {
		t.Fatalf("failed check did not back off: %v", delay)
	}
}

func TestSequencerHeadAcceptsConcurrentWritesAndRejectsUnsignedTail(t *testing.T) {
	_, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events...)
	authority.mu.Lock()
	authority.headLimit = 1
	authority.mu.Unlock()
	head, err := handle.sequencerHead(handle.ctx, handle.session, 1)
	if err != nil || head.seqno != 1 {
		t.Fatalf("concurrent write invalidated observed head: %#v %v", head, err)
	}
	corrupt := events[0]
	corrupt.Signature = bytes.Repeat([]byte{1}, ed25519.SignatureSize)
	authority.setEvents(corrupt)
	if _, err := handle.sequencerHead(handle.ctx, handle.session, 1); err == nil {
		t.Fatal("invalid commit signature authenticated a head")
	}
}

func TestRelayFreshnessMatchesCachedCheckpointAndRejectsRegression(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events...)
	relay.setEvents(events...)
	if err := handle.syncSessionLocked(handle.ctx, handle.session, 1); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	authority.headLimit = 1
	authority.mu.Unlock()
	now := time.Now()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.status != "verified" {
		t.Fatal("a matching checkpoint below the local head was rejected")
	}
	authority.mu.Lock()
	authority.headLimit = 3
	authority.mu.Unlock()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	authority.headLimit = 1
	authority.mu.Unlock()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.status != "unverified" || !handle.freshness.lastVerified.Equal(now.Add(time.Second)) {
		t.Fatal("regressed authority head refreshed the verification time")
	}
}

func TestFreshnessDeadlineSurvivesTwentySecondReconnects(t *testing.T) {
	instance := directTestClient(t)
	handle := &roomHandle{client: instance}
	start := time.Now()
	first := handle.freshnessDelay(start)
	for index := 1; index <= 3; index++ {
		session := &replica.Session{}
		if err := handle.installSession(session, instance.key, 1); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Duration(index) * 20 * time.Second
		if got, want := handle.freshnessDelay(start.Add(elapsed)), max(time.Duration(0), first-elapsed); got != want {
			t.Fatalf("reconnect %d postponed the authority check: got %v want %v", index, got, want)
		}
		handle.closeSession()
	}
	if handle.freshnessDelay(start.Add(time.Minute)) != 0 {
		t.Fatal("overdue check was not immediately due after reconnect")
	}
}

func TestFreshnessFailedCatchupNeverVerifiesPersistedOnlyHead(t *testing.T) {
	instance, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	relay.setEvents(events[0])
	relay.mu.Lock()
	relay.stateError = true
	relay.mu.Unlock()
	for _, offset := range []time.Duration{relayFreshnessGrace, 2 * relayFreshnessGrace} {
		if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(offset)); err != nil {
			t.Fatal(err)
		}
		record, err := instance.store.room(handle.ctx, handle.key)
		if err != nil || record.HeadSeqno != 1 || handle.verifiedHead != 0 || handle.freshness.status == "verified" {
			t.Fatalf("partial catchup was verified: db=%d applied=%d freshness=%s err=%v", record.HeadSeqno, handle.verifiedHead, handle.freshness.status, err)
		}
	}
	if !handle.isCurrentSession(session, 1) {
		t.Fatal("last available relay was dropped after partial catchup")
	}
}

func TestFreshnessSlowAuthorityDoesNotConsumeRelayRepairBudget(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	dial := handle.dialSequencer
	handle.dialSequencer = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		timer := time.NewTimer(14 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return dial(ctx, cfg)
		}
	}
	relay.setEvents(events[0])
	relay.mu.Lock()
	relay.eventDelay = 2 * time.Second
	relay.mu.Unlock()
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(relayFreshnessGrace)); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.status != "verified" || !handle.isCurrentSession(session, 1) || len(handle.excludedRelays) != 0 {
		t.Fatal("slow authority caused an honest relay to be rejected")
	}
}

func TestFreshnessAllRelaysExcludedKeepsStaleReads(t *testing.T) {
	for _, mode := range []string{"direct", "DHT"} {
		t.Run(mode, func(t *testing.T) {
			instance, handle, authority, _, events := freshnessTestRoom(t)
			authority.setEvents(events[0])
			session, now := handle.session, time.Now()
			if mode == "DHT" {
				instance.directAddress, instance.directPublic = "", nil
				handle.dialRoom = func(_ context.Context, cfg replica.Config) (*replica.Session, error) {
					if len(cfg.ExcludedPublicKeys) == 0 || cfg.Discovery != instance.discovery {
						t.Error("replacement lost exclusions or shared discovery")
					}
					return nil, errors.New("all targets excluded")
				}
			}
			for _, when := range []time.Time{now, now.Add(relayFreshnessGrace)} {
				if err := handle.checkFreshness(handle.ctx, session, 1, when); err != nil {
					t.Fatal(err)
				}
			}
			state, err := instance.RoomState(keyText(handle.key))
			if err != nil || state["freshness"].(map[string]any)["status"] != "stale" || !handle.isCurrentSession(session, 1) {
				t.Fatalf("last relay did not remain readable as stale: %#v %v", state, err)
			}
			if _, _, err := instance.Timeline(handle.ctx, handle.key, 0, 10); err != nil {
				t.Fatal(err)
			}
			if mode == "direct" {
				readKey, _ := ephemeralReadKey()
				fallback, err := replica.DialRoom(handle.ctx, replica.Config{RoomID: handle.key, NodeKey: readKey,
					DirectAddress: instance.directAddress, DirectPublic: instance.directPublic,
					ExcludedPublicKeys: [][]byte{instance.directPublic}, AllowExcluded: true})
				if err != nil {
					t.Fatalf("direct-mode excluded fallback disappeared: %v", err)
				}
				fallback.Close()
			}
		})
	}
}

func TestFreshnessConflictDoesNotBlameRelayOrRepeatNotifications(t *testing.T) {
	instance, handle, authority, _, events := freshnessTestRoom(t)
	session, now := handle.session, time.Now()
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	for len(instance.events) > 0 {
		<-instance.events
	}
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(time.Second)); err != nil || len(instance.events) != 0 {
		t.Fatalf("unchanged verification emitted a notification: %v", err)
	}
	authority.setEvents(events[0])
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	authority.setEvents()
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.reason != "checkpoint_conflict" || len(handle.excludedRelays) != 0 || !handle.isCurrentSession(session, 1) {
		t.Fatal("authority conflict was attributed to the relay")
	}
}

func TestFreshnessHistoryWaitIsBounded(t *testing.T) {
	_, handle, _, _, _ := freshnessTestRoom(t)
	handle.historyMu.Lock()
	defer handle.historyMu.Unlock()
	ctx, cancel := context.WithTimeout(handle.ctx, 30*time.Millisecond)
	defer cancel()
	if err := handle.lockFreshnessHistory(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("history wait ignored deadline: %v", err)
	}
}

func TestFreshnessUsesDifferentEphemeralKeys(t *testing.T) {
	_, handle, _, _, _ := freshnessTestRoom(t)
	dial := handle.dialSequencer
	var previous []byte
	handle.dialSequencer = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		public := cfg.NodeKey.Public().(ed25519.PublicKey)
		if bytes.Equal(previous, public) {
			t.Error("authority probes reused an ephemeral identity")
		}
		previous = append([]byte(nil), public...)
		return dial(ctx, cfg)
	}
	for index := 0; index < 2; index++ {
		if err := handle.checkFreshness(handle.ctx, handle.session, 1, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFreshnessReplacementMustReachCheckpoint(t *testing.T) {
	for _, caughtUp := range []bool{false, true} {
		t.Run(fmt.Sprint(caughtUp), func(t *testing.T) {
			instance, handle, authority, _, events := freshnessTestRoom(t)
			authority.setEvents(events[0])
			old, now := handle.session, time.Now()
			if err := handle.checkFreshness(handle.ctx, old, 1, now); err != nil {
				t.Fatal(err)
			}
			server := &freshnessTestServer{role: community.NodeRoleRelay}
			if caughtUp {
				server.setEvents(events[0])
			}
			key := clientTestPrivateKey(t)
			endpoint := freshnessTestEndpoint(t, key, old.Genesis, handle.state.State, server)
			var candidate *replica.Session
			handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
				cfg.DirectAddress, cfg.DirectPublic = endpoint, key.Public().(ed25519.PublicKey)
				var err error
				candidate, err = replica.DialRoom(ctx, cfg)
				return candidate, err
			}
			if err := handle.checkFreshness(handle.ctx, old, 1, now.Add(relayFreshnessGrace)); err != nil {
				t.Fatal(err)
			}
			if candidate == nil {
				t.Fatal("replacement was not attempted")
			}
			if caughtUp {
				if handle.session != candidate || handle.freshness.status != "verified" || handle.verifiedHead != 1 {
					t.Fatal("caught-up replacement was not installed")
				}
				select {
				case <-old.Done:
				case <-time.After(time.Second):
					t.Fatal("displaced connection leaked")
				}
			} else {
				if handle.session != old || handle.freshness.status != "stale" {
					t.Fatal("equally stale replacement displaced the readable session")
				}
				select {
				case <-candidate.Done:
				case <-time.After(time.Second):
					t.Fatal("rejected candidate leaked")
				}
			}
			if _, err := instance.RoomState(keyText(handle.key)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFreshnessCloseDuringReplacementClosesOldConnection(t *testing.T) {
	instance, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	old, now := handle.session, time.Now()
	if err := handle.checkFreshness(handle.ctx, old, 1, now); err != nil {
		t.Fatal(err)
	}
	server := &freshnessTestServer{role: community.NodeRoleRelay, eventDelay: 200 * time.Millisecond, onEvents: make(chan struct{}, 1)}
	server.setEvents(events[0])
	key := clientTestPrivateKey(t)
	endpoint := freshnessTestEndpoint(t, key, old.Genesis, handle.state.State, server)
	handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		cfg.DirectAddress, cfg.DirectPublic = endpoint, key.Public().(ed25519.PublicKey)
		return replica.DialRoom(ctx, cfg)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = handle.checkFreshness(handle.ctx, old, 1, now.Add(relayFreshnessGrace)) }()
	select {
	case <-server.onEvents:
	case <-handle.ctx.Done():
		t.Fatal("replacement did not start")
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("replacement ignored shutdown")
	}
	select {
	case <-old.Done:
	case <-time.After(time.Second):
		t.Fatal("old session leaked during replacement shutdown")
	}
}

func TestFreshnessUnchangedStaleChecksDoNotNotify(t *testing.T) {
	instance, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	for _, when := range []time.Time{now, now.Add(relayFreshnessGrace)} {
		if err := handle.checkFreshness(handle.ctx, session, 1, when); err != nil {
			t.Fatal(err)
		}
	}
	for len(instance.events) > 0 {
		<-instance.events
	}
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(2*relayFreshnessGrace)); err != nil || len(instance.events) != 0 {
		t.Fatalf("unchanged stale repair emitted duplicate state: %d %v", len(instance.events), err)
	}
}

func TestFreshnessWorkerChecksAcrossSessionChanges(t *testing.T) {
	_, handle, _, _, _ := freshnessTestRoom(t)
	original := handle.session
	t.Cleanup(original.Close)
	ctx, cancel := context.WithCancel(handle.ctx)
	defer cancel()
	checked := make(chan struct{}, 1)
	dial := handle.dialSequencer
	handle.dialSequencer = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		select {
		case checked <- struct{}{}:
		default:
		}
		return dial(ctx, cfg)
	}
	handle.nextFreshnessAt = time.Now().Add(60 * time.Millisecond)
	done := make(chan struct{})
	go func() { defer close(done); handle.freshnessLoop(ctx) }()
	for index := 0; index < 2; index++ {
		time.Sleep(20 * time.Millisecond)
		reconnected := &replica.Session{Genesis: original.Genesis, Peer: original.Peer, Done: original.Done}
		if err := handle.installSession(reconnected, handle.client.key, 1); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-checked:
	case <-time.After(time.Second):
		t.Fatal("session changes postponed the room's due check")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("freshness worker ignored cancellation")
	}
}
