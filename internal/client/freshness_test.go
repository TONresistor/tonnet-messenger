package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

type freshnessTestServer struct {
	mu           sync.Mutex
	events       []community.CommittedEvent
	role         int32
	headLimit    int64
	stateError   bool
	eventDelay   time.Duration
	onEvents     chan struct{}
	eventGate    <-chan struct{}
	pageLimit    int
	beforeEvents func(community.GetEvents)
	beforeState  func()
	onGenesis    func(*roomnet.Peer)
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
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(query *roomnet.Query) error {
			server.mu.Lock()
			defer server.mu.Unlock()
			switch req := query.Data.(type) {
			case community.GetRoomGenesis:
				if server.onGenesis != nil {
					server.onGenesis(peer)
				}
				return query.Answer(genesis)
			case community.GetRoomState:
				if server.beforeState != nil {
					server.beforeState()
				}
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
				if server.beforeEvents != nil {
					server.beforeEvents(req)
				}
				select {
				case server.onEvents <- struct{}{}:
				default:
				}
				if server.eventGate != nil {
					<-server.eventGate
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
				if server.pageLimit > 0 && server.pageLimit < limit {
					limit = server.pageLimit
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

func freshnessTestRoom(t *testing.T, eventCount ...int) (*Client, *roomHandle, *freshnessTestServer, *freshnessTestServer, []community.CommittedEvent) {
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
	count := 3
	if len(eventCount) > 0 {
		count = eventCount[0]
	}
	for seqno := int64(1); seqno <= int64(count); seqno++ {
		nonce := make([]byte, 32)
		binary.LittleEndian.PutUint64(nonce, uint64(seqno))
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
		if err := handle.installSession(session, instance.key, 1, handle.session); err != nil {
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
	var authorityCtx context.Context
	budgets := 0
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		if budget == freshnessTimeout {
			budgets++
			if budgets == 2 {
				if authorityCtx.Err() != context.Canceled {
					t.Fatal("authority work still owns the repair budget")
				}
			} else {
				var cancel context.CancelFunc
				authorityCtx, cancel = context.WithTimeout(ctx, budget)
				return authorityCtx, cancel
			}
		}
		return context.WithTimeout(ctx, budget)
	}
	relay.setEvents(events[0])
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(relayFreshnessGrace)); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.status != "verified" || !handle.isCurrentSession(session, 1) || len(handle.excludedRelays) != 0 {
		t.Fatal("slow authority caused an honest relay to be rejected")
	}
	if budgets < 2 {
		t.Fatalf("authority and repair did not get independent budgets: %d", budgets)
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
				if !handle.historyMu.TryLock() {
					t.Fatal("candidate dial blocks history ingestion")
				}
				handle.historyMu.Unlock()
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
				connected := false
				for len(instance.events) > 0 {
					notice := <-instance.events
					if notice.Method == "room.connection" {
						params := notice.Params.(map[string]any)
						if params["status"] != "connected" || params["connection"] == nil {
							t.Fatal("replacement reported disconnected")
						}
						connected = true
					}
				}
				if !connected {
					t.Fatal("replacement did not emit connected")
				}
				// This is the run loop's disconnect decision after old.Done wakes it.
				if handle.closeSessionIf(old) || handle.session != candidate {
					t.Fatal("retired session closure was treated as a disconnect")
				}
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
		if err := handle.installSession(reconnected, handle.client.key, 1, handle.session); err != nil {
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

func TestFreshnessRetainsHeadWhenRelayFlapsDuringProbe(t *testing.T) {
	_, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	old, now := handle.session, time.Now()
	t.Cleanup(old.Close)
	dial := handle.dialSequencer
	var replacement *replica.Session
	handle.dialSequencer = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		result, err := dial(ctx, cfg)
		replacement = &replica.Session{Genesis: old.Genesis, Peer: old.Peer, Done: old.Done}
		if installErr := handle.installSession(replacement, handle.client.key, 1, handle.session); installErr != nil {
			t.Fatal(installErr)
		}
		return result, err
	}
	if err := handle.checkFreshness(handle.ctx, old, 1, now); !errors.Is(err, errRoomSessionChanged) {
		t.Fatalf("expected displaced session: %v", err)
	}
	if handle.freshness.latest == nil || handle.freshness.pending == nil || !handle.freshness.pending.observed.Equal(now) {
		t.Fatal("authenticated evidence was lost during reconnect")
	}
	if err := handle.checkFreshness(handle.ctx, replacement, 1, now.Add(relayFreshnessGrace)); !errors.Is(err, errRoomSessionChanged) {
		t.Fatalf("second flapping session: %v", err)
	}
	if handle.freshness.status != "stale" || len(handle.excludedRelays) != 1 {
		t.Fatal("flapping identity was not judged against retained checkpoint")
	}
}

func TestFreshnessSlotTimeoutIsNotSequencerFailure(t *testing.T) {
	_, handle, _, _, _ := freshnessTestRoom(t)
	handle.freshness.failures = 2
	for i := 0; i < cap(handle.client.freshnessChecks); i++ {
		handle.client.freshnessChecks <- struct{}{}
	}
	defer func() {
		for len(handle.client.freshnessChecks) > 0 {
			<-handle.client.freshnessChecks
		}
	}()
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		if budget != freshnessLockTimeout {
			t.Fatal("authority was contacted without a slot")
		}
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		return ctx, cancel
	}
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.failures != 2 || handle.freshness.reason != "check_busy" {
		t.Fatal("local queue contention counted as sequencer failure")
	}
}

func TestFreshnessBusyHistoryStillDetectsBehindRelay(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now := time.Now()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now); err != nil {
		t.Fatal(err)
	}
	// A real gap-sync request owns historyMu while the relay withholds its page.
	gate := make(chan struct{})
	defer func() {
		if gate != nil {
			close(gate)
		}
	}()
	onEvents := make(chan struct{}, 1)
	relay.mu.Lock()
	relay.eventGate, relay.onEvents = gate, onEvents
	relay.mu.Unlock()
	waits := 0
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		if budget == freshnessLockTimeout {
			waits++
			if waits == 2 { // First wait is the global slot, second is historyMu.
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				return ctx, cancel
			}
		}
		return context.WithTimeout(ctx, budget)
	}
	done := make(chan error, 1)
	go func() { _, err := handle.processCanonical(handle.ctx, handle.session, 1, events[2]); done <- err }()
	select {
	case <-onEvents:
	case <-handle.ctx.Done():
		t.Fatal("gap sync did not request a page")
	}
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now.Add(catchupSlack+catchupRecovery+time.Second)); err != nil {
		t.Fatal(err)
	}
	handle.mu.RLock()
	stale := handle.freshness.status == "stale" && len(handle.excludedRelays) == 1 && handle.freshness.failures == 0
	handle.mu.RUnlock()
	if !stale {
		t.Fatal("history lock concealed proven lag or increased authority backoff")
	}
	close(gate)
	gate = nil
	select {
	case <-done:
	case <-handle.ctx.Done():
		t.Fatal("gap sync did not release historyMu")
	}
}

func TestFreshnessGapSyncHasOverallBudget(t *testing.T) {
	_, handle, _, relay, events := freshnessTestRoom(t)
	relay.setEvents(events...)
	calls := 0
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		calls++
		if budget != freshnessRepairTimeout {
			t.Fatalf("unexpected gap budget: %v", budget)
		}
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		return ctx, cancel
	}
	_, err := handle.processCanonical(handle.ctx, handle.session, 1, events[2])
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("unbounded gap sync: calls=%d err=%v", calls, err)
	}
}

func TestFreshnessConflictRecoversWithoutDiscardingCheckpoint(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	relay.setEvents(events[0])
	now := time.Now()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now); err != nil {
		t.Fatal(err)
	}
	authority.setEvents()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.reason != "checkpoint_conflict" {
		t.Fatal("rollback not detected")
	}
	authority.setEvents(events[0])
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now.Add(relayFreshnessGrace)); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.status != "verified" || handle.freshness.latest.seqno != 1 {
		t.Fatal("consistent checkpoint did not recover")
	}
}

func TestFreshnessTwentyMinuteBacklogAtMinimumRateIsNotCut(t *testing.T) {
	instance, handle, authority, relay, events := freshnessTestRoom(t, 1200)
	authority.setEvents(events...)
	now := time.Now()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now); err != nil {
		t.Fatal(err)
	}
	handle.closeSession()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	handle.syncNow = func() time.Time { return time.Unix(0, clock.Load()) }
	consumeCtx, cancel := context.WithCancel(handle.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case _, ok := <-instance.events:
				if !ok {
					return
				}
			case <-consumeCtx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); <-done }()
	relay.setEvents(events...)
	relay.mu.Lock()
	relay.beforeEvents = func(req community.GetEvents) {
		if req.Limit <= catchupPageLimit || req.Limit > maxCatchupPageLimit {
			t.Errorf("unexpected adaptive page size: %d", req.Limit)
		}
		clock.Store(now.Add(time.Duration(req.AfterSeqno+int64(req.Limit)) * time.Second).UnixNano())
		if req.AfterSeqno > 0 {
			handle.mu.RLock()
			session, epoch := handle.session, handle.sessionEpoch
			handle.mu.RUnlock()
			if err := handle.busyFreshness(handle.ctx, session, epoch, "history_busy", handle.syncTime()); err != nil {
				t.Error(err)
			}
		}
	}
	relay.mu.Unlock()
	if err := handle.connect(handle.ctx); err != nil {
		t.Fatal(err)
	}
	if handle.session == nil || handle.verifiedHead != 1200 || len(handle.excludedRelays) != 0 {
		t.Fatal("honest minimum-rate backlog was cut")
	}
	if handle.freshness.status == "verified" {
		t.Fatal("progress alone became a freshness verification")
	}
	if handle.freshness.rate.credits != 1200 || !handle.freshness.rate.recoveryUntil.IsZero() {
		t.Fatal("minimum-rate delivery consumed recovery")
	}
}

func TestFreshnessBelowMinimumRateIsCut(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t, 200)
	authority.setEvents(events...)
	now := time.Now()
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, now); err != nil {
		t.Fatal(err)
	}
	handle.closeSession()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	handle.syncNow = func() time.Time { return time.Unix(0, clock.Load()) }
	relay.setEvents(events...)
	relay.mu.Lock()
	relay.pageLimit = 1
	relay.beforeEvents = func(req community.GetEvents) {
		clock.Store(now.Add(time.Duration(req.AfterSeqno+1) * 10 * time.Second).UnixNano())
	}
	relay.mu.Unlock()
	if err := handle.connect(handle.ctx); err != nil {
		t.Fatal(err)
	}
	if handle.session == nil || len(handle.excludedRelays) != 1 || handle.freshness.status != "stale" || !handle.freshness.rate.failed {
		t.Fatal("below-rate relay was not excluded with a readable stale fallback")
	}
}

func TestFreshnessRateCreditsAreUniqueAndBoundedByH(t *testing.T) {
	instance := directTestClient(t)
	now := time.Now()
	handle := &roomHandle{client: instance, syncNow: func() time.Time { return now }}
	handle.ensureCatchupLocked(3, 0, now)
	progress := handle.beginRoomSync(&replica.Session{})
	handle.advanceRoomSync(progress, 1)
	handle.advanceRoomSync(progress, 1)   // replay
	handle.ensureCatchupLocked(3, 2, now) // known cache, not a new arrival
	handle.advanceRoomSync(progress, 2)
	handle.advanceRoomSync(progress, 3)
	handle.advanceRoomSync(progress, 4) // beyond fixed H
	if handle.freshness.rate.credits != 2 || handle.freshness.rate.target != 3 {
		t.Fatal("replay/known/after-H event earned credit")
	}
}

func TestFreshnessRecoveryIsSharedAndSuccessorCanRepayDebt(t *testing.T) {
	instance := directTestClient(t)
	now := time.Now()
	clock := now.Add(70 * time.Second)
	handle := &roomHandle{client: instance, syncNow: func() time.Time { return clock }}
	budget := handle.ensureCatchupLocked(1000, 0, now)
	first := handle.beginRoomSync(&replica.Session{})
	handle.advanceRoomSync(first, 1) // deficit starts recovery at t=60, ending t=120
	if !budget.recoveryUntil.Equal(now.Add(120 * time.Second)) {
		t.Fatal("recovery was rebased to detection time")
	}
	handle.endRoomSync(first)
	second := handle.beginRoomSync(&replica.Session{})
	for seqno := int64(2); seqno <= 11; seqno++ {
		handle.advanceRoomSync(second, seqno)
	}
	if !budget.baseDeadline().After(clock) {
		t.Fatal("honest successor did not repay deficit")
	}
	handle.endRoomSync(second)
	for i := 0; i < 10; i++ {
		progress := handle.beginRoomSync(&replica.Session{})
		handle.ensureCatchupLocked(2000, handle.receivedHead, clock)
		handle.endRoomSync(progress)
	}
	if budget.target != 1000 || !budget.started.Equal(now) || !budget.recoveryUntil.Equal(now.Add(120*time.Second)) {
		t.Fatal("flapping/newer heads reset the shared budget")
	}
	if _, err := budget.deadline(now.Add(121 * time.Second)); !errors.Is(err, errCatchupRate) {
		t.Fatal("second recovery window was granted")
	}
	budget.credits = int64(^uint64(0) >> 1)
	if budget.baseDeadline().Before(now) {
		t.Fatal("credit duration overflowed")
	}
}

func TestFreshnessBusyRelayIsLeftAndAnotherRelayConnects(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, original := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, original, 1, now); err != nil {
		t.Fatal(err)
	}
	handle.closeSession()
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	requested := make(chan struct{}, 1)
	relay.mu.Lock()
	relay.eventGate, relay.onEvents = gate, requested
	relay.mu.Unlock()
	dialed := make(chan *replica.Session, 1)
	handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		session, err := replica.DialRoom(ctx, cfg)
		if err == nil {
			dialed <- session
		}
		return session, err
	}
	done := make(chan error, 1)
	go func() { done <- handle.connect(handle.ctx) }()
	var slow *replica.Session
	select {
	case slow = <-dialed:
	case <-handle.ctx.Done():
		t.Fatal("initial dial did not start")
	}
	select {
	case <-requested:
	case <-handle.ctx.Done():
		t.Fatal("sync did not start")
	}
	key := clientTestPrivateKey(t)
	server := &freshnessTestServer{role: community.NodeRoleRelay}
	server.setEvents(events[0])
	endpoint := freshnessTestEndpoint(t, key, original.Genesis, handle.state.State, server)
	handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		release.Do(func() { close(gate) })
		cfg.DirectAddress, cfg.DirectPublic = endpoint, key.Public().(ed25519.PublicKey)
		return replica.DialRoom(ctx, cfg)
	}
	if err := handle.busyFreshness(handle.ctx, slow, 1, "history_busy", now.Add(catchupSlack+catchupRecovery+time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-handle.ctx.Done():
		t.Fatal("initial sync retained history lock")
	}
	if handle.session == nil || handle.session == slow || handle.verifiedHead != 1 {
		t.Fatal("honest replacement was not installed")
	}
	select {
	case <-slow.Done:
	case <-handle.ctx.Done():
		t.Fatal("displaced stale connection leaked")
	}
}

func TestFreshnessChecksSeveralRoomsConcurrently(t *testing.T) {
	var shared chan struct{}
	entered, release := make(chan struct{}, maxFreshnessChecks), make(chan struct{})
	defer close(release)
	var workers sync.WaitGroup
	cancels := make([]context.CancelFunc, 0, maxFreshnessChecks)
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
		workers.Wait()
	}()
	for i := 0; i < maxFreshnessChecks; i++ {
		_, handle, _, _, _ := freshnessTestRoom(t)
		if shared == nil {
			shared = handle.client.freshnessChecks
		}
		handle.client.freshnessChecks = shared
		dial := handle.dialSequencer
		handle.dialSequencer = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
			entered <- struct{}{}
			select {
			case <-release:
				return dial(ctx, cfg)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		ctx, cancel := context.WithCancel(handle.ctx)
		cancels = append(cancels, cancel)
		workers.Add(1)
		go func() { defer workers.Done(); _ = handle.checkFreshness(ctx, handle.session, 1, time.Now()) }()
	}
	for i := 0; i < maxFreshnessChecks; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("room checks were serialized")
		}
	}
	if len(shared) != maxFreshnessChecks {
		t.Fatalf("unexpected authority concurrency: %d", len(shared))
	}
}

func TestFreshnessReconnectNotifiesAfterSecondQuickDrop(t *testing.T) {
	instance, handle, _, _, _ := freshnessTestRoom(t)
	for len(instance.events) > 0 {
		<-instance.events
	}
	ctx, cancel := context.WithCancel(handle.ctx)
	dialEntered := make(chan struct{}, 1)
	dialRelease := make(chan struct{}, 1)
	handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		dialEntered <- struct{}{}
		select {
		case <-dialRelease:
			return replica.DialRoom(ctx, cfg)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	first, done := make(chan error), make(chan struct{})
	go func() { defer close(done); handle.run(ctx, first) }()
	defer func() { cancel(); <-done }()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	waitStatus := func(want string) {
		t.Helper()
		for {
			select {
			case notice := <-instance.events:
				if notice.Method == "room.connection" && notice.Params.(map[string]any)["status"] == want {
					return
				}
			case <-handle.ctx.Done():
				t.Fatalf("missing %s notice", want)
			}
		}
	}
	for drop := 0; drop < 2; drop++ {
		handle.mu.RLock()
		current := handle.session
		handle.mu.RUnlock()
		handle.closeSessionIf(current)
		select {
		case <-dialEntered:
		case <-handle.ctx.Done():
			t.Fatal("reconnect did not start")
		}
		waitStatus("reconnecting")
		dialRelease <- struct{}{}
		waitStatus("connected")
	}
}

func TestFreshnessConnectCannotOverwriteReplacement(t *testing.T) {
	_, handle, _, _, _ := freshnessTestRoom(t)
	genesis, state := handle.session.Genesis, handle.state.State
	handle.closeSession()
	dialed, release := make(chan *replica.Session, 1), make(chan struct{})
	handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		session, err := replica.DialRoom(ctx, cfg)
		if err != nil {
			return nil, err
		}
		dialed <- session
		select {
		case <-release:
			return session, nil
		case <-ctx.Done():
			session.Close()
			return nil, ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { done <- handle.connect(handle.ctx) }()
	var loser *replica.Session
	select {
	case loser = <-dialed:
	case <-handle.ctx.Done():
		t.Fatal("reconnect not started")
	}
	key := clientTestPrivateKey(t)
	endpoint := freshnessTestEndpoint(t, key, genesis, state, &freshnessTestServer{role: community.NodeRoleRelay})
	winner, err := replica.DialRoom(handle.ctx, replica.Config{RoomID: handle.key, NodeKey: handle.client.key, DirectAddress: endpoint, DirectPublic: key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	handle.historyMu.Lock()
	err = handle.installSession(winner, handle.client.key, 1, nil)
	handle.historyMu.Unlock()
	if err != nil {
		winner.Close()
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-handle.ctx.Done():
		t.Fatal("losing reconnect did not finish")
	}
	if handle.session != winner {
		t.Fatal("reconnect overwrote winning replacement")
	}
	select {
	case <-loser.Done:
	case <-handle.ctx.Done():
		t.Fatal("losing reconnect leaked")
	}
	select {
	case <-winner.Done:
		t.Fatal("winning replacement was closed")
	default:
	}
	if err := handle.installSession(loser, handle.client.key, 1, nil); !errors.Is(err, errRoomSessionChanged) {
		t.Fatal("session installation did not compare expected pointer")
	}
}

func TestFreshnessBusyClosureDoesNotWaitForNotifications(t *testing.T) {
	instance, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	for len(instance.events) < cap(instance.events) {
		instance.events <- Notification{}
	}
	done := make(chan error, 1)
	go func() {
		done <- handle.busyFreshness(handle.ctx, session, 1, "history_busy", now.Add(catchupSlack+catchupRecovery+time.Second))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale closure waits for notification delivery")
	}
	if !handle.isCurrentSession(session, 1) {
		t.Fatal("last readable fallback was dropped")
	}
	state, err := instance.RoomState(keyText(handle.key))
	if err != nil || state["freshness"].(map[string]any)["status"] != "stale" {
		t.Fatalf("stale state was lost: %#v %v", state, err)
	}
}

func TestFreshnessRetainedDeadlineAppliesWhenSequencerIsUnavailable(t *testing.T) {
	_, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	handle.dialSequencer = func(context.Context, replica.Config) (*replica.Session, error) {
		return nil, errors.New("sequencer unreachable")
	}
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(catchupSlack+catchupRecovery+time.Second)); err != nil {
		t.Fatal(err)
	}
	if handle.session != session || handle.freshness.status != "stale" || len(handle.excludedRelays) != 1 {
		t.Fatal("authority failure erased alarm or lost the readable fallback")
	}
}

func TestFreshnessFinalizationFreezesJAndHasBoundedBudget(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t, 4)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	relay.setEvents(events...)
	relay.mu.Lock()
	relay.headLimit = 2
	var cursors []int64
	relay.beforeEvents = func(req community.GetEvents) {
		cursors = append(cursors, req.AfterSeqno)
		if req.AfterSeqno == 1 {
			relay.headLimit = 4
		} // head moves AFTER J=2 was captured
	}
	relay.mu.Unlock()
	finalizations := 0
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		if budget == freshnessRepairTimeout {
			finalizations++
		}
		return context.WithTimeout(ctx, budget)
	}
	if err := handle.syncSessionLocked(handle.ctx, session, 1); err != nil {
		t.Fatal(err)
	}
	if handle.verifiedHead != 2 || handle.freshness.rate.target != 1 || handle.freshness.rate.credits != 1 || finalizations != 1 {
		t.Fatal("moving state head extended H/finalization or earned credit")
	}
	relay.mu.Lock()
	gotCursors := append([]int64(nil), cursors...)
	relay.mu.Unlock()
	if len(gotCursors) != 2 || gotCursors[0] != 0 || gotCursors[1] != 1 {
		t.Fatalf("followed moving HasMore: %v", gotCursors)
	}
}

func TestFreshnessFinalizationFailureNeverVerifies(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	session := handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	relay.setEvents(events[0])
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		if budget == freshnessRepairTimeout {
			return context.WithDeadline(ctx, time.Unix(0, 0))
		}
		return context.WithTimeout(ctx, budget)
	}
	if err := handle.syncSessionLocked(handle.ctx, session, 1); err == nil {
		t.Fatal("expired finalization succeeded")
	}
	record, err := handle.client.store.room(handle.ctx, handle.key)
	if err != nil || record.HeadSeqno != 1 || handle.verifiedHead != 0 || handle.freshness.status == "verified" {
		t.Fatal("persisted H was mistaken for applied verification")
	}
}

func TestFreshnessUnavailableSequencerRepairsMissedBroadcast(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	relay.setEvents(events[0])
	handle.dialSequencer = func(context.Context, replica.Config) (*replica.Session, error) { return nil, errors.New("unreachable") }
	if err := handle.checkFreshness(handle.ctx, session, 1, now.Add(relayFreshnessGrace)); err != nil {
		t.Fatal(err)
	}
	if !handle.isCurrentSession(session, 1) || handle.verifiedHead != 1 || len(handle.excludedRelays) != 0 {
		t.Fatal("honest missed broadcast was closed before repair")
	}
	if handle.freshness.status != "unverified" || handle.freshness.reason != "sequencer_unavailable" {
		t.Fatal("repair hid unavailable authority or manufactured verification")
	}
}

func TestFreshnessReconnectClosesExactSameIdentitySession(t *testing.T) {
	_, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, old := time.Now(), handle.session
	t.Cleanup(old.Close)
	if err := handle.checkFreshness(handle.ctx, old, 1, now); err != nil {
		t.Fatal(err)
	}
	instance := handle.client
	replacement, err := replica.DialRoom(handle.ctx, replica.Config{RoomID: handle.key, NodeKey: instance.key, DirectAddress: instance.directAddress, DirectPublic: instance.directPublic})
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.installSession(replacement, instance.key, 1, old); err != nil {
		replacement.Close()
		t.Fatal(err)
	}
	head := *handle.freshness.latest
	if err := handle.recordFreshnessHead(&head, old, 1, now.Add(relayFreshnessGrace)); err != nil {
		t.Fatal(err)
	}
	if handle.session != nil || handle.freshness.status != "stale" {
		t.Fatal("same-identity reconnect was not retired in the recording path")
	}
	select {
	case <-replacement.Done:
	case <-handle.ctx.Done():
		t.Fatal("retired replacement remained open")
	}
}

func TestFreshnessExpiredBudgetDoesNotBrickRoom(t *testing.T) {
	instance, handle, authority, relay, events := freshnessTestRoom(t, 5)
	authority.setEvents(events[:3]...)
	now, old := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, old, 1, now); err != nil {
		t.Fatal(err)
	}
	handle.mu.Lock()
	oldBudget := handle.ensureCatchupLocked(3, 0, now, old)
	handle.mu.Unlock()
	handle.closeSession()
	clock := now.Add(3 * time.Minute)
	handle.syncNow = func() time.Time { return clock }
	handle.mu.Lock()
	handle.rejectRelayLocked(old, oldBudget, clock)
	handle.mu.Unlock()
	relay.setEvents(events[:3]...)
	if err := handle.connect(handle.ctx); err != nil {
		t.Fatal(err)
	}
	if !handle.freshness.rate.failed || handle.freshness.status != "stale" || handle.session == nil {
		t.Fatal("excluded reconnect reset its budget or lost fallback")
	}
	handle.closeSession()
	authority.setEvents(events...)
	key := clientTestPrivateKey(t)
	honest := &freshnessTestServer{role: community.NodeRoleRelay}
	honest.setEvents(events...)
	endpoint := freshnessTestEndpoint(t, key, old.Genesis, handle.state.State, honest)
	handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		cfg.DirectAddress, cfg.DirectPublic = endpoint, key.Public().(ed25519.PublicKey)
		return replica.DialRoom(ctx, cfg)
	}
	if err := handle.connect(handle.ctx); err != nil {
		t.Fatal(err)
	}
	if handle.verifiedHead != 5 || handle.freshness.rate == oldBudget || handle.freshness.status != "stale" {
		t.Fatal("old budget condemned a new honest relay or hid alarm")
	}
	if _, _, err := instance.Timeline(handle.ctx, handle.key, 0, 10); err != nil {
		t.Fatal(err)
	}
	if err := handle.checkFreshness(handle.ctx, handle.session, 1, clock); err != nil {
		t.Fatal(err)
	}
	if handle.freshness.status != "verified" {
		t.Fatal("honest relay did not complete validation")
	}
}

func TestRelayReplacementReceivesDMDuringGenesis(t *testing.T) {
	for _, failCandidate := range []bool{false, true} {
		t.Run(fmt.Sprintf("candidate_failure_%v", failCandidate), func(t *testing.T) {
			instance, handle, _, _, _ := freshnessTestRoom(t, 0)
			old := handle.session
			if err := handle.checkFreshness(handle.ctx, old, 1, time.Now()); err != nil {
				t.Fatal(err)
			}
			sender, candidateKey := clientTestPrivateKey(t), clientTestPrivateKey(t)
			box, err := dm.SealForRoom(handle.key, sender, instance.key.Public().(ed25519.PublicKey), []byte("during handoff"))
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().Unix()
			direct, err := community.SignDirectMessage(sender, community.DirectMessage{RoomID: handle.key, ToKey: instance.key.Public().(ed25519.PublicKey), Timestamp: now, Ciphertext: box})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := community.Encode(direct)
			if err != nil {
				t.Fatal(err)
			}
			wrapper, err := broadcast.Sign(sender, nil, raw, now)
			if err != nil {
				t.Fatal(err)
			}
			received := make(chan struct{}, 1)
			server := &freshnessTestServer{role: community.NodeRoleRelay, stateError: failCandidate, onGenesis: func(peer *roomnet.Peer) {
				if err := peer.SendMessage(handle.ctx, wrapper); err != nil {
					t.Error(err)
				}
				select {
				case <-received:
				case <-handle.ctx.Done():
					t.Error("candidate did not receive the message during genesis")
				}
			}}
			endpoint := freshnessTestEndpoint(t, candidateKey, old.Genesis, handle.state.State, server)
			handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
				cfg.DirectAddress, cfg.DirectPublic = endpoint, candidateKey.Public().(ed25519.PublicKey)
				factory := cfg.OnPeer
				cfg.OnPeer = func(peer *roomnet.Peer) func(any) error {
					handler := factory(peer)
					return func(message any) error {
						err := handler(message)
						select {
						case received <- struct{}{}:
						default:
						}
						return err
					}
				}
				return replica.DialRoom(ctx, cfg)
			}
			if err := handle.replaceStaleRelay(handle.ctx, old, 1, time.Now()); err != nil {
				t.Fatal(err)
			}
			if (handle.session == old) != failCandidate {
				t.Fatal("unexpected candidate installation")
			}
			for {
				select {
				case notice := <-instance.events:
					if notice.Method == "dm.message" {
						if notice.Params.(map[string]any)["text"] != "during handoff" {
							t.Fatal("wrong message")
						}
						return
					}
				case <-handle.ctx.Done():
					t.Fatal("message during handoff was lost")
				}
			}
		})
	}
}

func TestFreshnessHonestFinalizationIsProtectedAfterH(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	handle.syncNow = func() time.Time { return time.Unix(0, clock.Load()) }
	relay.setEvents(events[0])
	relay.mu.Lock()
	relay.beforeEvents = func(community.GetEvents) { clock.Store(now.Add(60 * time.Second).UnixNano()) }
	relay.beforeState = func() {
		clock.Store(now.Add(65 * time.Second).UnixNano())
		if err := handle.busyFreshness(handle.ctx, session, 1, "history_busy", handle.syncTime()); err != nil {
			t.Error(err)
		}
		if !handle.isCurrentSession(session, 1) {
			t.Error("honest finalization was closed after H")
		}
	}
	relay.mu.Unlock()
	if err := handle.syncSessionLocked(handle.ctx, session, 1); err != nil {
		t.Fatal(err)
	}
	if handle.verifiedHead != 1 || len(handle.excludedRelays) != 0 {
		t.Fatal("bounded finalization failed to apply")
	}
}

func TestFreshnessOfflineTimeDoesNotCondemnNextRelay(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events...)
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	clock := now
	handle.syncNow = func() time.Time { return clock }
	progress := handle.beginRoomSync(session)
	handle.mu.Lock()
	budget := handle.ensureCatchupLocked(3, 0, now, session)
	handle.mu.Unlock()
	handle.endRoomSync(progress)
	handle.closeSession()
	clock = now.Add(time.Hour)
	relay.setEvents(events...)
	if err := handle.connect(handle.ctx); err != nil {
		t.Fatal(err)
	}
	if handle.verifiedHead != 3 || budget.failed || len(handle.excludedRelays) != 0 || !budget.started.Equal(clock) {
		t.Fatal("offline time became a relay deficit")
	}
}

func TestFreshnessPageStallExcludesRelayAndHonestAlternativeRecovers(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events...)
	now, old := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, old, 1, now); err != nil {
		t.Fatal(err)
	}
	handle.closeSession()
	clock := now
	handle.syncNow = func() time.Time { return clock }
	// Inject expiration of the page's deadline, without sleeping ten seconds.
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		if budget == 10*time.Second {
			return context.WithDeadline(ctx, time.Unix(0, 0))
		}
		return context.WithTimeout(ctx, budget)
	}
	if err := handle.connect(handle.ctx); err != nil {
		t.Fatal(err)
	}
	bad := handle.session
	budget := handle.freshness.rate
	until := budget.retryAfter
	if bad == nil || !budget.failed || handle.freshness.status != "stale" {
		t.Fatal("page stall was not quarantined with readable fallback")
	}
	relay.setEvents(events...)
	clock = clock.Add(time.Second)
	if err := handle.syncSessionLocked(handle.ctx, bad, 1); !errors.Is(err, errCatchupRate) {
		t.Fatalf("excluded reconnect resumed: %v", err)
	}
	if !budget.retryAfter.Equal(until) || budget.credits != 0 {
		t.Fatal("excluded peer renewed quarantine or budget")
	}
	handle.freshnessBudget = nil
	key := clientTestPrivateKey(t)
	server := &freshnessTestServer{role: community.NodeRoleRelay}
	server.setEvents(events...)
	endpoint := freshnessTestEndpoint(t, key, bad.Genesis, handle.state.State, server)
	handle.dialRoom = func(ctx context.Context, cfg replica.Config) (*replica.Session, error) {
		cfg.DirectAddress, cfg.DirectPublic = endpoint, key.Public().(ed25519.PublicKey)
		return replica.DialRoom(ctx, cfg)
	}
	if err := handle.replaceStaleRelay(handle.ctx, bad, 1, clock); err != nil {
		t.Fatal(err)
	}
	if handle.session == bad || handle.verifiedHead != 3 || handle.freshness.status != "verified" {
		t.Fatal("honest alternative inherited stalling peer's failure")
	}
}

func TestFreshnessFinalizationDeadlineAndSnapshotSurviveRetries(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	handle.syncNow = func() time.Time { return time.Unix(0, clock.Load()) }
	relay.setEvents(events...)
	var states atomic.Int32
	attemptCtx, cancelAttempt := context.WithCancel(handle.ctx)
	relay.mu.Lock()
	relay.headLimit = 2
	relay.beforeState = func() { states.Add(1) }
	relay.beforeEvents = func(req community.GetEvents) {
		if req.AfterSeqno == 1 {
			clock.Store(now.Add(5 * time.Second).UnixNano())
			cancelAttempt()
		}
	}
	relay.mu.Unlock()
	// A local cancellation is not evidence against the relay, but consumes active finalization time.
	if err := handle.syncSessionLocked(attemptCtx, session, 1); err == nil {
		t.Fatal("canceled attempt succeeded")
	}
	budget := handle.freshness.rate
	if budget.failed || budget.finalState == nil || budget.finalState.Stats.ReplicaSeqno != 2 {
		t.Fatal("frozen state was lost or local cancellation blamed on peer")
	}
	firstDeadline := budget.finalizingUntil
	handle.closeSession()
	clock.Store(now.Add(100 * time.Second).UnixNano()) // offline gap must not consume the remaining allowance
	relay.mu.Lock()
	relay.headLimit = 3
	relay.beforeEvents = nil
	relay.mu.Unlock()
	reconnected, err := replica.DialRoom(handle.ctx, replica.Config{RoomID: handle.key, NodeKey: handle.client.key, DirectAddress: handle.client.directAddress, DirectPublic: handle.client.directPublic})
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.installSession(reconnected, handle.client.key, 1, nil); err != nil {
		reconnected.Close()
		t.Fatal(err)
	}
	if err := handle.syncSessionLocked(handle.ctx, reconnected, 1); err != nil {
		t.Fatal(err)
	}
	if handle.verifiedHead != 2 || states.Load() != 1 || !budget.finalizingUntil.Equal(firstDeadline.Add(95*time.Second)) {
		t.Fatal("retry moved J or renewed its finalization allowance")
	}
}

func TestFreshnessFinalizationStallIsQuarantinedAcrossReconnects(t *testing.T) {
	_, handle, authority, relay, events := freshnessTestRoom(t)
	authority.setEvents(events[0])
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	relay.setEvents(events...)
	relay.mu.Lock()
	relay.headLimit = 3
	relay.mu.Unlock()
	handle.freshnessBudget = func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		if budget == freshnessRepairTimeout {
			return context.WithDeadline(ctx, time.Unix(0, 0))
		}
		return context.WithTimeout(ctx, budget)
	}
	if err := handle.syncSessionLocked(handle.ctx, session, 1); !errors.Is(err, errRelaySync) {
		t.Fatalf("finalization failure was not attributed: %v", err)
	}
	budget := handle.freshness.rate
	deadline, excludedUntil := budget.finalizingUntil, budget.retryAfter
	if !budget.failed || handle.freshness.status != "stale" || handle.verifiedHead != 0 {
		t.Fatal("finalization failure was not stale/excluded")
	}
	if err := handle.syncSessionLocked(handle.ctx, session, 1); !errors.Is(err, errCatchupRate) {
		t.Fatal("excluded retry regained finalization")
	}
	if budget != handle.freshness.rate || !budget.finalizingUntil.Equal(deadline) || !budget.retryAfter.Equal(excludedUntil) {
		t.Fatal("finalization was reset by reconnect")
	}
}

func TestFreshnessNewCheckpointDoesNotClearExistingAlarm(t *testing.T) {
	_, handle, authority, _, events := freshnessTestRoom(t)
	now, session := time.Now(), handle.session
	handle.mu.Lock()
	handle.rejectRelayLocked(session, handle.freshness.rate, now)
	handle.mu.Unlock()
	authority.setEvents(events[0])
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	if !handle.freshness.alarmed || handle.freshness.status != "stale" || handle.freshness.reason != "relay_behind" {
		t.Fatal("new checkpoint hid a prior relay alarm")
	}
}

func TestFreshnessLocalFailuresDoNotExcludeRelay(t *testing.T) {
	for _, failure := range []string{"cancel", "store", "unavailable_store"} {
		t.Run(failure, func(t *testing.T) {
			_, handle, authority, _, events := freshnessTestRoom(t)
			authority.setEvents(events[0])
			now, session := time.Now(), handle.session
			if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
				t.Fatal(err)
			}
			ctx := handle.ctx
			if failure == "unavailable_store" {
				handle.dialSequencer = func(context.Context, replica.Config) (*replica.Session, error) { return nil, errors.New("unreachable") }
			}
			if failure == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			} else {
				handle.client.store.db.Close()
			}
			_ = handle.checkFreshness(ctx, session, 1, now.Add(relayFreshnessGrace))
			if len(handle.excludedRelays) != 0 || handle.freshness.alarmed || !handle.isCurrentSession(session, 1) {
				t.Fatal("local failure was attributed to relay")
			}
		})
	}
}

func TestFreshnessExcludedFallbackSurvivesCanonicalGap(t *testing.T) {
	_, handle, authority, _, events := freshnessTestRoom(t)
	authority.setEvents(events...)
	now, session := time.Now(), handle.session
	if err := handle.checkFreshness(handle.ctx, session, 1, now); err != nil {
		t.Fatal(err)
	}
	handle.mu.Lock()
	budget := handle.ensureCatchupLocked(3, 0, now, session)
	handle.rejectRelayLocked(session, budget, now)
	handle.mu.Unlock()
	handle.events = make(chan canonicalEvent, 1)
	ctx, cancel := context.WithCancel(handle.ctx)
	done := make(chan struct{})
	go func() { defer close(done); handle.ingestLoop(ctx) }()
	defer func() { cancel(); <-done }()
	result := make(chan error, 1)
	handle.events <- canonicalEvent{session: session, epoch: 1, event: events[2], result: result}
	select {
	case err := <-result:
		if !errors.Is(err, errCatchupRate) {
			t.Fatalf("unexpected result: %v", err)
		}
	case <-handle.ctx.Done():
		t.Fatal("gap result missing")
	}
	if !handle.isCurrentSession(session, 1) || handle.freshness.status != "stale" {
		t.Fatal("gap closed last readable excluded fallback")
	}
}

func TestFreshnessQueryPacingMatchesNodeLeafAllowance(t *testing.T) {
	budget, now := &catchupRate{}, time.Now()
	for i := 0; i < 8; i++ {
		if delay := relayQueryDelay(budget, now); delay != 0 {
			t.Fatalf("initial burst delayed: %v", delay)
		}
	}
	if delay := relayQueryDelay(budget, now); delay != 500*time.Millisecond {
		t.Fatalf("query refill = %v", delay)
	}
	if delay := relayQueryDelay(budget, now.Add(500*time.Millisecond)); delay != 0 {
		t.Fatalf("refill not admitted: %v", delay)
	}
}
