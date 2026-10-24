package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
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
	mu        sync.Mutex
	events    []community.CommittedEvent
	role      int32
	headLimit int64
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	instance, err := Open(ctx, Config{StateDir: t.TempDir()})
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
	if handle.isCurrentSession(session, 1) || handle.freshness.status != "stale" {
		t.Fatal("withholding relay was not detected and abandoned")
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
