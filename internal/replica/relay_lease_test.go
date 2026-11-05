package replica

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func TestRelayLeaseSharesRoomConnectionAndIsolatesDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := newCapabilityEndpoint(t)
	f.capabilities.Store(community.Capabilities{VersionMinor: 5, Flags: 2})
	cfg := f.config(t)
	owner, err := NewConnector(ctx, cfg.NodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	cfg.Connector = owner
	dm, err := owner.AcquireRelay(ctx, f.target.address, f.target.public)
	if err != nil {
		t.Fatal(err)
	}
	if log := f.log(); len(log) != 1 || log[0] != "capabilities" {
		t.Fatal("non-room lease requested genesis", log)
	}
	room, err := DialRoom(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer room.Close()
	if f.probes.Load() != 1 || dm.lease.entry.peer != room.Peer {
		t.Fatal("DM replaced room transport or reprobed")
	}
	server := <-f.peers
	pushes := make(chan community.InboxPushV1, 4)
	events := make(chan any, 4)
	dm.SubscribeInboxPush(func(p community.InboxPushV1) error { pushes <- p; return nil })
	room.SetMessageHandler(func(v any) error { events <- v; return nil })
	proposal, err := community.SignProposal(f.roomKey, f.genesis.NodeKey, community.EventProposal{RoomID: f.genesis.RoomKey, Nonce: community.Zero256(), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "room"}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := community.SignCommit(f.roomKey, proposal, 1, community.Zero256(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := community.Encode(event)
	wrapper, err := broadcast.Sign(f.roomKey, nil, raw, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := server.SendMessage(ctx, community.InboxPushV1{Seqno: 1}); err != nil {
		t.Fatal(err)
	}
	if err := server.SendMessage(ctx, wrapper); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-pushes:
		if p.Seqno != 1 {
			t.Fatal(p)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-events:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-pushes:
		t.Fatal("DM handler received a room event")
	default:
	}
	select {
	case <-events:
		t.Fatal("room handler received inbox push")
	default:
	}
	dm.Close()
	var genesis community.Genesis
	if err := room.Peer.QueryRoom(ctx, cfg.RoomID, community.GetRoomGenesis{}, &genesis); err != nil {
		t.Fatal("DM release closed room", err)
	}
	next, err := owner.AcquireRelay(ctx, f.target.address, f.target.public)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.SubscribeInboxPush(func(p community.InboxPushV1) error { pushes <- p; return nil })
	room.Close()
	var clock broadcast.Time
	if err := next.Query(ctx, broadcast.GetTime{}, &clock); err != nil || f.probes.Load() != 1 {
		t.Fatal("room release closed/reprobed DM", err)
	}
	server.Close()
	select {
	case <-next.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.capabilities.Store(community.Capabilities{VersionMajor: 1, Flags: 6})
	fresh, err := owner.AcquireRelay(ctx, f.target.address, f.target.public)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if f.probes.Load() != 2 || fresh.Capabilities().VersionMajor != 1 {
		t.Fatal("new connection inherited old capabilities")
	}
	wrong := capabilityKey(t).Public().(ed25519.PublicKey)
	if l, err := owner.AcquireRelay(ctx, f.target.address, wrong); err == nil {
		l.Close()
		t.Fatal("endpoint key not pinned")
	}
}

func TestRelayLeaseUnsupportedDoesNotReleaseRoom(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := newCapabilityEndpoint(t)
	cfg := f.config(t)
	owner, err := NewConnector(ctx, cfg.NodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	cfg.Connector = owner
	room, err := DialRoom(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer room.Close()
	if l, err := owner.AcquireRelay(ctx, f.target.address, f.target.public); !errors.Is(err, ErrRelayUnsupported) {
		if l != nil {
			l.Close()
		}
		t.Fatal("missing DM flag accepted", err)
	}
	var genesis community.Genesis
	if err := room.Peer.QueryRoom(ctx, cfg.RoomID, community.GetRoomGenesis{}, &genesis); err != nil || f.probes.Load() != 1 {
		t.Fatal("unsupported DM corrupted room lease", err)
	}
}
