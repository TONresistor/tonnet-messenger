package replica

import (
	"context"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func TestConnectorLeasesReprobeAndIdentityOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newCapabilityEndpoint(t)
	cfg := f.config(t)
	connector, err := NewConnector(ctx, cfg.NodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	cfg.Connector = connector
	type result struct {
		session *Session
		err     error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() { s, err := DialRoom(ctx, cfg); results <- result{s, err} }()
	}
	a, b := <-results, <-results
	if a.err != nil || b.err != nil {
		t.Fatalf("concurrent acquire: %v / %v", a.err, b.err)
	}
	defer a.session.Close()
	defer b.session.Close()
	if a.session == b.session || a.session.Peer != b.session.Peer || f.probes.Load() != 1 {
		t.Fatal("leases did not share one probed connection")
	}
	a.session.Close()
	select {
	case <-a.session.Done:
	default:
		t.Fatal("closed lease remains live")
	}
	select {
	case <-b.session.Done:
		t.Fatal("closing A closed B")
	default:
	}
	query := func(s *Session) {
		t.Helper()
		var g community.Genesis
		if err := s.Peer.QueryRoom(ctx, cfg.RoomID, community.GetRoomGenesis{}, &g); err != nil {
			t.Fatal(err)
		}
	}
	query(b.session)
	unknown := cfg
	unknown.RoomID = community.Zero256()
	if s, err := DialRoom(ctx, unknown); err == nil {
		s.Close()
		t.Fatal("unknown room acquired a lease")
	}
	query(b.session)
	// Calibration knows the sequencer key; reuse it without a discovery dial.
	authority := cfg
	authority.DirectAddress, authority.DirectPublic = "", nil
	authority.BootstrapADNL, _ = community.KeyID(f.target.public)
	authority.ConfigURL = "invalid-discovery-must-not-be-used"
	s, err := DialSequencer(ctx, authority)
	if err != nil {
		t.Fatal(err)
	}
	if s.Peer != b.session.Peer || f.probes.Load() != 1 {
		t.Fatal("calibration replaced the shared connection")
	}
	s.Close()
	query(b.session)

	old := b.session.Peer
	old.Close()
	select {
	case <-b.session.Done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.capabilities.Store(community.Capabilities{VersionMinor: 6, Flags: 7})
	reconnected, err := DialRoom(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	if reconnected.Peer == old || reconnected.Capabilities.VersionMinor != 6 || f.probes.Load() != 2 {
		t.Fatal("reconnection reused a connection or its capabilities")
	}
	b.session.Close()
	query(reconnected)
	mismatch := cfg
	mismatch.NodeKey = capabilityKey(t)
	if s, err := DialRoom(ctx, mismatch); err == nil {
		s.Close()
		t.Fatal("connector accepted another identity")
	}
	connector.Close()
	select {
	case <-reconnected.Done:
	default:
		t.Fatal("owner shutdown left a lease live")
	}
	newOwner, err := NewConnector(ctx, mismatch.NodeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer newOwner.Close()
	mismatch.Connector = newOwner
	fresh, err := DialRoom(ctx, mismatch)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if f.probes.Load() != 3 {
		t.Fatal("new identity inherited capabilities")
	}
	reconnected.Close()
	query(fresh)
}
