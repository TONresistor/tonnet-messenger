package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/tl"
)

type poolEndpoint struct {
	key                   ed25519.PrivateKey
	address               string
	genesis               community.Genesis
	state                 community.RoomStateV3
	caps, card            atomic.Value
	probes, cards, resets atomic.Int32
	malformed, blocked    atomic.Bool
	extra                 atomic.Value
	peers                 chan *roomnet.Peer
}

func newPoolEndpoint(t *testing.T) *poolEndpoint {
	t.Helper()
	f := &poolEndpoint{key: clientTestPrivateKey(t), peers: make(chan *roomnet.Peer, 8)}
	room := clientTestPrivateKey(t)
	var err error
	f.genesis, err = community.NewGenesis(room, f.key, time.Now(), "Pool fixture", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := community.NewProjection(f.genesis)
	if err != nil {
		t.Fatal(err)
	}
	f.state, err = community.SignRoomStateV3(room, projection.State())
	if err != nil {
		t.Fatal(err)
	}
	f.caps.Store(community.Capabilities{VersionMinor: 5, Flags: 2})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.address = packet.LocalAddr().String()
	f.card.Store(f.sign(t, community.RelayCardV1{RelayKey: f.key.Public().(ed25519.PublicKey), Addrs: address.List{Addresses: []address.Address{&address.QUIC{IP: net.IPv4(127, 0, 0, 1).To4(), Port: int32(packet.LocalAddr().(*net.UDPAddr).Port)}}}, Services: 2, PaymentKey: community.Zero256(), Offers: []community.RelayOfferV1{{Services: 2, MaxObjectBytes: 65536, RetentionSeconds: 600, RequestsPerMinute: 100, InboxQuotaBytes: 1 << 20}}, Version: int32(time.Now().Unix())}))
	g, err := roomnet.NewGateway(f.key)
	if err != nil {
		t.Fatal(err)
	}
	g.SetConnectionHandler(func(raw *roomnet.RawPeer) error {
		p := roomnet.Wrap(raw)
		f.peers <- p
		p.SetQueryHandler(func(q *roomnet.Query) error {
			if hook := f.extra.Load(); hook != nil {
				if handled, err := hook.(func(*roomnet.Query) (bool, error))(q); handled || err != nil {
					return err
				}
			}
			switch q.Data.(type) {
			case community.GetCapabilities:
				f.probes.Add(1)
				if f.resets.Add(-1) >= 0 {
					return roomnet.ErrNoAnswer
				}
				if f.blocked.Load() {
					<-q.Context().Done()
					return q.Context().Err()
				}
				return q.Answer(f.caps.Load().(community.Capabilities))
			case community.GetRelayCardV1:
				f.cards.Add(1)
				if f.malformed.Load() {
					return q.Answer(tl.Raw{1, 2, 3, 4})
				}
				return q.Answer(f.card.Load().(community.RelayCardV1))
			}
			id, _ := community.OverlayID(f.genesis.RoomKey)
			if selected, err := q.SelectOverlay(id); err != nil || !selected {
				return err
			}
			switch q.Data.(type) {
			case community.GetRoomGenesis:
				return q.Answer(f.genesis)
			case community.GetRoomState:
				return q.Answer(community.RoomStateResult{State: f.state, Stats: community.RoomStats{ReplicaHash: f.state.RevisionHash, NodeRole: community.NodeRoleSequencer, Ready: true}})
			case community.GetEvents:
				return q.Answer(community.EventList{})
			}
			return roomnet.ErrNoAnswer
		})
		return nil
	})
	go func() { g.Serve(packet) }()
	t.Cleanup(func() { g.Close(); packet.Close() })
	return f
}
func (f *poolEndpoint) sign(t *testing.T, card community.RelayCardV1) community.RelayCardV1 {
	t.Helper()
	c, err := community.SignRelayCardV1(f.key, card)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRelayPoolReusesLeaseCardsAndReprobesOnDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := newPoolEndpoint(t)
	owner, err := replica.NewConnector(ctx, clientTestPrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	p := newRelayPool(ctx, owner)
	defer p.Close()
	now := time.Now()
	key := f.key.Public().(ed25519.PublicKey)
	first, err := p.acquire(ctx, key, f.address, now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.acquire(ctx, key, "unused endpoint", now)
	if err != nil || again != first || f.probes.Load() != 1 || f.cards.Load() != 1 || p.choose(now) != first {
		t.Fatal("cached pool entry redialed/reprobed", err)
	}
	card, ok := p.card(key)
	if !ok {
		t.Fatal("card missing")
	}
	card.Offers[0].MaxObjectBytes = 1
	card.Signature[0] ^= 1
	copy, ok := p.card(key)
	if !ok || copy.Verify() != nil || copy.Offers[0].MaxObjectBytes != 65536 {
		t.Fatal("mutable card escaped pool")
	}
	base := int64(copy.Version)
	copy.Version = int32(base + 300)
	f.card.Store(f.sign(t, copy))
	refreshed, err := p.acquire(ctx, key, f.address, time.Unix(base+300, 0))
	if err != nil || refreshed != first || f.probes.Load() != 1 || f.cards.Load() != 2 {
		t.Fatal("card refresh replaced transport", err)
	}
	copy.Version = int32(base + 299)
	f.card.Store(f.sign(t, copy))
	if _, err := p.acquire(ctx, key, f.address, time.Unix(base+600, 0)); err != nil {
		t.Fatal(err)
	}
	if card, _ := p.card(key); card.Version != int32(base+300) {
		t.Fatal("older card replaced higher version")
	}
	server := <-f.peers
	server.Close()
	select {
	case <-first.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.caps.Store(community.Capabilities{VersionMajor: 1, Flags: 6})
	copy.Version = int32(base + 601)
	f.card.Store(f.sign(t, copy))
	fresh, err := p.acquire(ctx, key, f.address, time.Unix(base+601, 0))
	if err != nil || fresh == first || f.probes.Load() != 2 || fresh.Capabilities().Flags != 6 {
		t.Fatal("reconnection reused old capabilities", err)
	}
}

func TestRelayPoolCardFailuresPreserveRoomAndUseTypedScoring(t *testing.T) {
	for _, mode := range []string{"signature", "owner", "freshness", "service", "limit", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f := newPoolEndpoint(t)
			key := clientTestPrivateKey(t)
			owner, err := replica.NewConnector(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			room, err := replica.DialRoom(ctx, replica.Config{Connector: owner, NodeKey: key, RoomID: f.genesis.RoomKey, DirectAddress: f.address, DirectPublic: f.key.Public().(ed25519.PublicKey)})
			if err != nil {
				t.Fatal(err)
			}
			defer room.Close()
			card := f.card.Load().(community.RelayCardV1)
			switch mode {
			case "signature":
				card.Signature = bytes.Clone(card.Signature)
				card.Signature[0] ^= 1
			case "owner":
				other := clientTestPrivateKey(t)
				card.RelayKey = other.Public().(ed25519.PublicKey)
				card, err = community.SignRelayCardV1(other, card)
				if err != nil {
					t.Fatal(err)
				}
			case "freshness":
				card.Version -= 601
				card = f.sign(t, card)
			case "service":
				card.Services |= 8
				card = f.sign(t, card)
			case "limit":
				card.Offers = append([]community.RelayOfferV1(nil), card.Offers...)
				card.Offers[0].MaxObjectBytes = 65537
			case "malformed":
				f.malformed.Store(true)
			}
			f.card.Store(card)
			p := newRelayPool(ctx, owner)
			defer p.Close()
			now := time.Now()
			remote := f.key.Public().(ed25519.PublicKey)
			if _, err := p.acquire(ctx, remote, f.address, now); err == nil {
				t.Fatal("invalid card accepted")
			}
			if mode == "signature" {
				if !p.policy.banned(string(remote), now) {
					t.Fatal("invalid owner signature not banned")
				}
			} else if p.policy.banned(string(remote), now) || p.policy.scores[string(remote)] != 1 {
				t.Fatal("card shape/owner/freshness failure misclassified")
			}
			var genesis community.Genesis
			if err := room.Peer.QueryRoom(ctx, f.genesis.RoomKey, community.GetRoomGenesis{}, &genesis); err != nil || f.probes.Load() != 1 {
				t.Fatal("invalid DM card damaged room ref/state", err)
			}
		})
	}
}

func TestRelayPoolUnsupportedAndTimeoutClassification(t *testing.T) {
	for _, mode := range []string{"flag", "reset twice", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f := newPoolEndpoint(t)
			switch mode {
			case "flag":
				f.caps.Store(community.Capabilities{VersionMinor: 5})
			case "reset twice":
				f.resets.Store(2)
			case "timeout":
				f.blocked.Store(true)
			}
			owner, err := replica.NewConnector(ctx, clientTestPrivateKey(t))
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			p := newRelayPool(ctx, owner)
			defer p.Close()
			call := ctx
			var stop context.CancelFunc
			if mode == "timeout" {
				call, stop = context.WithTimeout(ctx, 50*time.Millisecond)
				defer stop()
			}
			key := f.key.Public().(ed25519.PublicKey)
			_, err = p.acquire(call, key, f.address, time.Now())
			if mode == "timeout" {
				if !errors.Is(err, context.DeadlineExceeded) || p.policy.scores[string(key)] != 1 {
					t.Fatal("timeout scoring", err)
				}
			} else if !errors.Is(err, replica.ErrRelayUnsupported) || len(p.peers) != 0 || len(p.policy.bans) != 0 {
				t.Fatal("unsupported/reset scored or retained", err)
			}
			if mode == "reset twice" && f.probes.Load() != 2 {
				t.Fatal("capability reset did not retry once")
			}
		})
	}
}

func TestRelayPoolIdentityResetOwnsLeasesAndPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := newPoolEndpoint(t)
	c, err := Open(ctx, Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	oldPool := c.relays
	lease, err := oldPool.acquire(ctx, f.key.Public().(ed25519.PublicKey), f.address, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity := c.Identity()
	if _, err := c.ResetIdentity(ctx, oldIdentity.Key); err != nil {
		t.Fatal(err)
	}
	if c.relays == oldPool || !oldPool.closed || len(c.relays.policy.bans) != 0 || len(c.relays.peers) != 0 {
		t.Fatal("new principal inherited pool state")
	}
	select {
	case <-lease.Done():
	default:
		t.Fatal("old identity lease retained authority")
	}
	if _, err := c.relays.acquire(ctx, f.key.Public().(ed25519.PublicKey), f.address, time.Now()); err != nil || f.probes.Load() != 2 {
		t.Fatal("new identity reused old probe", err)
	}
}
