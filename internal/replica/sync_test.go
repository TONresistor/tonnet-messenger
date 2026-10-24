package replica

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/adnl/overlay"
)

type targetTestResolver struct {
	nodes      overlay.NodesList
	public     ed25519.PublicKey
	queried    bool
	queries    int
	byID       map[string]ed25519.PublicKey
	overlayErr error
}

func (r *targetTestResolver) FindOverlayNodes(context.Context, []byte, ...*tondht.Continuation) (*overlay.NodesList, *tondht.Continuation, error) {
	r.queried = true
	r.queries++
	return &r.nodes, nil, r.overlayErr
}

func (r *targetTestResolver) FindAddresses(_ context.Context, id []byte) (*address.List, ed25519.PublicKey, error) {
	public := r.public
	if r.byID != nil {
		public = r.byID[string(id)]
	}
	return &address.List{Addresses: []address.Address{&address.QUIC{IP: net.ParseIP("1.1.1.1"), Port: 17400}}}, public, nil
}

func TestDiscoveryRetainsExcludedFallbacksAndReusesResolver(t *testing.T) {
	room, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	overlayID, _ := community.OverlayID(room)
	resolver := &targetTestResolver{byID: make(map[string]ed25519.PublicKey)}
	var excluded [][]byte
	for index := 0; index < 2; index++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		advert := overlay.Node{ID: keys.PublicKeyED25519{Key: public}, Overlay: overlayID, Version: int32(time.Now().Unix())}
		if err := advert.Sign(private); err != nil {
			t.Fatal(err)
		}
		resolver.nodes.List = append(resolver.nodes.List, advert)
		id, _ := community.KeyID(public)
		resolver.byID[string(id)] = public
		excluded = append(excluded, public)
	}
	discovery := &Discovery{configURL: "must-not-download", resolver: resolver}
	cfg := Config{RoomID: room, ExcludedPublicKeys: excluded, AllowExcluded: true}
	for index := 0; index < 2; index++ {
		targets, err := discovery.targets(context.Background(), cfg)
		if err != nil || len(targets) != 2 {
			t.Fatalf("all excluded lost read fallbacks: %d %v", len(targets), err)
		}
	}
	if resolver.queries != 2 || discovery.resolver != resolver {
		t.Fatal("DHT resolver was recreated")
	}
	bootstrap, _ := community.KeyID(excluded[0])
	cfg.BootstrapADNL = bootstrap
	resolver.nodes.List = nil
	resolver.overlayErr = errors.New("overlay unavailable")
	if targets, err := discovery.targets(context.Background(), cfg); err != nil || len(targets) != 1 || !bytes.Equal(targets[0].public, excluded[0]) {
		t.Fatalf("excluded bootstrap disappeared on overlay error: %#v %v", targets, err)
	}
	discovery.Close()
	if _, err := discovery.targets(context.Background(), cfg); err == nil {
		t.Fatal("closed discovery remained usable")
	}
}

func TestPreferredTargetsPrecedeExcludedFallbacks(t *testing.T) {
	preferred, fallback := ed25519.PublicKey{1}, ed25519.PublicKey{2}
	got := preferTargets([]target{{public: fallback}, {public: preferred}}, [][]byte{fallback})
	if len(got) != 2 || !bytes.Equal(got[0].public, preferred) || !bytes.Equal(got[1].public, fallback) {
		t.Fatal("fallback preceded a non-excluded relay")
	}
}

func TestExcludedBootstrapFallsBackToOtherOverlayNodes(t *testing.T) {
	room, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stale, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	honest, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	overlayID, _ := community.OverlayID(room)
	advert := overlay.Node{ID: keys.PublicKeyED25519{Key: honest}, Overlay: overlayID, Version: int32(time.Now().Unix())}
	if err := advert.Sign(private); err != nil {
		t.Fatal(err)
	}
	resolver := &targetTestResolver{nodes: overlay.NodesList{List: []overlay.Node{advert}}, public: honest}
	bootstrap, _ := community.KeyID(stale)
	targets, err := resolveTargets(context.Background(), resolver, room, bootstrap, [][]byte{stale}, false)
	if err != nil || !resolver.queried || len(targets) != 1 || !bytes.Equal(targets[0].public, honest) {
		t.Fatalf("excluded bootstrap prevented honest fallback: targets=%#v queried=%v err=%v", targets, resolver.queried, err)
	}
}
