package replica

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	nodes   overlay.NodesList
	public  ed25519.PublicKey
	queried bool
}

func (r *targetTestResolver) FindOverlayNodes(context.Context, []byte, ...*tondht.Continuation) (*overlay.NodesList, *tondht.Continuation, error) {
	r.queried = true
	return &r.nodes, nil, nil
}

func (r *targetTestResolver) FindAddresses(context.Context, []byte) (*address.List, ed25519.PublicKey, error) {
	return &address.List{Addresses: []address.Address{&address.QUIC{IP: net.ParseIP("1.1.1.1"), Port: 17400}}}, r.public, nil
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
	targets, err := resolveTargets(context.Background(), resolver, room, bootstrap, [][]byte{stale})
	if err != nil || !resolver.queried || len(targets) != 1 || !bytes.Equal(targets[0].public, honest) {
		t.Fatalf("excluded bootstrap prevented honest fallback: targets=%#v queried=%v err=%v", targets, resolver.queried, err)
	}
}
