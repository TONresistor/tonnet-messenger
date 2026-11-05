package dht

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

func udpAddr(t *testing.T, ip string, port int32) address.Address {
	t.Helper()
	a, err := address.NewAddress(net.ParseIP(ip), port)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func quicAddr(ip string, port int32) address.Address {
	return &address.QUIC{IP: net.ParseIP(ip).To4(), Port: port}
}

func TestHasPublicEndpoint(t *testing.T) {
	if hasPublicEndpoint(address.List{}) {
		t.Fatal("empty list is not a public endpoint")
	}
	if hasPublicEndpoint(address.List{Addresses: []address.Address{quicAddr("127.0.0.1", 17400)}}) {
		t.Fatal("loopback must not be published")
	}
	if hasPublicEndpoint(address.List{Addresses: []address.Address{udpAddr(t, "159.195.83.116", 17400)}}) {
		t.Fatal("classic UDP ADNL must not satisfy the Messenger transport requirement")
	}
	if !hasPublicEndpoint(address.List{Addresses: []address.Address{quicAddr("159.195.83.116", 17400)}}) {
		t.Fatal("the advertised public TON QUIC endpoint must be publishable")
	}
}

func TestContainsPublishedEndpoint(t *testing.T) {
	published := address.List{Addresses: []address.Address{quicAddr("159.195.83.116", 17400)}}
	if containsPublishedEndpoint(address.List{}, published) {
		t.Fatal("an empty FindAddresses result is not visible")
	}
	if containsPublishedEndpoint(address.List{Addresses: []address.Address{quicAddr("1.1.1.1", 17400)}}, published) {
		t.Fatal("a different IP is not this node")
	}
	if containsPublishedEndpoint(address.List{Addresses: []address.Address{udpAddr(t, "159.195.83.116", 17400)}}, published) {
		t.Fatal("a UDP ADNL endpoint must not match a published TON QUIC endpoint")
	}
	if !containsPublishedEndpoint(address.List{Addresses: []address.Address{quicAddr("159.195.83.116", 17400)}}, published) {
		t.Fatal("FindAddresses must accept the published TON QUIC endpoint")
	}
}

func TestNextPublishDelay(t *testing.T) {
	if got := nextPublishDelay(true, true); got != RepublishEach {
		t.Fatalf("healthy publish delay = %s, want %s", got, RepublishEach)
	}
	if got := nextPublishDelay(false, true); got != storeRetryEach {
		t.Fatalf("missing address must retry in %s, got %s", storeRetryEach, got)
	}
	if got := nextPublishDelay(true, false); got != storeRetryEach {
		t.Fatalf("missing overlay must retry in %s, got %s", storeRetryEach, got)
	}
}

type fakeDHT struct {
	storeAddrN   int
	storeAddrErr error
	findAddr     *address.List
	findPub      ed25519.PublicKey
	findAddrErr  error
	storeOverN   int
	storeOverErr error
	storeAddr    int
	findCalls    int
	storeOver    int
}

func (f *fakeDHT) StoreAddress(context.Context, address.List, time.Duration, ed25519.PrivateKey) (int, []byte, error) {
	f.storeAddr++
	return f.storeAddrN, nil, f.storeAddrErr
}
func (f *fakeDHT) StoreOverlayNodes(context.Context, []byte, *overlay.NodesList, time.Duration) (int, []byte, error) {
	f.storeOver++
	return f.storeOverN, nil, f.storeOverErr
}
func (f *fakeDHT) FindAddresses(context.Context, []byte) (*address.List, ed25519.PublicKey, error) {
	f.findCalls++
	return f.findAddr, f.findPub, f.findAddrErr
}

func TestResolveAllRequiresQUICAndMatchingADNLID(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := key.Public().(ed25519.PublicKey)
	id, err := tl.Hash(keys.PublicKeyED25519{Key: public})
	if err != nil {
		t.Fatal(err)
	}
	addresses := &address.List{Addresses: []address.Address{
		udpAddr(t, "1.1.1.1", 17400),
		quicAddr("1.1.1.1", 17401),
	}}
	p := &Publisher{d: &fakeDHT{findAddr: addresses, findPub: public}}
	resolved, gotPublic, err := p.ResolveAll(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0] != "1.1.1.1:17401" {
		t.Fatalf("resolved = %v, want TON QUIC only", resolved)
	}
	if !gotPublic.Equal(public) {
		t.Fatal("resolved public key changed")
	}

	wrongID := append([]byte(nil), id...)
	wrongID[0] ^= 1
	if _, _, err := p.ResolveAll(context.Background(), wrongID); err == nil {
		t.Fatal("mismatched ADNL id was accepted")
	}
}
func (f *fakeDHT) FindOverlayNodes(context.Context, []byte, ...*tondht.Continuation) (*overlay.NodesList, *tondht.Continuation, error) {
	return nil, nil, nil
}

func testPublisher(t *testing.T, d dhtClient) *Publisher {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gw := adnl.NewGateway(key)
	gw.SetAddressList([]address.Address{quicAddr("159.195.83.116", 17400)})
	return &Publisher{d: d, gw: gw, key: key, room: []byte("tonnet:groupchat"), overlayID: make([]byte, 32)}
}

func TestPublishAddressRequiresFindableEndpoint(t *testing.T) {
	published := address.List{Addresses: []address.Address{quicAddr("159.195.83.116", 17400)}}
	ok := &fakeDHT{storeAddrN: 3, findAddr: &published, storeOverN: 1}
	p := testPublisher(t, ok)
	addrOK, overlayOK := p.publish(context.Background())
	if !addrOK || !overlayOK {
		t.Fatalf("findable address+overlay must count as published, got addr=%v overlay=%v", addrOK, overlayOK)
	}

	missing := &fakeDHT{storeAddrN: 3, findAddrErr: tondht.ErrDHTValueIsNotFound, storeOverN: 1}
	p = testPublisher(t, missing)
	addrOK, overlayOK = p.publish(context.Background())
	if addrOK {
		t.Fatal("StoreAddress without a findable record must not report address success")
	}
	if overlayOK || missing.storeOver != 0 {
		t.Fatal("overlay must not be published without a verified TON QUIC address")
	}
	if missing.storeAddr != 1 || missing.findCalls != 1 {
		t.Fatalf("expected one store + one find, got store=%d find=%d", missing.storeAddr, missing.findCalls)
	}
}

func TestPublicADNLIP(t *testing.T) {
	tests := map[string]bool{
		"1.1.1.1":      true,
		"2606:4700::1": true,
		"127.0.0.1":    false,
		"10.0.0.1":     false,
		"169.254.1.1":  false,
		"100.64.0.1":   false,
		"192.0.2.1":    false,
		"192.88.99.2":  false,
		"198.18.0.1":   false,
		"198.51.100.1": false,
		"203.0.113.1":  false,
		"240.0.0.1":    false,
		"::1":          false,
		"100::1":       false,
		"100:0:0:1::1": false,
		"2001:db8::1":  false,
		"2002::1":      false,
		"3fff::1":      false,
		"5f00::1":      false,
		"fd00::1":      false,
		"fe80::1":      false,
		"224.0.0.1":    false,
	}
	for raw, want := range tests {
		if got := PublicADNLIP(net.ParseIP(raw)); got != want {
			t.Errorf("PublicADNLIP(%q) = %v, want %v", raw, got, want)
		}
	}
}

type publicationDHT struct {
	fakeDHT
	rooms [][]byte
	nodes []overlay.Node
	order []string
}

func (f *publicationDHT) StoreAddress(ctx context.Context, list address.List, ttl time.Duration, key ed25519.PrivateKey) (int, []byte, error) {
	f.order = append(f.order, "address")
	return f.fakeDHT.StoreAddress(ctx, list, ttl, key)
}

func (f *publicationDHT) StoreOverlayNodes(ctx context.Context, room []byte, nodes *overlay.NodesList, ttl time.Duration) (int, []byte, error) {
	f.order = append(f.order, "overlay")
	f.rooms = append(f.rooms, append([]byte(nil), room...))
	f.nodes = append(f.nodes, nodes.List...)
	return f.fakeDHT.StoreOverlayNodes(ctx, room, nodes, ttl)
}

func TestSharedDHTPublishesDistinctRoomsAfterAddressVerification(t *testing.T) {
	for _, failure := range []string{"none", "address error", "zero addresses", "find error", "wrong endpoint", "overlay error", "zero overlays"} {
		t.Run(failure, func(t *testing.T) {
			list := address.List{Addresses: []address.Address{quicAddr("1.1.1.1", 17400)}}
			f := &publicationDHT{fakeDHT: fakeDHT{storeAddrN: 1, findAddr: &list, storeOverN: 1}}
			switch failure {
			case "address error":
				f.storeAddrErr = errors.New("store failed")
			case "zero addresses":
				f.storeAddrN = 0
			case "find error":
				f.findAddrErr = errors.New("find failed")
			case "wrong endpoint":
				f.findAddr = &address.List{Addresses: []address.Address{quicAddr("1.0.0.1", 17400)}}
			case "overlay error":
				f.storeOverErr = errors.New("overlay failed")
			case "zero overlays":
				f.storeOverN = 0
			}
			owner := testPublisher(t, f)
			owner.gw.SetAddressList(list.Addresses)
			closes := 0
			owner.close = func() { closes++ }
			var roomKeys [][]byte
			for range 2 {
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				roomKeys = append(roomKeys, public)
				id, _ := tl.Hash(keys.PublicKeyOverlay{Key: public})
				p := owner.ForRoom(public, id)
				if p.d != owner.d || p.gw != owner.gw {
					t.Fatal("room created another discovery owner")
				}
				addrOK, overlayOK := p.publish(context.Background())
				wantAddress := failure == "none" || failure == "overlay error" || failure == "zero overlays"
				if addrOK != wantAddress || overlayOK != (failure == "none") {
					t.Fatalf("publish %s: address=%v overlay=%v", failure, addrOK, overlayOK)
				}
				p.Close()
			}
			if closes != 0 {
				t.Fatal("borrower closed the shared client/gateway")
			}
			owner.Close()
			owner.Close()
			if closes != 1 {
				t.Fatal("DHT owner was not closed exactly once")
			}
			if failure == "none" {
				if len(f.nodes) != 2 || len(f.order) != 4 || f.order[0] != "address" || f.order[1] != "overlay" || f.order[2] != "address" || f.order[3] != "overlay" {
					t.Fatal("overlay published before its findable address")
				}
				for i, nd := range f.nodes {
					id, _ := tl.Hash(keys.PublicKeyOverlay{Key: roomKeys[i]})
					public := nd.ID.(keys.PublicKeyED25519).Key
					if !public.Equal(owner.key.Public()) || string(f.rooms[i]) != string(roomKeys[i]) || string(nd.Overlay) != string(id) || nd.CheckSignature() != nil {
						t.Fatal("room publication has wrong identity, overlay or signature")
					}
				}
			} else if failure != "overlay error" && failure != "zero overlays" && f.storeOver != 0 {
				t.Fatal("failed address verification published an overlay")
			}
		})
	}
}

func TestPublicRoomsPublisherUsesGlobalNameAndSharedIdentity(t *testing.T) {
	list := address.List{Addresses: []address.Address{quicAddr("1.1.1.1", 17400)}}
	f := &publicationDHT{fakeDHT: fakeDHT{storeAddrN: 1, findAddr: &list, storeOverN: 1}}
	owner := testPublisher(t, f)
	owner.gw.SetAddressList(list.Addresses)
	id, err := ov.PublicRoomsID()
	if err != nil {
		t.Fatal(err)
	}
	global := owner.ForRoom([]byte(ov.PublicRooms), id)
	if addr, overlayOK := global.publish(context.Background()); !addr || !overlayOK {
		t.Fatal("global publication failed")
	}
	if len(f.rooms) != 1 || string(f.rooms[0]) != ov.PublicRooms || !bytes.Equal(f.nodes[0].Overlay, id) || f.nodes[0].CheckSignature() != nil || !f.nodes[0].ID.(keys.PublicKeyED25519).Key.Equal(owner.key.Public()) {
		t.Fatal("global publication used a room or another identity")
	}
	if len(f.order) != 2 || f.order[0] != "address" || f.order[1] != "overlay" {
		t.Fatal("global overlay preceded verified address publication")
	}
}
