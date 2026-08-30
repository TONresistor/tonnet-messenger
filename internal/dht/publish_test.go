package dht

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/overlay"
)

func udpAddr(t *testing.T, ip string, port int32) address.Address {
	t.Helper()
	a, err := address.NewAddress(net.ParseIP(ip), port)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestHasPublicEndpoint(t *testing.T) {
	if hasPublicEndpoint(address.List{}) {
		t.Fatal("empty list is not a public endpoint")
	}
	if hasPublicEndpoint(address.List{Addresses: []address.Address{udpAddr(t, "127.0.0.1", 17400)}}) {
		t.Fatal("loopback must not be published")
	}
	if !hasPublicEndpoint(address.List{Addresses: []address.Address{udpAddr(t, "159.195.83.116", 17400)}}) {
		t.Fatal("the advertised public UDP endpoint must be publishable")
	}
}

func TestContainsPublishedEndpoint(t *testing.T) {
	published := address.List{Addresses: []address.Address{udpAddr(t, "159.195.83.116", 17400)}}
	if containsPublishedEndpoint(address.List{}, published) {
		t.Fatal("an empty FindAddresses result is not visible")
	}
	if containsPublishedEndpoint(address.List{Addresses: []address.Address{udpAddr(t, "1.1.1.1", 17400)}}, published) {
		t.Fatal("a different IP is not this node")
	}
	if !containsPublishedEndpoint(address.List{Addresses: []address.Address{udpAddr(t, "159.195.83.116", 17400)}}, published) {
		t.Fatal("FindAddresses must accept the published UDP endpoint")
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
	return f.findAddr, nil, f.findAddrErr
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
	gw.SetAddressList([]address.Address{udpAddr(t, "159.195.83.116", 17400)})
	return &Publisher{d: d, gw: gw, key: key, room: []byte("tonnet:groupchat"), overlayID: make([]byte, 32)}
}

func TestPublishAddressRequiresFindableEndpoint(t *testing.T) {
	published := address.List{Addresses: []address.Address{udpAddr(t, "159.195.83.116", 17400)}}
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
	if !overlayOK {
		t.Fatal("overlay publish is independent of address visibility")
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
