package roomnet_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

func TestStrictOutboundOperationsNeverUseInbound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keyA, keyB := testKey(t), testKey(t)
	id := community.Zero256()
	listen := func(key ed25519.PrivateKey) (*quic.Gateway, string) {
		gateway, err := roomnet.NewGateway(key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { gateway.Close() })
		gateway.SetConnectionHandler(func(raw *quic.Peer) error {
			peer := roomnet.Wrap(raw)
			peer.SetQueryHandler(func(q *roomnet.Query) error {
				if _, ok := q.Data.(community.GetCapabilities); ok {
					return q.Answer(roomnet.LocalCapabilities())
				}
				if selected, err := q.SelectOverlay(id); err != nil || !selected {
					return err
				}
				return q.Answer(broadcast.Time{Now: 42})
			})
			return nil
		})
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { packet.Close() })
		go func() { _ = gateway.Serve(packet) }()
		if err := gateway.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		return gateway, packet.LocalAddr().String()
	}
	a, addressA := listen(keyA)
	b, addressB := listen(keyB)
	raw, err := a.DialDefault(ctx, keyB.Public().(ed25519.PublicKey), addressB)
	if err != nil {
		t.Fatal(err)
	}
	peer := roomnet.Wrap(raw)
	if caps, err := peer.ProbeCapabilitiesOutbound(ctx); err != nil || caps != roomnet.LocalCapabilities() {
		t.Fatalf("strict probe: %+v %v", caps, err)
	}
	if _, err := b.DialDefault(ctx, keyA.Public().(ed25519.PublicKey), addressA); err != nil {
		t.Fatal(err)
	}
	shadow, err := roomnet.NewGateway(keyA)
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	shadowRaw, err := shadow.DialDefault(ctx, keyB.Public().(ed25519.PublicKey), addressB)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := community.Encode(community.GetCapabilities{})
	if _, err := shadowRaw.Query(ctx, request, roomnet.MaxAnswerObjectSize); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := a.OutboundPeer(keyA.Public().(ed25519.PublicKey), keyB.Public().(ed25519.PublicKey))
		if errors.Is(err, quic.ErrOutboundPeerNotFound) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	if a.Peer(keyA.Public().(ed25519.PublicKey), keyB.Public().(ed25519.PublicKey)) != raw {
		t.Fatal("managed peer did not survive")
	}
	var answer broadcast.Time
	if err := peer.Query(ctx, broadcast.GetTime{}, &answer); err != nil || answer.Now != 42 {
		t.Fatalf("inbound fallback fixture is not live: %v", err)
	}
	if err := peer.QueryOutbound(ctx, broadcast.GetTime{}, &answer); !errors.Is(err, quic.ErrOutboundPeerNotFound) {
		t.Fatalf("strict bare query: %v", err)
	}
	if err := peer.QueryOverlayOutbound(ctx, id, community.GetEvents{}, &answer); !errors.Is(err, quic.ErrOutboundPeerNotFound) {
		t.Fatalf("strict overlay query: %v", err)
	}
	if _, err := peer.ProbeCapabilitiesOutbound(ctx); !errors.Is(err, quic.ErrOutboundPeerNotFound) {
		t.Fatalf("strict capability probe: %v", err)
	}
	if err := peer.SendOutboundMessage(ctx, broadcast.Time{Now: 1}); !errors.Is(err, quic.ErrOutboundPeerNotFound) {
		t.Fatalf("strict message: %v", err)
	}
}
