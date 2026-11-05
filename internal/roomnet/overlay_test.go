package roomnet_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

func overlayPeer(t *testing.T, handler func(*roomnet.Query) error) (*roomnet.Peer, *quic.Peer) {
	t.Helper()
	serverKey := testKey(t)
	server, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	server.SetConnectionHandler(func(raw *quic.Peer) error { roomnet.Wrap(raw).SetQueryHandler(handler); return nil })
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	go func() { _ = server.Serve(packet) }()
	client, err := roomnet.NewGateway(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := client.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return roomnet.Wrap(raw), raw
}

func TestOverlaySelectionOrderAndRemoteStreamReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := bytes.Repeat([]byte{1}, 32)
	peer, _ := overlayPeer(t, func(q *roomnet.Query) error {
		selected, err := q.SelectOverlay(id)
		if err != nil || !selected {
			return err
		}
		if request, ok := q.Data.(community.GetEvents); ok && request.AfterSeqno != 0 {
			return q.Answer(community.OverlayRejectedV1{Code: int32(request.AfterSeqno), Message: "test rejection"})
		}
		return q.Answer(broadcast.Time{Now: 42})
	})
	for _, test := range []struct {
		overlay []byte
		tier    int32
		code    int32
	}{{community.Zero256(), 7, 19}, {community.Zero256(), 0, 19}, {id, 7, 1}} {
		var answer community.OverlayRejectedV1
		if err := peer.Query(ctx, community.OverlayQueryV1{Overlay: test.overlay, Tier: test.tier, Query: []byte{255}}, &answer); err != nil || answer.Code != test.code {
			t.Fatalf("rejection order: %+v %v", answer, err)
		}
	}
	for _, request := range []any{community.GetRoomGenesis{}, community.GetRoomState{}, community.GetEvents{}, community.GetMessagesRecent{}, community.GetMessagesBefore{MessageID: 1}, community.Batch{}, overlay.GetRandomPeers{}, community.OverlayQueryV1{Overlay: id, Query: []byte{255}}} {
		var answer any
		err := peer.Query(ctx, request, &answer)
		if err == nil || !strings.Contains(err.Error(), "canceled by remote with error code 1") {
			t.Fatalf("%T did not reset its stream: %v", request, err)
		}
	}
	var answer broadcast.Time
	if err := peer.Query(ctx, broadcast.GetTime{}, &answer); err != nil || answer.Now != 42 {
		t.Fatalf("bare time after resets: %+v %v", answer, err)
	}
	if err := peer.QueryOverlay(ctx, id, community.GetEvents{}, &answer); err != nil || answer.Now != 42 {
		t.Fatalf("wrapped query: %+v %v", answer, err)
	}
	for _, code := range []int64{1, 19, 2, 20} {
		err := peer.QueryOverlay(ctx, id, community.GetEvents{AfterSeqno: code}, &answer)
		var rejected *roomnet.OverlayRejection
		if !errors.As(err, &rejected) || rejected.Code != int32(code) {
			t.Fatalf("lost wrapper rejection: %v", err)
		}
		if errors.Is(err, roomnet.ErrMalformedAnswer) != (code != 1 && code != 19) {
			t.Fatalf("wrapper code validation: %v", err)
		}
	}
}

func TestOverlaySizeBoundIncludesCompleteWrapper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer, rawPeer := overlayPeer(t, func(q *roomnet.Query) error { return q.Answer(broadcast.Time{Now: 1}) })
	id := community.Zero256()
	inner := tl.Raw(bytes.Repeat([]byte{0}, roomnet.MaxWireObjectSize-44))
	wrapped := community.OverlayQueryV1{Overlay: id, Query: inner}
	encoded, err := community.Encode(wrapped)
	if err != nil || len(encoded) != roomnet.MaxWireObjectSize {
		t.Fatalf("boundary fixture: %d %v", len(encoded), err)
	}
	var answer broadcast.Time
	if err := peer.QueryOverlay(ctx, id, inner, &answer); err != nil {
		t.Fatalf("exact request boundary: %v", err)
	}
	if err := peer.QueryOverlay(ctx, id, tl.Raw(append(inner, 0)), &answer); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized wrapper sent: %v", err)
	}
	wrapped.Query = append(wrapped.Query, 0)
	oversized, err := community.Encode(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rawPeer.Query(ctx, oversized, quic.DefaultMaxObjectSize); err == nil {
		t.Fatal("inbound oversized wrapper accepted")
	}
	// Upstream also bounds outgoing requests. Use a wider upstream sender to
	// ensure the Messenger receiver rejects an oversized object on the wire.
	unbounded, err := quic.NewGateway(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer unbounded.Close()
	incoming, err := unbounded.DialDefault(ctx, peer.GetPubKey(), peer.RemoteAddr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incoming.Query(ctx, oversized, roomnet.MaxAnswerObjectSize); err == nil {
		t.Fatal("receiver accepted an oversized wrapper from a wider sender")
	}
}
