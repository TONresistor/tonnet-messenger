package roomnet_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestOversizedAnswerIsRejectedBeforeTransport(t *testing.T) {
	serverKey, clientKey := testKey(t), testKey(t)
	serverGateway, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer serverGateway.Close()
	clientGateway, err := roomnet.NewGateway(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clientGateway.Close()
	serverGateway.SetConnectionHandler(func(raw *quic.Peer) error {
		roomnet.Wrap(raw).SetQueryHandler(func(query *roomnet.Query) error {
			return query.Answer(community.BatchResult{Items: []community.BatchItem{{
				Data: make([]byte, roomnet.MaxAnswerPayloadSize),
			}}})
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go serverGateway.Serve(packet)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rawPeer, err := clientGateway.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	var response community.BatchResult
	if err := roomnet.Wrap(rawPeer).Query(ctx, broadcast.GetTime{}, &response); err == nil {
		t.Fatal("oversized answer was delivered")
	}
}

func TestQueryAndMessageUseAuthenticatedTONQUIC(t *testing.T) {
	serverKey, clientKey := testKey(t), testKey(t)
	serverGateway, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer serverGateway.Close()
	clientGateway, err := roomnet.NewGateway(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clientGateway.Close()

	messages := make(chan broadcast.Time, 1)
	serverGateway.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(query *roomnet.Query) error {
			switch query.Data.(type) {
			case broadcast.GetTime, *broadcast.GetTime:
				return query.Answer(broadcast.Time{Now: 42})
			default:
				return roomnet.ErrNoAnswer
			}
		})
		peer.SetMessageHandler(func(value any) error {
			switch message := value.(type) {
			case broadcast.Time:
				messages <- message
			case *broadcast.Time:
				messages <- *message
			}
			return nil
		})
		return nil
	})

	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- serverGateway.Serve(packet) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rawPeer, err := clientGateway.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := roomnet.Wrap(rawPeer)
	if got := peer.GetPubKey(); !got.Equal(serverKey.Public()) {
		t.Fatal("authenticated peer key does not match the server")
	}

	var response broadcast.Time
	if err := peer.Query(ctx, broadcast.GetTime{}, &response); err != nil {
		t.Fatal(err)
	}
	if response.Now != 42 {
		t.Fatalf("query answer = %d, want 42", response.Now)
	}
	if err := peer.SendMessage(ctx, broadcast.Time{Now: 7}); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messages:
		if message.Now != 7 {
			t.Fatalf("message = %d, want 7", message.Now)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := serverGateway.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serveErr:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
