package roomnet_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

func TestAnswerLimitRemainsFourMiBWithUpstreamDefaults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := community.BatchResult{Items: []community.BatchItem{{Data: make([]byte, roomnet.MaxAnswerPayloadSize)}}}
	encoded, err := community.Encode(result)
	if err != nil {
		t.Fatal(err)
	}
	overhead := len(encoded) - len(result.Items[0].Data)
	result.Items[0].Data = make([]byte, roomnet.MaxAnswerPayloadSize-overhead)
	boundary, err := community.Encode(result)
	if err != nil || len(boundary) != roomnet.MaxAnswerPayloadSize {
		t.Fatalf("answer boundary fixture: %d %v", len(boundary), err)
	}
	result.Items[0].Data = append(result.Items[0].Data, 0, 0, 0, 0)
	oversized, err := community.Encode(result)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := testKey(t)
	server, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var sendOversized atomic.Bool
	server.SetConnectionHandler(func(raw *quic.Peer) error {
		// Bypass the application answer guard to exercise the receive cap.
		raw.SetQueryHandler(func(context.Context, []byte) ([]byte, error) {
			if sendOversized.Load() {
				return oversized, nil
			}
			return boundary, nil
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() { _ = server.Serve(packet) }()
	client, err := roomnet.NewGateway(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw, err := client.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := roomnet.Wrap(raw)
	var answer community.BatchResult
	if err := peer.Query(ctx, broadcast.GetTime{}, &answer); err != nil || len(answer.Items) != 1 || len(answer.Items[0].Data) != len(boundary)-overhead {
		t.Fatalf("exact 4 MiB answer object rejected: %v", err)
	}
	sendOversized.Store(true)
	if err := peer.Query(ctx, broadcast.GetTime{}, &answer); err == nil || errors.Is(err, roomnet.ErrMalformedAnswer) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized answer was not rejected by the transport cap: %v", err)
	}
}

func TestGatewayKeepsFourIncomingStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{}, roomnet.MaxIncomingStreams+1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	peer, _ := overlayPeer(t, func(query *roomnet.Query) error {
		entered <- struct{}{}
		select {
		case <-release:
			return query.Answer(broadcast.Time{Now: 42})
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	results := make(chan error, roomnet.MaxIncomingStreams)
	for i := 0; i < roomnet.MaxIncomingStreams; i++ {
		go func() {
			var answer broadcast.Time
			results <- peer.Query(ctx, broadcast.GetTime{}, &answer)
		}()
	}
	for i := 0; i < roomnet.MaxIncomingStreams; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	fifthCtx, fifthCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	var answer broadcast.Time
	err := peer.Query(fifthCtx, broadcast.GetTime{}, &answer)
	fifthCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fifth stream did not wait for credit: %v", err)
	}
	select {
	case <-entered:
		t.Fatal("a fifth incoming stream reached its handler")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	for i := 0; i < roomnet.MaxIncomingStreams; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := peer.Query(ctx, broadcast.GetTime{}, &answer); err != nil || answer.Now != 42 {
		t.Fatalf("stream credit was not returned: %+v %v", answer, err)
	}
}

func TestGatewayRejectsWrongEndpointKey(t *testing.T) {
	peer, _ := overlayPeer(t, func(query *roomnet.Query) error {
		return query.Answer(broadcast.Time{Now: 42})
	})
	client, err := roomnet.NewGateway(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if raw, err := client.DialDefault(ctx, testKey(t).Public().(ed25519.PublicKey), peer.RemoteAddr()); err == nil {
		raw.Close()
		t.Fatal("wrong-key endpoint was accepted")
	}
	raw, err := client.DialDefault(ctx, peer.GetPubKey(), peer.RemoteAddr())
	if err != nil {
		t.Fatalf("matching endpoint key rejected: %v", err)
	}
	var answer broadcast.Time
	if err := roomnet.Wrap(raw).Query(ctx, broadcast.GetTime{}, &answer); err != nil || answer.Now != 42 {
		t.Fatalf("authenticated endpoint query: %+v %v", answer, err)
	}
}
