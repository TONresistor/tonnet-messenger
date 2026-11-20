package roomnet_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	quicgo "github.com/xssnick/quic-go-ton"
	"github.com/xssnick/quic-go-ton/tls"
	tonquic "github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

type wireEndpoint interface {
	Query(context.Context, []byte, int64) ([]byte, error)
	SendMessage(context.Context, []byte) error
}

func TestUpstreamTONQUICInteroperability(t *testing.T) {
	for _, nativeServer := range []bool{false, true} {
		name := "upstream-server"
		if nativeServer {
			name = "upstream-client"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serverKey, clientKey := testKey(t), testKey(t)
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			serverMessages, clientMessages := make(chan int32, 1), make(chan int32, 1)
			serverEndpoint := make(chan wireEndpoint, 1)
			answer, _ := community.Encode(broadcast.Time{Now: 42})
			decodeMessage := func(target chan int32, payload []byte) {
				var value broadcast.Time
				if rest, err := tl.Parse(&value, payload, true); err == nil && len(rest) == 0 {
					target <- value.Now
				}
			}
			var peer wireEndpoint
			if nativeServer {
				server, err := roomnet.NewGateway(serverKey)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				server.SetConnectionHandler(func(p *roomnet.RawPeer) error {
					p.SetQueryHandler(func(context.Context, []byte) ([]byte, error) { return answer, nil })
					p.SetMessageHandler(func(_ context.Context, b []byte) { decodeMessage(serverMessages, b) })
					serverEndpoint <- p
					return nil
				})
				go func() { _ = server.Serve(packet) }()
				client, err := tonquic.NewGateway(clientKey)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				p, err := client.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				p.SetMessageHandler(func(_ context.Context, b []byte) { decodeMessage(clientMessages, b) })
				peer = p
			} else {
				server, err := tonquic.NewGateway(serverKey)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				server.SetConnectionHandler(func(p *tonquic.Peer) error {
					p.SetQueryHandler(func(context.Context, []byte) ([]byte, error) { return answer, nil })
					p.SetMessageHandler(func(_ context.Context, b []byte) { decodeMessage(serverMessages, b) })
					serverEndpoint <- p
					return nil
				})
				go func() { _ = server.Serve(packet) }()
				client, err := roomnet.NewGateway(clientKey)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				p, err := client.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				p.SetMessageHandler(func(_ context.Context, b []byte) { decodeMessage(clientMessages, b) })
				peer = p
			}
			request, _ := community.Encode(broadcast.GetTime{})
			got, err := peer.Query(ctx, request, roomnet.MaxAnswerObjectSize)
			if err != nil || string(got) != string(answer) {
				t.Fatalf("query interoperability: %v", err)
			}
			message, _ := community.Encode(broadcast.Time{Now: 7})
			if err := peer.SendMessage(ctx, message); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-serverMessages:
				if got != 7 {
					t.Fatal(got)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var serverPeer wireEndpoint
			select {
			case serverPeer = <-serverEndpoint:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := serverPeer.SendMessage(ctx, message); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-clientMessages:
				if got != 7 {
					t.Fatal(got)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestGatewayRejectsWrongALPNAndMissingRawKey(t *testing.T) {
	serverKey := testKey(t)
	server, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() { _ = server.Serve(packet) }()
	for _, missingKey := range []bool{false, true} {
		config := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"ton"}, InsecureSkipVerify: true}
		if !missingKey {
			config.NextProtos = []string{"wrong"}
			config.RawPublicKeys = &tls.RawPublicKeyConfig{PrivateKey: testKey(t), Verify: func(ed25519.PublicKey) error { return nil }}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := quicgo.DialAddr(ctx, packet.LocalAddr().String(), config, &quicgo.Config{Versions: []quicgo.Version{quicgo.Version1}})
		cancel()
		if err == nil {
			conn.CloseWithError(0, "")
			t.Fatalf("missing key=%v: invalid authentication profile accepted", missingKey)
		}
	}
}

func TestGatewayCloseBeforeHandlerRegistration(t *testing.T) {
	serverKey := testKey(t)
	server, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() { _ = server.Serve(packet) }()
	clientKey := testKey(t)
	client, err := roomnet.NewGateway(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := client.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()
	// Wait until transport cleanup finished before attaching the application.
	for client.Peer(clientKey.Public().(ed25519.PublicKey), serverKey.Public().(ed25519.PublicKey)) != nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	peer := roomnet.Wrap(raw)
	select {
	case <-peer.Done():
	case <-ctx.Done():
		t.Fatal("late subscriber missed physical disconnection")
	}
}
