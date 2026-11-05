package replica

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

func TestOverlayNotServedTriesNextDiscoveryCandidate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	room, nodeKey := key(), key()
	genesis, err := community.NewGenesis(room, nodeKey, time.Now(), "Candidates", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := community.OverlayID(genesis.RoomKey)
	calls := make(chan bool, 3)
	endpoint := func(private ed25519.PrivateKey, serve bool) target {
		gateway, err := roomnet.NewGateway(private)
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
				calls <- serve
				selectedID := id
				if !serve {
					selectedID = community.Zero256()
				}
				if selected, err := q.SelectOverlay(selectedID); err != nil || !selected {
					return err
				}
				return q.Answer(genesis)
			})
			return nil
		})
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { packet.Close() })
		go func() { _ = gateway.Serve(packet) }()
		return target{address: packet.LocalAddr().String(), public: private.Public().(ed25519.PublicKey)}
	}
	bad, good := endpoint(key(), false), endpoint(nodeKey, true)
	cfg := Config{RoomID: genesis.RoomKey, NodeKey: key()}
	connection, closeConnection, err := connectTargets(ctx, cfg, nil, true, []target{bad, good})
	if err != nil {
		t.Fatal(err)
	}
	defer closeConnection()
	if !connection.peer.GetPubKey().Equal(nodeKey.Public()) || <-calls || !<-calls {
		t.Fatal("did not advance to the next overlay candidate")
	}
	_, _, err = connectTargets(ctx, cfg, nil, true, []target{bad})
	var rejected *roomnet.OverlayRejection
	if !errors.As(err, &rejected) || rejected.Code != community.RejectOverlayNotServed {
		t.Fatalf("lost availability rejection: %v", err)
	}
}
