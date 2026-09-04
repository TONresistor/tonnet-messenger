package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

func TestSequencerTimestampNeverTrustsRelayClock(t *testing.T) {
	identity := clockTestKey(t)
	room := clockTestKey(t)
	sequencer := clockTestKey(t)
	relay := clockTestKey(t)
	genesis, err := community.NewGenesis(room, sequencer, time.Now(), "Room", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	sequencerID, err := community.KeyID(genesis.NodeKey)
	if err != nil {
		t.Fatal(err)
	}
	var relayQueries, sequencerQueries atomic.Int32
	relayPeer := clockTestPeer(t, identity, relay, int32(now+240), &relayQueries)
	sequencerPeer := clockTestPeer(t, identity, sequencer, int32(now), &sequencerQueries)
	relaySession := &replica.Session{Genesis: genesis, Peer: relayPeer, Done: relayPeer.Done()}
	sequencerSession := &replica.Session{Genesis: genesis, Peer: sequencerPeer, Done: sequencerPeer.Done()}
	handle := &roomHandle{
		client: &Client{configURL: "unused"}, key: genesis.RoomKey,
		session: relaySession, sessionEpoch: 1,
		dialSequencer: func(_ context.Context, cfg replica.Config) (*replica.Session, error) {
			if !bytes.Equal(cfg.RoomID, genesis.RoomKey) || !bytes.Equal(cfg.NodeKey, identity) ||
				!bytes.Equal(cfg.BootstrapADNL, sequencerID) {
				t.Fatal("unexpected sequencer dial configuration")
			}
			return sequencerSession, nil
		},
	}
	snapshot := roomIdentitySnapshot{key: identity, session: relaySession, epoch: 1}

	timestamp, err := handle.sequencerTimestamp(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if timestamp < now-1 || timestamp > now+1 {
		t.Fatalf("timestamp = %d, want sequencer time near %d", timestamp, now)
	}
	if relayQueries.Load() != 0 || sequencerQueries.Load() != 1 {
		t.Fatalf("time queries: relay=%d sequencer=%d", relayQueries.Load(), sequencerQueries.Load())
	}
	if _, err := handle.sequencerTimestamp(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if sequencerQueries.Load() != 1 {
		t.Fatal("fresh sequencer calibration was not cached")
	}
}

func TestSequencerTimestampFailsClosedWhenAuthorityIsUnavailable(t *testing.T) {
	identity := clockTestKey(t)
	room := clockTestKey(t)
	sequencer := clockTestKey(t)
	relay := clockTestKey(t)
	genesis, err := community.NewGenesis(room, sequencer, time.Now(), "Room", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	relayPeer := clockTestPeer(t, identity, relay, int32(time.Now().Unix()), nil)
	relaySession := &replica.Session{Genesis: genesis, Peer: relayPeer, Done: relayPeer.Done()}
	handle := &roomHandle{
		client: &Client{}, key: genesis.RoomKey, session: relaySession, sessionEpoch: 1,
		dialSequencer: func(context.Context, replica.Config) (*replica.Session, error) {
			return nil, errors.New("offline")
		},
	}
	_, err = handle.sequencerTimestamp(context.Background(), roomIdentitySnapshot{
		key: identity, session: relaySession, epoch: 1,
	})
	if !errors.Is(err, ErrSequencerUnavailable) {
		t.Fatalf("error = %v, want sequencer unavailable", err)
	}
}

func TestSequencerTimestampRejectsExcessiveSkew(t *testing.T) {
	identity := clockTestKey(t)
	room := clockTestKey(t)
	sequencer := clockTestKey(t)
	genesis, err := community.NewGenesis(room, sequencer, time.Now(), "Room", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := clockTestPeer(t, identity, sequencer, int32(time.Now().Add(community.MutationClockSkew+time.Minute).Unix()), nil)
	session := &replica.Session{Genesis: genesis, Peer: peer, Done: peer.Done()}
	handle := &roomHandle{client: &Client{}, key: genesis.RoomKey, session: session, sessionEpoch: 1}
	_, err = handle.sequencerTimestamp(context.Background(), roomIdentitySnapshot{
		key: identity, session: session, epoch: 1,
	})
	if !errors.Is(err, ErrSequencerClockSkew) {
		t.Fatalf("error = %v, want clock skew", err)
	}
}

func clockTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func clockTestPeer(
	t *testing.T,
	clientKey, serverKey ed25519.PrivateKey,
	remoteTime int32,
	queries *atomic.Int32,
) *roomnet.Peer {
	t.Helper()
	serverGateway, err := roomnet.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientGateway, err := roomnet.NewGateway(clientKey)
	if err != nil {
		serverGateway.Close()
		t.Fatal(err)
	}
	serverGateway.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(query *roomnet.Query) error {
			switch query.Data.(type) {
			case broadcast.GetTime, *broadcast.GetTime:
				if queries != nil {
					queries.Add(1)
				}
				return query.Answer(broadcast.Time{Now: remoteTime})
			default:
				return roomnet.ErrNoAnswer
			}
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		clientGateway.Close()
		serverGateway.Close()
		t.Fatal(err)
	}
	serveDone := make(chan struct{})
	go func() {
		_ = serverGateway.Serve(packet)
		close(serveDone)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	rawPeer, err := clientGateway.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), packet.LocalAddr().String())
	cancel()
	if err != nil {
		packet.Close()
		clientGateway.Close()
		serverGateway.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clientGateway.Close()
		serverGateway.Close()
		packet.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("clock test gateway did not stop")
		}
	})
	return roomnet.Wrap(rawPeer)
}
