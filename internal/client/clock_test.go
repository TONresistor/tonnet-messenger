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

func TestSequencerTimestampFailsClosedWithoutVerifiedReplica(t *testing.T) {
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

type replicaClockFixture struct {
	handle          *roomHandle
	snapshot        roomIdentitySnapshot
	room, sequencer ed25519.PrivateKey
	replicaQueries  atomic.Int32
}

func verifiedReplicaClock(t *testing.T) *replicaClockFixture {
	t.Helper()
	f := &replicaClockFixture{room: clockTestKey(t), sequencer: clockTestKey(t)}
	identity := clockTestKey(t)
	genesis, err := community.NewGenesis(f.room, f.sequencer, time.Now(), "Room", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := clockTestPeer(t, identity, clockTestKey(t), int32(time.Now().Add(4*time.Minute).Unix()), &f.replicaQueries)
	session := &replica.Session{Genesis: genesis, Peer: peer, Done: peer.Done()}
	projection, err := community.NewProjection(genesis)
	if err != nil {
		t.Fatal(err)
	}
	state, err := community.SignRoomStateV3(f.room, projection.State())
	if err != nil {
		t.Fatal(err)
	}
	f.handle = &roomHandle{client: &Client{}, key: genesis.RoomKey, session: session, sessionEpoch: 1, projection: projection,
		state: community.RoomStateResult{State: state, Stats: community.RoomStats{NodeRole: community.NodeRoleRelay, Ready: true}}}
	f.snapshot = roomIdentitySnapshot{key: identity, session: session, epoch: 1}
	return f
}

func TestReplicaTimestampFallbackThenDirectCalibration(t *testing.T) {
	f := verifiedReplicaClock(t)
	var queries atomic.Int32
	now := time.Now()
	peer := clockTestPeer(t, f.snapshot.key, f.sequencer, int32(now.Add(2*time.Minute).Unix()), &queries)
	authority := &replica.Session{Genesis: f.snapshot.session.Genesis, Peer: peer, Done: peer.Done()}
	dials := 0
	f.handle.dialSequencer = func(ctx context.Context, _ replica.Config) (*replica.Session, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > timeQueryTimeout {
			t.Fatal("direct calibration attempt has no bounded deadline")
		}
		dials++
		if dials == 1 {
			return nil, errors.New("direct discovery unavailable")
		}
		return authority, nil
	}
	before := time.Now().Unix()
	local, err := f.handle.sequencerTimestamp(context.Background(), f.snapshot)
	if err != nil || local < before || local > time.Now().Unix() {
		t.Fatalf("local fallback: %d %v", local, err)
	}
	if !f.handle.clockCalibrated.IsZero() || f.handle.clockSession != nil {
		t.Fatal("local time was cached as sequencer calibration")
	}
	calibrated, err := f.handle.sequencerTimestamp(context.Background(), f.snapshot)
	if err != nil || calibrated < now.Unix()+119 || dials != 2 || queries.Load() != 1 {
		t.Fatalf("direct calibration did not recover: %d %v", calibrated, err)
	}
	if _, err := f.handle.sequencerTimestamp(context.Background(), f.snapshot); err != nil || dials != 2 || queries.Load() != 1 {
		t.Fatal("direct calibration cache was lost", err)
	}
	if f.replicaQueries.Load() != 0 {
		t.Fatal("replica clock was queried")
	}
	// A valid cached calibration cannot bypass cancellation or identity fencing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.handle.sequencerTimestamp(ctx, f.snapshot); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	f.handle.mu.Lock()
	f.handle.sessionEpoch++
	f.handle.mu.Unlock()
	if _, err := f.handle.sequencerTimestamp(context.Background(), f.snapshot); !errors.Is(err, errRoomSessionChanged) {
		t.Fatal(err)
	}
}

func TestReplicaTimestampRejectsInconsistenciesAndAuthenticatedSkew(t *testing.T) {
	for _, failure := range []string{"genesis", "identity", "malformed discovery", "skew"} {
		t.Run(failure, func(t *testing.T) {
			f := verifiedReplicaClock(t)
			genesis, peerKey, now := f.snapshot.session.Genesis, f.sequencer, time.Now()
			if failure == "genesis" {
				var err error
				genesis, err = community.NewGenesis(f.room, f.sequencer, now, "Conflicting", "", true, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if failure == "identity" {
				peerKey = clockTestKey(t)
			}
			if failure == "skew" {
				now = now.Add(community.MutationClockSkew + time.Minute)
			}
			peer := clockTestPeer(t, f.snapshot.key, peerKey, int32(now.Unix()), nil)
			f.handle.dialSequencer = func(context.Context, replica.Config) (*replica.Session, error) {
				if failure == "malformed discovery" {
					return nil, roomnet.ErrMalformedAnswer
				}
				return &replica.Session{Genesis: genesis, Peer: peer, Done: peer.Done()}, nil
			}
			_, err := f.handle.sequencerTimestamp(context.Background(), f.snapshot)
			want := ErrSequencerUnavailable
			if failure == "skew" {
				want = ErrSequencerClockSkew
			}
			if !errors.Is(err, want) || !f.handle.clockCalibrated.IsZero() || f.replicaQueries.Load() != 0 {
				t.Fatalf("unsafe fallback after %s: %v", failure, err)
			}
		})
	}
}

func TestReplicaTimestampCancellationAndSessionChangesDuringDial(t *testing.T) {
	for _, failure := range []string{"cancelled", "deadline", "epoch", "closed"} {
		t.Run(failure, func(t *testing.T) {
			f := verifiedReplicaClock(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := errRoomSessionChanged
			if failure == "cancelled" {
				want = context.Canceled
			}
			if failure == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 5*time.Millisecond)
				defer stop()
				want = context.DeadlineExceeded
			}
			f.handle.dialSequencer = func(dialCtx context.Context, _ replica.Config) (*replica.Session, error) {
				switch failure {
				case "cancelled":
					cancel()
				case "deadline":
					<-dialCtx.Done()
				case "epoch":
					f.handle.mu.Lock()
					f.handle.sessionEpoch++
					f.handle.mu.Unlock()
				case "closed":
					f.snapshot.session.Peer.Close()
				}
				return nil, errors.New("unavailable")
			}
			if _, err := f.handle.sequencerTimestamp(ctx, f.snapshot); !errors.Is(err, want) {
				t.Fatalf("fallback ignored %s: %v", failure, err)
			}
		})
	}
}

func TestReplicaTimestampFallsBackAfterDirectTimeConnectionLoss(t *testing.T) {
	f := verifiedReplicaClock(t)
	peer := clockTestPeer(t, f.snapshot.key, f.sequencer, int32(time.Now().Unix()), nil)
	peer.Close()
	f.handle.dialSequencer = func(context.Context, replica.Config) (*replica.Session, error) {
		return &replica.Session{Genesis: f.snapshot.session.Genesis, Peer: peer, Done: peer.Done()}, nil
	}
	before := time.Now().Unix()
	stamp, err := f.handle.sequencerTimestamp(context.Background(), f.snapshot)
	if err != nil || stamp < before || stamp > time.Now().Unix() || !f.handle.clockCalibrated.IsZero() || f.replicaQueries.Load() != 0 {
		t.Fatalf("time connection loss fallback: %d %v", stamp, err)
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
	serverGateway.SetConnectionHandler(func(raw *roomnet.RawPeer) error {
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
