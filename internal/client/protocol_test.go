package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

func TestSubmitRejectsUnrelatedCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	roomKey, sequencerKey, relayKey, otherAuthor := clockTestKey(t), clockTestKey(t), clockTestKey(t), clockTestKey(t)
	genesis, err := community.NewGenesis(roomKey, sequencerKey, time.Now(), "Audit", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := community.SignProposal(otherAuthor, genesis.NodeKey, community.EventProposal{RoomID: genesis.RoomKey, Nonce: make([]byte, 32), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "OLD MESSAGE FROM SOMEONE ELSE"}})
	if err != nil {
		t.Fatal(err)
	}
	oldCommit, err := community.SignCommit(roomKey, proposal, 1, community.Zero256(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := community.NewProjection(genesis)
	if err != nil {
		t.Fatal(err)
	}
	state, err := community.SignRoomState(roomKey, projection.State())
	if err != nil {
		t.Fatal(err)
	}
	headHash, err := oldCommit.Hash()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := roomnet.NewGateway(relayKey)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	gateway.SetConnectionHandler(func(raw *quic.Peer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(query *roomnet.Query) error {
			switch query.Data.(type) {
			case community.GetRoomGenesis:
				return query.Answer(genesis)
			case community.GetRoomState:
				return query.Answer(community.RoomStateResult{State: state, Stats: community.RoomStats{NodeRole: community.NodeRoleRelay, Ready: true, ReplicaSeqno: 1, ReplicaHash: headHash}})
			case community.GetEvents:
				return query.Answer(community.EventList{Events: []community.CommittedEvent{oldCommit}})
			case community.SubmitEvent:
				return query.Answer(community.SubmitAccepted{Event: oldCommit})
			default:
				return roomnet.ErrNoAnswer
			}
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() { _ = gateway.Serve(packet) }()
	instance, err := Open(ctx, Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	go func() {
		for range instance.Notifications() {
		}
	}()
	if err := instance.store.addRoom(ctx, genesis.RoomKey, keyText(genesis.RoomKey), nil); err != nil {
		t.Fatal(err)
	}
	session, err := replica.DialRoom(ctx, replica.Config{RoomID: genesis.RoomKey, NodeKey: instance.key, DirectAddress: packet.LocalAddr().String(), DirectPublic: relayKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	clockPeer := clockTestPeer(t, instance.key, sequencerKey, int32(time.Now().Unix()), nil)
	roomCtx, roomCancel := context.WithCancel(ctx)
	handle := &roomHandle{client: instance, key: genesis.RoomKey, ctx: roomCtx, cancel: roomCancel, session: session, sessionEpoch: 1, events: make(chan canonicalEvent, canonicalEventQueueCapacity)}
	handle.dialSequencer = func(context.Context, replica.Config) (*replica.Session, error) {
		return &replica.Session{Genesis: genesis, Peer: clockPeer, Done: clockPeer.Done()}, nil
	}
	instance.rooms[keyText(genesis.RoomKey)] = handle
	if err := handle.syncSessionLocked(ctx, session, 1); err != nil {
		t.Fatal(err)
	}
	handle.workers.Add(1)
	go func() { defer handle.workers.Done(); handle.ingestLoop(roomCtx) }()
	result, err := instance.SendMessage(ctx, keyText(genesis.RoomKey), "MY NEW MESSAGE")
	var failure *OperationError
	if result != nil || !errors.As(err, &failure) || failure.Code != "PROTOCOL_ERROR" {
		t.Fatalf("unrelated commit accepted: %#v %v", result, err)
	}
	pending, err := instance.GetPending(ctx, keyText(genesis.RoomKey))
	if err != nil || pending == nil {
		t.Fatalf("uncertain operation lost: %#v %v", pending, err)
	}
}

func TestClientRejectsInvalidDMPlaintext(t *testing.T) {
	ctx := context.Background()
	roomKey, sender, recipient := clockTestKey(t), clockTestKey(t), clockTestKey(t)
	roomID := roomKey.Public().(ed25519.PublicKey)
	instance := &Client{ctx: ctx, key: recipient, identityEpoch: 1, profiles: make(map[string]string), events: make(chan Notification, 4)}
	session := &replica.Session{}
	handle := &roomHandle{client: instance, key: roomID, ctx: ctx, session: session, sessionEpoch: 1}
	for _, plaintext := range []string{string([]byte{0xff, 0xfe})} {
		box, err := dm.SealForRoom(roomID, sender, recipient.Public().(ed25519.PublicKey), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		direct, err := community.SignDirectMessage(sender, community.DirectMessage{RoomID: roomID, ToKey: recipient.Public().(ed25519.PublicKey), Timestamp: time.Now().Unix(), Ciphertext: box})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := community.Encode(direct)
		if err != nil {
			t.Fatal(err)
		}
		wrapper, err := broadcast.Sign(sender, tonoverlay.CertificateEmpty{}, raw, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		handle.ingestSerializable(session, 1, wrapper)
		select {
		case notification := <-instance.events:
			t.Fatalf("invalid plaintext accepted as %s", notification.Method)
		default:
		}
	}
}

func TestClientRejectsNonemptyBroadcastCertificate(t *testing.T) {
	ctx := context.Background()
	roomKey, sender, recipient := clockTestKey(t), clockTestKey(t), clockTestKey(t)
	roomID := roomKey.Public().(ed25519.PublicKey)
	instance := &Client{ctx: ctx, key: recipient, identityEpoch: 1, profiles: make(map[string]string), events: make(chan Notification, 4)}
	session := &replica.Session{}
	handle := &roomHandle{client: instance, key: roomID, ctx: ctx, session: session, sessionEpoch: 1}
	box, err := dm.SealForRoom(roomID, sender, recipient.Public().(ed25519.PublicKey), []byte("valid plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := community.SignDirectMessage(sender, community.DirectMessage{RoomID: roomID, ToKey: recipient.Public().(ed25519.PublicKey), Timestamp: time.Now().Unix(), Ciphertext: box})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := community.Encode(direct)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := broadcast.Sign(sender, tonoverlay.CertificateEmpty{}, raw, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	for _, certificateLength := range []int{64, 5000} {
		wrapper.Certificate = tonoverlay.Certificate{IssuedBy: wrapper.Src, ExpireAt: uint32(time.Now().Unix() + 60), MaxSize: 4096, Signature: make([]byte, certificateLength)}
		encoded, err := community.Encode(wrapper)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := community.DecodeAny(encoded)
		if err != nil {
			t.Fatal(err)
		}
		handle.ingestSerializable(session, 1, decoded)
		select {
		case <-instance.events:
			t.Fatal("nonempty certificate accepted")
		default:
		}
	}
}
