package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func TestInteractiveSessionSyncAndDirectMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	roomKey, nodeKey := clientTestPrivateKey(t), clientTestPrivateKey(t)
	now := time.Now()
	genesis, err := community.NewGenesis(roomKey, nodeKey, now, "Interactive", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Initialize(ctx, genesis, roomKey); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 270; index++ {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		proposal, err := community.SignProposal(roomKey, genesis.NodeKey, community.EventProposal{
			RoomID: genesis.RoomKey, Nonce: nonce, Timestamp: now.Unix(), Body: community.EventMessage{Text: "history"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Commit(ctx, proposal, roomKey, now); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	listener.Close()
	runtime, err := node.New(node.Config{
		Key: nodeKey, Listen: address, Socket: filepath.Join(t.TempDir(), "node.sock"), Genesis: &genesis,
		Store: database, RoomKey: roomKey, NodeRole: community.NodeRoleSequencer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	connect := func(name string) (*Client, <-chan Notification) {
		t.Helper()
		instance, err := Open(ctx, Config{StateDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { instance.Close() })
		directs := make(chan Notification, 4)
		go func() {
			defer close(directs)
			for notification := range instance.Notifications() {
				if notification.Method == "dm.message" {
					select {
					case directs <- notification:
					case <-ctx.Done():
					}
				}
			}
		}()
		if _, err := instance.SetName(ctx, name); err != nil {
			t.Fatal(err)
		}
		if err := instance.store.addRoom(ctx, genesis.RoomKey, keyText(genesis.RoomKey), nil); err != nil {
			t.Fatal(err)
		}
		session, err := replica.DialRoom(ctx, replica.Config{
			RoomID: genesis.RoomKey, NodeKey: instance.key, DirectAddress: address, DirectPublic: nodeKey.Public().(ed25519.PublicKey),
		})
		if err != nil {
			t.Fatal(err)
		}
		roomCtx, roomCancel := context.WithCancel(ctx)
		handle := &roomHandle{
			client: instance, key: genesis.RoomKey, ctx: roomCtx, cancel: roomCancel,
			session: session, sessionEpoch: 1, events: make(chan canonicalEvent, canonicalEventQueueCapacity),
		}
		instance.rooms[keyText(genesis.RoomKey)] = handle
		session.Peer.SetMessageHandler(func(value any) error { handle.ingestSerializable(session, 1, value); return nil })
		if err := handle.syncSessionLocked(ctx, session, 1); err != nil {
			t.Fatal(err)
		}
		handle.workers.Add(1)
		go func() { defer handle.workers.Done(); handle.ingestLoop(roomCtx) }()
		items, more, err := instance.Timeline(ctx, genesis.RoomKey, 0, 100)
		if err != nil || len(items) != 100 || !more {
			t.Fatalf("large history sync failed: len=%d more=%v err=%v", len(items), more, err)
		}
		return instance, directs
	}
	alice, aliceDirects := connect("Alice")
	bob, bobDirects := connect("Bob")
	if _, err := alice.SendMessage(ctx, keyText(genesis.RoomKey), "public message"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SendDM(ctx, keyText(genesis.RoomKey), bob.Identity().Key, "encrypted hello"); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct {
		channel   <-chan Notification
		direction string
	}{{aliceDirects, "sent"}, {bobDirects, "received"}} {
		select {
		case notification := <-expected.channel:
			value, ok := notification.Params.(map[string]any)
			if !ok || value["direction"] != expected.direction || value["text"] != "encrypted hello" {
				t.Fatalf("unexpected DM notification: %#v", notification)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
