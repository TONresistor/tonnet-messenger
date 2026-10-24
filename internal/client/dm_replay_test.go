package client

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
)

func TestClientDeduplicatesReceivedDMs(t *testing.T) {
	for _, mode := range []string{"sequential", "concurrent", "reconnect", "rejoin", "rewrapped", "invalid_then_valid", "two_distinct_messages", "obsolete_session"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			room, sender, recipient := clientTestPrivateKey(t), clientTestPrivateKey(t), clientTestPrivateKey(t)
			roomID := room.Public().(ed25519.PublicKey)
			instance := directTestClient(t)
			instance.key = recipient
			session := &replica.Session{}
			handle := &roomHandle{client: instance, key: roomID, ctx: ctx, session: session, sessionEpoch: 1}
			create := func() (community.DirectMessage, broadcast.Broadcast) {
				box, err := dm.SealForRoom(roomID, sender, recipient.Public().(ed25519.PublicKey), []byte("same text"))
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
				wrapper, err := broadcast.Sign(sender, nil, raw, time.Now().Unix())
				if err != nil {
					t.Fatal(err)
				}
				return direct, wrapper
			}
			direct, wrapper := create()
			expected := 1
			switch mode {
			case "concurrent":
				var wg sync.WaitGroup
				for i := 0; i < 32; i++ {
					wg.Add(1)
					go func() { defer wg.Done(); handle.ingestSerializable(session, 1, wrapper) }()
				}
				wg.Wait()
			case "invalid_then_valid":
				invalid := wrapper
				invalid.Signature = append([]byte(nil), wrapper.Signature...)
				invalid.Signature[0] ^= 1
				handle.ingestSerializable(session, 1, invalid)
				if len(instance.events) != 0 {
					t.Fatal("invalid signature was accepted")
				}
				handle.ingestSerializable(session, 1, wrapper)
			case "obsolete_session":
				handle.session = &replica.Session{}
				handle.ingestSerializable(session, 1, wrapper)
				expected = 0
			default:
				handle.ingestSerializable(session, 1, wrapper)
				switch mode {
				case "reconnect":
					session = &replica.Session{}
					handle.session = session
				case "rejoin":
					session = &replica.Session{}
					handle = &roomHandle{client: instance, key: roomID, ctx: ctx, session: session, sessionEpoch: 1}
				case "rewrapped":
					var err error
					wrapper, err = broadcast.Sign(sender, nil, wrapper.Data, int64(wrapper.Date)+1)
					if err != nil {
						t.Fatal(err)
					}
				case "two_distinct_messages":
					other, next := create()
					expected = 2
					oldID, _ := community.HashBoxed(direct)
					newID, _ := community.HashBoxed(other)
					if string(oldID) == string(newID) {
						t.Fatal("distinct sends unexpectedly have same ID")
					}
					wrapper = next
				}
				handle.ingestSerializable(session, 1, wrapper)
			}
			if len(instance.events) != expected {
				t.Fatalf("observed %d notifications, want %d", len(instance.events), expected)
			}
		})
	}
}

func directTestClient(t *testing.T) *Client {
	t.Helper()
	instance, err := Open(context.Background(), Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func directTestBroadcast(t *testing.T, roomID []byte, sender, recipient ed25519.PrivateKey) broadcast.Broadcast {
	t.Helper()
	box, err := dm.SealForRoom(roomID, sender, recipient.Public().(ed25519.PublicKey), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := community.SignDirectMessage(sender, community.DirectMessage{
		RoomID: roomID, ToKey: recipient.Public().(ed25519.PublicKey), Timestamp: time.Now().Unix(), Ciphertext: box,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := community.Encode(direct)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := broadcast.Sign(sender, nil, raw, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func directTestRowCount(t *testing.T, instance *Client) int {
	t.Helper()
	var count int
	if err := instance.store.db.QueryRow("SELECT COUNT(*) FROM received_direct_messages").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestDirectReplayProtectionHasNoCapacityLimit(t *testing.T) {
	ctx := context.Background()
	instance := directTestClient(t)
	room, sender := clientTestPrivateKey(t), clientTestPrivateKey(t)
	roomID := room.Public().(ed25519.PublicKey)
	session := &replica.Session{}
	handle := &roomHandle{client: instance, key: roomID, ctx: ctx, session: session, sessionEpoch: 1}
	now := time.Now()
	expires := now.Add(community.MutationClockSkew)
	for i := 0; i < 8193; i++ {
		var id [32]byte
		binary.BigEndian.PutUint64(id[:8], uint64(i))
		inserted, err := instance.store.claimDirectMessage(ctx, instance.key.Public().(ed25519.PublicKey), id, expires, now)
		if err != nil || !inserted {
			t.Fatalf("record id %d: inserted=%v err=%v", i, inserted, err)
		}
	}
	wrapper := directTestBroadcast(t, roomID, sender, instance.key)
	handle.ingestSerializable(session, 1, wrapper)
	if len(instance.events) != 1 {
		t.Fatalf("new DM produced %d notifications, want 1", len(instance.events))
	}
	notification := <-instance.events
	if notification.Method != "dm.message" {
		t.Fatalf("notification = %#v", notification)
	}
	handle.ingestSerializable(session, 1, wrapper)
	if len(instance.events) != 0 || directTestRowCount(t, instance) != 8194 {
		t.Fatal("replayed DM was emitted or new DM was not recorded")
	}
	if err := handle.notifyDirectForSession(ctx, session, 1, [32]byte{}, expires, "old duplicate"); err != nil || len(instance.events) != 0 {
		t.Fatalf("live id was evicted: %v", err)
	}
}

func TestClientDeduplicatesReceivedDMAfterRestart(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	instance, err := Open(ctx, Config{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	room, sender := clientTestPrivateKey(t), clientTestPrivateKey(t)
	roomID := room.Public().(ed25519.PublicKey)
	wrapper := directTestBroadcast(t, roomID, sender, instance.key)
	session := &replica.Session{}
	handle := &roomHandle{client: instance, key: roomID, ctx: ctx, session: session, sessionEpoch: 1}
	handle.ingestSerializable(session, 1, wrapper)
	if len(instance.events) != 1 {
		t.Fatalf("first delivery produced %d notifications", len(instance.events))
	}
	<-instance.events
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, Config{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	session = &replica.Session{}
	handle = &roomHandle{client: reopened, key: roomID, ctx: ctx, session: session, sessionEpoch: 1}
	handle.ingestSerializable(session, 1, wrapper)
	if len(reopened.events) != 0 || directTestRowCount(t, reopened) != 1 {
		t.Fatal("restart forgot the delivered DM")
	}
}

func TestDirectReplayProtectionPrunesExpiredRowsAndScopesRecipients(t *testing.T) {
	ctx := context.Background()
	instance := directTestClient(t)
	recipient := instance.key.Public().(ed25519.PublicKey)
	other := clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	now := time.Now()
	id, liveID := [32]byte{1}, [32]byte{2}
	for index, expiry := range []time.Time{now.Add(-time.Nanosecond), now} {
		expiredID := id
		expiredID[1] = byte(index)
		inserted, err := instance.store.claimDirectMessage(ctx, recipient, expiredID, expiry, now.Add(-time.Second))
		if err != nil || !inserted {
			t.Fatalf("record expiring row: inserted=%v err=%v", inserted, err)
		}
	}
	if inserted, err := instance.store.claimDirectMessage(ctx, recipient, liveID, now.Add(time.Minute), now); err != nil || !inserted {
		t.Fatalf("record live row: inserted=%v err=%v", inserted, err)
	}
	if directTestRowCount(t, instance) != 1 {
		t.Fatal("expired rows remain or live row was deleted")
	}
	if inserted, err := instance.store.claimDirectMessage(ctx, other, liveID, now.Add(time.Minute), now); err != nil || !inserted {
		t.Fatalf("other recipient incorrectly deduplicated: inserted=%v err=%v", inserted, err)
	}
	if inserted, err := instance.store.claimDirectMessage(ctx, recipient, liveID, now.Add(time.Minute), now); err != nil || inserted {
		t.Fatalf("same recipient not deduplicated: inserted=%v err=%v", inserted, err)
	}
}

func TestFailedDirectNotificationRemainsRetryable(t *testing.T) {
	ctx := context.Background()
	instance := directTestClient(t)
	session := &replica.Session{}
	handle := &roomHandle{client: instance, session: session, sessionEpoch: 1}
	id := [32]byte{1}
	expires := time.Now().Add(community.MutationClockSkew)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := handle.notifyDirectForSession(canceled, session, 1, id, expires, "hello"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled notification: %v", err)
	}
	instance.notifyClosed = true
	if err := handle.notifyDirectForSession(ctx, session, 1, id, expires, "hello"); !errors.Is(err, context.Canceled) || directTestRowCount(t, instance) != 0 {
		t.Fatalf("notification failure was recorded as a delivery: %v", err)
	}
	instance.notifyClosed = false
	// Cancellation during notification must not cancel the subsequent DELETE.
	instance.events = make(chan Notification)
	deadline, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := handle.notifyDirectForSession(deadline, session, 1, id, expires, "hello"); !errors.Is(err, context.DeadlineExceeded) || directTestRowCount(t, instance) != 0 {
		t.Fatalf("canceled notification left a claim: %v", err)
	}
	instance.events = make(chan Notification, 1)
	if err := handle.notifyDirectForSession(ctx, session, 1, id, expires, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := handle.notifyDirectForSession(ctx, session, 1, id, expires, "hello"); err != nil {
		t.Fatal(err)
	}
	if len(instance.events) != 1 || directTestRowCount(t, instance) != 1 {
		t.Fatal("retry was not delivered exactly once and remembered")
	}
}

func TestClientDeliversDirectMessageWhenReplayStorageFails(t *testing.T) {
	instance := directTestClient(t)
	room, sender := clientTestPrivateKey(t), clientTestPrivateKey(t)
	roomID := room.Public().(ed25519.PublicKey)
	wrapper := directTestBroadcast(t, roomID, sender, instance.key)
	if err := instance.store.Close(); err != nil {
		t.Fatal(err)
	}
	session := &replica.Session{}
	handle := &roomHandle{client: instance, key: roomID, ctx: instance.ctx, session: session, sessionEpoch: 1}
	handle.ingestSerializable(session, 1, wrapper)
	if len(instance.events) != 1 {
		t.Fatalf("storage failure produced %d notifications, want 1", len(instance.events))
	}
	notification := <-instance.events
	if notification.Method != "dm.message" || notification.Params.(map[string]any)["text"] != "hello" {
		t.Fatalf("notification = %#v", notification)
	}
}

func TestDirectNotificationRejectsExpiredAndStaleInputs(t *testing.T) {
	ctx := context.Background()
	instance := directTestClient(t)
	session := &replica.Session{}
	handle := &roomHandle{client: instance, session: session, sessionEpoch: 1}
	id := [32]byte{1}
	if err := handle.notifyDirectForSession(ctx, session, 1, id, time.Now().Add(-time.Second), "expired"); !errors.Is(err, community.ErrTimestamp) {
		t.Fatalf("expired DM accepted: %v", err)
	}
	instance.identityEpoch = 2
	if err := handle.notifyDirectForSession(ctx, session, 1, id, time.Now().Add(time.Minute), "old identity"); !errors.Is(err, errRoomSessionChanged) {
		t.Fatalf("old identity accepted: %v", err)
	}
	instance.identityEpoch = 1
	done := make(chan struct{})
	close(done)
	session.Done = done
	if err := handle.notifyDirectForSession(ctx, session, 1, id, time.Now().Add(time.Minute), "closed session"); !errors.Is(err, errRoomSessionChanged) {
		t.Fatalf("closed session accepted: %v", err)
	}
	if len(instance.events) != 0 || directTestRowCount(t, instance) != 0 {
		t.Fatal("rejected input emitted a notification or populated the database")
	}
}

func TestClientStoreMigratesV2DirectReplayProtection(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "client.db")
	database, err := openClientStore(ctx, filename)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.setMeta(ctx, "author_name", "preserved"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, "DROP TABLE received_direct_messages; UPDATE client_meta SET value='2' WHERE key='schema_version'"); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := openClientStore(ctx, filename)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var version string
	if err := restored.db.QueryRowContext(ctx, "SELECT value FROM client_meta WHERE key='schema_version'").Scan(&version); err != nil || version != "3" {
		t.Fatalf("version=%s err=%v", version, err)
	}
	if name, _, err := restored.profile(ctx); err != nil || name != "preserved" {
		t.Fatalf("migration lost existing data: name=%s err=%v", name, err)
	}
	recipient := clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	if inserted, err := restored.claimDirectMessage(ctx, recipient, [32]byte{1}, time.Now().Add(time.Minute), time.Now()); err != nil || !inserted {
		t.Fatalf("migration did not create usable replay protection: inserted=%v err=%v", inserted, err)
	}
}
