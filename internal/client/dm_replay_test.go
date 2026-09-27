package client

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
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
			instance := &Client{ctx: ctx, key: recipient, identityEpoch: 1, events: make(chan Notification, 64)}
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

func TestDirectReplayCacheExpiresOnlyAfterAcceptanceWindow(t *testing.T) {
	now := time.Now()
	var cache directReplayCache
	id := [32]byte{1}
	expires := now.Add(community.MutationClockSkew)
	cache.record(id, expires)
	futureID := [32]byte{2}
	cache.record(futureID, now.Add(2*community.MutationClockSkew))
	for _, when := range []time.Time{now.Add(61 * time.Second), expires} {
		cache.prune(when)
		if len(cache.entries) != 2 {
			t.Fatal("cache forgot a DM that could still be accepted")
		}
	}
	cache.prune(expires.Add(time.Nanosecond))
	if _, exists := cache.entries[id]; exists || len(cache.entries) != 1 {
		t.Fatal("cache did not expire only the old DM")
	}
	cache.prune(now.Add(2*community.MutationClockSkew + time.Nanosecond))
	if len(cache.entries) != 0 || !cache.nextExpiry.IsZero() {
		t.Fatal("expired IDs remain in the cache")
	}
}

func TestDirectReplayCacheRejectsOverflowWithoutEvictingLiveIDs(t *testing.T) {
	ctx := context.Background()
	instance := &Client{ctx: ctx, events: make(chan Notification, 1)}
	session := &replica.Session{}
	handle := &roomHandle{client: instance, session: session}
	expires := time.Now().Add(community.MutationClockSkew)
	for i := 0; i < maxReceivedDMs; i++ {
		var id [32]byte
		binary.BigEndian.PutUint64(id[:8], uint64(i))
		instance.receivedDMs.record(id, expires)
	}
	newID := [32]byte{31: 1}
	if err := handle.notifyDirectForSession(ctx, session, 0, newID, expires, "new"); !errors.Is(err, errDirectReplayCacheFull) {
		t.Fatalf("full cache accepted another ID: %v", err)
	}
	if err := handle.notifyDirectForSession(ctx, session, 0, [32]byte{}, expires, "duplicate"); err != nil {
		t.Fatal(err)
	}
	if len(instance.events) != 0 || len(instance.receivedDMs.entries) != maxReceivedDMs {
		t.Fatal("overflow evicted a live ID or delivered a duplicate")
	}
	instance.receivedDMs.record([32]byte{}, time.Now().Add(-time.Second))
	if err := handle.notifyDirectForSession(ctx, session, 0, newID, expires, "new"); err != nil {
		t.Fatalf("expired entry did not free capacity: %v", err)
	}
	if len(instance.events) != 1 || len(instance.receivedDMs.entries) != maxReceivedDMs {
		t.Fatal("unexpected delivery or cache size after expiry")
	}
}

func TestFailedDirectNotificationRemainsRetryable(t *testing.T) {
	ctx := context.Background()
	instance := &Client{ctx: ctx, events: make(chan Notification, 1)}
	session := &replica.Session{}
	handle := &roomHandle{client: instance, session: session}
	id := [32]byte{1}
	expires := time.Now().Add(community.MutationClockSkew)
	instance.events <- Notification{Method: "occupied"}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := handle.notifyDirectForSession(canceled, session, 0, id, expires, "hello"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled notification: %v", err)
	}
	if len(instance.receivedDMs.entries) != 0 {
		t.Fatal("failed notification poisoned the replay cache")
	}
	instance.notifyClosed = true
	if err := handle.notifyDirectForSession(ctx, session, 0, id, expires, "hello"); !errors.Is(err, context.Canceled) || len(instance.receivedDMs.entries) != 0 {
		t.Fatalf("notification failure was recorded as a delivery: %v", err)
	}
	instance.notifyClosed = false
	<-instance.events
	if err := handle.notifyDirectForSession(ctx, session, 0, id, expires, "hello"); err != nil {
		t.Fatal(err)
	}
	if len(instance.events) != 1 || len(instance.receivedDMs.entries) != 1 {
		t.Fatal("retry was not delivered and remembered")
	}
}

func TestDirectNotificationRejectsExpiredAndStaleInputs(t *testing.T) {
	ctx := context.Background()
	instance := &Client{ctx: ctx, identityEpoch: 1, events: make(chan Notification, 1)}
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
	if len(instance.events) != 0 || len(instance.receivedDMs.entries) != 0 {
		t.Fatal("rejected input emitted a notification or populated the cache")
	}
}
