package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
)

func TestClientStoreValidatesRoomStateRevision(t *testing.T) {
	ctx := context.Background()
	store, err := openClientStore(ctx, filepath.Join(t.TempDir(), "client.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	room := clientTestPrivateKey(t)
	node := clientTestPrivateKey(t)
	genesis, err := community.NewGenesis(room, node, now, "Room", "Description", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addRoom(ctx, genesis.RoomKey, "room", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.pinGenesis(ctx, genesis.RoomKey, genesis); err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	proposal, err := community.SignProposal(room, genesis.NodeKey, community.EventProposal{
		RoomID: genesis.RoomKey, Nonce: nonce, Timestamp: now.Unix(),
		Body: community.EventMetadata{Name: "Updated", Description: "Current"},
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := community.SignCommit(room, proposal, 1, community.Zero256(), now)
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := store.appendEvent(ctx, genesis.RoomKey, event); err != nil || !inserted {
		t.Fatalf("append event: inserted=%v err=%v", inserted, err)
	}
	eventHash, err := event.Hash()
	if err != nil {
		t.Fatal(err)
	}
	current, err := community.SignRoomState(room, community.RoomState{
		RoomID: genesis.RoomKey, RevisionSeqno: 1, RevisionHash: eventHash,
		Name: "Updated", Description: "Current", WritePolicy: genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := store.projectRoom(ctx, genesis.RoomKey, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.validateRoomState(ctx, genesis.RoomKey, genesis, projection, current); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	inconsistent, err := community.SignRoomState(room, community.RoomState{
		RoomID: genesis.RoomKey, RevisionSeqno: 1, RevisionHash: eventHash,
		Name: "Forged", Description: "Current", WritePolicy: genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.validateRoomState(ctx, genesis.RoomKey, genesis, projection, inconsistent); err == nil {
		t.Fatal("state content inconsistent with canonical events was accepted")
	}

	genesisHash, err := genesis.Hash()
	if err != nil {
		t.Fatal(err)
	}
	stale, err := community.SignRoomState(room, community.RoomState{
		RoomID: genesis.RoomKey, RevisionHash: genesisHash,
		Name: genesis.Name, Description: genesis.Description, WritePolicy: genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.validateRoomState(ctx, genesis.RoomKey, genesis, projection, stale); err == nil {
		t.Fatal("stale state accepted")
	}

	otherRoom := clientTestPrivateKey(t)
	otherHash := make([]byte, 32)
	wrongRoom, err := community.SignRoomState(otherRoom, community.RoomState{
		RoomID: otherRoom.Public().(ed25519.PublicKey), RevisionHash: otherHash,
		Name: "Other", Description: "Other", WritePolicy: genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.validateRoomState(ctx, genesis.RoomKey, genesis, projection, wrongRoom); err == nil {
		t.Fatal("state from another room accepted")
	}
}

func clientTestPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func TestRoomHandleInvalidatesOnlyExpectedSession(t *testing.T) {
	oldSession := &replica.Session{}
	newSession := &replica.Session{}
	handle := &roomHandle{
		ctx: context.Background(), session: newSession,
		events: make(chan canonicalEvent, canonicalEventQueueCapacity),
	}

	if handle.closeSessionIf(oldSession) {
		t.Fatal("stale session closed its replacement")
	}
	if err := handle.enqueueCanonical(oldSession, 0, community.CommittedEvent{}, nil); err != errRoomSessionChanged {
		t.Fatalf("stale session enqueue error = %v", err)
	}
	if len(handle.events) != 0 {
		t.Fatal("stale session queued an event")
	}
	if !handle.isCurrentSession(newSession, 0) {
		t.Fatal("replacement session was detached")
	}
	if !handle.closeSessionIf(newSession) || handle.isCurrentSession(newSession, 0) {
		t.Fatal("current session was not invalidated")
	}
}

func TestRoomHandleIngestFailureInvalidatesSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &replica.Session{}
	handle := &roomHandle{
		client: &Client{ctx: ctx}, ctx: ctx, session: session,
		events: make(chan canonicalEvent, canonicalEventQueueCapacity),
	}
	handle.workers.Add(1)
	go func() {
		defer handle.workers.Done()
		handle.ingestLoop(ctx)
	}()
	result := make(chan error, 1)
	if err := handle.enqueueCanonical(session, 0, community.CommittedEvent{}, result); err != nil {
		t.Fatal(err)
	}

	if err := <-result; err == nil {
		t.Fatal("invalid canonical event was accepted")
	}

	if handle.isCurrentSession(session, 0) {
		t.Fatal("failed canonical ingestion left the session connected")
	}
	cancel()
	handle.workers.Wait()
}

func TestRoomHandleQueueOverflowInvalidatesSession(t *testing.T) {
	ctx := context.Background()
	session := &replica.Session{}
	handle := &roomHandle{
		ctx: ctx, session: session,
		events: make(chan canonicalEvent, 1),
	}
	if err := handle.enqueueCanonical(session, 0, community.CommittedEvent{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := handle.enqueueCanonical(session, 0, community.CommittedEvent{}, nil); err != errCanonicalQueueFull {
		t.Fatalf("queue overflow error = %v", err)
	}
	if handle.isCurrentSession(session, 0) {
		t.Fatal("queue overflow left the session connected")
	}
}

func TestRoomHandleSerializesDuplicateCanonicalEvents(t *testing.T) {
	f := newCanonicalIngestFixture(t)
	event := f.event(t, 1, community.Zero256(), community.EventMessage{Text: "once"})

	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- f.handle.ingestCanonical(f.ctx, f.session, 0, event)
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	items, _, err := f.store.timeline(f.ctx, f.genesis.RoomKey, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("stored events = %d", len(items))
	}
	if len(f.client.events) != 1 {
		t.Fatalf("notifications = %d", len(f.client.events))
	}
}

func TestClientStoreRejectsConflictingCommitForSameProposal(t *testing.T) {
	f := newCanonicalIngestFixture(t)
	first := f.event(t, 1, community.Zero256(), community.EventMessage{Text: "fork"})
	conflict, err := community.SignCommit(f.room, first.Proposal, 1, community.Zero256(), f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := f.store.appendEvent(f.ctx, f.genesis.RoomKey, first); err != nil || !inserted {
		t.Fatalf("first commit: inserted=%v err=%v", inserted, err)
	}
	if inserted, err := f.store.appendEvent(f.ctx, f.genesis.RoomKey, conflict); err == nil || inserted {
		t.Fatalf("conflicting commit: inserted=%v err=%v", inserted, err)
	}
	if exact, err := f.store.hasEvent(f.ctx, f.genesis.RoomKey, conflict); err == nil || exact {
		t.Fatalf("conflicting commit reported durable: exact=%v err=%v", exact, err)
	}
}

func TestClientStorePinsGenesisAcrossCacheReset(t *testing.T) {
	ctx := context.Background()
	store, err := openClientStore(ctx, filepath.Join(t.TempDir(), "client.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	room := clientTestPrivateKey(t)
	now := time.Now().UTC().Truncate(time.Second)
	genesis, err := community.NewGenesis(room, clientTestPrivateKey(t), now, "Room", "Description", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addRoom(ctx, genesis.RoomKey, "room", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.pinGenesis(ctx, genesis.RoomKey, genesis); err != nil {
		t.Fatal(err)
	}
	if err := store.pinGenesis(ctx, genesis.RoomKey, genesis); err != nil {
		t.Fatalf("identical genesis rejected: %v", err)
	}
	conflict, err := community.NewGenesis(room, clientTestPrivateKey(t), now, "Other", "Fork", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.pinGenesis(ctx, genesis.RoomKey, conflict); err == nil {
		t.Fatal("conflicting genesis accepted")
	}
	if err := store.resetRoomCache(ctx, genesis.RoomKey); err != nil {
		t.Fatal(err)
	}
	record, err := store.room(ctx, genesis.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := community.Encode(genesis)
	got, _ := community.Encode(record.Genesis)
	if !bytes.Equal(got, want) {
		t.Fatal("cache reset replaced pinned genesis")
	}
}

func TestRoomHandleRejectsUnrepairedGap(t *testing.T) {
	f := newCanonicalIngestFixture(t)
	event := f.event(t, 2, community.Zero256(), community.EventMessage{Text: "gap"})

	if err := f.handle.ingestCanonical(f.ctx, f.session, 0, event); err == nil {
		t.Fatal("event gap was accepted without repair")
	}
	items, _, err := f.store.timeline(f.ctx, f.genesis.RoomKey, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 || len(f.client.events) != 0 {
		t.Fatal("unrepaired gap was persisted or notified")
	}
}

func TestRoomHandlePreservesDurableEventWhenStateValidationFails(t *testing.T) {
	f := newCanonicalIngestFixture(t)
	event := f.event(t, 1, community.Zero256(), community.EventMetadata{Name: "Updated", Description: "Current"})

	if err := f.handle.ingestCanonical(f.ctx, f.session, 0, event); err != nil {
		t.Fatalf("durable event reported as failed: %v", err)
	}
	if f.handle.isCurrentSession(f.session, 0) {
		t.Fatal("state validation failure left the session connected")
	}
	items, _, err := f.store.timeline(f.ctx, f.genesis.RoomKey, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("durable canonical events = %d", len(items))
	}
	if len(f.client.events) != 1 {
		t.Fatalf("durable event notifications = %d", len(f.client.events))
	}
	notification := <-f.client.events
	if notification.Method != "room.event" {
		t.Fatalf("notification = %s", notification.Method)
	}
}

func TestRoomHandleAppliesNotificationBackpressure(t *testing.T) {
	f := newCanonicalIngestFixture(t)
	sessionDone := make(chan struct{})
	f.session.Done = sessionDone
	for range cap(f.client.events) {
		f.client.events <- Notification{Method: "occupied"}
	}
	event := f.event(t, 1, community.Zero256(), community.EventMessage{Text: "backpressure"})
	result := make(chan error, 1)
	go func() {
		result <- f.handle.ingestCanonical(f.ctx, f.session, 0, event)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		items, _, err := f.store.timeline(f.ctx, f.genesis.RoomKey, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canonical event was not persisted")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-result:
		t.Fatalf("ingestion bypassed notification backpressure: %v", err)
	default:
	}
	close(sessionDone)
	f.handle.closeSessionIf(f.session)
	select {
	case err := <-result:
		t.Fatalf("session close dropped a durable notification: %v", err)
	default:
	}
	for range cap(f.client.events) {
		<-f.client.events
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if notification := <-f.client.events; notification.Method != "room.event" {
		t.Fatalf("notification = %s", notification.Method)
	}
}

func TestClientCloseWaitsForRoomWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store, err := openClientStore(ctx, filepath.Join(t.TempDir(), "client.db"))
	if err != nil {
		t.Fatal(err)
	}
	room := clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	if err := store.addRoom(ctx, room, "room", nil); err != nil {
		t.Fatal(err)
	}
	roomCtx, roomCancel := context.WithCancel(ctx)
	client := &Client{
		ctx: ctx, cancel: cancel, store: store, events: make(chan Notification, 1),
		rooms: make(map[string]*roomHandle),
	}
	handle := &roomHandle{client: client, key: room, ctx: roomCtx, cancel: roomCancel}
	client.rooms[keyText(room)] = handle
	checked := make(chan error, 1)
	handle.workers.Add(1)
	go func() {
		defer handle.workers.Done()
		<-roomCtx.Done()
		_, err := store.room(context.Background(), room)
		checked <- err
	}()

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-checked; err != nil {
		t.Fatalf("database closed before room workers stopped: %v", err)
	}
	if _, open := <-client.events; open {
		t.Fatal("notification channel remained open")
	}
}

func TestClientLeaveWaitsForRoomWorkers(t *testing.T) {
	f := newCanonicalIngestFixture(t)
	f.handle.cancel = f.cancel
	f.client.rooms = map[string]*roomHandle{keyText(f.genesis.RoomKey): f.handle}
	checked := make(chan error, 1)
	f.handle.workers.Add(1)
	go func() {
		defer f.handle.workers.Done()
		<-f.ctx.Done()
		_, err := f.store.room(context.Background(), f.genesis.RoomKey)
		checked <- err
	}()

	if err := f.client.Leave(context.Background(), keyText(f.genesis.RoomKey)); err != nil {
		t.Fatal(err)
	}
	if err := <-checked; err != nil {
		t.Fatalf("room was deleted before its workers stopped: %v", err)
	}
	if _, err := f.store.room(context.Background(), f.genesis.RoomKey); err == nil {
		t.Fatal("room remained after leave")
	}
}

type canonicalIngestFixture struct {
	ctx     context.Context
	cancel  context.CancelFunc
	store   *clientStore
	room    ed25519.PrivateKey
	genesis community.Genesis
	session *replica.Session
	client  *Client
	handle  *roomHandle
	now     time.Time
}

func newCanonicalIngestFixture(t *testing.T) *canonicalIngestFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	store, err := openClientStore(ctx, filepath.Join(t.TempDir(), "client.db"))
	if err != nil {
		t.Fatal(err)
	}
	room := clientTestPrivateKey(t)
	node := clientTestPrivateKey(t)
	now := time.Now().UTC().Truncate(time.Second)
	genesis, err := community.NewGenesis(room, node, now, "Room", "Description", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addRoom(ctx, genesis.RoomKey, "room", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.pinGenesis(ctx, genesis.RoomKey, genesis); err != nil {
		t.Fatal(err)
	}
	session := &replica.Session{Genesis: genesis}
	client := &Client{ctx: ctx, store: store, events: make(chan Notification, 8)}
	handle := &roomHandle{
		client: client, key: genesis.RoomKey, ctx: ctx, session: session,
		events: make(chan canonicalEvent, canonicalEventQueueCapacity),
	}
	handle.workers.Add(1)
	go func() {
		defer handle.workers.Done()
		handle.ingestLoop(ctx)
	}()
	f := &canonicalIngestFixture{
		ctx: ctx, cancel: cancel, store: store, room: room, genesis: genesis,
		session: session, client: client, handle: handle, now: now,
	}
	t.Cleanup(func() {
		cancel()
		handle.workers.Wait()
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (f *canonicalIngestFixture) event(t *testing.T, seqno int64, previous []byte, body any) community.CommittedEvent {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	proposal, err := community.SignProposal(f.room, f.genesis.NodeKey, community.EventProposal{
		RoomID: f.genesis.RoomKey, Nonce: nonce, Timestamp: f.now.Unix(), Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := community.SignCommit(f.room, proposal, seqno, previous, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return event
}
