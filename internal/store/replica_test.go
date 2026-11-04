package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func TestReplicaAppendAndSignedStateInstallation(t *testing.T) {
	authority := newFixture(t)
	commit := func(body any) community.CommittedEvent {
		t.Helper()
		proposal := authority.proposal(t, authority.room, body, randomNonce(t), authority.now)
		result, err := authority.store.Commit(authority.ctx, proposal, authority.room, authority.now)
		if err != nil {
			t.Fatal(err)
		}
		return result.Event
	}
	events := []community.CommittedEvent{
		commit(community.EventAdminGrant{SubjectKey: authority.admin.Public().(ed25519.PublicKey)}),
		commit(community.EventWritePolicy{AnyoneCanWrite: false}),
		commit(community.EventMessage{Text: "replicated"}),
	}
	signedState, err := authority.store.State(authority.ctx)
	if err != nil {
		t.Fatal(err)
	}

	replica, err := Open(context.Background(), filepath.Join(t.TempDir(), "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	if err := replica.InitializeReplica(context.Background(), authority.genesis); err != nil {
		t.Fatal(err)
	}
	if err := replica.ReplicaReady(context.Background()); err == nil {
		t.Fatal("unsigned bootstrap state reported ready")
	}
	for _, event := range events {
		appended, err := replica.AppendReplica(context.Background(), event)
		if err != nil || !appended {
			t.Fatalf("append seqno %d: appended=%v err=%v", event.Seqno, appended, err)
		}
	}
	if err := replica.ReplicaReady(context.Background()); err == nil {
		t.Fatal("replica with an uncovered state transition reported ready")
	}
	if appended, err := replica.AppendReplica(context.Background(), events[len(events)-1]); err != nil || appended {
		t.Fatalf("duplicate append: appended=%v err=%v", appended, err)
	}
	if err := replica.InstallReplicaState(context.Background(), signedState); err != nil {
		t.Fatal(err)
	}
	if err := replica.ReplicaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	head, err := replica.Head(context.Background())
	if err != nil || head.Seqno != int64(len(events)) {
		t.Fatalf("replica head = %+v err=%v", head, err)
	}
}

func TestReplicaVerifiesBanProjectionAndBannedAuthors(t *testing.T) {
	f := newFixture(t)
	initial, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	subject := f.user.Public().(ed25519.PublicKey)
	for _, body := range []any{community.EventAdminGrant{SubjectKey: subject}, community.EventModeratorGrant{SubjectKey: subject}, community.EventBanV1{SubjectKey: subject}} {
		proposal := f.proposal(t, f.room, body, randomNonce(t), f.now)
		if _, err := f.store.Commit(f.ctx, proposal, f.room, f.now); err != nil {
			t.Fatal(err)
		}
	}
	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "replica.db")
	replica, err := Open(f.ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { replica.Close() }()
	if err := replica.InitializeReplica(f.ctx, f.genesis); err != nil {
		t.Fatal(err)
	}
	if err := replica.InstallReplicaState(f.ctx, initial); err != nil {
		t.Fatal(err)
	}
	page, err := f.store.Events(f.ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range page.Events {
		if _, err := replica.AppendReplica(f.ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := replica.ReplicaReady(f.ctx); err == nil {
		t.Fatal("stale signed state covered a ban")
	}
	forged := state
	forged.Banned = nil
	forged, err = community.SignRoomStateV3(f.room, forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.InstallReplicaState(f.ctx, forged); err == nil {
		t.Fatal("signed state omitted a canonical ban")
	}
	forged = state
	forged.Banned = append(append([][]byte(nil), state.Banned...), f.admin.Public().(ed25519.PublicKey))
	forged, err = community.SignRoomStateV3(f.room, forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.InstallReplicaState(f.ctx, forged); err == nil {
		t.Fatal("signed state invented a ban")
	}
	if err := replica.InstallReplicaState(f.ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := replica.ReplicaReady(f.ctx); err != nil {
		t.Fatal(err)
	}
	head, err := replica.Head(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	proposal := f.proposal(t, f.user, community.EventMessage{Text: "forged room-signed commit"}, randomNonce(t), f.now)
	event, err := community.SignCommit(f.room, proposal, head.Seqno+1, head.Hash, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replica.AppendReplica(f.ctx, event); rejectionCode(err) != 6 {
		t.Fatalf("banned canonical author accepted: %v", err)
	}
	after, err := replica.Head(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Seqno != head.Seqno || !bytes.Equal(after.Hash, head.Hash) {
		t.Fatal("rejected canonical event persisted")
	}
	if err := replica.Close(); err != nil {
		t.Fatal(err)
	}
	replica, err = Open(f.ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Audit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.AppendReplica(f.ctx, event); rejectionCode(err) != 6 {
		t.Fatalf("ban lost after replica reopen: %v", err)
	}
}

func TestLegacyReplicaRequiresVerifiedV3WithoutSigning(t *testing.T) {
	f := newFixture(t)
	proposal := f.proposal(t, f.user, community.EventMessage{Text: "retained"}, randomNonce(t), f.now)
	if _, err := f.store.Commit(f.ctx, proposal, f.room, f.now); err != nil {
		t.Fatal(err)
	}
	state, legacyRaw := legacySnapshot(t, f)
	before := preservedRoomRows(t, f.store)
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.store, err = Open(f.ctx, f.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.ReplicaReady(f.ctx); err == nil {
		t.Fatal("legacy replica reported ready without V3")
	}
	var raw []byte
	if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&raw); err != nil || !bytes.Equal(raw, legacyRaw) {
		t.Fatalf("opening replica re-signed state: %v", err)
	}
	invalid := state
	invalid.Signature = append([]byte(nil), state.Signature...)
	invalid.Signature[0] ^= 1
	if err := f.store.InstallReplicaState(f.ctx, invalid); err == nil {
		t.Fatal("replica accepted an unverified replacement")
	}
	if err := f.store.ReplicaReady(f.ctx); err == nil {
		t.Fatal("failed replacement made replica ready")
	}
	if err := f.store.InstallReplicaState(f.ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ReplicaReady(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, preservedRoomRows(t, f.store)) {
		t.Fatal("replica state replacement changed history")
	}
	if err := f.store.Audit(f.ctx); err != nil {
		t.Fatal(err)
	}
}
