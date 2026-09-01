package store

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
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
