package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

type fixture struct {
	ctx       context.Context
	now       time.Time
	room      ed25519.PrivateKey
	node      ed25519.PrivateKey
	user      ed25519.PrivateKey
	admin     ed25519.PrivateKey
	genesis   community.Genesis
	store     *Store
	storePath string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{ctx: context.Background(), now: time.Now().UTC().Truncate(time.Second)}
	f.room = privateKey(t)
	f.node = privateKey(t)
	f.user = privateKey(t)
	f.admin = privateKey(t)
	var err error
	f.genesis, err = community.NewGenesis(f.room, f.node, f.now, "Room", "Description", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.storePath = filepath.Join(t.TempDir(), "room.db")
	f.store, err = Open(f.ctx, f.storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	if err := f.store.Initialize(f.ctx, f.genesis, f.room); err != nil {
		t.Fatal(err)
	}
	return f
}

func privateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func randomNonce(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func (f *fixture) proposal(t *testing.T, author ed25519.PrivateKey, body any, nonce []byte, at time.Time) community.EventProposal {
	t.Helper()
	proposal, err := community.SignProposal(author, f.genesis.NodeKey, community.EventProposal{
		RoomID: f.genesis.RoomKey, Nonce: nonce, Timestamp: at.Unix(), Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func TestCommitIsDurableOrderedAndIdempotent(t *testing.T) {
	f := newFixture(t)
	nonce := randomNonce(t)
	proposal := f.proposal(t, f.user, community.EventMessage{
		Text: "one",
	}, nonce, f.now)
	first, err := f.store.Commit(f.ctx, proposal, f.room, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate || first.Event.Seqno != 1 || first.Event.MessageID != 1 {
		t.Fatalf("first commit = %+v", first)
	}
	duplicate, err := f.store.Commit(f.ctx, proposal, f.room, f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate || duplicate.Event.Seqno != first.Event.Seqno {
		t.Fatalf("duplicate commit = %+v", duplicate)
	}

	reused := f.proposal(t, f.user, community.EventMessage{
		Text: "different",
	}, nonce, f.now)
	if _, err := f.store.Commit(f.ctx, reused, f.room, f.now); rejectionCode(err) != community.RejectReusedNonce {
		t.Fatalf("reused nonce error = %v", err)
	}
	head, err := f.store.Head(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seqno != 1 {
		t.Fatalf("head after rejection = %d", head.Seqno)
	}

	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(f.ctx, f.storePath)
	if err != nil {
		t.Fatal(err)
	}
	f.store = reopened
	if err := reopened.ValidateGenesis(f.ctx, f.genesis); err != nil {
		t.Fatal(err)
	}
	head, err = reopened.Head(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seqno != 1 || len(head.Hash) != 32 {
		t.Fatalf("reopened head = %+v", head)
	}
	page, err := reopened.MessagesRecent(f.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Messages) != 1 || page.Messages[0].Proposal.Body.(community.EventMessage).Text != "one" {
		t.Fatalf("reopened messages = %+v", page)
	}
}

func TestRolesPolicyPinsAndPagination(t *testing.T) {
	f := newFixture(t)
	commit := func(author ed25519.PrivateKey, body any) community.CommittedEvent {
		t.Helper()
		proposal := f.proposal(t, author, body, randomNonce(t), f.now)
		result, err := f.store.Commit(f.ctx, proposal, f.room, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return result.Event
	}

	commit(f.room, community.EventAdminGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)})
	commit(f.admin, community.EventWritePolicy{AnyoneCanWrite: false})
	denied := f.proposal(t, f.user, community.EventMessage{
		Text: "denied",
	}, randomNonce(t), f.now)
	if _, err := f.store.Commit(f.ctx, denied, f.room, f.now); rejectionCode(err) != community.RejectPermissionDenied {
		t.Fatalf("write-policy rejection = %v", err)
	}

	for _, text := range []string{"one", "two", "three"} {
		commit(f.admin, community.EventMessage{Text: text})
	}
	commit(f.admin, community.EventPin{MessageID: 3})
	commit(f.admin, community.EventMetadata{Name: "Renamed", Description: "Updated"})
	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Verify(); err != nil {
		t.Fatal(err)
	}
	if state.Name != "Renamed" || state.WritePolicy.AnyoneCanWrite || !bytes.Equal(state.Admins[0], f.admin.Public().(ed25519.PublicKey)) {
		t.Fatalf("state = %+v", state)
	}
	if len(state.PinnedMessages) != 1 || state.PinnedMessages[0] != 3 {
		t.Fatalf("pins = %v", state.PinnedMessages)
	}

	recent, err := f.store.MessagesRecent(f.ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !recent.HasMore || len(recent.Messages) != 2 || recent.Messages[0].MessageID >= recent.Messages[1].MessageID {
		t.Fatalf("recent page = %+v", recent)
	}
	before, err := f.store.MessagesBefore(f.ctx, recent.Messages[0].MessageID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Messages) != 1 || before.Messages[0].MessageID >= recent.Messages[0].MessageID {
		t.Fatalf("before page = %+v", before)
	}
	events, err := f.store.Events(f.ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !events.HasMore || len(events.Events) != 2 || events.Events[0].Seqno != 3 {
		t.Fatalf("events page = %+v", events)
	}
	if err := f.store.IntegrityCheck(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func rejectionCode(err error) int32 {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Code
	}
	return 0
}
