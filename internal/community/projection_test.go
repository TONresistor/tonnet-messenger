package community

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestProjectionAppliesCanonicalAuthorizationAndState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	room, node := testPrivate(t), testPrivate(t)
	admin, moderator, user := testPrivate(t), testPrivate(t), testPrivate(t)
	genesis, err := NewGenesis(room, node, now, "Room", "Description", false, [][]byte{admin.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := NewProjection(genesis)
	if err != nil {
		t.Fatal(err)
	}

	commit := func(author ed25519.PrivateKey, body any) CommittedEvent {
		t.Helper()
		seqno, previous := projection.Head()
		proposal, err := SignProposal(author, genesis.NodeKey, EventProposal{
			RoomID: genesis.RoomKey, Nonce: testNonce(t), Timestamp: now.Unix(), Body: body,
		})
		if err != nil {
			t.Fatal(err)
		}
		event, err := SignCommit(room, proposal, seqno+1, previous, now)
		if err != nil {
			t.Fatal(err)
		}
		return event
	}

	if err := projection.Apply(commit(user, EventMessage{Text: "denied"})); !errors.Is(err, ErrProjectionUnauthorized) {
		t.Fatalf("unauthorized message error = %v", err)
	}
	messageTransition, err := projection.Prepare(commit(admin, EventMessage{Text: "allowed"}))
	if err != nil {
		t.Fatal(err)
	}
	if seqno, _ := projection.Head(); seqno != 0 {
		t.Fatal("prepare mutated the projection")
	}
	if err := projection.Commit(messageTransition); err != nil {
		t.Fatal(err)
	}
	if err := projection.Commit(messageTransition); err == nil {
		t.Fatal("stale transition committed twice")
	}
	if err := projection.Apply(commit(admin, EventModeratorGrant{SubjectKey: moderator.Public().(ed25519.PublicKey)})); err != nil {
		t.Fatal(err)
	}
	if err := projection.Apply(commit(moderator, EventPin{MessageID: 1})); err != nil {
		t.Fatal(err)
	}
	if err := projection.Apply(commit(room, EventAdminGrant{SubjectKey: moderator.Public().(ed25519.PublicKey)})); err != nil {
		t.Fatal(err)
	}
	if err := projection.Apply(commit(room, EventAdminRevoke{SubjectKey: moderator.Public().(ed25519.PublicKey)})); err != nil {
		t.Fatal(err)
	}
	metadataTransition, err := projection.Prepare(commit(admin, EventMetadata{Name: "Updated", Description: "Current"}))
	if err != nil {
		t.Fatal(err)
	}
	if state := projection.State(); state.Name != "Room" || state.Description != "Description" {
		t.Fatalf("prepare mutated projected state = %+v", state)
	}
	if err := projection.Commit(metadataTransition); err != nil {
		t.Fatal(err)
	}

	state := projection.State()
	if len(state.Admins) != 1 || len(state.Moderators) != 1 || len(state.PinnedMessages) != 1 || state.Name != "Updated" {
		t.Fatalf("projected state = %+v", state)
	}
	signed, err := SignRoomState(room, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.ValidateState(signed); err != nil {
		t.Fatal(err)
	}
	signed.Name = "Forged"
	signed, err = SignRoomState(room, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.ValidateState(signed); err == nil {
		t.Fatal("inconsistent signed state accepted")
	}
}
