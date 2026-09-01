package community

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func testPrivate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testNonce(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestIdentityAndRoomKeyText(t *testing.T) {
	public := testPrivate(t).Public().(ed25519.PublicKey)
	text, err := RoomKeyText(public)
	if err != nil || len(text) != 43 {
		t.Fatalf("text=%q err=%v", text, err)
	}
	decoded, err := ParseRoomKeyText(text)
	if err != nil || !bytes.Equal(decoded, public) {
		t.Fatalf("roundtrip failed: %v", err)
	}
}

func TestV2ProposalCommitAndProfileBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	room, node, author := testPrivate(t), testPrivate(t), testPrivate(t)
	proposal, err := SignProposal(author, node.Public().(ed25519.PublicKey), EventProposal{
		RoomID: room.Public().(ed25519.PublicKey), AuthorName: "alice", AuthorDomain: "alice.ton",
		Nonce: testNonce(t), Timestamp: now.Unix(), Body: EventMessage{Text: "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := proposal.Verify(node.Public().(ed25519.PublicKey), now); err != nil {
		t.Fatal(err)
	}
	tampered := proposal
	tampered.AuthorDomain = "mallory.ton"
	if !errors.Is(tampered.Verify(node.Public().(ed25519.PublicKey), now), ErrBadSignature) {
		t.Fatal("profile change did not invalidate signature")
	}
	commit, err := SignCommit(room, proposal, 1, Zero256(), now)
	if err != nil || commit.Verify(room.Public().(ed25519.PublicKey), node.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("commit failed: %v", err)
	}
}

func TestDirectMessageIsRoomBound(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	from, to := testPrivate(t), testPrivate(t).Public().(ed25519.PublicKey)
	roomA, roomB := testPrivate(t).Public().(ed25519.PublicKey), testPrivate(t).Public().(ed25519.PublicKey)
	message, err := SignDirectMessage(from, DirectMessage{
		RoomID: roomA, ToKey: to, AuthorName: "alice", Timestamp: now.Unix(), Ciphertext: make([]byte, 28),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := message.Verify(roomA, now); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(message.Verify(roomB, now), ErrWrongRoom) {
		t.Fatal("cross-room direct message accepted")
	}
}
