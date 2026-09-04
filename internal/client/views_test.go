package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func TestStateViewExcludesNodeLocalStats(t *testing.T) {
	room, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := community.RoomStateResult{
		State: community.RoomState{RoomID: room, Name: "Room"},
		Stats: community.RoomStats{OnlineUsers: 12, ReplicaSeqno: 99, NodeRole: community.NodeRoleRelay, Ready: true},
	}
	view := stateView(result.State, 7)
	for _, field := range []string{"online_users", "node_role", "ready"} {
		if _, exists := view[field]; exists {
			t.Fatalf("verified room state contains %q", field)
		}
	}
	if view["latest_seqno"] != "7" {
		t.Fatalf("latest_seqno = %v, want locally verified head", view["latest_seqno"])
	}
	presence := presenceView(result)
	if presence["online_users"] != int32(12) || presence["room"] != keyText(room) {
		t.Fatalf("presence = %#v", presence)
	}
}

func TestConnectionViewRequiresAuthenticatedPeer(t *testing.T) {
	if _, err := connectionView(nil); !errors.Is(err, errRoomSessionChanged) {
		t.Fatalf("connectionView(nil) error = %v", err)
	}
}
