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
		State: community.RoomStateV3{RoomID: room, Name: "Room", Banned: [][]byte{room}},
		Stats: community.RoomStats{OnlineUsers: 12, ReplicaSeqno: 99, NodeRole: community.NodeRoleRelay, Ready: true},
	}
	view := stateView(result.State, 7)
	banned, ok := view["banned"].([]string)
	if !ok || len(banned) != 1 || banned[0] != keyText(room) {
		t.Fatalf("banned = %#v", view["banned"])
	}
	empty := stateView(community.RoomStateV3{}, 0)
	if values, ok := empty["banned"].([]string); !ok || values == nil || len(values) != 0 {
		t.Fatalf("empty banned = %#v", empty["banned"])
	}
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
