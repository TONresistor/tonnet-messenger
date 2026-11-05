package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomstate"
)

func TestInspectLegacyRoomInSharedDatabase(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	a, err := roomstate.Create(ctx, filepath.Join(t.TempDir(), "node"), "Legacy", "Keep", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roomstate.CreateRoom(ctx, a.Paths.Dir, "Additional", "", now); err != nil {
		t.Fatal(err)
	}
	got, err := inspectRoom(ctx, a.Paths.Dir, now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := community.RoomKeyText(a.Genesis.RoomKey)
	if got.RoomID != key || got.Name != "Legacy" || got.LatestSeqno != 0 {
		t.Fatal("inspection silently chose another room")
	}
}
