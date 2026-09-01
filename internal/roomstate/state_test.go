package roomstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func TestCreateAndLoadAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := filepath.Join(t.TempDir(), "community")
	created, err := Create(context.Background(), dir, "Community", "Description", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.GenesisHash) != 32 || len(created.OverlayID) != 32 {
		t.Fatalf("created artifacts = %+v", created)
	}
	for _, path := range []string{created.Paths.RoomKey, created.Paths.NodeKey, created.Paths.Genesis, created.Paths.Database} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
	if _, err := Create(context.Background(), dir, "Overwrite", "", now); err == nil {
		t.Fatal("room creation overwrote existing state")
	}
	loaded, err := LoadAuthority(context.Background(), dir, now)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Store.Close()
	if !bytes.Equal(loaded.Genesis.RoomKey, created.Genesis.RoomKey) || !bytes.Equal(loaded.OverlayID, created.OverlayID) {
		t.Fatal("loaded identity changed")
	}
}

func TestLoadAuthorityRejectsMismatchedDatabase(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := t.TempDir()
	first, err := Create(context.Background(), filepath.Join(root, "first"), "First", "", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(context.Background(), filepath.Join(root, "second"), "Second", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(second.Paths.Database, first.Paths.Database); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthority(context.Background(), first.Paths.Dir, now); !errors.Is(err, store.ErrGenesisMismatch) {
		t.Fatalf("mismatched database error = %v", err)
	}
}
