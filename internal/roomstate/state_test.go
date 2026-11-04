package roomstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
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

func TestLoadAuthorityRecoversLegacyStateAtEveryStart(t *testing.T) {
	for _, schemaMigrated := range []bool{false, true} {
		t.Run(fmt.Sprint("schema_already_migrated=", schemaMigrated), func(t *testing.T) {
			ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
			created, err := Create(ctx, filepath.Join(t.TempDir(), "room"), "Legacy", "Keep", now)
			if err != nil {
				t.Fatal(err)
			}
			authority, err := LoadAuthority(ctx, created.Paths.Dir, now)
			if err != nil {
				t.Fatal(err)
			}
			state, err := authority.Store.State(ctx)
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := community.SignRoomState(authority.RoomPrivate, community.RoomState{
				RoomID: state.RoomID, RevisionHash: state.RevisionHash, Name: state.Name,
				Description: state.Description, WritePolicy: state.WritePolicy,
			})
			if err != nil {
				t.Fatal(err)
			}
			rawLegacy, err := community.Encode(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.Store.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", created.Paths.Database)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("UPDATE room_state SET raw_signed_state=?", rawLegacy); err != nil {
				t.Fatal(err)
			}
			if !schemaMigrated {
				if _, err := db.Exec("DROP TABLE bans; DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (2, 0)"); err != nil {
					t.Fatal(err)
				}
			}
			paths := []string{created.Paths.RoomKey, created.Paths.NodeKey, created.Paths.Genesis}
			artifacts := make([][]byte, len(paths))
			for i, path := range paths {
				artifacts[i], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if loaded, err := LoadAuthorityReadOnly(ctx, created.Paths.Dir, now); err == nil {
				loaded.Store.Close()
				t.Fatal("read-only startup converted V2")
			}
			var raw []byte
			if err := db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&raw); err != nil || !bytes.Equal(raw, rawLegacy) {
				t.Fatalf("read-only entry point changed state: %v", err)
			}
			var version int
			if err := db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil || (!schemaMigrated && version != 2) {
				t.Fatalf("read-only entry point migrated schema: %d %v", version, err)
			}
			for i := 0; i < 2; i++ {
				loaded, err := LoadAuthority(ctx, created.Paths.Dir, now)
				if err != nil {
					t.Fatal(err)
				}
				got, err := loaded.Store.State(ctx)
				wantRaw, _ := community.Encode(state)
				gotRaw, _ := community.Encode(got)
				if err != nil || got.Verify() != nil || !bytes.Equal(gotRaw, wantRaw) {
					t.Fatalf("startup state changed: %v", err)
				}
				if err := loaded.Store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for i, path := range paths {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, artifacts[i]) {
					t.Fatalf("startup changed generated key or genesis artifact: %v", err)
				}
			}
			loaded, err := LoadAuthorityReadOnly(ctx, created.Paths.Dir, now)
			if err != nil {
				t.Fatal(err)
			}
			loaded.Store.Close()
		})
	}
}

func TestLoadAuthorityRejectsInvalidLegacySignature(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	created, err := Create(ctx, filepath.Join(t.TempDir(), "room"), "Room", "", now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Load(created.Paths.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	state, err := community.SignRoomState(key, community.RoomState{
		RoomID: created.Genesis.RoomKey, RevisionHash: created.GenesisHash, Name: created.Genesis.Name,
		WritePolicy: created.Genesis.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	state.Signature[0] ^= 1
	raw, err := community.Encode(state)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", created.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE room_state SET raw_signed_state=?", raw); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadAuthority(ctx, created.Paths.Dir, now); err == nil {
		loaded.Store.Close()
		t.Fatal("invalid legacy signature was accepted at startup")
	}
	var got []byte
	if err := db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&got); err != nil || !bytes.Equal(raw, got) {
		t.Fatalf("invalid legacy state was changed: %v", err)
	}
}

func TestNodeStartupConvertsAuthorityAndReplicaFetchesV3(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	created, err := Create(ctx, filepath.Join(t.TempDir(), "room"), "Room", "", now)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := LoadAuthority(ctx, created.Paths.Dir, now)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Store.Close()
	for i, body := range []any{community.EventMessage{Text: "retained history"}, community.EventMetadata{Name: "Updated"}} {
		nonce := make([]byte, 32)
		nonce[0] = byte(i)
		proposal, err := community.SignProposal(authority.RoomPrivate, authority.Genesis.NodeKey, community.EventProposal{
			RoomID: authority.Genesis.RoomKey, Nonce: nonce, Timestamp: now.Unix(), Body: body,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authority.Store.Commit(ctx, proposal, authority.RoomPrivate, now); err != nil {
			t.Fatal(err)
		}
	}
	state, err := authority.Store.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := community.SignRoomState(authority.RoomPrivate, community.RoomState{
		RoomID: state.RoomID, RevisionSeqno: state.RevisionSeqno, RevisionHash: state.RevisionHash,
		Name: state.Name, Description: state.Description, WritePolicy: state.WritePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawLegacy, err := community.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", created.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE room_state SET raw_signed_state=?", rawLegacy); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// Node.New is also an authority startup entry point, independently of
	// LoadAuthority. It must repair a previously migrated store before serving.
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := packet.LocalAddr().String()
	packet.Close()
	runtime, err := node.New(node.Config{
		Key: authority.NodePrivate, Genesis: &authority.Genesis, Store: authority.Store,
		RoomKey: authority.RoomPrivate, Listen: listen, Socket: created.Paths.Socket,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	got, err := authority.Store.State(ctx)
	if err != nil || got.Verify() != nil || got.RevisionSeqno != state.RevisionSeqno {
		t.Fatalf("direct sequencer startup failed to convert: %v", err)
	}
	destination, err := OpenRelay(ctx, t.TempDir(), created.Genesis, now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { destination.Store.Close() }()
	page, err := authority.Store.Events(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range page.Events {
		if _, err := destination.Store.AppendReplica(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	db, err = sql.Open("sqlite", destination.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE room_state SET raw_signed_state=?,revision_seqno=?,revision_hash=?", rawLegacy, legacy.RevisionSeqno, legacy.RevisionHash); err != nil {
		t.Fatal(err)
	}
	if err := destination.Store.Close(); err != nil {
		t.Fatal(err)
	}
	destination, err = OpenRelay(ctx, destination.Paths.Dir, created.Genesis, now)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&raw); err != nil || !bytes.Equal(raw, rawLegacy) {
		t.Fatalf("replica startup re-signed state: %v", err)
	}
	if err := destination.Store.ReplicaReady(ctx); err == nil {
		t.Fatal("legacy replica became ready before fetching V3")
	}
	if _, err := replica.Sync(ctx, replica.Config{
		RoomID: created.Genesis.RoomKey, NodeKey: destination.NodePrivate,
		DirectAddress: listen, DirectPublic: authority.NodePrivate.Public().(ed25519.PublicKey),
	}, destination.Store); err != nil {
		t.Fatal(err)
	}
	if err := destination.Store.ReplicaReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	want, _ := community.Encode(state)
	if !bytes.Equal(raw, want) {
		t.Fatal("replica did not install the sequencer's exact V3 signature")
	}
}
