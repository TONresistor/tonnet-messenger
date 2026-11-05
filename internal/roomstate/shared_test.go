package roomstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func sharedArtifacts(t *testing.T) (Artifacts, Artifacts) {
	t.Helper()
	ctx, now := context.Background(), time.Now()
	a, err := Create(ctx, filepath.Join(t.TempDir(), "node"), "Legacy", "Keep", now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CreateRoom(ctx, a.Paths.Dir, "Additional", "", now)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func artifactBytes(t *testing.T, a Artifacts) [][]byte {
	t.Helper()
	var out [][]byte
	for _, path := range []string{a.Paths.NodeKey, a.Paths.RoomKey, a.Paths.Genesis} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, data)
	}
	return out
}

func assertArtifacts(t *testing.T, a Artifacts, before [][]byte) {
	t.Helper()
	for i, value := range artifactBytes(t, a) {
		if !bytes.Equal(value, before[i]) {
			t.Fatal("existing identity/artifact changed")
		}
	}
}

func replicaGenesis(t *testing.T, name string) (community.Genesis, ed25519.PrivateKey) {
	t.Helper()
	_, room, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, node, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := community.NewGenesis(room, node, time.Now(), name, "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g, room
}

func rawStoredState(t *testing.T, a Artifacts) []byte {
	t.Helper()
	db, err := sql.Open("sqlite", a.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw []byte
	if err := db.QueryRow("SELECT raw_signed_state FROM room_state WHERE room_id=?", a.Genesis.RoomKey).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func legacyStoredState(t *testing.T, a Artifacts) []byte {
	t.Helper()
	state, err := community.DecodeRoomStateV3(rawStoredState(t, a))
	if err != nil {
		t.Fatal(err)
	}
	private, err := keys.Load(a.Paths.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	old, err := community.SignRoomState(private, community.RoomState{RoomID: state.RoomID, RevisionSeqno: state.RevisionSeqno, RevisionHash: state.RevisionHash, Name: state.Name, Description: state.Description, WritePolicy: state.WritePolicy, Admins: state.Admins, Moderators: state.Moderators, PinnedMessages: state.PinnedMessages})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := community.Encode(old)
	if err != nil {
		t.Fatal(err)
	}
	replaceStoredState(t, a, raw)
	return raw
}

func replaceStoredState(t *testing.T, a Artifacts, raw []byte) {
	t.Helper()
	db, err := sql.Open("sqlite", a.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE room_state SET raw_signed_state=? WHERE room_id=?", raw, a.Genesis.RoomKey); err != nil {
		t.Fatal(err)
	}
}

func TestSharedArtifactsRolesAndDatabaseOwnership(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	a, err := Create(ctx, filepath.Join(t.TempDir(), "node"), "Legacy", "Keep", now)
	if err != nil {
		t.Fatal(err)
	}
	before := artifactBytes(t, a)
	owner, err := LoadAuthority(ctx, a.Paths.Dir, now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := community.SignProposal(owner.RoomPrivate, a.Genesis.NodeKey, community.EventProposal{RoomID: a.Genesis.RoomKey, Nonce: community.Zero256(), Timestamp: now.Unix(), Body: community.EventMessage{Text: "preserve history"}})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := owner.Store.Commit(ctx, p, owner.RoomPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	owner.Close()
	b, err := CreateRoom(ctx, a.Paths.Dir, "Second", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Genesis.NodeKey, b.Genesis.NodeKey) || a.Paths.Database != b.Paths.Database || a.Paths.NodeKey != b.Paths.NodeKey || a.Paths.Socket != b.Paths.Socket {
		t.Fatal("additional room created another node")
	}
	if b.Paths.Genesis != filepath.Join(a.Paths.Dir, "rooms", hex.EncodeToString(b.Genesis.RoomKey), GenesisFile) {
		t.Fatal("non-canonical artifact path")
	}
	for _, file := range []string{NodeKeyFile, DatabaseFile} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(b.Paths.Genesis), file)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("additional room duplicated node resources")
		}
	}
	g, private := replicaGenesis(t, "Remote")
	r, err := RetainReplica(ctx, a.Paths.Dir, g, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(r.Paths.RoomKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replica retained private authority")
	}
	selections := []Selection{{a.Genesis.RoomKey, community.NodeRoleSequencer}, {b.Genesis.RoomKey, community.NodeRoleSequencer}, {g.RoomKey, community.NodeRoleRelay}}
	n, err := LoadRooms(ctx, a.Paths.Dir, selections, now)
	if err != nil {
		t.Fatal(err)
	}
	if n.Rooms[2].Ready || len(n.Rooms[2].RoomPrivate) != 0 || !n.Rooms[0].Ready || !n.Rooms[1].Ready {
		t.Fatal("room role authority/readiness escaped selection")
	}
	if _, _, err := n.Store.Genesis(ctx); !errors.Is(err, store.ErrAmbiguousRoom) {
		t.Fatal("root database silently selected a room")
	}
	page, err := n.Rooms[0].Store.Events(ctx, 0, 100)
	want, _ := community.Encode(commit.Event)
	if err != nil || len(page.Events) != 1 {
		t.Fatal("existing history lost", err)
	}
	got, _ := community.Encode(page.Events[0])
	if !bytes.Equal(got, want) {
		t.Fatal("existing signed history changed")
	}
	if err := n.Rooms[0].Store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Rooms[1].Store.Head(ctx); err != nil {
		t.Fatal("closing one room closed siblings", err)
	}
	projection, _ := community.NewProjection(g)
	state, err := community.SignRoomStateV3(private, projection.State())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Rooms[2].Store.InstallReplicaState(ctx, state); err != nil {
		t.Fatal(err)
	}
	views := []*store.Store{n.Rooms[0].Store, n.Rooms[1].Store, n.Rooms[2].Store}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		if _, err := view.Head(ctx); err == nil {
			t.Fatal("owner close left database open")
		}
	}
	readOnly, err := LoadRoomsReadOnly(ctx, a.Paths.Dir, selections, now)
	if err != nil {
		t.Fatal(err)
	}
	if !readOnly.Rooms[2].Ready {
		t.Fatal("verified V3 replica stayed unready")
	}
	keyB := readOnly.Rooms[1].RoomPrivate
	proposalB, err := community.SignProposal(keyB, b.Genesis.NodeKey, community.EventProposal{RoomID: b.Genesis.RoomKey, Nonce: community.Zero256(), Timestamp: now.Unix(), Body: community.EventMessage{Text: "must not write"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = readOnly.Rooms[1].Store.Commit(ctx, proposalB, keyB, now)
	var rejected *store.Rejection
	if !errors.As(err, &rejected) || rejected.Code != community.RejectPersistenceFailure {
		t.Fatalf("read-only write was not blocked by storage: %v", err)
	}
	readOnly.Close()
	legacy, err := LoadAuthorityReadOnly(ctx, a.Paths.Dir, now)
	if err != nil {
		t.Fatal("legacy loader used ambiguous root", err)
	}
	legacy.Close()
	loadedReplica, err := OpenRelay(ctx, a.Paths.Dir, g, now)
	if err != nil {
		t.Fatal("legacy replica adapter used ambiguous root", err)
	}
	if !bytes.Equal(loadedReplica.NodePrivate.Public().(ed25519.PublicKey), a.Genesis.NodeKey) || loadedReplica.Paths.Genesis != r.Paths.Genesis {
		t.Fatal("replica adapter changed node identity or selection")
	}
	loadedReplica.Close()
	other, _ := replicaGenesis(t, "Another remote")
	loadedReplica, err = OpenRelay(ctx, a.Paths.Dir, other, now)
	if err != nil {
		t.Fatal(err)
	}
	loadedReplica.Close()
	// Unselecting does not remove any sibling's artifacts or database history.
	subset, err := LoadRooms(ctx, a.Paths.Dir, selections[:1], now)
	if err != nil {
		t.Fatal(err)
	}
	view, _ := subset.Store.ForRoom(b.Genesis.RoomKey)
	if _, err := view.Head(ctx); err != nil {
		t.Fatal(err)
	}
	subset.Close()
	assertArtifacts(t, a, before)
	if _, err := os.Stat(b.Paths.RoomKey); err != nil {
		t.Fatal(err)
	}
}

func TestSharedLoadingConvertsOnlySelectedAuthorityAndKeepsReadOnlyPure(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	a, b := sharedArtifacts(t)
	beforeA, beforeB := artifactBytes(t, a), artifactBytes(t, b)
	oldA, oldB := legacyStoredState(t, a), legacyStoredState(t, b)
	selection := []Selection{{a.Genesis.RoomKey, community.NodeRoleSequencer}}
	if n, err := LoadRoomsReadOnly(ctx, a.Paths.Dir, selection, now); err == nil {
		n.Close()
		t.Fatal("read-only loading accepted V2 as current")
	}
	if !bytes.Equal(rawStoredState(t, a), oldA) || !bytes.Equal(rawStoredState(t, b), oldB) {
		t.Fatal("read-only loading converted stored state")
	}
	// No unselected private authority is needed to start A.
	keyB, err := os.ReadFile(b.Paths.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b.Paths.RoomKey); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		n, err := LoadRooms(ctx, a.Paths.Dir, selection, now)
		if err != nil {
			t.Fatal(err)
		}
		state, err := n.Rooms[0].Store.State(ctx)
		if err != nil || state.Verify() != nil || len(state.Banned) != 0 {
			t.Fatal("selected conversion failed", err)
		}
		n.Close()
		if !bytes.Equal(rawStoredState(t, b), oldB) {
			t.Fatal("selected startup converted sibling")
		}
	}
	if err := os.WriteFile(b.Paths.RoomKey, keyB, 0o600); err != nil {
		t.Fatal(err)
	}
	// A later invalid selection must fail before A can be upgraded.
	replaceStoredState(t, a, oldA)
	wrong := bytes.Repeat([]byte{1}, ed25519.SeedSize)
	if err := os.WriteFile(b.Paths.RoomKey, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := LoadRooms(ctx, a.Paths.Dir, append(selection, Selection{b.Genesis.RoomKey, community.NodeRoleSequencer}), now); err == nil {
		n.Close()
		t.Fatal("wrong sibling authority was accepted")
	}
	if !bytes.Equal(rawStoredState(t, a), oldA) {
		t.Fatal("invalid authority selection re-signed another room")
	}
	if err := os.WriteFile(b.Paths.RoomKey, keyB, 0o600); err != nil {
		t.Fatal(err)
	}
	invalid, err := community.DecodeRoomState(oldB)
	if err != nil {
		t.Fatal(err)
	}
	invalid.Signature[0] ^= 1
	corrupt, err := community.Encode(invalid)
	if err != nil {
		t.Fatal(err)
	}
	replaceStoredState(t, b, corrupt)
	if n, err := LoadRooms(ctx, a.Paths.Dir, []Selection{{b.Genesis.RoomKey, community.NodeRoleSequencer}}, now); err == nil {
		n.Close()
		t.Fatal("invalid V2 was legitimized")
	}
	if !bytes.Equal(rawStoredState(t, b), corrupt) {
		t.Fatal("invalid legacy state changed")
	}
	replaceStoredState(t, b, oldB)
	n, err := LoadRooms(ctx, a.Paths.Dir, []Selection{{b.Genesis.RoomKey, community.NodeRoleSequencer}}, now)
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	if !bytes.Equal(rawStoredState(t, a), oldA) {
		t.Fatal("B startup converted A")
	}
	assertArtifacts(t, a, beforeA)
	assertArtifacts(t, b, beforeB)
}

func TestSharedSelectionAndArtifactRejections(t *testing.T) {
	for _, mode := range []string{"empty", "short", "duplicate", "unknown", "role", "missing authority", "wrong node", "replica authority", "wrong artifact", "duplicate legacy", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			ctx, now := context.Background(), time.Now()
			a, b := sharedArtifacts(t)
			selection := []Selection{{b.Genesis.RoomKey, community.NodeRoleSequencer}}
			switch mode {
			case "empty":
				selection = nil
			case "short":
				selection[0].RoomID = []byte("invalid")
			case "duplicate":
				selection = append(selection, selection[0])
			case "unknown":
				g, _ := replicaGenesis(t, "Unknown")
				selection[0].RoomID = g.RoomKey
			case "role":
				selection[0].Role = 99
			case "missing authority":
				if err := os.Remove(b.Paths.RoomKey); err != nil {
					t.Fatal(err)
				}
			case "wrong node":
				if err := os.WriteFile(a.Paths.NodeKey, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
					t.Fatal(err)
				}
			case "replica authority":
				selection[0].Role = community.NodeRoleRelay
			case "wrong artifact":
				data, _ := os.ReadFile(a.Paths.Genesis)
				if err := os.WriteFile(b.Paths.Genesis, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "duplicate legacy":
				p, _ := additionalPaths(a.Paths, a.Genesis.RoomKey)
				if err := os.Mkdir(filepath.Dir(p.Genesis), 0o700); err != nil {
					t.Fatal(err)
				}
				selection[0].RoomID = a.Genesis.RoomKey
			case "symlink":
				if err := os.Remove(b.Paths.RoomKey); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(a.Paths.RoomKey, b.Paths.RoomKey); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := LoadRooms(ctx, a.Paths.Dir, selection, now); err == nil {
				n.Close()
				t.Fatal("invalid selection or authority accepted")
			}
		})
	}
}

func TestSharedCreationNeverOverwritesOrReplacesMissingIdentity(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	a, _ := sharedArtifacts(t)
	before := artifactBytes(t, a)
	g, private := replicaGenesis(t, "Remote")
	r, err := RetainReplica(ctx, a.Paths.Dir, g, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(r.Paths.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RetainReplica(ctx, a.Paths.Dir, g, now); !errors.Is(err, store.ErrAlreadyInitialized) {
		t.Fatal("existing room overwritten", err)
	}
	conflict, err := community.NewGenesis(private, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), now, "Conflicting", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RetainReplica(ctx, a.Paths.Dir, conflict, now); !errors.Is(err, store.ErrGenesisMismatch) {
		t.Fatal("conflicting room retained", err)
	}
	if loaded, err := OpenRelay(ctx, a.Paths.Dir, conflict, now); err == nil {
		loaded.Close()
		t.Fatal("replica adapter accepted conflicting artifact")
	}
	after, _ := os.ReadFile(r.Paths.Genesis)
	if !bytes.Equal(raw, after) {
		t.Fatal("replica artifact overwritten")
	}
	other, _ := replicaGenesis(t, "Reserved")
	reserved, _ := additionalPaths(a.Paths, other.RoomKey)
	if err := os.Mkdir(filepath.Dir(reserved.Genesis), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reserved.Genesis, []byte("existing fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RetainReplica(ctx, a.Paths.Dir, other, now); err == nil {
		t.Fatal("existing artifact directory overwritten")
	}
	if data, _ := os.ReadFile(reserved.Genesis); string(data) != "existing fixture" {
		t.Fatal("failed creation removed pre-existing artifacts")
	}
	assertArtifacts(t, a, before)
	if err := os.Remove(a.Paths.NodeKey); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRoom(ctx, a.Paths.Dir, "Missing identity", "", now); err == nil {
		t.Fatal("additional room replaced node identity")
	}
	if _, _, err := LoadOrCreateRelayKey(a.Paths.Dir); err == nil {
		t.Fatal("legacy helper replaced missing shared identity")
	}
	if _, err := os.Lstat(a.Paths.NodeKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("node key was regenerated")
	}
}

func TestSharedUnreadyReplicaRejectsInvalidRetainedHistory(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	a, _ := sharedArtifacts(t)
	g, private := replicaGenesis(t, "Remote")
	r, err := RetainReplica(ctx, a.Paths.Dir, g, now)
	if err != nil {
		t.Fatal(err)
	}
	selection := []Selection{{g.RoomKey, community.NodeRoleRelay}}
	n, err := LoadRooms(ctx, a.Paths.Dir, selection, now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := community.SignProposal(private, g.NodeKey, community.EventProposal{RoomID: g.RoomKey, Nonce: community.Zero256(), Timestamp: now.Unix(), Body: community.EventMessage{Text: "retained"}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := community.SignCommit(private, p, 1, community.Zero256(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Rooms[0].Store.AppendReplica(ctx, event); err != nil {
		t.Fatal(err)
	}
	n.Close()
	n, err = LoadRoomsReadOnly(ctx, a.Paths.Dir, selection, now)
	if err != nil {
		t.Fatal("valid unready replica was rejected", err)
	}
	if n.Rooms[0].Ready {
		t.Fatal("unsigned state became ready")
	}
	n.Close()
	db, err := sql.Open("sqlite", r.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE replica_head SET latest_hash=zeroblob(32) WHERE room_id=?", g.RoomKey); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if n, err := LoadRooms(ctx, a.Paths.Dir, selection, now); err == nil {
		n.Close()
		t.Fatal("invalid unready replica history was accepted")
	}
}
