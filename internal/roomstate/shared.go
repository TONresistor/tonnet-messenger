package roomstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type Selection struct {
	RoomID []byte
	Role   int32
}

// Room borrows its selected Store. Only sequencer selections load RoomPrivate.
// An unready replica exposes verified genesis, never a trusted current state.
type Room struct {
	Artifacts
	Role        int32
	RoomPrivate ed25519.PrivateKey
	Store       *store.Store
	Ready       bool
}

// NodeState owns exactly one database and node identity. Closing a room's view
// cannot close its siblings; callers close NodeState after the runtime stops.
type NodeState struct {
	Paths       Paths
	NodePrivate ed25519.PrivateKey
	Store       *store.Store
	Rooms       []Room
}

func (n *NodeState) Close() error { return n.Store.Close() }

// OpenNode opens only the node identity and shared database. Existing room
// artifacts remain unselected and their private authority is never loaded.
func OpenNode(ctx context.Context, dir string) (*NodeState, error) {
	paths, key, err := LoadOrCreateRelayKey(dir)
	if err != nil {
		return nil, err
	}
	if err := regularFile(paths.Database); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, artifact := range []string{paths.RoomKey, paths.Genesis, filepath.Join(paths.Dir, "rooms")} {
			if _, err := os.Lstat(artifact); err == nil {
				return nil, fmt.Errorf("room state: existing rooms are missing the shared database")
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	db, err := store.Open(ctx, paths.Database)
	if err != nil {
		return nil, err
	}
	return &NodeState{Paths: paths, NodePrivate: key, Store: db}, nil
}

func regularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("room state: expected regular file %s", path)
	}
	return nil
}

func realDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("room state: expected directory %s", path)
	}
	return nil
}

func additionalPaths(root Paths, roomID []byte) (Paths, error) {
	if len(roomID) != ed25519.PublicKeySize {
		return Paths{}, community.ErrMalformedKey
	}
	dir := filepath.Join(root.Dir, "rooms", hex.EncodeToString(roomID))
	root.Genesis, root.RoomKey = filepath.Join(dir, GenesisFile), filepath.Join(dir, RoomKeyFile)
	return root, nil
}

func selectedArtifacts(root Paths, roomID []byte, now time.Time) (Artifacts, error) {
	paths, err := additionalPaths(root, roomID)
	if err != nil {
		return Artifacts{}, err
	}
	if err := realDirectory(root.Dir); err != nil {
		return Artifacts{}, err
	}
	// Verify the public legacy artifact to disambiguate it from an additional
	// directory. Unselected private keys are never loaded.
	legacy := false
	if err := regularFile(root.Genesis); err == nil {
		g, err := LoadGenesis(root.Genesis, now)
		if err != nil {
			return Artifacts{}, err
		}
		legacy = bytes.Equal(g.RoomKey, roomID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Artifacts{}, err
	}
	if legacy {
		// A second artifact for the legacy key is ambiguous, even if identical.
		if _, err := os.Lstat(filepath.Dir(paths.Genesis)); err == nil {
			return Artifacts{}, fmt.Errorf("room state: duplicate legacy room artifacts")
		} else if !errors.Is(err, os.ErrNotExist) {
			return Artifacts{}, err
		}
		paths = root
	} else {
		if err := realDirectory(filepath.Join(root.Dir, "rooms")); err != nil {
			return Artifacts{}, err
		}
		if err := realDirectory(filepath.Dir(paths.Genesis)); err != nil {
			return Artifacts{}, err
		}
	}
	if err := regularFile(paths.Genesis); err != nil {
		return Artifacts{}, err
	}
	genesis, err := LoadGenesis(paths.Genesis, now)
	if err != nil {
		return Artifacts{}, err
	}
	if !bytes.Equal(genesis.RoomKey, roomID) {
		return Artifacts{}, community.ErrWrongRoom
	}
	return roomArtifacts(paths, genesis)
}

func roomArtifacts(paths Paths, genesis community.Genesis) (Artifacts, error) {
	hash, err := genesis.Hash()
	if err != nil {
		return Artifacts{}, err
	}
	id, err := community.OverlayID(genesis.RoomKey)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{Paths: paths, Genesis: genesis, GenesisHash: hash, OverlayID: id}, nil
}

// LoadArtifacts selects public artifacts without acquiring private authority or
// opening the database. An omitted room key retains the legacy root selection.
func LoadArtifacts(dir string, roomID []byte, now time.Time) (Artifacts, error) {
	paths, err := Resolve(dir)
	if err != nil {
		return Artifacts{}, err
	}
	if len(roomID) == 0 {
		genesis, err := LoadGenesis(paths.Genesis, now)
		if err != nil {
			return Artifacts{}, err
		}
		roomID = genesis.RoomKey
	}
	return selectedArtifacts(paths, roomID, now)
}

func LoadRooms(ctx context.Context, dir string, selections []Selection, now time.Time) (*NodeState, error) {
	return loadRooms(ctx, dir, selections, now, false)
}

func LoadRoomsReadOnly(ctx context.Context, dir string, selections []Selection, now time.Time) (*NodeState, error) {
	return loadRooms(ctx, dir, selections, now, true)
}

func loadRooms(ctx context.Context, dir string, selections []Selection, now time.Time, readOnly bool) (*NodeState, error) {
	if len(selections) == 0 {
		return nil, fmt.Errorf("room state: explicit room selections are required")
	}
	seen := make(map[string]bool)
	for _, s := range selections {
		if len(s.RoomID) != ed25519.PublicKeySize || seen[string(s.RoomID)] || (s.Role != community.NodeRoleSequencer && s.Role != community.NodeRoleRelay) {
			return nil, fmt.Errorf("room state: invalid or duplicate room selection")
		}
		seen[string(s.RoomID)] = true
	}
	paths, err := Resolve(dir)
	if err != nil {
		return nil, err
	}
	if err := regularFile(paths.NodeKey); err != nil {
		return nil, err
	}
	key, err := keys.Load(paths.NodeKey)
	if err != nil {
		return nil, err
	}
	n := &NodeState{Paths: paths, NodePrivate: key}
	// Validate all selected authorities before opening/migrating the database or
	// upgrading any state. A bad later selection cannot re-sign an earlier one.
	for _, selection := range selections {
		artifacts, err := selectedArtifacts(paths, selection.RoomID, now)
		if err != nil {
			return nil, err
		}
		r := Room{Artifacts: artifacts, Role: selection.Role}
		if r.Role == community.NodeRoleSequencer {
			if err := regularFile(r.Paths.RoomKey); err != nil {
				return nil, err
			}
			r.RoomPrivate, err = keys.Load(r.Paths.RoomKey)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(r.RoomPrivate.Public().(ed25519.PublicKey), r.Genesis.RoomKey) || !bytes.Equal(key.Public().(ed25519.PublicKey), r.Genesis.NodeKey) {
				return nil, fmt.Errorf("room state: authority does not match genesis")
			}
		} else if _, err := os.Lstat(r.Paths.RoomKey); err == nil {
			return nil, fmt.Errorf("room state: replica artifact contains room authority")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		n.Rooms = append(n.Rooms, r)
	}
	if err := regularFile(paths.Database); err != nil {
		return nil, err
	}
	if readOnly {
		n.Store, err = store.OpenReadOnly(ctx, paths.Database)
	} else {
		n.Store, err = store.Open(ctx, paths.Database)
	}
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			n.Close()
		}
	}()
	for i := range n.Rooms {
		r := &n.Rooms[i]
		r.Store, err = n.Store.ForRoom(r.Genesis.RoomKey)
		if err != nil {
			return nil, err
		}
		if err := r.Store.ValidateGenesis(ctx, r.Genesis); err != nil {
			return nil, errors.Join(store.ErrGenesisMismatch, err)
		}
	}
	for i := range n.Rooms {
		r := &n.Rooms[i]
		if r.Role == community.NodeRoleSequencer {
			if !readOnly {
				if err := r.Store.UpgradeRoomState(ctx, r.RoomPrivate); err != nil {
					return nil, fmt.Errorf("room state: upgrade signed state: %w", err)
				}
			}
			if err := r.Store.Audit(ctx); err != nil {
				return nil, fmt.Errorf("room state: database audit: %w", err)
			}
			r.Ready = true
		} else {
			if err := r.Store.IntegrityCheck(ctx); err != nil {
				return nil, err
			}
			r.Ready = r.Store.ReplicaReady(ctx) == nil
			if r.Ready {
				if err := r.Store.Audit(ctx); err != nil {
					return nil, err
				}
			} else if err := verifyReplicaHistory(ctx, r); err != nil {
				return nil, err
			}
		}
	}
	complete = true
	return n, nil
}

// An interrupted replica may have no current V3 snapshot yet. Validate its
// retained chain without trusting that snapshot or acquiring signing authority.
func verifyReplicaHistory(ctx context.Context, r *Room) error {
	projection, err := community.NewProjection(r.Genesis)
	if err != nil {
		return err
	}
	for {
		seqno, _ := projection.Head()
		page, err := r.Store.Events(ctx, seqno, community.MaxPageLimit)
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if err := projection.Apply(event); err != nil {
				return err
			}
		}
		if !page.HasMore {
			break
		}
		if len(page.Events) == 0 {
			return fmt.Errorf("room state: empty replica history page")
		}
	}
	head, err := r.Store.Head(ctx)
	if err != nil {
		return err
	}
	seqno, hash := projection.Head()
	if head.Seqno != seqno || !bytes.Equal(head.Hash, hash) {
		return fmt.Errorf("room state: replica history/head mismatch")
	}
	return nil
}

// CreateRoom adds authority using the existing node identity/database. It never
// replaces legacy artifacts and never creates another node key or database.
func CreateRoom(ctx context.Context, dir, name, description string, now time.Time) (Artifacts, error) {
	paths, key, err := existingNode(dir)
	if err != nil {
		return Artifacts{}, err
	}
	_, room, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Artifacts{}, err
	}
	genesis, err := community.NewGenesis(room, key, now, name, description, true, nil)
	if err != nil {
		return Artifacts{}, err
	}
	return addRoom(ctx, paths, genesis, room, now)
}

// RetainReplica stores verified public genesis without loading room authority.
func RetainReplica(ctx context.Context, dir string, genesis community.Genesis, now time.Time) (Artifacts, error) {
	paths, _, err := existingNode(dir)
	if err != nil {
		return Artifacts{}, err
	}
	return addRoom(ctx, paths, genesis, nil, now)
}

func existingNode(dir string) (Paths, ed25519.PrivateKey, error) {
	paths, err := Resolve(dir)
	if err != nil {
		return Paths{}, nil, err
	}
	if err := realDirectory(paths.Dir); err != nil {
		return Paths{}, nil, err
	}
	if err := regularFile(paths.NodeKey); err != nil {
		return Paths{}, nil, err
	}
	if err := regularFile(paths.Database); err != nil {
		return Paths{}, nil, err
	}
	key, err := keys.Load(paths.NodeKey)
	return paths, key, err
}

func addRoom(ctx context.Context, root Paths, genesis community.Genesis, private ed25519.PrivateKey, now time.Time) (Artifacts, error) {
	if err := genesis.Verify(now); err != nil {
		return Artifacts{}, err
	}
	database, err := store.Open(ctx, root.Database)
	if err != nil {
		return Artifacts{}, err
	}
	defer database.Close()
	view, err := database.ForRoom(genesis.RoomKey)
	if err != nil {
		return Artifacts{}, err
	}
	if err := view.ValidateGenesis(ctx, genesis); err == nil {
		return Artifacts{}, store.ErrAlreadyInitialized
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return Artifacts{}, err
	}
	paths, err := additionalPaths(root, genesis.RoomKey)
	if err != nil {
		return Artifacts{}, err
	}
	parent := filepath.Join(root.Dir, "rooms")
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return Artifacts{}, err
	}
	if err := realDirectory(parent); err != nil {
		return Artifacts{}, err
	}
	dir := filepath.Dir(paths.Genesis)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Artifacts{}, err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(dir)
		}
	}()
	if len(private) != 0 {
		if err := writeExclusive(paths.RoomKey, private.Seed(), 0o600); err != nil {
			return Artifacts{}, err
		}
	}
	raw, err := EncodeGenesisArtifact(genesis)
	if err != nil {
		return Artifacts{}, err
	}
	if err := writeExclusive(paths.Genesis, raw, 0o600); err != nil {
		return Artifacts{}, err
	}
	// Match legacy creation's best-effort directory sync, before the database
	// can commit a room whose private artifact must remain recoverable.
	for _, path := range []string{dir, parent, root.Dir} {
		if handle, err := os.Open(path); err == nil {
			_ = handle.Sync()
			_ = handle.Close()
		}
	}
	if len(private) != 0 {
		err = view.Initialize(ctx, genesis, private)
	} else {
		err = view.InitializeReplica(ctx, genesis)
	}
	if err != nil {
		return Artifacts{}, err
	}
	complete = true
	return roomArtifacts(paths, genesis)
}
