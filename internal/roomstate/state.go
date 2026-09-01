package roomstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xssnick/tonutils-go/tvm/cell"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

const (
	RoomKeyFile  = "room.key"
	NodeKeyFile  = "node.key"
	GenesisFile  = "genesis.boc"
	DatabaseFile = "room.db"
	SocketFile   = "node.sock"
)

var genesisArtifactPrefix = []byte("tonnet-genesis-v1\x00")

type Paths struct {
	Dir      string
	RoomKey  string
	NodeKey  string
	Genesis  string
	Database string
	Socket   string
}

func Resolve(dir string) (Paths, error) {
	if dir == "" {
		return Paths{}, fmt.Errorf("room state: empty directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Paths{}, err
	}
	return Paths{
		Dir: abs, RoomKey: filepath.Join(abs, RoomKeyFile), NodeKey: filepath.Join(abs, NodeKeyFile),
		Genesis: filepath.Join(abs, GenesisFile), Database: filepath.Join(abs, DatabaseFile),
		Socket: filepath.Join(abs, SocketFile),
	}, nil
}

type Artifacts struct {
	Paths       Paths
	Genesis     community.Genesis
	GenesisHash []byte
	OverlayID   []byte
}

type Authority struct {
	Artifacts
	RoomPrivate ed25519.PrivateKey
	NodePrivate ed25519.PrivateKey
	Store       *store.Store
}

func Create(ctx context.Context, dir, name, description string, now time.Time) (artifacts Artifacts, err error) {
	paths, err := Resolve(dir)
	if err != nil {
		return Artifacts{}, err
	}
	if err := os.MkdirAll(filepath.Dir(paths.Dir), 0o700); err != nil {
		return Artifacts{}, err
	}
	if err := os.Mkdir(paths.Dir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Artifacts{}, fmt.Errorf("room state: %s already exists", paths.Dir)
		}
		return Artifacts{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(paths.Dir)
		}
	}()

	roomPrivate, err := keys.GenerateExclusive(paths.RoomKey)
	if err != nil {
		return Artifacts{}, fmt.Errorf("room state: generate room key: %w", err)
	}
	nodePrivate, err := keys.GenerateExclusive(paths.NodeKey)
	if err != nil {
		return Artifacts{}, fmt.Errorf("room state: generate node key: %w", err)
	}
	genesis, err := community.NewGenesis(roomPrivate, nodePrivate, now, name, description, true, nil)
	if err != nil {
		return Artifacts{}, err
	}
	rawGenesis, err := EncodeGenesisArtifact(genesis)
	if err != nil {
		return Artifacts{}, err
	}
	if err := writeExclusive(paths.Genesis, rawGenesis, 0o600); err != nil {
		return Artifacts{}, fmt.Errorf("room state: write genesis: %w", err)
	}
	database, err := store.Open(ctx, paths.Database)
	if err != nil {
		return Artifacts{}, err
	}
	if err := database.Initialize(ctx, genesis, roomPrivate); err != nil {
		database.Close()
		return Artifacts{}, err
	}
	if err := database.Close(); err != nil {
		return Artifacts{}, err
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		return Artifacts{}, err
	}
	overlayID, err := community.OverlayID(genesis.RoomKey)
	if err != nil {
		return Artifacts{}, err
	}
	if dirHandle, openErr := os.Open(paths.Dir); openErr == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	complete = true
	return Artifacts{Paths: paths, Genesis: genesis, GenesisHash: genesisHash, OverlayID: overlayID}, nil
}

func LoadAuthority(ctx context.Context, dir string, now time.Time) (*Authority, error) {
	return loadAuthority(ctx, dir, now, false)
}

func LoadAuthorityReadOnly(ctx context.Context, dir string, now time.Time) (*Authority, error) {
	return loadAuthority(ctx, dir, now, true)
}

func loadAuthority(ctx context.Context, dir string, now time.Time, readOnly bool) (*Authority, error) {
	paths, err := Resolve(dir)
	if err != nil {
		return nil, err
	}
	roomPrivate, err := keys.Load(paths.RoomKey)
	if err != nil {
		return nil, fmt.Errorf("room state: load room key: %w", err)
	}
	nodePrivate, err := keys.Load(paths.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("room state: load node key: %w", err)
	}
	genesis, err := LoadGenesis(paths.Genesis, now)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(roomPrivate.Public().(ed25519.PublicKey), genesis.RoomKey) {
		return nil, fmt.Errorf("room state: room key does not match genesis")
	}
	if !bytes.Equal(nodePrivate.Public().(ed25519.PublicKey), genesis.NodeKey) {
		return nil, fmt.Errorf("room state: node key does not match genesis")
	}
	var database *store.Store
	if readOnly {
		database, err = store.OpenReadOnly(ctx, paths.Database)
	} else {
		database, err = store.Open(ctx, paths.Database)
	}
	if err != nil {
		return nil, err
	}
	if err := database.ValidateGenesis(ctx, genesis); err != nil {
		database.Close()
		return nil, err
	}
	if err := database.Audit(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("room state: database audit: %w", err)
	}
	state, err := database.State(ctx)
	if err != nil {
		database.Close()
		return nil, err
	}
	if err := state.Verify(); err != nil {
		database.Close()
		return nil, fmt.Errorf("room state: invalid signed state: %w", err)
	}
	if !bytes.Equal(state.RoomID, genesis.RoomKey) {
		database.Close()
		return nil, fmt.Errorf("room state: signed state belongs to another room")
	}
	head, err := database.Head(ctx)
	if err != nil {
		database.Close()
		return nil, err
	}
	if state.RevisionSeqno > head.Seqno {
		database.Close()
		return nil, fmt.Errorf("room state: signed state revision is ahead of event head")
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		database.Close()
		return nil, err
	}
	overlayID, err := community.OverlayID(genesis.RoomKey)
	if err != nil {
		database.Close()
		return nil, err
	}
	return &Authority{
		Artifacts:   Artifacts{Paths: paths, Genesis: genesis, GenesisHash: genesisHash, OverlayID: overlayID},
		RoomPrivate: roomPrivate, NodePrivate: nodePrivate, Store: database,
	}, nil
}

func LoadGenesis(path string, now time.Time) (community.Genesis, error) {
	artifact, err := os.ReadFile(path)
	if err != nil {
		return community.Genesis{}, fmt.Errorf("room state: read genesis: %w", err)
	}
	genesis, err := DecodeGenesisArtifact(artifact)
	if err != nil {
		return community.Genesis{}, fmt.Errorf("room state: decode genesis: %w", err)
	}
	if err := genesis.Verify(now); err != nil {
		return community.Genesis{}, fmt.Errorf("room state: verify genesis: %w", err)
	}
	return genesis, nil
}

func EncodeGenesisArtifact(genesis community.Genesis) ([]byte, error) {
	raw, err := community.Encode(genesis)
	if err != nil {
		return nil, err
	}
	payload := append(append([]byte(nil), genesisArtifactPrefix...), raw...)
	builder := cell.BeginCell()
	if err := builder.StoreBinarySnake(payload); err != nil {
		return nil, err
	}
	return builder.EndCell().ToBOC(), nil
}

func DecodeGenesisArtifact(artifact []byte) (community.Genesis, error) {
	root, err := cell.FromBOC(artifact)
	if err != nil {
		return community.Genesis{}, fmt.Errorf("room state: invalid genesis BoC: %w", err)
	}
	payload, err := root.MustBeginParse().LoadBinarySnake()
	if err != nil {
		return community.Genesis{}, fmt.Errorf("room state: invalid genesis snake: %w", err)
	}
	if !bytes.HasPrefix(payload, genesisArtifactPrefix) {
		return community.Genesis{}, fmt.Errorf("room state: invalid genesis artifact domain")
	}
	return community.DecodeGenesis(payload[len(genesisArtifactPrefix):])
}

func writeExclusive(path string, value []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
