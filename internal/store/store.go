package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

const schemaVersion = 4

var (
	ErrAlreadyInitialized = errors.New("store: room is already initialized")
	ErrNotInitialized     = errors.New("store: room is not initialized")
	ErrGenesisMismatch    = errors.New("store: genesis does not match database")
)

type Rejection struct {
	Code    int32
	Message string
	Err     error
}

func (e *Rejection) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Rejection) Unwrap() error { return e.Err }

func reject(code int32, message string, err error) error {
	return &Rejection{Code: code, Message: message, Err: err}
}

type Head struct {
	Seqno int64
	Hash  []byte
}

type CommitResult struct {
	Event     community.CommittedEvent
	Duplicate bool
}

type Store struct {
	db     *sql.DB
	path   string
	mu     *sync.Mutex
	roomID []byte
	view   bool
}

func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: empty database path")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if path != ":memory:" {
		if err := os.Chmod(path, 0o600); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{db: db, path: path, mu: &sync.Mutex{}}, nil
}

func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	if path == "" || path == ":memory:" {
		return nil, fmt.Errorf("store: read-only database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: abs}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA query_only=ON"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}
	var version int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version > schemaVersion {
		db.Close()
		return nil, fmt.Errorf("store: database schema %d is newer than supported version %d", version, schemaVersion)
	}
	if version != schemaVersion {
		db.Close()
		return nil, fmt.Errorf("%w: schema %d", ErrMigrationRequired, version)
	}
	return &Store{db: db, path: abs, mu: &sync.Mutex{}}, nil
}

func (s *Store) Close() error {
	if s.view {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Initialize(ctx context.Context, genesis community.Genesis, roomPrivate ed25519.PrivateKey) error {
	if err := genesis.Verify(time.Now()); err != nil {
		return fmt.Errorf("store: invalid genesis: %w", err)
	}
	if len(roomPrivate) != ed25519.PrivateKeySize || !bytes.Equal(roomPrivate.Public().(ed25519.PublicKey), genesis.RoomKey) {
		return community.ErrWrongRoom
	}
	rawGenesis, err := community.Encode(genesis)
	if err != nil {
		return err
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		return err
	}
	state, err := community.SignRoomStateV3(roomPrivate, community.RoomStateV3{
		RoomID: genesis.RoomKey, RevisionSeqno: 0, RevisionHash: genesisHash,
		Name: genesis.Name, Description: genesis.Description,
		WritePolicy: genesis.WritePolicy, Admins: genesis.InitialAdmins,
	})
	if err != nil {
		return err
	}
	rawState, err := community.Encode(state)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.beginRoom(ctx, genesis.RoomKey)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM room_genesis WHERE room_id=?", tx.roomID).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return ErrAlreadyInitialized
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO room_genesis
(room_id, raw_tl, genesis_hash, room_key, node_key, created_at)
VALUES (?, ?, ?, ?, ?, ?)`, tx.roomID, rawGenesis, genesisHash, genesis.RoomKey, genesis.NodeKey, genesis.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO room_state
(room_id, revision_seqno, revision_hash, raw_signed_state, name, description, anyone_can_write)
VALUES (?, 0, ?, ?, ?, ?, ?)`, tx.roomID, genesisHash, rawState, genesis.Name, genesis.Description, boolInt(genesis.WritePolicy.AnyoneCanWrite)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replica_head(room_id, latest_seqno, latest_hash) VALUES (?, 0, ?)", tx.roomID, community.Zero256()); err != nil {
		return err
	}
	for _, admin := range genesis.InitialAdmins {
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles(room_id, subject_key, role, granted_seqno, granted_by)
VALUES (?, ?, 'admin', 0, ?)`, tx.roomID, admin, genesis.RoomKey); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Genesis(ctx context.Context) (community.Genesis, []byte, error) {
	tx, err := s.beginRoom(ctx, nil)
	if err != nil {
		return community.Genesis{}, nil, err
	}
	defer tx.Rollback()
	return genesisTx(ctx, tx)
}

func (s *Store) ValidateGenesis(ctx context.Context, genesis community.Genesis) error {
	stored, hash, err := s.Genesis(ctx)
	if err != nil {
		return err
	}
	want, err := genesis.Hash()
	if err != nil {
		return err
	}
	storedHash, err := stored.Hash()
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, want) || !bytes.Equal(storedHash, want) {
		return ErrGenesisMismatch
	}
	return nil
}

func (s *Store) State(ctx context.Context) (community.RoomStateV3, error) {
	tx, err := s.beginRoom(ctx, nil)
	if err != nil {
		return community.RoomStateV3{}, err
	}
	defer tx.Rollback()
	return stateTx(ctx, tx)
}

func (s *Store) Head(ctx context.Context) (Head, error) {
	var head Head
	tx, err := s.beginRoom(ctx, nil)
	if err != nil {
		return head, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, "SELECT latest_seqno, latest_hash FROM replica_head WHERE room_id=?", tx.roomID).Scan(&head.Seqno, &head.Hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Head{}, ErrNotInitialized
		}
		return Head{}, err
	}
	return head, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
