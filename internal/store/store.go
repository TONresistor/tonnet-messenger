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

const schemaVersion = 1

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
	db   *sql.DB
	path string
	mu   sync.Mutex
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
	return &Store{db: db, path: path}, nil
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
	return &Store{db: db, path: abs}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS room_genesis (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    raw_tl BLOB NOT NULL,
    genesis_hash BLOB NOT NULL UNIQUE CHECK (length(genesis_hash) = 32),
    room_key BLOB NOT NULL CHECK (length(room_key) = 32),
    node_key BLOB NOT NULL CHECK (length(node_key) = 32),
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS room_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    revision_seqno INTEGER NOT NULL,
    revision_hash BLOB NOT NULL CHECK (length(revision_hash) = 32),
    raw_signed_state BLOB NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    anyone_can_write INTEGER NOT NULL CHECK (anyone_can_write IN (0, 1))
);
CREATE TABLE IF NOT EXISTS replica_head (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    latest_seqno INTEGER NOT NULL,
    latest_hash BLOB NOT NULL CHECK (length(latest_hash) = 32)
);
CREATE TABLE IF NOT EXISTS events (
    seqno INTEGER PRIMARY KEY,
    event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 32),
    commit_hash BLOB NOT NULL UNIQUE CHECK (length(commit_hash) = 32),
    previous_hash BLOB NOT NULL CHECK (length(previous_hash) = 32),
    author_key BLOB NOT NULL CHECK (length(author_key) = 32),
    body_type TEXT NOT NULL,
    raw_proposal BLOB NOT NULL,
    raw_commit BLOB NOT NULL,
    committed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY,
    creation_seqno INTEGER NOT NULL UNIQUE,
    author_key BLOB NOT NULL CHECK (length(author_key) = 32),
    nick TEXT NOT NULL,
    text TEXT NOT NULL,
    client_ts INTEGER NOT NULL,
    committed_at INTEGER NOT NULL,
    raw_commit BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pins (
    message_id INTEGER PRIMARY KEY REFERENCES messages(message_id),
    pinned_seqno INTEGER NOT NULL,
    pinned_by BLOB NOT NULL CHECK (length(pinned_by) = 32)
);
CREATE TABLE IF NOT EXISTS roles (
    subject_key BLOB NOT NULL CHECK (length(subject_key) = 32),
    role TEXT NOT NULL CHECK (role IN ('admin', 'moderator')),
    granted_seqno INTEGER NOT NULL,
    granted_by BLOB NOT NULL CHECK (length(granted_by) = 32),
    PRIMARY KEY(subject_key, role)
);
CREATE TABLE IF NOT EXISTS request_nonces (
    author_key BLOB NOT NULL CHECK (length(author_key) = 32),
    nonce BLOB NOT NULL CHECK (length(nonce) = 32),
    accepted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(author_key, nonce)
);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_messages_creation ON messages(creation_seqno);
CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON request_nonces(expires_at);
`); err != nil {
		return fmt.Errorf("store: migrate schema: %w", err)
	}
	var currentVersion int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion); err != nil {
		return err
	}
	if currentVersion > schemaVersion {
		return fmt.Errorf("store: database schema %d is newer than supported version %d", currentVersion, schemaVersion)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
		schemaVersion, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
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
	state, err := community.SignRoomState(roomPrivate, community.RoomState{
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM room_genesis").Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return ErrAlreadyInitialized
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO room_genesis
(singleton_id, raw_tl, genesis_hash, room_key, node_key, created_at)
VALUES (1, ?, ?, ?, ?, ?)`, rawGenesis, genesisHash, genesis.RoomKey, genesis.NodeKey, genesis.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO room_state
(singleton_id, revision_seqno, revision_hash, raw_signed_state, name, description, anyone_can_write)
VALUES (1, 0, ?, ?, ?, ?, ?)`, genesisHash, rawState, genesis.Name, genesis.Description, boolInt(genesis.WritePolicy.AnyoneCanWrite)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replica_head(singleton_id, latest_seqno, latest_hash) VALUES (1, 0, ?)", community.Zero256()); err != nil {
		return err
	}
	for _, admin := range genesis.InitialAdmins {
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles(subject_key, role, granted_seqno, granted_by)
VALUES (?, 'admin', 0, ?)`, admin, genesis.RoomKey); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Genesis(ctx context.Context) (community.Genesis, []byte, error) {
	var raw, hash []byte
	if err := s.db.QueryRowContext(ctx, "SELECT raw_tl, genesis_hash FROM room_genesis WHERE singleton_id=1").Scan(&raw, &hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return community.Genesis{}, nil, ErrNotInitialized
		}
		return community.Genesis{}, nil, err
	}
	g, err := community.DecodeGenesis(raw)
	if err != nil {
		return community.Genesis{}, nil, err
	}
	return g, hash, nil
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

func (s *Store) State(ctx context.Context) (community.RoomState, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT raw_signed_state FROM room_state WHERE singleton_id=1").Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return community.RoomState{}, ErrNotInitialized
		}
		return community.RoomState{}, err
	}
	return community.DecodeRoomState(raw)
}

func (s *Store) Head(ctx context.Context) (Head, error) {
	var head Head
	if err := s.db.QueryRowContext(ctx, "SELECT latest_seqno, latest_hash FROM replica_head WHERE singleton_id=1").Scan(&head.Seqno, &head.Hash); err != nil {
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
