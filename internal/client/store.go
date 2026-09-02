package client

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

type RoomRecord struct {
	RoomKey   []byte
	Reference string
	Bootstrap []byte
	Genesis   community.Genesis
	State     community.RoomState
	HeadSeqno int64
	HeadHash  []byte
}

type clientStore struct {
	db *sql.DB
}

type clientQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func openClientStore(ctx context.Context, path string) (*clientStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS client_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS joined_rooms (
    room_key BLOB PRIMARY KEY CHECK(length(room_key)=32),
    reference TEXT NOT NULL,
    bootstrap BLOB,
    raw_genesis BLOB,
    raw_state BLOB,
    head_seqno INTEGER NOT NULL DEFAULT 0,
    head_hash BLOB NOT NULL CHECK(length(head_hash)=32)
);
CREATE TABLE IF NOT EXISTS room_events (
    room_key BLOB NOT NULL REFERENCES joined_rooms(room_key) ON DELETE CASCADE,
    seqno INTEGER NOT NULL,
    event_id BLOB NOT NULL CHECK(length(event_id)=32),
    message_id INTEGER NOT NULL,
    raw_event BLOB NOT NULL,
    PRIMARY KEY(room_key, seqno),
    UNIQUE(room_key, event_id)
);
CREATE INDEX IF NOT EXISTS idx_client_events_message ON room_events(room_key, message_id);
INSERT OR IGNORE INTO client_meta(key,value) VALUES ('schema_version','1');
`); err != nil {
		db.Close()
		return nil, fmt.Errorf("client store migration: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return &clientStore{db: db}, nil
}

func (s *clientStore) Close() error { return s.db.Close() }

func (s *clientStore) profile(ctx context.Context) (string, string, error) {
	values := map[string]string{}
	rows, err := s.db.QueryContext(ctx, "SELECT key,value FROM client_meta WHERE key IN ('author_name','author_domain')")
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return "", "", err
		}
		values[key] = value
	}
	return values["author_name"], values["author_domain"], rows.Err()
}

func (s *clientStore) setMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO client_meta(key,value) VALUES (?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *clientStore) addRoom(ctx context.Context, roomKey []byte, reference string, bootstrap []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO joined_rooms(room_key,reference,bootstrap,head_hash)
VALUES (?,?,?,?) ON CONFLICT(room_key) DO UPDATE SET reference=excluded.reference,bootstrap=excluded.bootstrap`,
		roomKey, reference, nullableBytes(bootstrap), community.Zero256())
	return err
}

func (s *clientStore) pinGenesis(ctx context.Context, roomKey []byte, genesis community.Genesis) error {
	if err := genesis.VerifyNow(); err != nil {
		return fmt.Errorf("client store: invalid genesis: %w", err)
	}
	raw, err := community.Encode(genesis)
	if err != nil {
		return err
	}
	if !bytes.Equal(genesis.RoomKey, roomKey) {
		return fmt.Errorf("client store: genesis belongs to another room")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pinned []byte
	if err := tx.QueryRowContext(ctx, "SELECT raw_genesis FROM joined_rooms WHERE room_key=?", roomKey).Scan(&pinned); err != nil {
		return err
	}
	if len(pinned) > 0 {
		if !bytes.Equal(pinned, raw) {
			return fmt.Errorf("client store: genesis mismatch")
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx, "UPDATE joined_rooms SET raw_genesis=? WHERE room_key=?", raw, roomKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *clientStore) installRoom(ctx context.Context, roomKey []byte, genesis community.Genesis, projection *community.Projection, state community.RoomState) error {
	rawState, err := community.Encode(state)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateRoomState(ctx, tx, roomKey, genesis, projection, state); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE joined_rooms SET raw_state=? WHERE room_key=?", rawState, roomKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *clientStore) updateState(ctx context.Context, roomKey []byte, genesis community.Genesis, projection *community.Projection, state community.RoomState) error {
	raw, err := community.Encode(state)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateRoomState(ctx, tx, roomKey, genesis, projection, state); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE joined_rooms SET raw_state=? WHERE room_key=?", raw, roomKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *clientStore) validateRoomState(ctx context.Context, roomKey []byte, genesis community.Genesis, projection *community.Projection, state community.RoomState) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return validateRoomState(ctx, tx, roomKey, genesis, projection, state)
}

func validateRoomState(ctx context.Context, query clientQueryer, roomKey []byte, genesis community.Genesis, projection *community.Projection, state community.RoomState) error {
	if !bytes.Equal(genesis.RoomKey, roomKey) || !bytes.Equal(state.RoomID, roomKey) {
		return fmt.Errorf("client store: room state belongs to another room")
	}
	rawGenesis, err := community.Encode(genesis)
	if err != nil {
		return err
	}
	if err := validatePinnedGenesis(ctx, query, roomKey, rawGenesis); err != nil {
		return err
	}
	record, err := queryRoom(ctx, query, roomKey)
	if err != nil {
		return err
	}
	if projection == nil {
		return fmt.Errorf("client store: room projection is unavailable")
	}
	headSeqno, headHash := projection.Head()
	if headSeqno != record.HeadSeqno || !bytes.Equal(headHash, record.HeadHash) {
		return fmt.Errorf("client store: projection head disagrees with event cache")
	}
	if err := projection.ValidateState(state); err != nil {
		return fmt.Errorf("client store: invalid room state projection: %w", err)
	}
	return nil
}

func validatePinnedGenesis(ctx context.Context, query clientQueryer, roomKey, expected []byte) error {
	var pinned []byte
	if err := query.QueryRowContext(ctx, "SELECT raw_genesis FROM joined_rooms WHERE room_key=?", roomKey).Scan(&pinned); err != nil {
		return err
	}
	if len(pinned) == 0 || !bytes.Equal(pinned, expected) {
		return fmt.Errorf("client store: genesis mismatch")
	}
	return nil
}

func (s *clientStore) projectRoom(ctx context.Context, roomKey []byte, genesis community.Genesis) (*community.Projection, error) {
	projection, err := community.NewProjection(genesis)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT raw_event FROM room_events WHERE room_key=? ORDER BY seqno", roomKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		event, err := community.DecodeCommittedEvent(raw)
		if err != nil {
			return nil, err
		}
		if err := projection.Apply(event); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	record, err := s.room(ctx, roomKey)
	if err != nil {
		return nil, err
	}
	headSeqno, headHash := projection.Head()
	if headSeqno != record.HeadSeqno || !bytes.Equal(headHash, record.HeadHash) {
		return nil, fmt.Errorf("client store: projected event head mismatch")
	}
	return projection, nil
}

func (s *clientStore) rooms(ctx context.Context) ([]RoomRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT room_key,reference,bootstrap,raw_genesis,raw_state,head_seqno,head_hash FROM joined_rooms ORDER BY reference")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RoomRecord
	for rows.Next() {
		var record RoomRecord
		var rawGenesis, rawState []byte
		if err := rows.Scan(&record.RoomKey, &record.Reference, &record.Bootstrap, &rawGenesis, &rawState, &record.HeadSeqno, &record.HeadHash); err != nil {
			return nil, err
		}
		if len(rawGenesis) > 0 {
			record.Genesis, err = community.DecodeGenesis(rawGenesis)
			if err != nil {
				return nil, err
			}
		}
		if len(rawState) > 0 {
			record.State, err = community.DecodeRoomState(rawState)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *clientStore) room(ctx context.Context, roomKey []byte) (RoomRecord, error) {
	return queryRoom(ctx, s.db, roomKey)
}

func queryRoom(ctx context.Context, query clientQueryer, roomKey []byte) (RoomRecord, error) {
	var record RoomRecord
	var rawGenesis, rawState []byte
	err := query.QueryRowContext(ctx, "SELECT room_key,reference,bootstrap,raw_genesis,raw_state,head_seqno,head_hash FROM joined_rooms WHERE room_key=?", roomKey).
		Scan(&record.RoomKey, &record.Reference, &record.Bootstrap, &rawGenesis, &rawState, &record.HeadSeqno, &record.HeadHash)
	if err != nil {
		return RoomRecord{}, err
	}
	if len(rawGenesis) > 0 {
		record.Genesis, err = community.DecodeGenesis(rawGenesis)
		if err != nil {
			return RoomRecord{}, err
		}
	}
	if len(rawState) > 0 {
		record.State, err = community.DecodeRoomState(rawState)
	}
	return record, err
}

func (s *clientStore) appendEvent(ctx context.Context, roomKey []byte, event community.CommittedEvent) (bool, error) {
	raw, err := community.Encode(event)
	if err != nil {
		return false, err
	}
	id, err := event.Proposal.ID()
	if err != nil {
		return false, err
	}
	hash, err := event.Hash()
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var head int64
	var headHash []byte
	if err := tx.QueryRowContext(ctx, "SELECT head_seqno,head_hash FROM joined_rooms WHERE room_key=?", roomKey).Scan(&head, &headHash); err != nil {
		return false, err
	}
	if event.Seqno <= head {
		var existingRaw []byte
		if err := tx.QueryRowContext(ctx, "SELECT raw_event FROM room_events WHERE room_key=? AND seqno=?", roomKey, event.Seqno).Scan(&existingRaw); err != nil {
			return false, err
		}
		if !bytes.Equal(existingRaw, raw) {
			return false, fmt.Errorf("client store: conflicting event at seqno %d", event.Seqno)
		}
		return false, nil
	}
	if event.Seqno != head+1 || !bytes.Equal(event.PreviousHash, headHash) {
		return false, fmt.Errorf("client store: non-contiguous event %d after %d", event.Seqno, head)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO room_events(room_key,seqno,event_id,message_id,raw_event) VALUES (?,?,?,?,?)", roomKey, event.Seqno, id, event.MessageID, raw); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE joined_rooms SET head_seqno=?,head_hash=? WHERE room_key=?", event.Seqno, hash, roomKey); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *clientStore) hasEvent(ctx context.Context, roomKey []byte, event community.CommittedEvent) (bool, error) {
	raw, err := community.Encode(event)
	if err != nil {
		return false, err
	}
	var storedRaw []byte
	err = s.db.QueryRowContext(ctx, "SELECT raw_event FROM room_events WHERE room_key=? AND seqno=?", roomKey, event.Seqno).Scan(&storedRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(storedRaw, raw) {
		return false, fmt.Errorf("client store: conflicting event at seqno %d", event.Seqno)
	}
	return true, nil
}

func (s *clientStore) timeline(ctx context.Context, roomKey []byte, before int64, limit int) ([]community.CommittedEvent, bool, error) {
	if limit <= 0 || limit > community.MaxPageLimit {
		limit = community.DefaultPageLimit
	}
	query := "SELECT raw_event FROM room_events WHERE room_key=?"
	args := []any{roomKey}
	if before > 0 {
		query += " AND seqno<?"
		args = append(args, before)
	}
	query += " ORDER BY seqno DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var reversed []community.CommittedEvent
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, false, err
		}
		event, err := community.DecodeCommittedEvent(raw)
		if err != nil {
			return nil, false, err
		}
		reversed = append(reversed, event)
	}
	hasMore := len(reversed) > limit
	if hasMore {
		reversed = reversed[:limit]
	}
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return reversed, hasMore, rows.Err()
}

func (s *clientStore) deleteRoom(ctx context.Context, roomKey []byte) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM joined_rooms WHERE room_key=?", roomKey)
	return err
}

func (s *clientStore) resetRoomCache(ctx context.Context, roomKey []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM room_events WHERE room_key=?", roomKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE joined_rooms SET raw_state=NULL,head_seqno=0,head_hash=? WHERE room_key=?`, community.Zero256(), roomKey); err != nil {
		return err
	}
	return tx.Commit()
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
