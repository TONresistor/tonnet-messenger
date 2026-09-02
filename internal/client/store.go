package client

import (
	"bytes"
	"context"
	"database/sql"
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

func (s *clientStore) installRoom(ctx context.Context, roomKey []byte, genesis community.Genesis, state community.RoomState) error {
	rawGenesis, err := community.Encode(genesis)
	if err != nil {
		return err
	}
	rawState, err := community.Encode(state)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateRoomState(ctx, tx, roomKey, genesis, state); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE joined_rooms SET raw_genesis=?,raw_state=? WHERE room_key=?", rawGenesis, rawState, roomKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *clientStore) updateState(ctx context.Context, roomKey []byte, genesis community.Genesis, state community.RoomState) error {
	raw, err := community.Encode(state)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateRoomState(ctx, tx, roomKey, genesis, state); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE joined_rooms SET raw_state=? WHERE room_key=?", raw, roomKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *clientStore) validateRoomState(ctx context.Context, roomKey []byte, genesis community.Genesis, state community.RoomState) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return validateRoomState(ctx, tx, roomKey, genesis, state)
}

func validateRoomState(ctx context.Context, query clientQueryer, roomKey []byte, genesis community.Genesis, state community.RoomState) error {
	if err := state.Verify(); err != nil {
		return fmt.Errorf("client store: invalid room state: %w", err)
	}
	if !bytes.Equal(genesis.RoomKey, roomKey) || !bytes.Equal(state.RoomID, roomKey) {
		return fmt.Errorf("client store: room state belongs to another room")
	}
	record, err := queryRoom(ctx, query, roomKey)
	if err != nil {
		return err
	}
	if state.RevisionSeqno > record.HeadSeqno {
		return fmt.Errorf("client store: room state revision is ahead of event head")
	}

	expectedHash, err := genesis.Hash()
	if err != nil {
		return err
	}
	if state.RevisionSeqno > 0 {
		var raw []byte
		if err := query.QueryRowContext(ctx, "SELECT raw_event FROM room_events WHERE room_key=? AND seqno=?", roomKey, state.RevisionSeqno).Scan(&raw); err != nil {
			return err
		}
		event, err := community.DecodeCommittedEvent(raw)
		if err != nil {
			return err
		}
		if !stateChanging(event.Proposal.Body) {
			return fmt.Errorf("client store: room state revision is not a state-changing event")
		}
		expectedHash, err = event.Hash()
		if err != nil {
			return err
		}
	}
	if !bytes.Equal(state.RevisionHash, expectedHash) {
		return fmt.Errorf("client store: room state revision hash mismatch")
	}

	rows, err := query.QueryContext(ctx, "SELECT raw_event FROM room_events WHERE room_key=? AND seqno>? ORDER BY seqno", roomKey, state.RevisionSeqno)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		event, err := community.DecodeCommittedEvent(raw)
		if err != nil {
			return err
		}
		if stateChanging(event.Proposal.Body) {
			return fmt.Errorf("client store: stale room state")
		}
	}
	return rows.Err()
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
		var existing []byte
		if err := tx.QueryRowContext(ctx, "SELECT event_id FROM room_events WHERE room_key=? AND seqno=?", roomKey, event.Seqno).Scan(&existing); err != nil {
			return false, err
		}
		if !bytes.Equal(existing, id) {
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
	if _, err := tx.ExecContext(ctx, `UPDATE joined_rooms SET raw_genesis=NULL,raw_state=NULL,head_seqno=0,head_hash=? WHERE room_key=?`, community.Zero256(), roomKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *clientStore) auditRoom(ctx context.Context, roomKey []byte, genesis community.Genesis) error {
	rows, err := s.db.QueryContext(ctx, "SELECT seqno,raw_event FROM room_events WHERE room_key=? ORDER BY seqno", roomKey)
	if err != nil {
		return err
	}
	defer rows.Close()
	expectedSeqno := int64(1)
	previous := community.Zero256()
	for rows.Next() {
		var seqno int64
		var raw []byte
		if err := rows.Scan(&seqno, &raw); err != nil {
			return err
		}
		event, err := community.DecodeCommittedEvent(raw)
		if err != nil || seqno != expectedSeqno || event.Seqno != expectedSeqno || !bytes.Equal(event.PreviousHash, previous) {
			return fmt.Errorf("client store: invalid cached event at seqno %d", seqno)
		}
		if err := event.Verify(roomKey, genesis.NodeKey); err != nil {
			return err
		}
		previous, err = event.Hash()
		if err != nil {
			return err
		}
		expectedSeqno++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var head int64
	var headHash []byte
	if err := s.db.QueryRowContext(ctx, "SELECT head_seqno,head_hash FROM joined_rooms WHERE room_key=?", roomKey).Scan(&head, &headHash); err != nil {
		return err
	}
	if head != expectedSeqno-1 || !bytes.Equal(headHash, previous) {
		return fmt.Errorf("client store: cached head mismatch")
	}
	return nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
