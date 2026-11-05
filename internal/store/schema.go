package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const roomSchema = `
CREATE TABLE room_genesis (
    room_id BLOB PRIMARY KEY NOT NULL CHECK(length(room_id)=32 AND room_id=room_key),
    raw_tl BLOB NOT NULL,
    genesis_hash BLOB NOT NULL UNIQUE CHECK(length(genesis_hash)=32),
    room_key BLOB NOT NULL CHECK(length(room_key)=32),
    node_key BLOB NOT NULL CHECK(length(node_key)=32),
    created_at INTEGER NOT NULL
);
CREATE TABLE room_state (
    room_id BLOB PRIMARY KEY NOT NULL REFERENCES room_genesis(room_id),
    revision_seqno INTEGER NOT NULL,
    revision_hash BLOB NOT NULL CHECK(length(revision_hash)=32),
    raw_signed_state BLOB NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    anyone_can_write INTEGER NOT NULL CHECK(anyone_can_write IN (0,1))
);
CREATE TABLE replica_head (
    room_id BLOB PRIMARY KEY NOT NULL REFERENCES room_genesis(room_id),
    latest_seqno INTEGER NOT NULL,
    latest_hash BLOB NOT NULL CHECK(length(latest_hash)=32)
);
CREATE TABLE events (
    room_id BLOB NOT NULL REFERENCES room_genesis(room_id),
    seqno INTEGER NOT NULL,
    event_id BLOB NOT NULL CHECK(length(event_id)=32),
    commit_hash BLOB NOT NULL CHECK(length(commit_hash)=32),
    previous_hash BLOB NOT NULL CHECK(length(previous_hash)=32),
    author_key BLOB NOT NULL CHECK(length(author_key)=32),
    body_type TEXT NOT NULL,
    raw_proposal BLOB NOT NULL,
    raw_commit BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    PRIMARY KEY(room_id,seqno), UNIQUE(room_id,event_id), UNIQUE(room_id,commit_hash)
);
CREATE TABLE messages (
    room_id BLOB NOT NULL REFERENCES room_genesis(room_id),
    message_id INTEGER NOT NULL,
    creation_seqno INTEGER NOT NULL,
    author_key BLOB NOT NULL CHECK(length(author_key)=32),
    nick TEXT NOT NULL,
    text TEXT NOT NULL,
    client_ts INTEGER NOT NULL,
    committed_at INTEGER NOT NULL,
    raw_commit BLOB NOT NULL,
    PRIMARY KEY(room_id,message_id), UNIQUE(room_id,creation_seqno)
);
CREATE TABLE pins (
    room_id BLOB NOT NULL,
    message_id INTEGER NOT NULL,
    pinned_seqno INTEGER NOT NULL,
    pinned_by BLOB NOT NULL CHECK(length(pinned_by)=32),
    PRIMARY KEY(room_id,message_id),
    FOREIGN KEY(room_id,message_id) REFERENCES messages(room_id,message_id)
);
CREATE TABLE roles (
    room_id BLOB NOT NULL REFERENCES room_genesis(room_id),
    subject_key BLOB NOT NULL CHECK(length(subject_key)=32),
    role TEXT NOT NULL CHECK(role IN ('admin','moderator')),
    granted_seqno INTEGER NOT NULL,
    granted_by BLOB NOT NULL CHECK(length(granted_by)=32),
    PRIMARY KEY(room_id,subject_key,role)
);
CREATE TABLE bans (
    room_id BLOB NOT NULL REFERENCES room_genesis(room_id),
    subject_key BLOB NOT NULL CHECK(length(subject_key)=32),
    banned_seqno INTEGER NOT NULL,
    banned_by BLOB NOT NULL CHECK(length(banned_by)=32),
    PRIMARY KEY(room_id,subject_key)
);
CREATE TABLE request_nonces (
    room_id BLOB NOT NULL REFERENCES room_genesis(room_id),
    author_key BLOB NOT NULL CHECK(length(author_key)=32),
    nonce BLOB NOT NULL CHECK(length(nonce)=32),
    accepted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(room_id,author_key,nonce)
);
CREATE INDEX idx_room_nonces_expiry ON request_nonces(room_id,expires_at);
CREATE INDEX idx_room_events_state_change ON events(room_id,seqno DESC) WHERE body_type <> 'message';
`

var roomTables = []struct{ name, columns string }{
	{"room_genesis", "raw_tl,genesis_hash,room_key,node_key,created_at"},
	{"room_state", "revision_seqno,revision_hash,raw_signed_state,name,description,anyone_can_write"},
	{"replica_head", "latest_seqno,latest_hash"},
	{"events", "seqno,event_id,commit_hash,previous_hash,author_key,body_type,raw_proposal,raw_commit,committed_at"},
	{"messages", "message_id,creation_seqno,author_key,nick,text,client_ts,committed_at,raw_commit"},
	{"pins", "message_id,pinned_seqno,pinned_by"},
	{"roles", "subject_key,role,granted_seqno,granted_by"},
	{"bans", "subject_key,banned_seqno,banned_by"},
	{"request_nonces", "author_key,nonce,accepted_at,expires_at"},
}

func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("store: database schema %d is newer than supported version %d", version, schemaVersion)
	}
	if version == schemaVersion {
		return nil
	}
	if version < 4 {
		legacy := version > 0
		var hasBans bool
		if legacy {
			if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='bans')").Scan(&hasBans); err != nil {
				return err
			}
			for _, table := range roomTables {
				if table.name == "bans" && !hasBans && version < 3 {
					continue
				}
				if _, err := tx.ExecContext(ctx, "ALTER TABLE "+table.name+" RENAME TO legacy_"+table.name); err != nil {
					return fmt.Errorf("store: migrate %s: %w", table.name, err)
				}
			}
		}
		if _, err := tx.ExecContext(ctx, roomSchema); err != nil {
			return fmt.Errorf("store: create room schema: %w", err)
		}
		if legacy {
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM legacy_room_genesis").Scan(&count); err != nil {
				return err
			}
			if count > 1 {
				return fmt.Errorf("store: legacy database contains multiple genesis rows")
			}
			for _, table := range roomTables {
				if table.name == "bans" && !hasBans {
					continue
				}
				roomID := "(SELECT room_key FROM legacy_room_genesis WHERE singleton_id=1)"
				if _, err := tx.ExecContext(ctx, "INSERT INTO "+table.name+"(room_id,"+table.columns+") SELECT "+roomID+","+table.columns+" FROM legacy_"+table.name); err != nil {
					return fmt.Errorf("store: copy legacy %s: %w", table.name, err)
				}
			}
			// Drop children before their parents while foreign-key checks remain on.
			for i := len(roomTables) - 1; i >= 0; i-- {
				table := roomTables[i]
				if table.name == "bans" && !hasBans {
					continue
				}
				if _, err := tx.ExecContext(ctx, "DROP TABLE legacy_"+table.name); err != nil {
					return err
				}
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES (?,?)", 4, time.Now().Unix()); err != nil {
			return err
		}
	}
	if version < 5 {
		if _, err := tx.ExecContext(ctx, inboxSchema); err != nil {
			return fmt.Errorf("store: create inbox schema: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES (?,?)", 5, time.Now().Unix()); err != nil {
			return err
		}
	}

	if version < 6 {
		if _, err := tx.ExecContext(ctx, paymentSchema); err != nil {
			return fmt.Errorf("store: create payment schema: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES (?,?)", 6, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
