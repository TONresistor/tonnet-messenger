package store

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

const legacySchema = `
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
CREATE TABLE IF NOT EXISTS bans (
    subject_key BLOB PRIMARY KEY CHECK(length(subject_key)=32),
    banned_seqno INTEGER NOT NULL,
    banned_by BLOB NOT NULL CHECK(length(banned_by)=32)
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
CREATE INDEX IF NOT EXISTS idx_events_state_change ON events(seqno DESC) WHERE body_type <> 'message';
`

// Rebuild a local one-room fixture using the legacy table definitions. Signed
// payloads are copied without decoding or signing them.
func legacyLayout(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"inbox_messages", "inbox_rate", "inbox_receipts", "inbox_counters", "relay_payments", "prepaid_balances", "payment_identity"} {
		if _, err := tx.Exec("DROP TABLE IF EXISTS " + table); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range roomTables {
		if _, err := tx.Exec("ALTER TABLE " + table.name + " RENAME TO fixture_" + table.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	for i, table := range roomTables {
		columns, values := table.columns, table.columns
		if i < 3 {
			columns, values = "singleton_id,"+columns, "1,"+values
		}
		if _, err := tx.Exec("INSERT INTO " + table.name + "(" + columns + ") SELECT " + values + " FROM fixture_" + table.name); err != nil {
			t.Fatal(err)
		}
	}
	for i := len(roomTables) - 1; i >= 0; i-- {
		if _, err := tx.Exec("DROP TABLE fixture_" + roomTables[i].name); err != nil {
			t.Fatal(err)
		}
	}
	if version < 3 {
		if _, err := tx.Exec("DROP TABLE bans"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec("DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (?,0)", version); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func sharedRooms(t *testing.T) (*Store, *fixture, *fixture) {
	t.Helper()
	a := newFixture(t)
	root := a.store
	t.Cleanup(func() { root.Close() })
	var err error
	a.store, err = root.ForRoom(a.genesis.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	b := &fixture{ctx: a.ctx, now: a.now, room: privateKey(t), node: a.node, user: a.user, admin: a.admin}
	b.genesis, err = community.NewGenesis(b.room, b.node, b.now, "Second", "Independent", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.store, err = root.ForRoom(b.genesis.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.store.Initialize(b.ctx, b.genesis, b.room); err != nil {
		t.Fatal(err)
	}
	return root, a, b
}

func roomCommit(t *testing.T, f *fixture, author ed25519.PrivateKey, body any, nonce []byte) community.CommittedEvent {
	t.Helper()
	if nonce == nil {
		nonce = randomNonce(t)
	}
	proposal := f.proposal(t, author, body, nonce, f.now)
	result, err := f.store.Commit(f.ctx, proposal, f.room, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return result.Event
}

func TestSharedRoomsCountersNoncesAndReads(t *testing.T) {
	root, a, b := sharedRooms(t)
	nonce := randomNonce(t)
	for _, f := range []*fixture{a, b} {
		event := roomCommit(t, f, f.user, community.EventMessage{Text: f.genesis.Name}, nonce)
		if event.Seqno != 1 || event.MessageID != 1 {
			t.Fatal("room counters did not start independently")
		}
		duplicate, err := f.store.Commit(f.ctx, event.Proposal, f.room, f.now.Add(community.NonceRetention))
		if err != nil || !duplicate.Duplicate {
			t.Fatalf("durable duplicate: %v", err)
		}
		reused := f.proposal(t, f.user, community.EventMessage{Text: "reused"}, nonce, f.now)
		if _, err := f.store.Commit(f.ctx, reused, f.room, f.now); rejectionCode(err) != community.RejectReusedNonce {
			t.Fatalf("nonce reuse: %v", err)
		}
		roomCommit(t, f, f.user, community.EventMessage{Text: "second"}, nil)
		roomCommit(t, f, f.room, community.EventPin{MessageID: 1}, nil)
		roomCommit(t, f, f.room, community.EventMetadata{Name: f.genesis.Name, Description: "changed"}, nil)
	}
	for _, f := range []*fixture{a, b} {
		page, err := f.store.Events(f.ctx, 0, 1)
		if err != nil || !page.HasMore || len(page.Events) != 1 || !bytes.Equal(page.Events[0].Proposal.RoomID, f.genesis.RoomKey) {
			t.Fatalf("room events: %+v %v", page, err)
		}
		recent, err := f.store.MessagesRecent(f.ctx, 1)
		if err != nil || !recent.HasMore || len(recent.Messages) != 1 || recent.Messages[0].MessageID != 2 || !bytes.Equal(recent.Messages[0].Proposal.RoomID, f.genesis.RoomKey) {
			t.Fatalf("recent: %+v %v", recent, err)
		}
		before, err := f.store.MessagesBefore(f.ctx, 2, 100)
		if err != nil || len(before.Messages) != 1 || before.Messages[0].MessageID != 1 || !bytes.Equal(before.Messages[0].Proposal.RoomID, f.genesis.RoomKey) {
			t.Fatalf("messages before: %+v %v", before, err)
		}
		if err := f.store.Audit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	path := root.path
	if err := a.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.store.Head(b.ctx); err != nil {
		t.Fatalf("closing a view closed its sibling: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(a.ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	readOnly, err := OpenReadOnly(a.ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	for _, database := range []*Store{reopened, readOnly} {
		for _, f := range []*fixture{a, b} {
			selected, err := database.ForRoom(f.genesis.RoomKey)
			if err != nil {
				t.Fatal(err)
			}
			head, err := selected.Head(f.ctx)
			if err != nil || head.Seqno != 4 {
				t.Fatalf("reopened head: %+v %v", head, err)
			}
			state, err := selected.State(f.ctx)
			if err != nil || state.Name != f.genesis.Name || len(state.PinnedMessages) != 1 {
				t.Fatalf("reopened state: %+v %v", state, err)
			}
			if err := selected.Audit(f.ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestRoomSelectionNeverFallsBack(t *testing.T) {
	root, a, b := sharedRooms(t)
	if _, err := root.ForRoom([]byte{1}); !errors.Is(err, community.ErrMalformedKey) {
		t.Fatalf("invalid selector: %v", err)
	}
	key := bytes.Clone(a.genesis.RoomKey)
	selected, err := root.ForRoom(key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 1
	if err := selected.ValidateGenesis(a.ctx, a.genesis); err != nil {
		t.Fatal("selector aliases caller memory", err)
	}
	unknown, err := root.ForRoom(privateKey(t).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	proposal := a.proposal(t, a.user, community.EventMessage{Text: "selection"}, randomNonce(t), a.now)
	eventForSelection, err := community.SignCommit(a.room, proposal, 1, community.Zero256(), a.now)
	if err != nil {
		t.Fatal(err)
	}
	stateForSelection, err := a.store.State(a.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		s    *Store
		want error
	}{{root, ErrAmbiguousRoom}, {unknown, ErrNotInitialized}} {
		checks := []func() error{
			func() error { _, e := test.s.Commit(a.ctx, proposal, a.room, a.now); return e },
			func() error { _, e := test.s.AppendReplica(a.ctx, eventForSelection); return e },
			func() error { return test.s.InstallReplicaState(a.ctx, stateForSelection) },
			func() error { _, _, e := test.s.Genesis(a.ctx); return e },
			func() error { _, e := test.s.State(a.ctx); return e },
			func() error { _, e := test.s.Head(a.ctx); return e },
			func() error { _, e := test.s.Events(a.ctx, 0, 100); return e },
			func() error { _, e := test.s.MessagesRecent(a.ctx, 100); return e },
			func() error { _, _, e := test.s.FindCommitted(a.ctx, community.Zero256()); return e },
			func() error { return test.s.Audit(a.ctx) },
			func() error { return test.s.ReplicaReady(a.ctx) },
			func() error { return test.s.UpgradeRoomState(a.ctx, a.room) },
		}
		for i, check := range checks {
			if err := check(); !errors.Is(err, test.want) {
				t.Fatalf("selection check %d: %v", i, err)
			}
		}
	}
	event := roomCommit(t, a, a.user, community.EventMessage{Text: "A only"}, nil)
	id, _ := event.Proposal.ID()
	if _, ok, err := b.store.FindCommitted(a.ctx, id); err != nil || ok {
		t.Fatalf("cross-room duplicate lookup: %v %v", ok, err)
	}
	if _, err := b.store.Commit(a.ctx, event.Proposal, b.room, a.now); rejectionCode(err) != community.RejectWrongRoom {
		t.Fatalf("cross-room proposal: %v", err)
	}
	if _, err := b.store.AppendReplica(a.ctx, event); err == nil {
		t.Fatal("cross-room replica append accepted")
	}
	state, err := a.store.State(a.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.store.InstallReplicaState(a.ctx, state); !errors.Is(err, community.ErrWrongRoom) {
		t.Fatalf("cross-room state: %v", err)
	}
	if err := b.store.Initialize(a.ctx, a.genesis, a.room); !errors.Is(err, community.ErrWrongRoom) {
		t.Fatalf("cross-room initialization: %v", err)
	}
	if err := b.store.UpgradeRoomState(a.ctx, a.room); !errors.Is(err, community.ErrWrongRoom) {
		t.Fatalf("cross-room upgrade: %v", err)
	}
	if err := b.store.ValidateGenesis(a.ctx, a.genesis); !errors.Is(err, ErrGenesisMismatch) {
		t.Fatalf("wrong genesis: %v", err)
	}
	pin := b.proposal(t, b.room, community.EventPin{MessageID: 1}, randomNonce(t), b.now)
	if _, err := b.store.Commit(b.ctx, pin, b.room, b.now); rejectionCode(err) != community.RejectUnknownMessage {
		t.Fatalf("pin used sibling's message: %v", err)
	}
	if _, err := root.db.Exec("INSERT INTO pins VALUES (?,1,1,?)", b.genesis.RoomKey, b.genesis.RoomKey); err == nil {
		t.Fatal("foreign key allowed a cross-room pin")
	}
	head, err := b.store.Head(a.ctx)
	if err != nil || head.Seqno != 0 {
		t.Fatalf("wrong-room requests changed sibling: %+v %v", head, err)
	}
}

func TestSharedRoomAuthorizationBansAndLimits(t *testing.T) {
	root, a, b := sharedRooms(t)
	subject := a.user.Public().(ed25519.PublicKey)
	roomCommit(t, a, a.room, community.EventAdminGrant{SubjectKey: subject}, nil)
	roomCommit(t, a, a.user, community.EventMetadata{Name: "Allowed"}, nil)
	for _, body := range []any{community.EventMetadata{Name: "Denied"}, community.EventBanV1{SubjectKey: a.admin.Public().(ed25519.PublicKey)}} {
		p := b.proposal(t, b.user, body, randomNonce(t), b.now)
		if _, err := b.store.Commit(b.ctx, p, b.room, b.now); rejectionCode(err) != community.RejectPermissionDenied {
			t.Fatalf("role leaked: %v", err)
		}
	}
	roomCommit(t, b, b.room, community.EventAdminGrant{SubjectKey: subject}, nil)
	roomCommit(t, a, a.room, community.EventBanV1{SubjectKey: subject}, nil)
	p := a.proposal(t, a.user, community.EventMessage{Text: "banned"}, randomNonce(t), a.now)
	if _, err := a.store.Commit(a.ctx, p, a.room, a.now); rejectionCode(err) != community.RejectPermissionDenied {
		t.Fatalf("ban ignored: %v", err)
	}
	roomCommit(t, b, b.user, community.EventMetadata{Name: "Still admin"}, nil)
	// Fill only A's bans; B must still be able to add its own first ban.
	for i := 1; i < community.MaxBanned; i++ {
		key := make([]byte, 32)
		binary.BigEndian.PutUint64(key, uint64(i))
		roomCommit(t, a, a.room, community.EventBanV1{SubjectKey: key}, nil)
	}
	p = a.proposal(t, a.room, community.EventBanV1{SubjectKey: a.admin.Public().(ed25519.PublicKey)}, randomNonce(t), a.now)
	if _, err := a.store.Commit(a.ctx, p, a.room, a.now); rejectionCode(err) != community.RejectLimitExceeded {
		t.Fatalf("ban cap: %v", err)
	}
	roomCommit(t, b, b.room, community.EventBanV1{SubjectKey: b.admin.Public().(ed25519.PublicKey)}, nil)
	for _, f := range []*fixture{a, b} {
		if err := f.store.Audit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	// One room's broken projection must not taint the sibling's audit.
	if _, err := root.db.Exec("UPDATE room_state SET name='corrupt' WHERE room_id=?", a.genesis.RoomKey); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Audit(a.ctx); err == nil {
		t.Fatal("audit missed selected-room corruption")
	}
	if err := b.store.Audit(b.ctx); err != nil {
		t.Fatal("audit included another room", err)
	}
}

func TestLegacyLayoutsMigrateWithoutChangingPayloadsAndRollback(t *testing.T) {
	for _, mode := range []string{"v2_state_schema2", "v2_state_schema3", "v3_bans_schema3"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			roomCommit(t, f, f.user, community.EventMessage{Text: "retained"}, nil)
			roomCommit(t, f, f.room, community.EventAdminGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)}, nil)
			roomCommit(t, f, f.room, community.EventModeratorGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)}, nil)
			roomCommit(t, f, f.room, community.EventPin{MessageID: 1}, nil)
			version := 3
			if mode == "v3_bans_schema3" {
				roomCommit(t, f, f.room, community.EventBanV1{SubjectKey: f.user.Public().(ed25519.PublicKey)}, nil)
			} else {
				legacySnapshot(t, f)
				if mode == "v2_state_schema2" {
					version = 2
				}
			}
			before := preservedRoomRows(t, f.store)
			var raw []byte
			if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&raw); err != nil {
				t.Fatal(err)
			}
			legacyLayout(t, f.store.db, version)
			// This fails after the copies and table drops, proving their DDL
			// and data changes roll back with the migration-version write.
			if _, err := f.store.db.Exec(`CREATE TRIGGER interrupt_layout BEFORE INSERT ON schema_migrations
WHEN NEW.version=4 BEGIN SELECT RAISE(ABORT,'interrupted layout'); END`); err != nil {
				t.Fatal(err)
			}
			oldSchema := schemaRows(t, f.store.db)
			oldData := preservedRoomRows(t, f.store)
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			if db, err := OpenReadOnly(f.ctx, f.storePath); !errors.Is(err, ErrMigrationRequired) {
				if db != nil {
					db.Close()
				}
				t.Fatalf("read-only legacy open: %v", err)
			}
			if db, err := Open(f.ctx, f.storePath); err == nil {
				db.Close()
				t.Fatal("interrupted migration succeeded")
			}
			db, err := sql.Open("sqlite", f.storePath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if !reflect.DeepEqual(oldSchema, schemaRows(t, db)) || !reflect.DeepEqual(oldData, preservedRoomRows(t, &Store{db: db})) {
				t.Fatal("failed migration changed legacy schema/data")
			}
			if _, err := db.Exec("DROP TRIGGER interrupt_layout"); err != nil {
				t.Fatal(err)
			}
			f.store, err = Open(f.ctx, f.storePath)
			if err != nil {
				t.Fatal(err)
			}
			var got []byte
			if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&got); err != nil || !bytes.Equal(raw, got) || !reflect.DeepEqual(before, preservedRoomRows(t, f.store)) {
				t.Fatalf("layout migration changed payloads/projections: %v", err)
			}
			if mode == "v3_bans_schema3" {
				if err := f.store.Audit(f.ctx); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := f.store.db.QueryRow("SELECT COUNT(*) FROM bans").Scan(&count); err != nil || count != 1 {
					t.Fatalf("bans lost: %d %v", count, err)
				}
			} else if err := f.store.UpgradeRoomState(f.ctx, f.room); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Audit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			f.store, err = Open(f.ctx, f.storePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.Audit(f.ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func schemaRows(t *testing.T, db *sql.DB) [][3]string {
	t.Helper()
	rows, err := db.Query("SELECT type,name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result [][3]string
	for rows.Next() {
		var row [3]string
		if err := rows.Scan(&row[0], &row[1], &row[2]); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRoomScopedUpgradeAndReplicaState(t *testing.T) {
	_, a, b := sharedRooms(t)
	roomCommit(t, a, a.user, community.EventMessage{Text: "one"}, nil)
	roomCommit(t, a, a.room, community.EventMetadata{Name: "Changed"}, nil)
	roomCommit(t, b, b.room, community.EventBanV1{SubjectKey: b.user.Public().(ed25519.PublicKey)}, nil)
	wantA, _ := legacySnapshot(t, a)
	wantB, err := b.store.State(b.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.UpgradeRoomState(a.ctx, a.room); err != nil {
		t.Fatal(err)
	}
	if got, err := a.store.State(a.ctx); err != nil || !reflect.DeepEqual(got, wantA) {
		t.Fatalf("selected conversion: %v", err)
	}
	if got, err := b.store.State(b.ctx); err != nil || !reflect.DeepEqual(got, wantB) {
		t.Fatalf("conversion changed sibling bans: %v", err)
	}
	replicas, err := Open(a.ctx, filepath.Join(t.TempDir(), "replicas.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer replicas.Close()
	for _, f := range []*fixture{a, b} {
		r, err := replicas.ForRoom(f.genesis.RoomKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.InitializeReplica(f.ctx, f.genesis); err != nil {
			t.Fatal(err)
		}
		page, err := f.store.Events(f.ctx, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			if _, err := r.AppendReplica(f.ctx, event); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.ReplicaReady(f.ctx); err == nil {
			t.Fatal("replica ready without signed state")
		}
		state, err := f.store.State(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.InstallReplicaState(f.ctx, state); err != nil {
			t.Fatal(err)
		}
		if err := r.ReplicaReady(f.ctx); err != nil {
			t.Fatal(err)
		}
		if err := r.Audit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSharedRoomCommitRollbackAndConcurrentCounters(t *testing.T) {
	root, a, b := sharedRooms(t)
	if _, err := root.db.Exec(`CREATE TRIGGER fail_room_nonce BEFORE INSERT ON request_nonces
WHEN NEW.room_id=x'` + hex.EncodeToString(a.genesis.RoomKey) + `' BEGIN SELECT RAISE(ABORT,'failed nonce'); END`); err != nil {
		t.Fatal(err)
	}
	nonce := randomNonce(t)
	proposal := a.proposal(t, a.user, community.EventMessage{Text: "atomic"}, nonce, a.now)
	if _, err := a.store.Commit(a.ctx, proposal, a.room, a.now); rejectionCode(err) != community.RejectPersistenceFailure {
		t.Fatalf("failed transaction: %v", err)
	}
	head, err := a.store.Head(a.ctx)
	if err != nil || head.Seqno != 0 {
		t.Fatalf("failed commit advanced head: %+v %v", head, err)
	}
	events, err := a.store.Events(a.ctx, 0, 100)
	if err != nil || len(events.Events) != 0 {
		t.Fatalf("failed commit stored event: %v", err)
	}
	messages, err := a.store.MessagesRecent(a.ctx, 100)
	if err != nil || len(messages.Messages) != 0 {
		t.Fatalf("failed commit stored message: %v", err)
	}
	roomCommit(t, b, b.user, community.EventMessage{Text: "independent"}, nonce)
	if _, err := root.db.Exec("DROP TRIGGER fail_room_nonce"); err != nil {
		t.Fatal(err)
	}
	result, err := a.store.Commit(a.ctx, proposal, a.room, a.now)
	if err != nil || result.Event.Seqno != 1 {
		t.Fatalf("retry failed: %+v %v", result, err)
	}
	const count = 12
	results := make(chan error, 2)
	for _, f := range []*fixture{a, b} {
		proposals := make([]community.EventProposal, count)
		for i := range proposals {
			proposals[i] = f.proposal(t, f.user, community.EventMessage{Text: "concurrent"}, randomNonce(t), f.now)
		}
		go func(f *fixture, proposals []community.EventProposal) {
			for _, p := range proposals {
				if _, err := f.store.Commit(f.ctx, p, f.room, f.now); err != nil {
					results <- err
					return
				}
			}
			results <- nil
		}(f, proposals)
	}
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []*fixture{a, b} {
		head, err := f.store.Head(f.ctx)
		if err != nil || head.Seqno != count+1 {
			t.Fatalf("concurrent room head: %+v %v", head, err)
		}
		if err := f.store.Audit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
}
