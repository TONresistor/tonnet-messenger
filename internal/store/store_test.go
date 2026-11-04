package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

type fixture struct {
	ctx       context.Context
	now       time.Time
	room      ed25519.PrivateKey
	node      ed25519.PrivateKey
	user      ed25519.PrivateKey
	admin     ed25519.PrivateKey
	genesis   community.Genesis
	store     *Store
	storePath string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{ctx: context.Background(), now: time.Now().UTC().Truncate(time.Second)}
	f.room = privateKey(t)
	f.node = privateKey(t)
	f.user = privateKey(t)
	f.admin = privateKey(t)
	var err error
	f.genesis, err = community.NewGenesis(f.room, f.node, f.now, "Room", "Description", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.storePath = filepath.Join(t.TempDir(), "room.db")
	f.store, err = Open(f.ctx, f.storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	if err := f.store.Initialize(f.ctx, f.genesis, f.room); err != nil {
		t.Fatal(err)
	}
	return f
}

func privateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func randomNonce(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func (f *fixture) proposal(t *testing.T, author ed25519.PrivateKey, body any, nonce []byte, at time.Time) community.EventProposal {
	t.Helper()
	proposal, err := community.SignProposal(author, f.genesis.NodeKey, community.EventProposal{
		RoomID: f.genesis.RoomKey, Nonce: nonce, Timestamp: at.Unix(), Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func TestCommitIsDurableOrderedAndIdempotent(t *testing.T) {
	f := newFixture(t)
	nonce := randomNonce(t)
	proposal := f.proposal(t, f.user, community.EventMessage{
		Text: "one",
	}, nonce, f.now)
	first, err := f.store.Commit(f.ctx, proposal, f.room, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate || first.Event.Seqno != 1 || first.Event.MessageID != 1 {
		t.Fatalf("first commit = %+v", first)
	}
	duplicate, err := f.store.Commit(f.ctx, proposal, f.room, f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate || duplicate.Event.Seqno != first.Event.Seqno {
		t.Fatalf("duplicate commit = %+v", duplicate)
	}

	reused := f.proposal(t, f.user, community.EventMessage{
		Text: "different",
	}, nonce, f.now)
	if _, err := f.store.Commit(f.ctx, reused, f.room, f.now); rejectionCode(err) != community.RejectReusedNonce {
		t.Fatalf("reused nonce error = %v", err)
	}
	head, err := f.store.Head(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seqno != 1 {
		t.Fatalf("head after rejection = %d", head.Seqno)
	}

	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(f.ctx, f.storePath)
	if err != nil {
		t.Fatal(err)
	}
	f.store = reopened
	if err := reopened.ValidateGenesis(f.ctx, f.genesis); err != nil {
		t.Fatal(err)
	}
	head, err = reopened.Head(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seqno != 1 || len(head.Hash) != 32 {
		t.Fatalf("reopened head = %+v", head)
	}
	page, err := reopened.MessagesRecent(f.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Messages) != 1 || page.Messages[0].Proposal.Body.(community.EventMessage).Text != "one" {
		t.Fatalf("reopened messages = %+v", page)
	}
}

func TestCommitAcceptsNonceAfterRetentionExpires(t *testing.T) {
	f := newFixture(t)
	nonce := randomNonce(t)
	first := f.proposal(t, f.user, community.EventMessage{Text: "one"}, nonce, f.now)
	if _, err := f.store.Commit(f.ctx, first, f.room, f.now); err != nil {
		t.Fatal(err)
	}

	after := f.now.Add(community.NonceRetention)
	second := f.proposal(t, f.user, community.EventMessage{Text: "two"}, nonce, after)
	result, err := f.store.Commit(f.ctx, second, f.room, after)
	if err != nil {
		t.Fatal(err)
	}
	if result.Event.Seqno != 2 {
		t.Fatalf("seqno = %d", result.Event.Seqno)
	}
}

func TestRolesPolicyPinsAndPagination(t *testing.T) {
	f := newFixture(t)
	commit := func(author ed25519.PrivateKey, body any) community.CommittedEvent {
		t.Helper()
		proposal := f.proposal(t, author, body, randomNonce(t), f.now)
		result, err := f.store.Commit(f.ctx, proposal, f.room, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return result.Event
	}

	commit(f.room, community.EventAdminGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)})
	commit(f.admin, community.EventWritePolicy{AnyoneCanWrite: false})
	denied := f.proposal(t, f.user, community.EventMessage{
		Text: "denied",
	}, randomNonce(t), f.now)
	if _, err := f.store.Commit(f.ctx, denied, f.room, f.now); rejectionCode(err) != community.RejectPermissionDenied {
		t.Fatalf("write-policy rejection = %v", err)
	}

	for _, text := range []string{"one", "two", "three"} {
		commit(f.admin, community.EventMessage{Text: text})
	}
	commit(f.admin, community.EventPin{MessageID: 3})
	commit(f.admin, community.EventMetadata{Name: "Renamed", Description: "Updated"})
	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Verify(); err != nil {
		t.Fatal(err)
	}
	if state.Name != "Renamed" || state.WritePolicy.AnyoneCanWrite || !bytes.Equal(state.Admins[0], f.admin.Public().(ed25519.PublicKey)) {
		t.Fatalf("state = %+v", state)
	}
	if len(state.PinnedMessages) != 1 || state.PinnedMessages[0] != 3 {
		t.Fatalf("pins = %v", state.PinnedMessages)
	}

	recent, err := f.store.MessagesRecent(f.ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !recent.HasMore || len(recent.Messages) != 2 || recent.Messages[0].MessageID >= recent.Messages[1].MessageID {
		t.Fatalf("recent page = %+v", recent)
	}
	before, err := f.store.MessagesBefore(f.ctx, recent.Messages[0].MessageID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Messages) != 1 || before.Messages[0].MessageID >= recent.Messages[0].MessageID {
		t.Fatalf("before page = %+v", before)
	}
	events, err := f.store.Events(f.ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !events.HasMore || len(events.Events) != 2 || events.Events[0].Seqno != 3 {
		t.Fatalf("events page = %+v", events)
	}
	if err := f.store.IntegrityCheck(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAdminRevokePreservesModeratorRole(t *testing.T) {
	f := newFixture(t)
	subject := f.admin.Public().(ed25519.PublicKey)
	commit := func(body any) {
		t.Helper()
		proposal := f.proposal(t, f.room, body, randomNonce(t), f.now)
		if _, err := f.store.Commit(f.ctx, proposal, f.room, f.now); err != nil {
			t.Fatal(err)
		}
	}

	commit(community.EventModeratorGrant{SubjectKey: subject})
	commit(community.EventAdminGrant{SubjectKey: subject})
	commit(community.EventAdminRevoke{SubjectKey: subject})

	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Admins) != 0 || len(state.Moderators) != 1 || !bytes.Equal(state.Moderators[0], subject) {
		t.Fatalf("roles after admin revoke: admins=%x moderators=%x", state.Admins, state.Moderators)
	}
}

func rejectionCode(err error) int32 {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Code
	}
	return 0
}

func TestBanAuthorizationAndCanonicalReplay(t *testing.T) {
	for _, test := range []struct {
		name, actor, target string
		unban, preban       bool
		code                int32
	}{
		{"owner bans member", "owner", "member", false, false, 0},
		{"admin bans member", "admin", "member", false, false, 0},
		{"admin bans moderator", "admin", "moderator", false, false, 0},
		{"owner bans admin", "owner", "admin", false, false, 0},
		{"admin bans other admin", "admin", "other-admin", false, false, 6},
		{"admin bans itself", "admin", "admin", false, false, 6},
		{"moderator cannot ban", "moderator", "member", false, false, 6},
		{"member cannot ban", "member", "moderator", false, false, 6},
		{"owner cannot ban itself", "owner", "owner", false, false, 8},
		{"admin cannot ban owner", "admin", "owner", false, false, 8},
		{"already banned", "owner", "member", false, true, 8},
		{"owner unbans", "owner", "member", true, true, 0},
		{"admin unbans", "admin", "member", true, true, 0},
		{"moderator cannot unban", "moderator", "member", true, true, 6},
		{"member cannot unban", "member", "moderator", true, true, 6},
		{"banned member cannot unban itself", "member", "member", true, true, 6},
		{"unban absent", "owner", "member", true, false, 8},
		{"admin unban absent", "admin", "member", true, false, 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			keys := map[string]ed25519.PrivateKey{"owner": f.room, "admin": f.admin, "member": f.user,
				"moderator": privateKey(t), "other-admin": privateKey(t)}
			projection, err := community.NewProjection(f.genesis)
			if err != nil {
				t.Fatal(err)
			}
			commit := func(body any) {
				t.Helper()
				p := f.proposal(t, f.room, body, randomNonce(t), f.now)
				result, err := f.store.Commit(f.ctx, p, f.room, f.now)
				if err != nil {
					t.Fatal(err)
				}
				if err := projection.Apply(result.Event); err != nil {
					t.Fatal(err)
				}
			}
			for _, role := range []string{"admin", "other-admin"} {
				commit(community.EventAdminGrant{SubjectKey: keys[role].Public().(ed25519.PublicKey)})
			}
			commit(community.EventModeratorGrant{SubjectKey: keys["moderator"].Public().(ed25519.PublicKey)})
			subject := keys[test.target].Public().(ed25519.PublicKey)
			if test.preban {
				commit(community.EventBanV1{SubjectKey: subject})
			}
			var body any = community.EventBanV1{SubjectKey: subject}
			if test.unban {
				body = community.EventUnbanV1{SubjectKey: subject}
			}
			proposal := f.proposal(t, keys[test.actor], body, randomNonce(t), f.now)
			before, err := f.store.Head(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			result, err := f.store.Commit(f.ctx, proposal, f.room, f.now)
			if got := rejectionCode(err); got != test.code || (test.code == 0 && err != nil) {
				t.Fatalf("code=%d want=%d err=%v", got, test.code, err)
			}
			if test.code == 0 {
				if err := projection.Apply(result.Event); err != nil {
					t.Fatal(err)
				}
				state, err := f.store.State(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := projection.ValidateState(state); err != nil {
					t.Fatal(err)
				}
				if err := f.store.Audit(f.ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				forged, err := community.SignCommit(f.room, proposal, before.Seqno+1, before.Hash, f.now)
				if err != nil {
					t.Fatal(err)
				}
				want := community.ErrProjectionConflict
				if test.code == 6 {
					want = community.ErrProjectionUnauthorized
				}
				if err := projection.Apply(forged); !errors.Is(err, want) {
					t.Fatalf("canonical replay accepted invalid transition: %v", err)
				}
				after, err := f.store.Head(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if before.Seqno != after.Seqno || !bytes.Equal(before.Hash, after.Hash) {
					t.Fatal("rejection advanced the chain")
				}
			}
		})
	}
}

func TestBanRemovesRolesPersistsAndBlocksEveryProposal(t *testing.T) {
	f := newFixture(t)
	subject := f.user.Public().(ed25519.PublicKey)
	commit := func(author ed25519.PrivateKey, body any) CommitResult {
		t.Helper()
		result, err := f.store.Commit(f.ctx, f.proposal(t, author, body, randomNonce(t), f.now), f.room, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	original := f.proposal(t, f.user, community.EventMessage{Text: "before ban"}, randomNonce(t), f.now)
	if _, err := f.store.Commit(f.ctx, original, f.room, f.now); err != nil {
		t.Fatal(err)
	}
	commit(f.room, community.EventAdminGrant{SubjectKey: subject})
	commit(f.room, community.EventModeratorGrant{SubjectKey: subject})
	ban := commit(f.room, community.EventBanV1{SubjectKey: subject})
	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Banned) != 1 || !bytes.Equal(state.Banned[0], subject) || len(state.Admins) != 0 || len(state.Moderators) != 0 || state.RevisionSeqno != ban.Event.Seqno {
		t.Fatalf("state after ban=%+v", state)
	}
	for _, body := range []any{
		community.EventMessage{Text: "denied"}, community.EventMetadata{Name: "Denied"}, community.EventWritePolicy{AnyoneCanWrite: false},
		community.EventPin{MessageID: 1}, community.EventUnpin{MessageID: 1},
		community.EventAdminGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)}, community.EventAdminRevoke{SubjectKey: subject},
		community.EventModeratorGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)}, community.EventModeratorRevoke{SubjectKey: subject},
		community.EventBanV1{SubjectKey: f.admin.Public().(ed25519.PublicKey)}, community.EventUnbanV1{SubjectKey: subject},
	} {
		p := f.proposal(t, f.user, body, randomNonce(t), f.now)
		if _, err := f.store.Commit(f.ctx, p, f.room, f.now); rejectionCode(err) != 6 {
			t.Fatalf("%T from banned author: %v", body, err)
		}
	}
	duplicate, err := f.store.Commit(f.ctx, original, f.room, f.now.Add(time.Hour))
	if err != nil || !duplicate.Duplicate || duplicate.Event.Seqno != 1 {
		t.Fatalf("duplicate after ban=%+v err=%v", duplicate, err)
	}
	reused := f.proposal(t, f.user, community.EventMessage{Text: "nonce reused"}, original.Nonce, f.now)
	if _, err := f.store.Commit(f.ctx, reused, f.room, f.now); rejectionCode(err) != 4 {
		t.Fatalf("nonce precedence changed: %v", err)
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
	reopened, err := f.store.State(f.ctx)
	if err != nil || !reflect.DeepEqual(state, reopened) {
		t.Fatalf("reopened state=%+v err=%v", reopened, err)
	}
	commit(f.room, community.EventUnbanV1{SubjectKey: subject})
	state, err = f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Banned) != 0 || len(state.Admins) != 0 || len(state.Moderators) != 0 {
		t.Fatal("unban restored removed roles")
	}
	commit(f.user, community.EventMessage{Text: "after unban"})
}

func TestBanLimitAndSortedProjection(t *testing.T) {
	f := newFixture(t)
	projection, err := community.NewProjection(f.genesis)
	if err != nil {
		t.Fatal(err)
	}
	for i := 256; i > 0; i-- {
		subject := community.Zero256()
		binary.BigEndian.PutUint64(subject[24:], uint64(i))
		proposal := f.proposal(t, f.room, community.EventBanV1{SubjectKey: subject}, randomNonce(t), f.now)
		result, err := f.store.Commit(f.ctx, proposal, f.room, f.now)
		if err != nil {
			t.Fatalf("ban %d: %v", i, err)
		}
		if err := projection.Apply(result.Event); err != nil {
			t.Fatal(err)
		}
	}
	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Banned) != 256 {
		t.Fatalf("banned count=%d", len(state.Banned))
	}
	for i, key := range state.Banned {
		if binary.BigEndian.Uint64(key[24:]) != uint64(i+1) {
			t.Fatal("bans are not sorted by raw key bytes")
		}
	}
	if err := projection.ValidateState(state); err != nil {
		t.Fatal(err)
	}
	subject := community.Zero256()
	binary.BigEndian.PutUint64(subject[24:], 257)
	proposal := f.proposal(t, f.room, community.EventBanV1{SubjectKey: subject}, randomNonce(t), f.now)
	if _, err := f.store.Commit(f.ctx, proposal, f.room, f.now); rejectionCode(err) != 9 {
		t.Fatalf("257th ban: %v", err)
	}
	head, err := f.store.Head(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := community.SignCommit(f.room, proposal, head.Seqno+1, head.Hash, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Apply(forged); !errors.Is(err, community.ErrProjectionLimit) {
		t.Fatalf("projection overflow: %v", err)
	}
	duplicate := f.proposal(t, f.room, community.EventBanV1{SubjectKey: state.Banned[0]}, randomNonce(t), f.now)
	if _, err := f.store.Commit(f.ctx, duplicate, f.room, f.now); rejectionCode(err) != 8 {
		t.Fatalf("duplicate at cap: %v", err)
	}
	if err := f.store.Audit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.ExecContext(f.ctx, "DELETE FROM bans WHERE subject_key=?", state.Banned[0]); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Audit(f.ctx); err == nil {
		t.Fatal("audit accepted a corrupt ban projection")
	}
}

func TestCommitTimeClampKeepsHistoricalTolerance(t *testing.T) {
	f := newFixture(t)
	first, err := f.store.Commit(f.ctx, f.proposal(t, f.user, community.EventMessage{Text: "first"}, randomNonce(t), f.now), f.room, f.now)
	if err != nil {
		t.Fatal(err)
	}
	earlier := f.now.Add(-time.Minute)
	proposal := f.proposal(t, f.user, community.EventMessage{Text: "clock moved back"}, randomNonce(t), earlier)
	second, err := f.store.Commit(f.ctx, proposal, f.room, earlier)
	if err != nil {
		t.Fatal(err)
	}
	if second.Event.CommittedAt != first.Event.CommittedAt {
		t.Fatalf("commit time decreased: %d -> %d", first.Event.CommittedAt, second.Event.CommittedAt)
	}
	replica, err := Open(f.ctx, filepath.Join(t.TempDir(), "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	if err := replica.InitializeReplica(f.ctx, f.genesis); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.AppendReplica(f.ctx, first.Event); err != nil {
		t.Fatal(err)
	}
	hash, err := first.Event.Hash()
	if err != nil {
		t.Fatal(err)
	}
	historical, err := community.SignCommit(f.room, proposal, 2, hash, earlier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replica.AppendReplica(f.ctx, historical); err != nil {
		t.Fatalf("decreasing historical timestamp rejected: %v", err)
	}
	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.InstallReplicaState(f.ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := replica.Audit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func legacySnapshot(t *testing.T, f *fixture) (community.RoomStateV3, []byte) {
	t.Helper()
	state, err := f.store.State(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := community.SignRoomState(f.room, community.RoomState{
		RoomID: state.RoomID, RevisionSeqno: state.RevisionSeqno, RevisionHash: state.RevisionHash,
		Name: state.Name, Description: state.Description, WritePolicy: state.WritePolicy,
		Admins: state.Admins, Moderators: state.Moderators, PinnedMessages: state.PinnedMessages,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := community.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.ExecContext(f.ctx, "UPDATE room_state SET raw_signed_state=?", raw); err != nil {
		t.Fatal(err)
	}
	return state, raw
}

func preservedRoomRows(t *testing.T, s *Store) [][][]any {
	t.Helper()
	var result [][][]any
	for _, query := range []string{
		"SELECT * FROM room_genesis", "SELECT * FROM replica_head", "SELECT * FROM events ORDER BY seqno",
		"SELECT * FROM messages ORDER BY message_id", "SELECT * FROM pins ORDER BY message_id",
		"SELECT * FROM roles ORDER BY subject_key,role", "SELECT * FROM request_nonces ORDER BY author_key,nonce",
		"SELECT revision_seqno,revision_hash,name,description,anyone_can_write FROM room_state",
	} {
		rows, err := s.db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var table [][]any
		for rows.Next() {
			row := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range row {
				pointers[i] = &row[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			table = append(table, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		result = append(result, table)
	}
	return result
}

func TestUpgradeRoomStatePreservesHistoryAndRecovers(t *testing.T) {
	for _, schemaMigrated := range []bool{false, true} {
		t.Run(fmt.Sprint("schema_already_migrated=", schemaMigrated), func(t *testing.T) {
			f := newFixture(t)
			first := f.proposal(t, f.user, community.EventMessage{Text: "preserved"}, randomNonce(t), f.now)
			if _, err := f.store.Commit(f.ctx, first, f.room, f.now); err != nil {
				t.Fatal(err)
			}
			for _, body := range []any{
				community.EventAdminGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)},
				community.EventModeratorGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)},
				community.EventPin{MessageID: 1}, community.EventMetadata{Name: "Renamed", Description: "Keep"},
				community.EventMessage{Text: "head beyond state revision"},
			} {
				proposal := f.proposal(t, f.room, body, randomNonce(t), f.now)
				if _, err := f.store.Commit(f.ctx, proposal, f.room, f.now); err != nil {
					t.Fatal(err)
				}
			}
			want, rawLegacy := legacySnapshot(t, f)
			before := preservedRoomRows(t, f.store)
			if !schemaMigrated {
				if _, err := f.store.db.Exec("DROP TABLE bans; DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (2, 0)"); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			f.store, err = Open(f.ctx, f.storePath)
			if err != nil {
				t.Fatal(err)
			}
			var raw []byte
			if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&raw); err != nil || !bytes.Equal(raw, rawLegacy) {
				t.Fatalf("schema migration changed signed state: %v", err)
			}
			var version int
			if err := f.store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil || version != schemaVersion {
				t.Fatalf("schema version=%d err=%v", version, err)
			}
			// Simulate failure after replacement starts, then restart with schema
			// migration already complete. Neither attempt may alter history.
			if _, err := f.store.db.Exec(`CREATE TRIGGER interrupt_upgrade AFTER UPDATE OF raw_signed_state ON room_state
BEGIN SELECT RAISE(ABORT, 'interrupted upgrade'); END`); err != nil {
				t.Fatal(err)
			}
			if err := f.store.UpgradeRoomState(f.ctx, f.room); err == nil {
				t.Fatal("interrupted conversion succeeded")
			}
			if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&raw); err != nil || !bytes.Equal(raw, rawLegacy) {
				t.Fatalf("failed conversion changed signed state: %v", err)
			}
			if _, err := f.store.db.Exec("DROP TRIGGER interrupt_upgrade"); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			f.store, err = Open(f.ctx, f.storePath)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := f.store.UpgradeRoomState(f.ctx, f.room); err != nil {
					t.Fatal(err)
				}
				got, err := f.store.State(f.ctx)
				gotRaw, encodeErr := community.Encode(got)
				wantRaw, _ := community.Encode(want)
				if err != nil || encodeErr != nil || !bytes.Equal(gotRaw, wantRaw) || got.Verify() != nil || len(got.Banned) != 0 {
					t.Fatalf("converted state changed revision or fields: %v %v", err, encodeErr)
				}
				if !reflect.DeepEqual(before, preservedRoomRows(t, f.store)) {
					t.Fatal("conversion changed existing history or projections")
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
			}
			duplicate, err := f.store.Commit(f.ctx, first, f.room, f.now)
			if err != nil || !duplicate.Duplicate || duplicate.Event.Seqno != 1 {
				t.Fatalf("preserved request stopped deduplicating: %+v %v", duplicate, err)
			}
			reused := f.proposal(t, f.user, community.EventMessage{Text: "new"}, first.Nonce, f.now)
			if _, err := f.store.Commit(f.ctx, reused, f.room, f.now); rejectionCode(err) != community.RejectReusedNonce {
				t.Fatalf("preserved nonce stopped rejecting reuse: %v", err)
			}
		})
	}
}

func TestUpgradeRoomStateRejectsInvalidLegacyDataAtomically(t *testing.T) {
	for _, corruption := range []string{"signature", "trailing_bytes", "unknown_type", "wrong_room", "signed_state_content", "signed_state_revision", "genesis", "event_signature", "authorization", "chain", "head", "metadata", "roles", "pins", "messages", "bans", "revision_columns", "wrong_key"} {
		t.Run(corruption, func(t *testing.T) {
			f := newFixture(t)
			proposal := f.proposal(t, f.user, community.EventMessage{Text: "keep"}, randomNonce(t), f.now)
			if _, err := f.store.Commit(f.ctx, proposal, f.room, f.now); err != nil {
				t.Fatal(err)
			}
			_, raw := legacySnapshot(t, f)
			key := f.room
			query := ""
			var args []any
			switch corruption {
			case "signature", "trailing_bytes", "unknown_type", "wrong_room", "signed_state_content", "signed_state_revision":
				legacy, err := community.DecodeRoomState(raw)
				if err != nil {
					t.Fatal(err)
				}
				switch corruption {
				case "signature":
					legacy.Signature[0] ^= 1
				case "signed_state_content":
					legacy.Name = "Forged"
				case "signed_state_revision":
					legacy.RevisionSeqno = 1
				case "wrong_room":
					key = privateKey(t)
					legacy.RoomID = key.Public().(ed25519.PublicKey)
				}
				if corruption == "wrong_room" || corruption == "signed_state_content" || corruption == "signed_state_revision" {
					legacy, err = community.SignRoomState(key, legacy)
					if err != nil {
						t.Fatal(err)
					}
					key = f.room
				}
				raw, err = community.Encode(legacy)
				if err != nil {
					t.Fatal(err)
				}
				if corruption == "trailing_bytes" {
					raw = append(raw, 0)
				} else if corruption == "unknown_type" {
					raw = []byte{1, 2, 3, 4}
				}
				query, args = "UPDATE room_state SET raw_signed_state=?", []any{raw}
			case "genesis":
				query = "UPDATE room_genesis SET genesis_hash=zeroblob(32)"
			case "event_signature":
				query = "UPDATE events SET raw_commit=x'010203'"
			case "authorization":
				// A room signature cannot authorize an ordinary member's role grant.
				p := f.proposal(t, f.user, community.EventAdminGrant{SubjectKey: f.admin.Public().(ed25519.PublicKey)}, randomNonce(t), f.now)
				event, err := community.SignCommit(f.room, p, 1, community.Zero256(), f.now)
				if err != nil {
					t.Fatal(err)
				}
				rawEvent, err := community.Encode(event)
				if err != nil {
					t.Fatal(err)
				}
				query, args = "UPDATE events SET raw_commit=?", []any{rawEvent}
			case "chain":
				query = "UPDATE events SET commit_hash=zeroblob(32)"
			case "head":
				query = "UPDATE replica_head SET latest_seqno=2"
			case "metadata":
				query = "UPDATE room_state SET name='Forged'"
			case "roles":
				query, args = "INSERT INTO roles VALUES (?, 'admin', 0, ?)", []any{f.admin.Public().(ed25519.PublicKey), f.genesis.RoomKey}
			case "pins":
				query, args = "INSERT INTO pins VALUES (1, 1, ?)", []any{f.genesis.RoomKey}
			case "messages":
				query = "UPDATE messages SET raw_commit=x'010203'"
			case "bans":
				query, args = "INSERT INTO bans VALUES (?, 1, ?)", []any{f.admin.Public().(ed25519.PublicKey), f.genesis.RoomKey}
			case "revision_columns":
				query = "UPDATE room_state SET revision_seqno=1"
			case "wrong_key":
				key = f.user
			}
			if query != "" {
				if _, err := f.store.db.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			before := preservedRoomRows(t, f.store)
			var beforeRaw, afterRaw []byte
			if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&beforeRaw); err != nil {
				t.Fatal(err)
			}
			if err := f.store.UpgradeRoomState(f.ctx, key); err == nil {
				t.Fatal("invalid legacy store was re-signed")
			}
			if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&afterRaw); err != nil || !bytes.Equal(beforeRaw, afterRaw) || !reflect.DeepEqual(before, preservedRoomRows(t, f.store)) {
				t.Fatalf("failed conversion changed durable data: %v", err)
			}
		})
	}
}

func TestUpgradeLeavesExistingV3BansUnchanged(t *testing.T) {
	f := newFixture(t)
	proposal := f.proposal(t, f.room, community.EventBanV1{SubjectKey: f.user.Public().(ed25519.PublicKey)}, randomNonce(t), f.now)
	if _, err := f.store.Commit(f.ctx, proposal, f.room, f.now); err != nil {
		t.Fatal(err)
	}
	var before, after []byte
	if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := f.store.UpgradeRoomState(f.ctx, f.room); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.db.QueryRow("SELECT raw_signed_state FROM room_state").Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("V3 snapshot changed: %v", err)
	}
	if err := f.store.Audit(f.ctx); err != nil {
		t.Fatal(err)
	}
}
