package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

func clientInboxStore(t *testing.T) (*clientStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.db")
	s, err := openClientStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func clientInboxEnvelope(t *testing.T, sender, recipient ed25519.PrivateKey, plaintext string, created, expire int64) community.DirectMessageV3 {
	t.Helper()
	box, err := dm.SealV3(sender, recipient.Public().(ed25519.PublicKey), []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	m, err := community.SignDirectMessageV3(sender, community.DirectMessageV3{ToKey: recipient.Public().(ed25519.PublicKey), AuthorName: "Sender", AuthorDomain: "alice.ton", CreatedAt: created, ExpireAt: expire, Ciphertext: box})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInboxReceiveChecksDropAckAndKeepSignedClaims(t *testing.T) {
	ctx, now := context.Background(), time.Now().Truncate(time.Second)
	s, _ := clientInboxStore(t)
	sender, recipient, relay := clientTestPrivateKey(t), clientTestPrivateKey(t), clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	for _, mode := range []string{"valid historical", "valid future", "1400 bytes", "signature", "recipient", "cipher", "UTF8 plaintext", "long plaintext", "name", "domain", "name UTF8", "expired grace", "at grace", "within grace", "max expiry", "unencodable"} {
		t.Run(mode, func(t *testing.T) {
			text := "received"
			if mode == "1400 bytes" {
				text = strings.Repeat("x", 1400)
			}
			m := clientInboxEnvelope(t, sender, recipient, text, now.Unix()-86400, now.Unix()+600)
			want := inboxDropped
			resign := false
			switch mode {
			case "valid historical", "1400 bytes":
				want = inboxAccepted
			case "valid future":
				m.CreatedAt = now.Unix() + 400
				resign = true
				want = inboxAccepted
			case "signature":
				m.Signature[0] ^= 1
			case "recipient":
				m.ToKey = clientTestPrivateKey(t).Public().(ed25519.PublicKey)
				resign = true
			case "cipher":
				m.Ciphertext[12] ^= 1
				resign = true
			case "UTF8 plaintext", "long plaintext":
				plain := []byte{0xff, 0xfe}
				if mode == "long plaintext" {
					plain = bytes.Repeat([]byte{'x'}, 1401)
				}
				// Reuse the existing unchecked encryption primitive to construct
				// invalid plaintext in an otherwise authentic V3 AEAD envelope.
				tag := sha256.Sum256([]byte("tonnet-dm-v3"))
				var err error
				m.Ciphertext, err = dm.SealForRoom(tag[:], sender, recipient.Public().(ed25519.PublicKey), plain)
				if err != nil {
					t.Fatal(err)
				}
				resign = true
			case "name":
				m.AuthorName = strings.Repeat("x", 65)
				resign = true
			case "domain":
				m.AuthorDomain = "INVALID CLAIM"
				resign = true
			case "name UTF8":
				m.AuthorName = string([]byte{0xff})
				resign = true
			case "expired grace":
				m.ExpireAt = now.Unix() - 301
				resign = true
			case "at grace":
				m.ExpireAt = now.Unix() - 300
				resign = true
			case "within grace":
				m.ExpireAt = now.Unix() - 299
				resign = true
				want = inboxAccepted
			case "max expiry":
				m.ExpireAt = math.MaxInt64
				resign = true
				want = inboxAccepted
			case "unencodable":
				m.FromKey = []byte{1}
			}
			if resign {
				var err error
				m, err = community.SignDirectMessageV3(sender, m)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := s.receiveInboxPush(ctx, recipient, relay, community.InboxPushV1{Seqno: 1, Message: m}, now)
			if mode == "unencodable" {
				if !errors.Is(err, roomnet.ErrMalformedAnswer) || len(result.decisions) != 0 {
					t.Fatal("invented an ack ID for unencodable data", err)
				}
				return
			}
			id, _ := community.HashBoxed(m)
			if err != nil || len(result.decisions) != 1 || !bytes.Equal(result.decisions[0].id, id) || result.decisions[0].disposition != want {
				t.Fatal("receive classification/ack", result, err)
			}
			stored, err := s.receivedInboxDM(ctx, recipient, id)
			if err != nil {
				t.Fatal(err)
			}
			if want == inboxDropped {
				if stored != nil || result.decisions[0].message != nil {
					t.Fatal("invalid envelope stored or exposed")
				}
			} else if stored == nil || stored.text != text || stored.createdAt != m.CreatedAt || stored.claimedDomain != "alice.ton" || !bytes.Equal(stored.fromKey, m.FromKey) {
				t.Fatal("accepted content/timestamp/signed claim lost")
			}
		})
	}
	for _, tc := range []struct {
		expire, now int64
		expired     bool
	}{
		{math.MaxInt64, math.MaxInt64, false},
		{math.MaxInt64 - 299, math.MaxInt64, false},
		{math.MaxInt64 - 300, math.MaxInt64, true},
		{math.MaxInt64 - 300, math.MaxInt64 - 1, false},
		{math.MinInt64, math.MinInt64 + 299, false},
		{math.MinInt64, math.MinInt64 + 300, true},
	} {
		if expiredInboxDM(tc.expire, tc.now) != tc.expired {
			t.Fatal("overflow in expiry grace boundary", tc)
		}
	}
}

func TestInboxPageContinuesAfterInvalidAndPersistsMonotonicCursors(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	s, path := clientInboxStore(t)
	sender, recipient := clientTestPrivateKey(t), clientTestPrivateKey(t)
	a, b := clientTestPrivateKey(t).Public().(ed25519.PublicKey), clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	valid := clientInboxEnvelope(t, sender, recipient, "valid after bad entry", 1, now.Unix()+600)
	bad := valid
	bad.Signature = bytes.Clone(valid.Signature)
	bad.Signature[0] ^= 1
	page := community.InboxPageV1{Messages: []community.DirectMessageV3{bad, valid}, LastSeqno: 42, HasMore: true}
	result, err := s.receiveInboxPage(ctx, recipient, a, 0, page, now)
	if err != nil || len(result.decisions) != 2 || result.decisions[0].disposition != inboxDropped || result.decisions[1].disposition != inboxAccepted {
		t.Fatal("bad envelope aborted later valid entry", err)
	}
	goodID, _ := community.HashBoxed(valid)
	badID, _ := community.HashBoxed(bad)
	if bytes.Equal(goodID, badID) || !bytes.Equal(result.decisions[0].id, badID) {
		t.Fatal("dm_id omitted signature")
	}
	if !bytes.Equal(result.relayKey, a) {
		t.Fatal("ack decision lost returning relay")
	}
	if _, err := s.receiveInboxPage(ctx, recipient, a, 10, community.InboxPageV1{LastSeqno: 10}, now); err != nil {
		t.Fatal(err)
	}
	if cursor, err := s.inboxCursor(ctx, recipient.Public().(ed25519.PublicKey), a); err != nil || cursor != 42 {
		t.Fatal("cursor moved backwards across deleted/gapped page", cursor, err)
	}
	duplicate, err := s.receiveInboxPush(ctx, recipient, b, community.InboxPushV1{Seqno: 90, Message: valid}, now)
	if err != nil || duplicate.decisions[0].disposition != inboxDuplicate || duplicate.decisions[0].message != nil || !bytes.Equal(duplicate.relayKey, b) {
		t.Fatal("cross-relay duplicate/ack", err)
	}
	if cursor, err := s.inboxCursor(ctx, recipient.Public().(ed25519.PublicKey), b); err != nil || cursor != 0 {
		t.Fatal("push advanced fetch cursor", cursor, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openClientStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if cursor, err := reopened.inboxCursor(ctx, recipient.Public().(ed25519.PublicKey), a); err != nil || cursor != 42 {
		t.Fatal("cursor not durable", cursor, err)
	}
	acks, err := reopened.pendingInboxAcks(ctx, recipient.Public().(ed25519.PublicKey), a)
	if err != nil || len(acks) != 2 {
		t.Fatal("page cursor committed without durable accepted/dropped ack IDs", err)
	}
	seen := map[string]bool{}
	for _, id := range acks {
		seen[string(id)] = true
	}
	if !seen[string(goodID)] || !seen[string(badID)] {
		t.Fatal("dropped ack ID lost after reopen")
	}
	if err := reopened.completeInboxAcks(ctx, recipient.Public().(ed25519.PublicKey), a, [][]byte{{1}}); err == nil {
		t.Fatal("malformed ack completion accepted")
	}
	if err := reopened.completeInboxAcks(ctx, recipient.Public().(ed25519.PublicKey), a, acks); err != nil {
		t.Fatal(err)
	}
	if acks, err := reopened.pendingInboxAcks(ctx, recipient.Public().(ed25519.PublicKey), a); err != nil || len(acks) != 0 {
		t.Fatal("confirmed ack intents retained", err)
	}
	if acks, err := reopened.pendingInboxAcks(ctx, recipient.Public().(ed25519.PublicKey), b); err != nil || len(acks) != 1 {
		t.Fatal("ack completion affected another returning relay", err)
	}
	stored, err := reopened.receivedInboxDM(ctx, recipient, goodID)
	if err != nil || stored == nil || stored.text != "valid after bad entry" {
		t.Fatal("accepted source not recoverable", err)
	}
	// History remains readable after the receive-time grace expires, while a
	// newly returned expired copy is dropped/acked and cannot notify again.
	old, err := reopened.receiveInboxPush(ctx, recipient, b, community.InboxPushV1{Seqno: 91, Message: valid}, time.Unix(valid.ExpireAt+300, 0))
	if err != nil || old.decisions[0].disposition != inboxDropped {
		t.Fatal("late copy redisplayed", err)
	}
	for _, badPage := range []community.InboxPageV1{{LastSeqno: 9}, {LastSeqno: 11}, {LastSeqno: 10, HasMore: true}} {
		failed, err := reopened.receiveInboxPage(ctx, recipient, a, 10, badPage, now)
		if !errors.Is(err, roomnet.ErrMalformedAnswer) || len(failed.decisions) != 0 {
			t.Fatal("malformed page accepted", err)
		}
	}
}

func TestInboxReceiveConcurrentCopiesAcceptOnlyOnce(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	s, _ := clientInboxStore(t)
	sender, recipient := clientTestPrivateKey(t), clientTestPrivateKey(t)
	a, b := clientTestPrivateKey(t).Public().(ed25519.PublicKey), clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	m := clientInboxEnvelope(t, sender, recipient, "one durable acceptance", 1, now.Unix()+600)
	type response struct {
		result inboxReceiveResult
		err    error
	}
	results := make(chan response, 2)
	start := make(chan struct{})
	go func() {
		<-start
		r, e := s.receiveInboxPage(ctx, recipient, a, 0, community.InboxPageV1{Messages: []community.DirectMessageV3{m}, LastSeqno: 7}, now)
		results <- response{r, e}
	}()
	go func() {
		<-start
		r, e := s.receiveInboxPush(ctx, recipient, b, community.InboxPushV1{Seqno: 8, Message: m}, now)
		results <- response{r, e}
	}()
	close(start)
	accepted, duplicates := 0, 0
	for i := 0; i < 2; i++ {
		response := <-results
		if response.err != nil {
			t.Fatal(response.err)
		}
		decision := response.result.decisions[0]
		switch decision.disposition {
		case inboxAccepted:
			accepted++
			if decision.message == nil {
				t.Fatal("new acceptance lost content")
			}
		case inboxDuplicate:
			duplicates++
			if decision.message != nil {
				t.Fatal("duplicate can notify twice")
			}
		}
	}
	if accepted != 1 || duplicates != 1 {
		t.Fatal("concurrent duplicate suppression failed", accepted, duplicates)
	}
	for _, relay := range []ed25519.PublicKey{a, b} {
		if ids, err := s.pendingInboxAcks(ctx, recipient.Public().(ed25519.PublicKey), relay); err != nil || len(ids) != 1 {
			t.Fatal("concurrent copy lost its returning-relay ack", err)
		}
	}
}

func TestInboxReceiveRollbackReturnsNoAckOrAcceptance(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	s, _ := clientInboxStore(t)
	sender, recipient := clientTestPrivateKey(t), clientTestPrivateKey(t)
	relay := clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	m := clientInboxEnvelope(t, sender, recipient, "must roll back with cursor", 1, now.Unix()+600)
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER refuse_inbox_cursor BEFORE INSERT ON inbox_cursors
BEGIN SELECT RAISE(ABORT,'cursor failure'); END;`); err != nil {
		t.Fatal(err)
	}
	page := community.InboxPageV1{Messages: []community.DirectMessageV3{m}, LastSeqno: 10}
	result, err := s.receiveInboxPage(ctx, recipient, relay, 0, page, now)
	if err == nil || len(result.decisions) != 0 || len(result.relayKey) != 0 {
		t.Fatal("storage failure exposed successful ack/notification", result, err)
	}
	id, _ := community.HashBoxed(m)
	if stored, err := s.receivedInboxDM(ctx, recipient, id); err != nil || stored != nil {
		t.Fatal("message survived failed page transaction", err)
	}
	if cursor, err := s.inboxCursor(ctx, recipient.Public().(ed25519.PublicKey), relay); err != nil || cursor != 0 {
		t.Fatal("failed page advanced cursor", cursor, err)
	}
	if acks, err := s.pendingInboxAcks(ctx, recipient.Public().(ed25519.PublicKey), relay); err != nil || len(acks) != 0 {
		t.Fatal("failed page leaked durable ack intent", err)
	}
	if _, err := s.db.ExecContext(ctx, "DROP TRIGGER refuse_inbox_cursor"); err != nil {
		t.Fatal(err)
	}
	result, err = s.receiveInboxPage(ctx, recipient, relay, 0, page, now)
	if err != nil || result.decisions[0].disposition != inboxAccepted {
		t.Fatal("failed transaction poisoned retry", err)
	}
	unencodable := m
	unencodable.ToKey = []byte{1}
	result, err = s.receiveInboxPage(ctx, recipient, relay, 10, community.InboxPageV1{Messages: []community.DirectMessageV3{m, unencodable}, LastSeqno: 20}, now)
	if !errors.Is(err, roomnet.ErrMalformedAnswer) || len(result.decisions) != 0 {
		t.Fatal("unencodable page supplied invented/partial ack decisions", err)
	}
	if cursor, err := s.inboxCursor(ctx, recipient.Public().(ed25519.PublicKey), relay); err != nil || cursor != 10 {
		t.Fatal("protocol failure advanced cursor", cursor, err)
	}
}

func TestInboxCacheScopesIdentityAndSurvivesRoomLeave(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	s, _ := clientInboxStore(t)
	sender, oldIdentity, newIdentity := clientTestPrivateKey(t), clientTestPrivateKey(t), clientTestPrivateKey(t)
	relay := clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	m := clientInboxEnvelope(t, sender, oldIdentity, "old principal", 1, now.Unix()+600)
	if _, err := s.receiveInboxPage(ctx, oldIdentity, relay, 0, community.InboxPageV1{Messages: []community.DirectMessageV3{m}, LastSeqno: 50}, now); err != nil {
		t.Fatal(err)
	}
	if cursor, err := s.inboxCursor(ctx, newIdentity.Public().(ed25519.PublicKey), relay); err != nil || cursor != 0 {
		t.Fatal("new identity inherited cursor", cursor, err)
	}
	if acks, err := s.pendingInboxAcks(ctx, newIdentity.Public().(ed25519.PublicKey), relay); err != nil || len(acks) != 0 {
		t.Fatal("new identity inherited ack state", err)
	}
	id, _ := community.HashBoxed(m)
	if stored, err := s.receivedInboxDM(ctx, newIdentity, id); err != nil || stored != nil {
		t.Fatal("new identity inherited accepted data", err)
	}
	wrong, err := s.receiveInboxPush(ctx, newIdentity, relay, community.InboxPushV1{Seqno: 1, Message: m}, now)
	if err != nil || wrong.decisions[0].disposition != inboxDropped {
		t.Fatal("old principal data inherited delivery suppression", err)
	}
	next := clientInboxEnvelope(t, sender, newIdentity, "new principal", 1, now.Unix()+600)
	accepted, err := s.receiveInboxPage(ctx, newIdentity, relay, 0, community.InboxPageV1{Messages: []community.DirectMessageV3{next}, LastSeqno: 2}, now)
	if err != nil || accepted.decisions[0].disposition != inboxAccepted {
		t.Fatal("new identity could not accept independently", err)
	}
	room := clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	if err := s.addRoom(ctx, room, keyText(room), nil); err != nil {
		t.Fatal(err)
	}
	c := &Client{store: s, rooms: make(map[string]*roomHandle)}
	if err := c.Leave(ctx, keyText(room)); err != nil {
		t.Fatal(err)
	}
	if stored, err := s.receivedInboxDM(ctx, oldIdentity, id); err != nil || stored == nil {
		t.Fatal("room.leave cascaded independent DM cache", err)
	}
	if cursor, err := s.inboxCursor(ctx, oldIdentity.Public().(ed25519.PublicKey), relay); err != nil || cursor != 50 {
		t.Fatal("room.leave/reset changed old principal cursor", cursor, err)
	}
}

func TestInboxSchemaUpgradePreservesRoomsHistoryAndPendingAtomically(t *testing.T) {
	ctx := context.Background()
	s, path := clientInboxStore(t)
	room, node := clientTestPrivateKey(t), clientTestPrivateKey(t)
	genesis, err := community.NewGenesis(room, node, time.Now(), "Preserved", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.addRoom(ctx, genesis.RoomKey, "saved reference", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.pinGenesis(ctx, genesis.RoomKey, genesis); err != nil {
		t.Fatal(err)
	}
	proposal, err := community.SignProposal(room, genesis.NodeKey, community.EventProposal{RoomID: genesis.RoomKey, Nonce: make([]byte, 32), Timestamp: time.Now().Unix(), Body: community.EventMessage{Text: "history"}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := community.SignCommit(room, proposal, 1, community.Zero256(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.appendEvent(ctx, genesis.RoomKey, event); err != nil {
		t.Fatal(err)
	}
	pending := proposal
	pending.Nonce = bytes.Repeat([]byte{1}, 32)
	pending, err = community.SignProposal(room, genesis.NodeKey, pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.savePending(ctx, genesis, pending); err != nil {
		t.Fatal(err)
	}
	if err := s.setMeta(ctx, "author_name", "kept name"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TABLE received_inbox_dms; DROP TABLE inbox_cursors; DROP TABLE pending_inbox_acks;
UPDATE client_meta SET value='2' WHERE key='schema_version';
CREATE TRIGGER refuse_schema_upgrade BEFORE UPDATE ON client_meta WHEN NEW.key='schema_version'
BEGIN SELECT RAISE(ABORT,'migration failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if failed, err := openClientStore(ctx, path); err == nil {
		failed.Close()
		t.Fatal("failed migration accepted")
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	var tables int
	if err := raw.QueryRowContext(ctx, "SELECT value FROM client_meta WHERE key='schema_version'").Scan(&version); err != nil || version != "2" {
		t.Fatal("migration version did not roll back", version, err)
	}
	if err := raw.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('received_inbox_dms','inbox_cursors','pending_inbox_acks')").Scan(&tables); err != nil || tables != 0 {
		t.Fatal("partial inbox schema escaped rollback", tables, err)
	}
	if _, err := raw.ExecContext(ctx, "DROP TRIGGER refuse_schema_upgrade"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	restored, err := openClientStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if found, err := restored.hasEvent(ctx, genesis.RoomKey, event); err != nil || !found {
		t.Fatal("migration changed history", err)
	}
	operation, err := restored.pendingOperation(ctx, genesis.RoomKey)
	want, _ := pending.ID()
	if err != nil || operation == nil || !bytes.Equal(operation.ID, want) {
		t.Fatal("migration changed pending operation", err)
	}
	record, err := restored.room(ctx, genesis.RoomKey)
	if err != nil || !bytes.Equal(record.Genesis.Signature, genesis.Signature) || record.Reference != "saved reference" {
		t.Fatal("migration changed pinned room data", err)
	}
	if name, _, err := restored.profile(ctx); err != nil || name != "kept name" {
		t.Fatal("migration changed local name", err)
	}
	if err := restored.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM received_inbox_dms").Scan(&tables); err != nil || tables != 0 {
		t.Fatal("legacy room history was imported as V3 DMs", err)
	}
}
