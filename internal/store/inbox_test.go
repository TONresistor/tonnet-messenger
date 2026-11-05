package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

type inboxFixture struct {
	ctx                      context.Context
	store                    *Store
	path                     string
	now                      time.Time
	sender, recipient, relay ed25519.PrivateKey
	limits                   InboxLimits
}

func newInboxFixture(t *testing.T) *inboxFixture {
	t.Helper()
	f := &inboxFixture{ctx: context.Background(), path: filepath.Join(t.TempDir(), "node.db"), now: time.Now().Truncate(time.Second), sender: privateKey(t), recipient: privateKey(t), relay: privateKey(t)}
	var err error
	f.store, err = Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	f.limits = InboxLimits{Offer: &community.RelayOfferV1{Services: community.RelayServiceDM, MaxObjectBytes: 64 << 10, RetentionSeconds: 600, RequestsPerMinute: 100, InboxQuotaBytes: 1 << 20, PriceNanoton: -1, UnitBytes: -1}, MaxMessages: 100, MaxBytes: 1 << 20}
	return f
}

func (f *inboxFixture) message(t *testing.T, nonce byte, created time.Time, retention int64) community.InboxDepositV1 {
	t.Helper()
	m, err := community.SignDirectMessageV3(f.sender, community.DirectMessageV3{ToKey: f.recipient.Public().(ed25519.PublicKey), AuthorName: "Sender", CreatedAt: created.Unix(), ExpireAt: created.Unix() + retention, Ciphertext: bytes.Repeat([]byte{nonce}, 28)})
	if err != nil {
		t.Fatal(err)
	}
	return community.InboxDepositV1{Message: m}
}

func (f *inboxFixture) deposit(t *testing.T, q community.InboxDepositV1, now time.Time) InboxDepositResult {
	t.Helper()
	result, err := f.store.DepositInbox(f.ctx, q, f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, now)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func inboxReject(t *testing.T, result InboxDepositResult, err error, code int32) {
	t.Helper()
	var rejected *Rejection
	if !errors.As(err, &rejected) || rejected.Code != code {
		t.Fatalf("want rejection %d, got %v", code, err)
	}
	if len(result.Receipt.Signature) != 0 || result.Seqno != 0 || result.Duplicate {
		t.Fatal("rejected admission returned a receipt")
	}
}

func TestInboxAdmissionOrderAndTimeBoundaries(t *testing.T) {
	for _, mode := range []string{"malformed", "signature", "peer", "tier", "no offer", "size before time", "boxed size", "exact size", "past 300", "past 301", "future 300", "future 301", "retention", "expired", "empty retention"} {
		t.Run(mode, func(t *testing.T) {
			f := newInboxFixture(t)
			q := f.message(t, 1, f.now, 600)
			peer := f.sender.Public().(ed25519.PublicKey)
			code := int32(0)
			switch mode {
			case "malformed":
				q.Message.Ciphertext = []byte{1}
				q.Tier = 8
				code = 1
			case "signature":
				q.Message.Signature[0] ^= 1
				q.Tier = 8
				code = 5
			case "peer":
				peer = f.recipient.Public().(ed25519.PublicKey)
				q.Tier = 8
				code = 5
			case "tier":
				q.Tier = 8
				f.limits.Offer = nil
				code = 17
			case "no offer":
				f.limits.Offer = nil
				code = 17
			case "size before time":
				q = f.message(t, 1, f.now.Add(-301*time.Second), 600)
				f.limits.Offer.MaxObjectBytes = 1
				code = 9
			case "exact size":
				raw, _ := community.Encode(q)
				f.limits.Offer.MaxObjectBytes = int32(len(raw))
			case "boxed size":
				raw, _ := community.Encode(q.Message)
				f.limits.Offer.MaxObjectBytes = int32(len(raw))
				code = 9
			case "past 300":
				q = f.message(t, 1, f.now.Add(-300*time.Second), 600)
			case "past 301":
				q = f.message(t, 1, f.now.Add(-301*time.Second), 600)
				code = 3
			case "future 300":
				q = f.message(t, 1, f.now.Add(300*time.Second), 600)
			case "future 301":
				q = f.message(t, 1, f.now.Add(301*time.Second), 600)
				code = 3
			case "retention":
				q = f.message(t, 1, f.now, 601)
				code = 9
			case "expired":
				q = f.message(t, 1, f.now.Add(-10*time.Second), 10)
				code = 9
			case "empty retention":
				q = f.message(t, 1, f.now, 0)
				code = 9
			}
			result, err := f.store.DepositInbox(f.ctx, q, peer, f.relay, f.limits, f.now)
			if code != 0 {
				inboxReject(t, result, err, code)
				return
			}
			id, _ := community.HashBoxed(q.Message)
			inbox, _ := community.KeyID(q.Message.ToKey)
			if err != nil || result.Receipt.Verify() != nil || !bytes.Equal(id, result.Receipt.DMID) || !bytes.Equal(inbox, result.Receipt.InboxID) || result.Receipt.ExpireAt != q.Message.ExpireAt || result.Seqno != 1 {
				t.Fatalf("invalid free-tier receipt: %+v %v", result, err)
			}
		})
	}
}

func TestInboxDuplicateBeforeChangedOfferAndAuthentication(t *testing.T) {
	f := newInboxFixture(t)
	q := f.message(t, 1, f.now, 600)
	f.limits.Offer.RequestsPerMinute = 1
	first := f.deposit(t, q, f.now)
	ids := make([][]byte, community.MaxInboxAckIDs)
	for i := range ids {
		ids[i] = first.Receipt.DMID
	}
	if n, err := f.store.AckInbox(f.ctx, first.Receipt.InboxID, ids); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	q.Tier = 99
	duplicate, err := f.store.DepositInbox(f.ctx, q, f.sender.Public().(ed25519.PublicKey), nil, InboxLimits{}, f.now.Add(300*time.Second))
	want, _ := community.Encode(first.Receipt)
	got, _ := community.Encode(duplicate.Receipt)
	if err != nil || !duplicate.Duplicate || duplicate.Seqno != first.Seqno || !bytes.Equal(want, got) {
		t.Fatal("changed offer/tier rechecked a retained duplicate", err)
	}
	wrong, err := f.store.DepositInbox(f.ctx, q, f.recipient.Public().(ed25519.PublicKey), f.relay, f.limits, f.now)
	inboxReject(t, wrong, err, 5)
	q.Tier = 0
	q.Message.Signature[0] ^= 1
	wrong, err = f.store.DepositInbox(f.ctx, q, f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, f.now)
	inboxReject(t, wrong, err, 5)
	page, err := f.store.PageInbox(f.ctx, first.Receipt.InboxID, 0, 0, f.now)
	if err != nil || len(page.Page.Messages) != 0 {
		t.Fatal("duplicate stored an acked message again", err)
	}
}

func TestInboxFiniteQuotaCapacityAndSenderRate(t *testing.T) {
	for _, mode := range []string{"quota", "count", "bytes", "sender rate"} {
		t.Run(mode, func(t *testing.T) {
			f := newInboxFixture(t)
			q := f.message(t, 1, f.now, 600)
			raw, _ := community.Encode(q.Message)
			switch mode {
			case "quota":
				f.limits.Offer.InboxQuotaBytes = int64(len(raw))
			case "count":
				f.limits.MaxMessages = 1
			case "bytes":
				f.limits.MaxBytes = int64(len(raw))
			case "sender rate":
				f.limits.Offer.RequestsPerMinute = 1
			}
			first := f.deposit(t, q, f.now)
			second := f.message(t, 2, f.now, 600)
			result, err := f.store.DepositInbox(f.ctx, second, f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, f.now)
			inboxReject(t, result, err, 16)
			if _, err := f.store.AckInbox(f.ctx, first.Receipt.InboxID, [][]byte{first.Receipt.DMID}); err != nil {
				t.Fatal(err)
			}
			if mode == "sender rate" {
				if err := f.store.Close(); err != nil {
					t.Fatal(err)
				}
				f.store, err = Open(f.ctx, f.path)
				if err != nil {
					t.Fatal(err)
				}
				result, err = f.store.DepositInbox(f.ctx, second, f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, f.now.Add(59*time.Second))
				inboxReject(t, result, err, 16)
				other := f.message(t, 3, f.now, 600)
				other.Message.ToKey = privateKey(t).Public().(ed25519.PublicKey)
				other.Message, _ = community.SignDirectMessageV3(f.sender, other.Message)
				result, err = f.store.DepositInbox(f.ctx, other, f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, f.now.Add(59*time.Second))
				inboxReject(t, result, err, 16)
			}
			at := f.now
			if mode == "sender rate" {
				at = at.Add(time.Minute)
			}
			accepted := f.deposit(t, second, at)
			if accepted.Seqno != 2 {
				t.Fatal("deletion reused sequence")
			}
		})
	}
	f := newInboxFixture(t)
	f.limits.MaxMessages = 0
	if result, err := f.store.DepositInbox(f.ctx, f.message(t, 1, f.now, 600), f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, f.now); err == nil || len(result.Receipt.Signature) != 0 {
		t.Fatal("missing finite bounds became unlimited")
	}
}

func TestExpiredInboxMessagesDoNotUseLiveQuotaOrCapacity(t *testing.T) {
	f := newInboxFixture(t)
	first := f.message(t, 1, f.now, 10)
	raw, _ := community.Encode(first.Message)
	f.limits.MaxMessages = 1
	f.limits.MaxBytes = int64(len(raw))
	f.limits.Offer.InboxQuotaBytes = int64(len(raw))
	f.deposit(t, first, f.now)
	now := f.now.Add(10 * time.Second)
	if next := f.deposit(t, f.message(t, 2, now, 600), now); next.Seqno != 2 {
		t.Fatal("expired message still occupied live capacity")
	}
	if count, err := f.store.ExpireInboxes(f.ctx, now); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestInboxConcurrentAdmissionAndRollback(t *testing.T) {
	f := newInboxFixture(t)
	q := f.message(t, 1, f.now, 600)
	raw, _ := community.Encode(q.Message)
	f.limits.Offer.InboxQuotaBytes = int64(len(raw))
	view, err := f.store.ForRoom(f.recipient.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result InboxDepositResult
		err    error
	}
	results := make(chan outcome, 2)
	for i, s := range []*Store{f.store, view} {
		request := f.message(t, byte(i+1), f.now, 600)
		go func() {
			result, err := s.DepositInbox(f.ctx, request, f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, f.now)
			results <- outcome{result, err}
		}()
	}
	a, b := <-results, <-results
	if a.err != nil {
		a, b = b, a
	}
	if a.err != nil || a.result.Seqno != 1 {
		t.Fatal("no concurrent admission succeeded", a.err)
	}
	inboxReject(t, b.result, b.err, 16)
	if _, _, err := f.store.Genesis(f.ctx); !errors.Is(err, ErrNotInitialized) {
		t.Fatal("inbox use required or initialized a room", err)
	}
	rollback := newInboxFixture(t)
	if _, err := rollback.store.db.Exec(`CREATE TRIGGER fail_admission BEFORE INSERT ON inbox_rate BEGIN SELECT RAISE(ABORT,'rollback admission'); END`); err != nil {
		t.Fatal(err)
	}
	request := rollback.message(t, 1, rollback.now, 600)
	result, err := rollback.store.DepositInbox(rollback.ctx, request, rollback.sender.Public().(ed25519.PublicKey), rollback.relay, rollback.limits, rollback.now)
	inboxReject(t, result, err, community.RejectPersistenceFailure)
	for _, table := range []string{"inbox_messages", "inbox_receipts", "inbox_rate", "inbox_counters"} {
		var count int
		if err := rollback.store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("admission did not roll back", table, count, err)
		}
	}
	if _, err := rollback.store.db.Exec("DROP TRIGGER fail_admission"); err != nil {
		t.Fatal(err)
	}
	if result := rollback.deposit(t, request, rollback.now); result.Seqno != 1 || result.Duplicate {
		t.Fatal("failed admission consumed sequence or receipt")
	}
}

func TestInboxPaginationAckIsolationExpiryAndReopen(t *testing.T) {
	f := newInboxFixture(t)
	var accepted []InboxDepositResult
	for i := 0; i < 4; i++ {
		accepted = append(accepted, f.deposit(t, f.message(t, byte(i), f.now, 600), f.now))
	}
	q := f.message(t, 5, f.now, 600)
	q.Message.ToKey = f.sender.Public().(ed25519.PublicKey)
	q.Message, _ = community.SignDirectMessageV3(f.sender, q.Message)
	other := f.deposit(t, q, f.now)
	inbox := accepted[0].Receipt.InboxID
	if n, err := f.store.AckInbox(f.ctx, inbox, [][]byte{accepted[1].Receipt.DMID, other.Receipt.DMID}); err != nil || n != 1 {
		t.Fatal("ack escaped selected inbox", n, err)
	}
	page, err := f.store.PageInbox(f.ctx, inbox, 0, 2, f.now)
	if err != nil || !page.Page.HasMore || page.Page.LastSeqno != 3 || !reflect.DeepEqual(page.Seqnos, []int64{1, 3}) {
		t.Fatalf("page after holes: %+v %v", page, err)
	}
	page, err = f.store.PageInbox(f.ctx, inbox, 3, 0, f.now)
	if err != nil || page.Page.HasMore || page.Page.LastSeqno != 4 || len(page.Page.Messages) != 1 {
		t.Fatal("default page", page, err)
	}
	raw, _ := community.Encode(page.Page)
	if len(raw) > roomnet.MaxAnswerPayloadSize {
		t.Fatal("page exceeds wire answer bound")
	}
	empty, err := f.store.PageInbox(f.ctx, inbox, 99, 256, f.now)
	if err != nil || empty.Page.LastSeqno != 99 || empty.Page.HasMore {
		t.Fatal("empty cursor moved backwards", err)
	}
	foreign, err := f.store.PageInbox(f.ctx, other.Receipt.InboxID, 0, 100, f.now)
	if err != nil || len(foreign.Page.Messages) != 1 || foreign.Seqnos[0] != 1 {
		t.Fatal("cross-inbox ack deleted another envelope", err)
	}
	for _, limit := range []int{-1, 257} {
		if _, err := f.store.PageInbox(f.ctx, inbox, 0, limit, f.now); err == nil {
			t.Fatal("invalid page limit accepted")
		}
	}
	if _, err := f.store.AckInbox(f.ctx, inbox, make([][]byte, 257)); err == nil {
		t.Fatal("oversized ack accepted")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	if next := f.deposit(t, f.message(t, 9, f.now, 600), f.now); next.Seqno != 5 {
		t.Fatal("reopen reused sequence")
	}
	if n, err := f.store.ExpireInboxes(f.ctx, f.now.Add(600*time.Second)); err != nil || n != 5 {
		t.Fatal("expiry did not remove live messages", n, err)
	}
	if next := f.deposit(t, f.message(t, 10, f.now.Add(600*time.Second), 600), f.now.Add(600*time.Second)); next.Seqno != 6 {
		t.Fatal("expiry pruning reused sequence")
	}
}

func TestInboxReceiptWindowBoundaryAndRateSurviveDeletion(t *testing.T) {
	f := newInboxFixture(t)
	q := f.message(t, 1, f.now, 10)
	first := f.deposit(t, q, f.now)
	if n, err := f.store.ExpireInboxes(f.ctx, f.now.Add(10*time.Second)); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := f.store.ExpireInboxes(f.ctx, f.now.Add(300*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.store, err = Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := f.deposit(t, q, f.now.Add(300*time.Second))
	want, _ := community.Encode(first.Receipt)
	got, _ := community.Encode(duplicate.Receipt)
	if !duplicate.Duplicate || !bytes.Equal(want, got) {
		t.Fatal("receipt disappeared at inclusive skew boundary")
	}
	if page, err := f.store.PageInbox(f.ctx, first.Receipt.InboxID, 0, 100, f.now.Add(300*time.Second)); err != nil || len(page.Page.Messages) != 0 {
		t.Fatal("expired duplicate restored envelope", err)
	}
	if _, err := f.store.ExpireInboxes(f.ctx, f.now.Add(301*time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err := f.store.DepositInbox(f.ctx, q, f.sender.Public().(ed25519.PublicKey), f.relay, f.limits, f.now.Add(301*time.Second))
	inboxReject(t, result, err, 3)
}

func TestInboxV4MigrationPreservesRoomsAndRollsBack(t *testing.T) {
	f := newFixture(t)
	roomCommit(t, f, f.user, community.EventMessage{Text: "preserved"}, nil)
	legacySnapshot(t, f)
	before := preservedRoomRows(t, f.store)
	for _, table := range []string{"inbox_messages", "inbox_rate", "inbox_receipts", "inbox_counters"} {
		if _, err := f.store.db.Exec("DROP TABLE " + table); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.db.Exec("DELETE FROM schema_migrations WHERE version=5"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`CREATE TRIGGER fail_inbox_schema BEFORE INSERT ON schema_migrations WHEN NEW.version=5 BEGIN SELECT RAISE(ABORT,'rollback inbox schema'); END`); err != nil {
		t.Fatal(err)
	}
	oldSchema := schemaRows(t, f.store.db)
	f.store.Close()
	if root, err := OpenReadOnly(f.ctx, f.storePath); !errors.Is(err, ErrMigrationRequired) {
		if root != nil {
			root.Close()
		}
		t.Fatal("read-only migrated v4", err)
	}
	if root, err := Open(f.ctx, f.storePath); err == nil {
		root.Close()
		t.Fatal("failed schema migration accepted")
	}
	db, err := sql.Open("sqlite", f.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldSchema, schemaRows(t, db)) {
		t.Fatal("failed inbox migration changed schema")
	}
	if _, err := db.Exec("DROP TRIGGER fail_inbox_schema"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	f.store, err = Open(f.ctx, f.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, preservedRoomRows(t, f.store)) {
		t.Fatal("inbox migration changed room bytes or projections")
	}
	if _, err := f.store.State(f.ctx); err == nil {
		t.Fatal("storage migration re-signed legacy authority")
	}
}
