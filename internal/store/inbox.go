package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

const inboxSchema = `
CREATE TABLE inbox_counters (
    inbox_id BLOB PRIMARY KEY NOT NULL CHECK(length(inbox_id)=32),
    last_seqno INTEGER NOT NULL CHECK(last_seqno>=0)
);
CREATE TABLE inbox_receipts (
    dm_id BLOB PRIMARY KEY NOT NULL CHECK(length(dm_id)=32),
    inbox_id BLOB NOT NULL REFERENCES inbox_counters(inbox_id),
    seqno INTEGER NOT NULL CHECK(seqno>0),
    created_at INTEGER NOT NULL,
    expire_at INTEGER NOT NULL,
    keep_until INTEGER NOT NULL,
    raw_receipt BLOB NOT NULL,
    UNIQUE(inbox_id,seqno)
);
CREATE TABLE inbox_messages (
    dm_id BLOB PRIMARY KEY NOT NULL REFERENCES inbox_receipts(dm_id),
    raw_envelope BLOB NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes>0)
);
CREATE TABLE inbox_rate (
    sender_key BLOB NOT NULL CHECK(length(sender_key)=32),
    dm_id BLOB NOT NULL CHECK(length(dm_id)=32),
    accepted_at INTEGER NOT NULL,
    PRIMARY KEY(sender_key,dm_id)
);
CREATE INDEX idx_inbox_expiry ON inbox_receipts(expire_at);
CREATE INDEX idx_inbox_retention ON inbox_receipts(keep_until);
CREATE INDEX idx_inbox_rate_time ON inbox_rate(accepted_at);
`

// InboxLimits is explicit admission policy. Nil Offer means tier 0 is not
// offered. Message/byte capacity and offer limits must be finite and positive.
type InboxLimits struct {
	Offer       *community.RelayOfferV1
	PaidOffers  []community.RelayOfferV1
	MaxMessages int64
	MaxBytes    int64
}

type InboxDepositResult struct {
	Receipt   community.InboxReceiptV1
	Seqno     int64
	Duplicate bool
}

// Seqnos aligns with Page.Messages for future pushes; the wire page has only
// envelopes and its last cursor, so gaps must not be reconstructed by counting.
type InboxPageResult struct {
	Page   community.InboxPageV1
	Seqnos []int64
}

type LiveInbox struct {
	InboxID  []byte
	ExpireAt int64
}

// LiveInboxes ignores retained receipts and subscriptions. The last live
// expiry lets routing stop at expiry even before the deletion sweep runs.
func (s *Store) LiveInboxes(ctx context.Context, now time.Time) ([]LiveInbox, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.inbox_id,MAX(r.expire_at)
FROM inbox_messages m JOIN inbox_receipts r ON r.dm_id=m.dm_id
WHERE r.expire_at>? GROUP BY r.inbox_id ORDER BY r.inbox_id`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []LiveInbox
	for rows.Next() {
		var entry LiveInbox
		if err := rows.Scan(&entry.InboxID, &entry.ExpireAt); err != nil {
			return nil, err
		}
		if len(entry.InboxID) != 32 {
			return nil, fmt.Errorf("store: invalid live inbox id")
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}

func validInboxEnvelope(m community.DirectMessageV3) bool {
	return len(m.FromKey) == 32 && len(m.ToKey) == 32 && len(m.Ciphertext) >= 28 && len(m.Ciphertext) <= community.MaxDMCiphertextBytes &&
		community.ValidateAuthorProfile(m.AuthorName, m.AuthorDomain) == nil
}

func (s *Store) DepositInbox(ctx context.Context, request community.InboxDepositV1, authenticated ed25519.PublicKey, relay ed25519.PrivateKey, limits InboxLimits, now time.Time) (InboxDepositResult, error) {
	rawRequest, err := community.Encode(request)
	if err != nil || !validInboxEnvelope(request.Message) {
		return InboxDepositResult{}, reject(community.RejectMalformedRequest, "malformed DM envelope", err)
	}
	m := request.Message
	if err := m.Verify(); err != nil || !bytes.Equal(m.FromKey, authenticated) {
		return InboxDepositResult{}, reject(community.RejectInvalidSignature, "invalid sender signature or peer", err)
	}
	id, err := community.HashBoxed(m)
	if err != nil {
		return InboxDepositResult{}, reject(community.RejectMalformedRequest, "invalid DM id", err)
	}
	inbox, err := community.KeyID(m.ToKey)
	if err != nil {
		return InboxDepositResult{}, reject(community.RejectMalformedRequest, "invalid recipient", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot begin inbox admission", err)
	}
	defer tx.Rollback()
	var receiptRaw []byte
	var seqno int64
	err = tx.QueryRowContext(ctx, "SELECT raw_receipt,seqno FROM inbox_receipts WHERE dm_id=?", id).Scan(&receiptRaw, &seqno)
	if err == nil {
		receipt, err := community.DecodeInboxReceiptV1(receiptRaw)
		if err != nil || receipt.Verify() != nil || !bytes.Equal(receipt.DMID, id) || !bytes.Equal(receipt.InboxID, inbox) || receipt.ExpireAt != m.ExpireAt {
			return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "invalid persisted receipt", err)
		}
		return InboxDepositResult{Receipt: receipt, Seqno: seqno, Duplicate: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot look up receipt", err)
	}
	selected := limits.Offer
	if request.Tier != 0 {
		selected = nil
		for i := range limits.PaidOffers {
			if limits.PaidOffers[i].Tier == request.Tier {
				selected = &limits.PaidOffers[i]
				break
			}
		}
	}
	if selected == nil || selected.Tier != request.Tier || selected.Services != community.RelayServiceDM {
		return InboxDepositResult{}, reject(community.RejectInsufficientPrepaidBalance, "tier is not offered", nil)
	}
	offer := *selected
	if offer.Validate(community.RelayServiceDM) != nil || offer.MaxObjectBytes <= 0 || offer.RetentionSeconds <= 0 || offer.RequestsPerMinute <= 0 || offer.InboxQuotaBytes <= 0 || limits.MaxMessages <= 0 || limits.MaxBytes <= 0 {
		return InboxDepositResult{}, fmt.Errorf("store: finite positive inbox limits are required")
	}
	if len(rawRequest) > int(offer.MaxObjectBytes) {
		return InboxDepositResult{}, reject(community.RejectLimitExceeded, "deposit exceeds object limit", nil)
	}
	seconds := now.Unix()
	if seconds <= 0 || seconds > math.MaxInt64-600 {
		return InboxDepositResult{}, fmt.Errorf("store: invalid inbox clock")
	}
	if m.CreatedAt <= 0 || m.CreatedAt < seconds-300 || m.CreatedAt > seconds+300 {
		return InboxDepositResult{}, reject(community.RejectTimestamp, "DM outside live window", nil)
	}
	if m.ExpireAt <= m.CreatedAt || m.ExpireAt <= seconds || m.ExpireAt-m.CreatedAt > int64(offer.RetentionSeconds) {
		return InboxDepositResult{}, reject(community.RejectLimitExceeded, "DM exceeds retention or is expired", nil)
	}
	envelope, err := community.Encode(m)
	if err != nil {
		return InboxDepositResult{}, reject(community.RejectMalformedRequest, "invalid envelope", err)
	}

	var count, used, quota, rate int64
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(m.size_bytes),0),
COALESCE(SUM(CASE WHEN r.inbox_id=? THEN m.size_bytes ELSE 0 END),0)
FROM inbox_messages m JOIN inbox_receipts r ON r.dm_id=m.dm_id WHERE r.expire_at>?`, inbox, seconds).Scan(&count, &used, &quota)
	if err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot check inbox capacity", err)
	}
	if count >= limits.MaxMessages || int64(len(envelope)) > limits.MaxBytes-used || int64(len(envelope)) > offer.InboxQuotaBytes-quota {
		return InboxDepositResult{}, reject(community.RejectRelayFullOrQuotaExceeded, "inbox or relay is full", nil)
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM inbox_rate WHERE sender_key=? AND accepted_at>?", m.FromKey, seconds-60).Scan(&rate); err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot check sender rate", err)
	}
	if rate >= int64(offer.RequestsPerMinute) {
		return InboxDepositResult{}, reject(community.RejectRelayFullOrQuotaExceeded, "sender rate exceeded", nil)
	}
	if len(relay) != ed25519.PrivateKeySize {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "invalid receipt authority", nil)
	}
	receipt, err := community.SignInboxReceiptV1(relay, community.InboxReceiptV1{RelayKey: relay.Public().(ed25519.PublicKey), DMID: id, InboxID: inbox, ExpireAt: m.ExpireAt})
	if err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot sign receipt", err)
	}
	receiptRaw, err = community.Encode(receipt)
	if err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot encode receipt", err)
	}
	if request.Tier != 0 {
		// The shared writer mutex is also an admission permit: across all room
		// views and physical connections only one paid deposit can be admitted
		// but not stored/rejected here. This is stricter than four per key, and
		// serializes the balance check with every credit and debit.
		cost := int64(len(rawRequest)) + int64(len(receiptRaw))
		var balance int64
		err := tx.QueryRowContext(ctx, "SELECT balance_bytes FROM prepaid_balances WHERE client_key=? AND tier=?", authenticated, request.Tier).Scan(&balance)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return InboxDepositResult{}, reject(community.RejectRelayFullOrQuotaExceeded, "balance unavailable", err)
		}
		if balance < cost {
			return InboxDepositResult{}, reject(community.RejectInsufficientPrepaidBalance, "insufficient prepaid bytes", nil)
		}
		if balance-cost < -4*(roomnet.MaxWireObjectSize+176) {
			return InboxDepositResult{}, reject(community.RejectRelayFullOrQuotaExceeded, "paid admission bound exceeded", nil)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE prepaid_balances SET balance_bytes=balance_bytes-? WHERE client_key=? AND tier=?", cost, authenticated, request.Tier); err != nil {
			return InboxDepositResult{}, reject(community.RejectRelayFullOrQuotaExceeded, "cannot debit prepaid bytes", err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO inbox_counters(inbox_id,last_seqno) VALUES (?,0) ON CONFLICT(inbox_id) DO NOTHING", inbox); err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot initialize inbox sequence", err)
	}
	if err := tx.QueryRowContext(ctx, "UPDATE inbox_counters SET last_seqno=last_seqno+1 WHERE inbox_id=? AND last_seqno<? RETURNING last_seqno", inbox, int64(math.MaxInt64)).Scan(&seqno); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return InboxDepositResult{}, reject(community.RejectRelayFullOrQuotaExceeded, "inbox sequence exhausted", nil)
		}
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot allocate inbox sequence", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO inbox_receipts(dm_id,inbox_id,seqno,created_at,expire_at,keep_until,raw_receipt) VALUES (?,?,?,?,?,?,?)", id, inbox, seqno, m.CreatedAt, m.ExpireAt, m.CreatedAt+300, receiptRaw); err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot persist receipt", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO inbox_messages(dm_id,raw_envelope,size_bytes) VALUES (?,?,?)", id, envelope, len(envelope)); err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot persist envelope", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM inbox_rate WHERE accepted_at<=?", seconds-60); err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot prune sender rate", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO inbox_rate(sender_key,dm_id,accepted_at) VALUES (?,?,?)", m.FromKey, id, seconds); err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot persist sender rate", err)
	}
	if err := tx.Commit(); err != nil {
		return InboxDepositResult{}, reject(community.RejectPersistenceFailure, "cannot commit inbox admission", err)
	}
	return InboxDepositResult{Receipt: receipt, Seqno: seqno}, nil
}

func (s *Store) PageInbox(ctx context.Context, inbox []byte, after int64, limit int, now time.Time) (InboxPageResult, error) {
	limit, err := normalizeLimit(limit)
	if err != nil || len(inbox) != 32 || after < 0 {
		return InboxPageResult{}, reject(community.RejectMalformedRequest, "invalid inbox page", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return InboxPageResult{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT r.seqno,r.dm_id,m.raw_envelope FROM inbox_receipts r JOIN inbox_messages m ON m.dm_id=r.dm_id
WHERE r.inbox_id=? AND r.seqno>? AND r.expire_at>? ORDER BY r.seqno LIMIT ?`, inbox, after, now.Unix(), limit+1)
	if err != nil {
		return InboxPageResult{}, err
	}
	defer rows.Close()
	result := InboxPageResult{Page: community.InboxPageV1{LastSeqno: after}}
	header, _ := community.Encode(result.Page)
	size := len(header)
	for rows.Next() {
		var seq int64
		var id, raw []byte
		if err := rows.Scan(&seq, &id, &raw); err != nil {
			return InboxPageResult{}, err
		}
		if len(result.Seqnos) == limit || size+len(raw) > roomnet.MaxAnswerPayloadSize {
			if len(result.Seqnos) == 0 {
				return InboxPageResult{}, fmt.Errorf("store: envelope exceeds inbox answer bound")
			}
			result.Page.HasMore = true
			break
		}
		message, err := community.DecodeDirectMessageV3(raw)
		if err != nil || !validInboxEnvelope(message) || message.Verify() != nil {
			return InboxPageResult{}, fmt.Errorf("store: invalid inbox envelope")
		}
		computed, _ := community.HashBoxed(message)
		recipient, _ := community.KeyID(message.ToKey)
		if !bytes.Equal(computed, id) || !bytes.Equal(recipient, inbox) {
			return InboxPageResult{}, fmt.Errorf("store: inbox envelope identity mismatch")
		}
		result.Page.Messages = append(result.Page.Messages, message)
		result.Seqnos = append(result.Seqnos, seq)
		result.Page.LastSeqno = seq
		size += len(raw)
	}
	return result, rows.Err()
}

func (s *Store) AckInbox(ctx context.Context, inbox []byte, ids [][]byte) (int64, error) {
	if len(inbox) != 32 || len(ids) > community.MaxInboxAckIDs {
		return 0, reject(community.RejectMalformedRequest, "invalid inbox ack", nil)
	}
	for _, id := range ids {
		if len(id) != 32 {
			return 0, reject(community.RejectMalformedRequest, "invalid ack id", nil)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var deleted int64
	for _, id := range ids {
		result, err := tx.ExecContext(ctx, "DELETE FROM inbox_messages WHERE dm_id=? AND dm_id IN (SELECT dm_id FROM inbox_receipts WHERE inbox_id=?)", id, inbox)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// ExpireInboxes keeps receipt tombstones through the inclusive +300-second
// admission boundary. Counters survive all deletion and receipt pruning.
func (s *Store) ExpireInboxes(ctx context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM inbox_messages WHERE dm_id IN (SELECT dm_id FROM inbox_receipts WHERE expire_at<=?)", now.Unix())
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM inbox_receipts WHERE keep_until<? AND dm_id NOT IN (SELECT dm_id FROM inbox_messages)", now.Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM inbox_rate WHERE accepted_at<=?", now.Unix()-60); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}
