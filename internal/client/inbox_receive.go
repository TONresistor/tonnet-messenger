package client

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
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

type inboxDisposition uint8

const (
	inboxDropped inboxDisposition = iota
	inboxDuplicate
	inboxAccepted
)

// claimedDomain is signed data awaiting a later msg_id check, never a verified
// display alias. No public message/JSON view is created by these primitives.
type receivedInboxDM struct {
	id, fromKey                     []byte
	authorName, claimedDomain, text string
	createdAt, expireAt             int64
}

type inboxDecision struct {
	id          []byte
	disposition inboxDisposition
	message     *receivedInboxDM // Only a new durable acceptance can notify later.
}

// Every decision may be acked to this returning relay only after a successful
// return. On error the result is empty, including after a transaction rollback.
type inboxReceiveResult struct {
	relayKey, inboxID []byte
	decisions         []inboxDecision
}

type inboxCandidate struct {
	id, raw []byte
	message *receivedInboxDM
}

func inboxPrincipal(public ed25519.PublicKey) ([]byte, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("client inbox: invalid identity key")
	}
	return community.KeyID(public)
}

func openReceivedInboxDM(identity ed25519.PrivateKey, m community.DirectMessageV3, id []byte) (*receivedInboxDM, error) {
	if err := m.Verify(); err != nil {
		return nil, err
	}
	if !bytes.Equal(m.ToKey, identity.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("DM belongs to another identity")
	}
	if err := community.ValidateAuthorProfile(m.AuthorName, m.AuthorDomain); err != nil {
		return nil, err
	}
	plain, err := dm.OpenV3(identity, m.FromKey, m.Ciphertext)
	if err != nil {
		return nil, err
	}
	return &receivedInboxDM{id: bytes.Clone(id), fromKey: bytes.Clone(m.FromKey), authorName: m.AuthorName, claimedDomain: m.AuthorDomain, text: string(plain), createdAt: m.CreatedAt, expireAt: m.ExpireAt}, nil
}

func classifyInboxDM(identity ed25519.PrivateKey, m community.DirectMessageV3, now time.Time) (inboxCandidate, error) {
	// Hash the canonical boxed object, including its signature, even on a drop.
	// An impossible-to-encode object has no ack ID and is a protocol failure.
	id, err := community.HashBoxed(m)
	if err != nil {
		return inboxCandidate{}, fmt.Errorf("%w: inbox envelope: %w", roomnet.ErrMalformedAnswer, err)
	}
	candidate := inboxCandidate{id: id}
	// Addition would overflow only at the upper boundary. In that case the
	// mathematical expiry+300 is after every representable int64 Unix clock.
	if expiredInboxDM(m.ExpireAt, now.Unix()) {
		return candidate, nil
	}
	message, err := openReceivedInboxDM(identity, m, id)
	if err != nil {
		return candidate, nil
	}
	raw, err := community.Encode(m)
	if err != nil {
		return inboxCandidate{}, fmt.Errorf("%w: inbox envelope: %w", roomnet.ErrMalformedAnswer, err)
	}
	candidate.raw, candidate.message = raw, message
	return candidate, nil
}

func expiredInboxDM(expireAt, now int64) bool {
	return expireAt <= math.MaxInt64-300 && expireAt+300 <= now
}

func (s *clientStore) receiveInboxPage(ctx context.Context, identity ed25519.PrivateKey, relay ed25519.PublicKey, after int64, page community.InboxPageV1, now time.Time) (inboxReceiveResult, error) {
	if after < 0 || len(page.Messages) > community.MaxPageLimit || page.LastSeqno < after || len(page.Messages) == 0 && (page.LastSeqno != after || page.HasMore) || len(page.Messages) > 0 && page.LastSeqno <= after {
		return inboxReceiveResult{}, fmt.Errorf("%w: invalid inbox page cursor", roomnet.ErrMalformedAnswer)
	}
	return s.receiveInbox(ctx, identity, relay, page.Messages, &page.LastSeqno, now)
}

func (s *clientStore) receiveInboxPush(ctx context.Context, identity ed25519.PrivateKey, relay ed25519.PublicKey, push community.InboxPushV1, now time.Time) (inboxReceiveResult, error) {
	if push.Seqno <= 0 {
		return inboxReceiveResult{}, fmt.Errorf("%w: invalid inbox push sequence", roomnet.ErrMalformedAnswer)
	}
	return s.receiveInbox(ctx, identity, relay, []community.DirectMessageV3{push.Message}, nil, now)
}

func (s *clientStore) receiveInbox(ctx context.Context, identity ed25519.PrivateKey, relay ed25519.PublicKey, messages []community.DirectMessageV3, last *int64, now time.Time) (inboxReceiveResult, error) {
	if len(identity) != ed25519.PrivateKeySize || len(relay) != ed25519.PublicKeySize {
		return inboxReceiveResult{}, fmt.Errorf("client inbox: invalid local identity or relay key")
	}
	inbox, err := inboxPrincipal(identity.Public().(ed25519.PublicKey))
	if err != nil {
		return inboxReceiveResult{}, err
	}
	candidates := make([]inboxCandidate, 0, len(messages))
	for _, m := range messages {
		c, err := classifyInboxDM(identity, m, now)
		if err != nil {
			return inboxReceiveResult{}, err
		}
		candidates = append(candidates, c)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inboxReceiveResult{}, err
	}
	defer tx.Rollback()
	result := inboxReceiveResult{relayKey: bytes.Clone(relay), inboxID: inbox}
	for _, c := range candidates {
		decision := inboxDecision{id: c.id, disposition: inboxDropped}
		if c.message != nil {
			inserted, err := tx.ExecContext(ctx, `INSERT INTO received_inbox_dms(inbox_id,dm_id,raw_envelope)
VALUES (?,?,?) ON CONFLICT(inbox_id,dm_id) DO NOTHING`, inbox, c.id, c.raw)
			if err != nil {
				return inboxReceiveResult{}, err
			}
			n, err := inserted.RowsAffected()
			if err != nil {
				return inboxReceiveResult{}, err
			}
			if n == 1 {
				decision.disposition, decision.message = inboxAccepted, c.message
			} else {
				var raw []byte
				if err := tx.QueryRowContext(ctx, "SELECT raw_envelope FROM received_inbox_dms WHERE inbox_id=? AND dm_id=?", inbox, c.id).Scan(&raw); err != nil {
					return inboxReceiveResult{}, err
				}
				if !bytes.Equal(raw, c.raw) {
					return inboxReceiveResult{}, fmt.Errorf("client store: conflicting inbox DM id")
				}
				decision.disposition = inboxDuplicate
			}
		}
		// A crash after cursor commit must not forget even the dropped IDs.
		// These are ack intents only; rejected envelopes are never persisted.
		if _, err := tx.ExecContext(ctx, `INSERT INTO pending_inbox_acks(inbox_id,relay_key,dm_id)
VALUES (?,?,?) ON CONFLICT(inbox_id,relay_key,dm_id) DO NOTHING`, inbox, relay, c.id); err != nil {
			return inboxReceiveResult{}, err
		}
		result.decisions = append(result.decisions, decision)
	}
	if last != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO inbox_cursors(inbox_id,relay_key,after_seqno) VALUES (?,?,?)
ON CONFLICT(inbox_id,relay_key) DO UPDATE SET after_seqno=MAX(inbox_cursors.after_seqno,excluded.after_seqno)`, inbox, relay, *last); err != nil {
			return inboxReceiveResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return inboxReceiveResult{}, err
	}
	return result, nil
}

func (s *clientStore) inboxCursor(ctx context.Context, identity, relay ed25519.PublicKey) (int64, error) {
	inbox, err := inboxPrincipal(identity)
	if err != nil {
		return 0, err
	}
	if len(relay) != ed25519.PublicKeySize {
		return 0, fmt.Errorf("client inbox: invalid relay key")
	}
	var cursor int64
	err = s.db.QueryRowContext(ctx, "SELECT after_seqno FROM inbox_cursors WHERE inbox_id=? AND relay_key=?", inbox, relay).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return cursor, err
}

func (s *clientStore) pendingInboxAcks(ctx context.Context, identity, relay ed25519.PublicKey) ([][]byte, error) {
	inbox, err := inboxPrincipal(identity)
	if err != nil {
		return nil, err
	}
	if len(relay) != 32 {
		return nil, fmt.Errorf("client inbox: invalid relay key")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT dm_id FROM pending_inbox_acks WHERE inbox_id=? AND relay_key=? ORDER BY dm_id LIMIT ?`, inbox, relay, community.MaxInboxAckIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// The later network driver calls this only after a successful remote ack.
// Message history, dedup and fetch cursors are independent of ack completion.
func (s *clientStore) completeInboxAcks(ctx context.Context, identity, relay ed25519.PublicKey, ids [][]byte) error {
	inbox, err := inboxPrincipal(identity)
	if err != nil {
		return err
	}
	if len(relay) != 32 || len(ids) > community.MaxInboxAckIDs {
		return fmt.Errorf("client inbox: invalid ack batch")
	}
	for _, id := range ids {
		if len(id) != 32 {
			return fmt.Errorf("client inbox: invalid ack id")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, "DELETE FROM pending_inbox_acks WHERE inbox_id=? AND relay_key=? AND dm_id=?", inbox, relay, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// The accepted envelope is also the durable dedup record. Keep it as history;
// no cleanup policy is introduced here. Even if a later cleanup forgets IDs,
// classifyInboxDM's expiry check prevents an old envelope from being redisplayed.
func (s *clientStore) receivedInboxDM(ctx context.Context, identity ed25519.PrivateKey, id []byte) (*receivedInboxDM, error) {
	if len(identity) != ed25519.PrivateKeySize || len(id) != 32 {
		return nil, fmt.Errorf("client inbox: invalid identity or DM id")
	}
	inbox, err := inboxPrincipal(identity.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	var raw []byte
	err = s.db.QueryRowContext(ctx, "SELECT raw_envelope FROM received_inbox_dms WHERE inbox_id=? AND dm_id=?", inbox, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m, err := community.DecodeDirectMessageV3(raw)
	if err != nil {
		return nil, fmt.Errorf("client store: invalid received DM: %w", err)
	}
	actual, err := community.HashBoxed(m)
	if err != nil || !bytes.Equal(actual, id) {
		return nil, fmt.Errorf("client store: invalid received DM hash")
	}
	message, err := openReceivedInboxDM(identity, m, id)
	if err != nil {
		return nil, fmt.Errorf("client store: invalid received DM: %w", err)
	}
	return message, nil
}
