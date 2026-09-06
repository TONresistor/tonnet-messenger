package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

type OperationError struct {
	Code    string
	Room    string
	EventID string
	Outcome string
	Cause   error
}

func (failure *OperationError) Error() string {
	return fmt.Sprintf("%s: %s (room %s, event %s)", failure.Code, failure.Cause, failure.Room, failure.EventID)
}

func (failure *OperationError) Unwrap() error { return failure.Cause }

type PendingOperation struct {
	Room      string         `json:"room"`
	EventID   string         `json:"event_id"`
	Status    string         `json:"status"`
	Timestamp int64          `json:"timestamp"`
	Event     map[string]any `json:"event"`
}

type pendingOperation struct {
	ID          []byte
	GenesisHash []byte
	Proposal    community.EventProposal
	Commit      *community.CommittedEvent
}

func (pending *pendingOperation) outcome() string {
	if pending.Commit != nil {
		return "committed"
	}
	return "unknown"
}

func (database *clientStore) pendingOperation(ctx context.Context, roomKey []byte) (*pendingOperation, error) {
	var pending pendingOperation
	var rawProposal, rawCommit []byte
	err := database.db.QueryRowContext(ctx, "SELECT event_id,genesis_hash,raw_proposal,raw_commit FROM pending_operations WHERE room_key=?", roomKey).Scan(&pending.ID, &pending.GenesisHash, &rawProposal, &rawCommit)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pending.Proposal, err = community.DecodeProposal(rawProposal)
	if err != nil {
		return nil, err
	}
	actualID, err := pending.Proposal.ID()
	if err != nil || !bytes.Equal(actualID, pending.ID) || !bytes.Equal(pending.Proposal.RoomID, roomKey) {
		return nil, errors.New("client store: invalid pending proposal")
	}
	if len(rawCommit) != 0 {
		commit, err := community.DecodeCommittedEvent(rawCommit)
		if err != nil {
			return nil, err
		}
		pending.Commit = &commit
	}
	return &pending, nil
}

func (database *clientStore) savePending(ctx context.Context, genesis community.Genesis, proposal community.EventProposal) (*pendingOperation, error) {
	raw, err := community.Encode(proposal)
	if err != nil {
		return nil, err
	}
	identifier, err := proposal.ID()
	if err != nil {
		return nil, err
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		return nil, err
	}
	_, err = database.db.ExecContext(ctx, "INSERT INTO pending_operations(room_key,event_id,genesis_hash,raw_proposal) VALUES (?,?,?,?)", proposal.RoomID, identifier, genesisHash, raw)
	if err != nil {
		return nil, err
	}
	return &pendingOperation{ID: identifier, GenesisHash: genesisHash, Proposal: proposal}, nil
}

func (database *clientStore) clearPending(ctx context.Context, roomKey, identifier []byte) error {
	_, err := database.db.ExecContext(ctx, "DELETE FROM pending_operations WHERE room_key=? AND event_id=?", roomKey, identifier)
	return err
}

func (database *clientStore) requireNoPending(ctx context.Context, roomKey []byte) error {
	query := "SELECT room_key,event_id,raw_commit FROM pending_operations"
	var args []any
	if roomKey != nil {
		query += " WHERE room_key=?"
		args = append(args, roomKey)
	}
	query += " LIMIT 1"
	var room, identifier, rawCommit []byte
	err := database.db.QueryRowContext(ctx, query, args...).Scan(&room, &identifier, &rawCommit)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	outcome := "unknown"
	if len(rawCommit) > 0 {
		outcome = "committed"
	}
	return &OperationError{Code: "PENDING_OPERATION", Room: keyText(room), EventID: keyText(identifier), Outcome: outcome, Cause: errors.New("resolve or explicitly discard the pending operation first")}
}

func (instance *Client) GetPending(ctx context.Context, roomText string) (*PendingOperation, error) {
	instance.submissionMu.RLock()
	defer instance.submissionMu.RUnlock()
	roomKey, err := ParseKeyText(roomText)
	if err != nil {
		return nil, err
	}
	pending, err := instance.store.pendingOperation(ctx, roomKey)
	if err != nil || pending == nil {
		return nil, err
	}
	event, err := eventView(community.CommittedEvent{Proposal: pending.Proposal})
	if err != nil {
		return nil, err
	}
	for _, field := range []string{"seqno", "message_id", "committed_at", "event_id", "room"} {
		delete(event, field)
	}
	status := "uncertain"
	if pending.Commit != nil {
		status = "committed"
	}
	return &PendingOperation{Room: roomText, EventID: keyText(pending.ID), Status: status, Timestamp: pending.Proposal.Timestamp, Event: event}, nil
}

func (instance *Client) RetryPending(ctx context.Context, roomText, eventID string) (map[string]any, error) {
	instance.submissionMu.RLock()
	defer instance.submissionMu.RUnlock()
	identifier, err := ParseKeyText(eventID)
	if err != nil {
		return nil, err
	}
	handle, err := instance.connectedRoom(roomText)
	if err != nil {
		return nil, err
	}
	handle.submitMu.Lock()
	defer handle.submitMu.Unlock()
	snapshot, err := instance.snapshotRoomIdentity(handle)
	if err != nil {
		return nil, err
	}
	pending, err := instance.store.pendingOperation(ctx, handle.key)
	if err != nil {
		return nil, err
	}
	if pending == nil || !bytes.Equal(pending.ID, identifier) {
		return nil, errors.New("pending operation no longer matches this event")
	}
	return instance.sendPending(ctx, handle, snapshot, pending, false)
}

func (instance *Client) DiscardPending(ctx context.Context, roomText, eventID string) error {
	instance.submissionMu.Lock()
	defer instance.submissionMu.Unlock()
	roomKey, err := ParseKeyText(roomText)
	if err != nil {
		return err
	}
	identifier, err := ParseKeyText(eventID)
	if err != nil {
		return err
	}
	pending, err := instance.store.pendingOperation(ctx, roomKey)
	if err != nil {
		return err
	}
	if pending == nil {
		return nil
	}
	if !bytes.Equal(identifier, pending.ID) {
		return errors.New("pending operation no longer matches this event")
	}
	return instance.store.clearPending(ctx, roomKey, identifier)
}

func (instance *Client) sendPending(ctx context.Context, handle *roomHandle, snapshot roomIdentitySnapshot, pending *pendingOperation, firstAttempt bool) (map[string]any, error) {
	failure := func(code string, cause error) error {
		return &OperationError{Code: code, Room: keyText(handle.key), EventID: keyText(pending.ID), Cause: cause}
	}
	genesisHash, err := snapshot.session.Genesis.Hash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(genesisHash, pending.GenesisHash) || !bytes.Equal(snapshot.key.Public().(ed25519.PublicKey), pending.Proposal.AuthorKey) {
		return nil, failure("PROTOCOL_ERROR", errors.New("pending operation identity or genesis changed"))
	}
	if err := pending.Proposal.VerifyAt(snapshot.session.Genesis.NodeKey); err != nil {
		return nil, failure("PROTOCOL_ERROR", err)
	}
	finish := func(event community.CommittedEvent) (map[string]any, error) {
		identifier, err := event.Proposal.ID()
		if err != nil || !bytes.Equal(identifier, pending.ID) {
			handle.closeSessionIf(snapshot.session)
			return nil, failure("PROTOCOL_ERROR", errors.New("submit response belongs to another proposal"))
		}
		if err := handle.ingestCanonical(ctx, snapshot.session, snapshot.epoch, event); err != nil {
			handle.closeSessionIf(snapshot.session)
			return nil, failure("SEND_UNCERTAIN", err)
		}
		if err := instance.store.clearPending(ctx, handle.key, pending.ID); err != nil {
			return nil, failure("SEND_UNCERTAIN", err)
		}
		return eventView(event)
	}
	if pending.Commit != nil {
		return finish(*pending.Commit)
	}
	var response any
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = snapshot.session.Peer.Query(queryCtx, community.SubmitEvent{Proposal: pending.Proposal}, &response)
	cancel()
	if err != nil {
		if current, lookupErr := instance.store.pendingOperation(ctx, handle.key); lookupErr == nil && current != nil && current.Commit != nil {
			return finish(*current.Commit)
		}
		return nil, failure("SEND_UNCERTAIN", err)
	}
	switch result := response.(type) {
	case community.SubmitAccepted:
		return finish(result.Event)
	case community.SubmitDuplicate:
		return finish(result.Event)
	case community.SubmitRejected:
		rejection := &RejectedError{Code: result.Code, Message: result.Message}
		if result.Code < community.RejectMalformedRequest || result.Code > community.RejectInvalidIdentityDomain {
			handle.closeSessionIf(snapshot.session)
			return nil, failure("PROTOCOL_ERROR", rejection)
		}
		if current, lookupErr := instance.store.pendingOperation(ctx, handle.key); lookupErr == nil && current != nil && current.Commit != nil {
			return finish(*current.Commit)
		}
		authoritative := bytes.Equal(snapshot.session.Peer.GetPubKey(), snapshot.session.Genesis.NodeKey)
		if firstAttempt && authoritative && result.Code != community.RejectPersistenceFailure && result.Code != community.RejectSequencerUnavailable && result.Code != community.RejectInvalidCanonicalState {
			if err := instance.store.clearPending(ctx, handle.key, pending.ID); err != nil {
				return nil, failure("SEND_UNCERTAIN", err)
			}
			return nil, rejection
		}
		return nil, failure("SEND_UNCERTAIN", rejection)
	default:
		handle.closeSessionIf(snapshot.session)
		return nil, failure("PROTOCOL_ERROR", fmt.Errorf("unexpected submit response %T", response))
	}
}
