package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func (s *Store) InitializeReplica(ctx context.Context, genesis community.Genesis) error {
	if err := genesis.Verify(time.Now()); err != nil {
		return fmt.Errorf("store: invalid replica genesis: %w", err)
	}
	rawGenesis, err := community.Encode(genesis)
	if err != nil {
		return err
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		return err
	}
	unsignedState := community.RoomState{
		RoomID: genesis.RoomKey, RevisionHash: genesisHash, Name: genesis.Name,
		Description: genesis.Description, WritePolicy: genesis.WritePolicy,
		Admins: genesis.InitialAdmins,
	}
	rawState, err := community.Encode(unsignedState)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM room_genesis").Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return ErrAlreadyInitialized
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO room_genesis
(singleton_id, raw_tl, genesis_hash, room_key, node_key, created_at)
VALUES (1, ?, ?, ?, ?, ?)`, rawGenesis, genesisHash, genesis.RoomKey, genesis.NodeKey, genesis.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO room_state
(singleton_id, revision_seqno, revision_hash, raw_signed_state, name, description, anyone_can_write)
VALUES (1, 0, ?, ?, ?, ?, ?)`, genesisHash, rawState, genesis.Name, genesis.Description, boolInt(genesis.WritePolicy.AnyoneCanWrite)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replica_head(singleton_id, latest_seqno, latest_hash) VALUES (1, 0, ?)", community.Zero256()); err != nil {
		return err
	}
	for _, admin := range genesis.InitialAdmins {
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles(subject_key, role, granted_seqno, granted_by)
VALUES (?, 'admin', 0, ?)`, admin, genesis.RoomKey); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AppendReplica(ctx context.Context, event community.CommittedEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	genesis, _, err := genesisTx(ctx, tx)
	if err != nil {
		return false, err
	}
	if err := event.Verify(genesis.RoomKey, genesis.NodeKey); err != nil {
		return false, fmt.Errorf("store: invalid replica commit: %w", err)
	}
	commitHash, err := event.Hash()
	if err != nil {
		return false, err
	}
	var existingHash []byte
	err = tx.QueryRowContext(ctx, "SELECT commit_hash FROM events WHERE seqno=?", event.Seqno).Scan(&existingHash)
	if err == nil {
		if bytes.Equal(existingHash, commitHash) {
			return false, nil
		}
		return false, fmt.Errorf("store: fork at seqno %d", event.Seqno)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var headSeqno int64
	var headHash []byte
	if err := tx.QueryRowContext(ctx, "SELECT latest_seqno, latest_hash FROM replica_head WHERE singleton_id=1").Scan(&headSeqno, &headHash); err != nil {
		return false, err
	}
	if event.Seqno != headSeqno+1 || !bytes.Equal(event.PreviousHash, headHash) {
		return false, fmt.Errorf("store: replica gap or previous-hash mismatch at seqno %d", event.Seqno)
	}
	projected, err := projectedState(ctx, tx)
	if err != nil {
		return false, err
	}
	if err := authorize(ctx, tx, genesis, projected, event.Proposal); err != nil {
		return false, fmt.Errorf("store: canonical event violates authorization: %w", err)
	}
	eventID, err := event.Proposal.ID()
	if err != nil {
		return false, err
	}
	rawProposal, err := community.Encode(event.Proposal)
	if err != nil {
		return false, err
	}
	rawCommit, err := community.Encode(event)
	if err != nil {
		return false, err
	}
	bodyType, _ := bodyType(event.Proposal.Body)
	if bodyType == "" {
		return false, fmt.Errorf("store: unsupported canonical event")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events
(seqno, event_id, commit_hash, previous_hash, author_key, body_type, raw_proposal, raw_commit, committed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, event.Seqno, eventID, commitHash, event.PreviousHash,
		event.Proposal.AuthorKey, bodyType, rawProposal, rawCommit, event.CommittedAt); err != nil {
		return false, err
	}
	if err := applyProjection(ctx, tx, genesis, event, rawCommit); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO request_nonces(author_key, nonce, accepted_at, expires_at)
VALUES (?, ?, ?, ?)`, event.Proposal.AuthorKey, event.Proposal.Nonce, event.CommittedAt,
		time.Unix(event.CommittedAt, 0).Add(community.NonceRetention).Unix()); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE replica_head SET latest_seqno=?, latest_hash=? WHERE singleton_id=1", event.Seqno, commitHash); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) InstallReplicaState(ctx context.Context, state community.RoomState) error {
	if err := state.Verify(); err != nil {
		return fmt.Errorf("store: invalid replica state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	genesis, genesisHash, err := genesisTx(ctx, tx)
	if err != nil {
		return err
	}
	if !bytes.Equal(state.RoomID, genesis.RoomKey) {
		return community.ErrWrongRoom
	}
	var headSeqno int64
	if err := tx.QueryRowContext(ctx, "SELECT latest_seqno FROM replica_head WHERE singleton_id=1").Scan(&headSeqno); err != nil {
		return err
	}
	if state.RevisionSeqno > headSeqno {
		return fmt.Errorf("store: state revision is ahead of replica head")
	}
	expectedRevisionHash := genesisHash
	if state.RevisionSeqno > 0 {
		if err := tx.QueryRowContext(ctx, "SELECT commit_hash FROM events WHERE seqno=?", state.RevisionSeqno).Scan(&expectedRevisionHash); err != nil {
			return err
		}
	}
	if !bytes.Equal(state.RevisionHash, expectedRevisionHash) {
		return fmt.Errorf("store: state revision hash mismatch")
	}
	projected, err := projectedState(ctx, tx)
	if err != nil {
		return err
	}
	if state.Name != projected.Name || state.Description != projected.Description ||
		state.WritePolicy != projected.WritePolicy || !equalKeys(state.Admins, projected.Admins) ||
		!equalKeys(state.Moderators, projected.Moderators) || !equalLongs(state.PinnedMessages, projected.PinnedMessages) {
		return fmt.Errorf("store: signed state disagrees with event projections")
	}
	raw, err := community.Encode(state)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE room_state SET revision_seqno=?, revision_hash=?, raw_signed_state=?,
name=?, description=?, anyone_can_write=? WHERE singleton_id=1`, state.RevisionSeqno, state.RevisionHash, raw,
		state.Name, state.Description, boolInt(state.WritePolicy.AnyoneCanWrite)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReplicaReady(ctx context.Context) error {
	state, err := s.State(ctx)
	if err != nil {
		return err
	}
	if err := state.Verify(); err != nil {
		return err
	}
	head, err := s.Head(ctx)
	if err != nil {
		return err
	}
	if state.RevisionSeqno > head.Seqno {
		return fmt.Errorf("store: state is ahead of replica")
	}
	_, genesisHash, err := s.Genesis(ctx)
	if err != nil {
		return err
	}
	expectedSeqno := int64(0)
	expectedHash := genesisHash
	var latestSeqno int64
	var latestHash []byte
	err = s.db.QueryRowContext(ctx, `SELECT seqno,commit_hash FROM events
WHERE body_type <> 'message' ORDER BY seqno DESC LIMIT 1`).Scan(&latestSeqno, &latestHash)
	if err == nil {
		expectedSeqno, expectedHash = latestSeqno, latestHash
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if state.RevisionSeqno != expectedSeqno || !bytes.Equal(state.RevisionHash, expectedHash) {
		return fmt.Errorf("store: signed state does not cover latest state transition")
	}
	return nil
}

func equalKeys(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalLongs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
