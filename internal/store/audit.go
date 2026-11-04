package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func (s *Store) Audit(ctx context.Context) error {
	tx, err := s.beginRoom(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return audit(ctx, tx)
}

func audit(ctx context.Context, query *roomTx) error {
	var integrity string
	if err := query.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("store: integrity check: %s", integrity)
	}
	var rawGenesis, storedGenesisHash []byte
	if err := query.QueryRowContext(ctx, "SELECT raw_tl,genesis_hash FROM room_genesis WHERE room_id=?", query.roomID).Scan(&rawGenesis, &storedGenesisHash); err != nil {
		return err
	}
	genesis, err := community.DecodeGenesis(rawGenesis)
	if err != nil {
		return err
	}
	if !bytes.Equal(genesis.RoomKey, query.roomID) {
		return community.ErrWrongRoom
	}
	if err := genesis.VerifyNow(); err != nil {
		return fmt.Errorf("store: genesis audit: %w", err)
	}
	computedGenesisHash, err := genesis.Hash()
	if err != nil || !bytes.Equal(storedGenesisHash, computedGenesisHash) {
		return fmt.Errorf("store: genesis hash mismatch")
	}
	projection, err := community.NewProjection(genesis)
	if err != nil {
		return fmt.Errorf("store: initialize canonical projection: %w", err)
	}
	rows, err := query.QueryContext(ctx, `SELECT seqno,event_id,commit_hash,previous_hash,raw_commit
FROM events WHERE room_id=? ORDER BY seqno ASC`, query.roomID)
	if err != nil {
		return err
	}
	expectedSeqno := int64(1)
	expectedPrevious := community.Zero256()
	hashes := map[int64][]byte{0: computedGenesisHash}
	messageCount := 0
	type messageProjection struct {
		id  int64
		raw []byte
	}
	var messages []messageProjection
	for rows.Next() {
		var seqno int64
		var eventID, commitHash, previousHash, raw []byte
		if err := rows.Scan(&seqno, &eventID, &commitHash, &previousHash, &raw); err != nil {
			rows.Close()
			return err
		}
		event, err := community.DecodeCommittedEvent(raw)
		if err != nil || event.Verify(genesis.RoomKey, genesis.NodeKey) != nil {
			rows.Close()
			return fmt.Errorf("store: invalid committed event at seqno %d", seqno)
		}
		if err := projection.Apply(event); err != nil {
			rows.Close()
			return fmt.Errorf("store: invalid projected event at seqno %d: %w", seqno, err)
		}
		computedEventID, _ := event.Proposal.ID()
		computedCommitHash, _ := event.Hash()
		if seqno != expectedSeqno || event.Seqno != seqno ||
			!bytes.Equal(previousHash, expectedPrevious) || !bytes.Equal(event.PreviousHash, expectedPrevious) ||
			!bytes.Equal(eventID, computedEventID) || !bytes.Equal(commitHash, computedCommitHash) {
			rows.Close()
			return fmt.Errorf("store: event-chain mismatch at seqno %d", seqno)
		}
		if event.MessageID != 0 {
			messageCount++
			messages = append(messages, messageProjection{id: event.MessageID, raw: append([]byte(nil), raw...)})
		}
		hashes[seqno] = computedCommitHash
		expectedPrevious = computedCommitHash
		expectedSeqno++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, message := range messages {
		var projectedRaw []byte
		if err := query.QueryRowContext(ctx, "SELECT raw_commit FROM messages WHERE message_id=? AND room_id=?", message.id, query.roomID).Scan(&projectedRaw); err != nil || !bytes.Equal(projectedRaw, message.raw) {
			return fmt.Errorf("store: message projection mismatch at message %d", message.id)
		}
	}
	var projectedMessages int
	if err := query.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages WHERE room_id=?", query.roomID).Scan(&projectedMessages); err != nil || projectedMessages != messageCount {
		return fmt.Errorf("store: message projection count mismatch")
	}
	var head Head
	if err := query.QueryRowContext(ctx, "SELECT latest_seqno,latest_hash FROM replica_head WHERE room_id=?", query.roomID).Scan(&head.Seqno, &head.Hash); err != nil {
		return err
	}
	if head.Seqno != expectedSeqno-1 || !bytes.Equal(head.Hash, expectedPrevious) {
		return fmt.Errorf("store: replica head mismatch")
	}
	var rawState, revisionHash []byte
	var revisionSeqno int64
	if err := query.QueryRowContext(ctx, "SELECT raw_signed_state,revision_seqno,revision_hash FROM room_state WHERE room_id=?", query.roomID).Scan(&rawState, &revisionSeqno, &revisionHash); err != nil {
		return err
	}
	state, err := community.DecodeRoomStateV3(rawState)
	if err != nil {
		return err
	}
	if state.RevisionSeqno != revisionSeqno || !bytes.Equal(state.RevisionHash, revisionHash) {
		return fmt.Errorf("store: state revision projection mismatch")
	}
	if err := state.Verify(); err != nil {
		return fmt.Errorf("store: signed state audit: %w", err)
	}
	if err := projection.ValidateState(state); err != nil {
		return fmt.Errorf("store: canonical state projection mismatch: %w", err)
	}
	if !bytes.Equal(state.RoomID, genesis.RoomKey) || state.RevisionSeqno > head.Seqno ||
		!bytes.Equal(state.RevisionHash, hashes[state.RevisionSeqno]) {
		return fmt.Errorf("store: signed state revision mismatch")
	}
	if err := auditStateProjection(ctx, query, state); err != nil {
		return err
	}
	return nil
}

func auditStateProjection(ctx context.Context, query *roomTx, state community.RoomStateV3) error {
	var name, description string
	var policy int
	if err := query.QueryRowContext(ctx, "SELECT name,description,anyone_can_write FROM room_state WHERE room_id=?", query.roomID).Scan(&name, &description, &policy); err != nil {
		return err
	}
	if name != state.Name || description != state.Description || (policy != 0) != state.WritePolicy.AnyoneCanWrite {
		return fmt.Errorf("store: metadata projection mismatch")
	}
	roles := func(role string) ([][]byte, error) {
		rows, err := query.QueryContext(ctx, "SELECT subject_key FROM roles WHERE role=? AND room_id=? ORDER BY subject_key", role, query.roomID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var keys [][]byte
		for rows.Next() {
			var key []byte
			if err := rows.Scan(&key); err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
		return keys, rows.Err()
	}
	admins, err := roles("admin")
	if err != nil {
		return err
	}
	moderators, err := roles("moderator")
	if err != nil {
		return err
	}
	rows, err := query.QueryContext(ctx, "SELECT message_id FROM pins WHERE room_id=? ORDER BY message_id", query.roomID)
	if err != nil {
		return err
	}
	var pins []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		pins = append(pins, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	bannedRows, err := query.QueryContext(ctx, "SELECT subject_key FROM bans WHERE room_id=? ORDER BY subject_key", query.roomID)
	if err != nil {
		return err
	}
	var banned [][]byte
	for bannedRows.Next() {
		var key []byte
		if err := bannedRows.Scan(&key); err != nil {
			bannedRows.Close()
			return err
		}
		banned = append(banned, key)
	}
	if err := bannedRows.Err(); err != nil {
		bannedRows.Close()
		return err
	}
	bannedRows.Close()
	if !equalKeys(banned, state.Banned) {
		return fmt.Errorf("store: ban projection mismatch")
	}
	if !equalKeys(admins, state.Admins) || !equalKeys(moderators, state.Moderators) || !equalLongs(pins, state.PinnedMessages) {
		return fmt.Errorf("store: role or pin projection mismatch")
	}
	return nil
}

// UpgradeRoomState converts only a locally stored V2 snapshot. Authority startup
// calls it independently of schema migration so interrupted upgrades are retried.
func (s *Store) UpgradeRoomState(ctx context.Context, roomPrivate ed25519.PrivateKey) error {
	if len(roomPrivate) != ed25519.PrivateKeySize {
		return community.ErrWrongRoom
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.beginRoom(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	genesis, _, err := genesisTx(ctx, tx)
	if err != nil {
		return err
	}
	if !bytes.Equal(roomPrivate.Public().(ed25519.PublicKey), genesis.RoomKey) {
		return community.ErrWrongRoom
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT raw_signed_state FROM room_state WHERE room_id=?", tx.roomID).Scan(&raw); err != nil {
		return err
	}
	if _, err := community.DecodeRoomStateV3(raw); err == nil {
		return nil
	}
	legacy, err := community.DecodeRoomState(raw)
	if err != nil {
		return fmt.Errorf("store: decode legacy room state: %w", err)
	}
	if err := legacy.Verify(); err != nil {
		return fmt.Errorf("store: invalid legacy room state: %w", err)
	}
	if !bytes.Equal(legacy.RoomID, genesis.RoomKey) {
		return community.ErrWrongRoom
	}
	state, err := community.SignRoomStateV3(roomPrivate, community.RoomStateV3{
		RoomID: legacy.RoomID, RevisionSeqno: legacy.RevisionSeqno, RevisionHash: legacy.RevisionHash,
		Name: legacy.Name, Description: legacy.Description, WritePolicy: legacy.WritePolicy,
		Admins: legacy.Admins, Moderators: legacy.Moderators, PinnedMessages: legacy.PinnedMessages,
	})
	if err != nil {
		return err
	}
	raw, err = community.Encode(state)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE room_state SET raw_signed_state=? WHERE room_id=?", raw, tx.roomID); err != nil {
		return err
	}
	// Audit the tentative replacement in the same transaction. Invalid history,
	// signatures or projections roll back without publishing a new signed state.
	if err := audit(ctx, tx); err != nil {
		return fmt.Errorf("store: legacy room state audit: %w", err)
	}
	return tx.Commit()
}
