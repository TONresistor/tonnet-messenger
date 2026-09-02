package store

import (
	"bytes"
	"context"
	"fmt"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func (s *Store) Audit(ctx context.Context) error {
	if err := s.IntegrityCheck(ctx); err != nil {
		return err
	}
	genesis, storedGenesisHash, err := s.Genesis(ctx)
	if err != nil {
		return err
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
	rows, err := s.db.QueryContext(ctx, `SELECT seqno,event_id,commit_hash,previous_hash,raw_commit
FROM events ORDER BY seqno ASC`)
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
	if err := rows.Close(); err != nil {
		return err
	}
	for _, message := range messages {
		var projectedRaw []byte
		if err := s.db.QueryRowContext(ctx, "SELECT raw_commit FROM messages WHERE message_id=?", message.id).Scan(&projectedRaw); err != nil || !bytes.Equal(projectedRaw, message.raw) {
			return fmt.Errorf("store: message projection mismatch at message %d", message.id)
		}
	}
	var projectedMessages int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages").Scan(&projectedMessages); err != nil || projectedMessages != messageCount {
		return fmt.Errorf("store: message projection count mismatch")
	}
	head, err := s.Head(ctx)
	if err != nil {
		return err
	}
	if head.Seqno != expectedSeqno-1 || !bytes.Equal(head.Hash, expectedPrevious) {
		return fmt.Errorf("store: replica head mismatch")
	}
	state, err := s.State(ctx)
	if err != nil {
		return err
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
	if err := s.auditStateProjection(ctx, state); err != nil {
		return err
	}
	return nil
}

func (s *Store) auditStateProjection(ctx context.Context, state community.RoomState) error {
	var name, description string
	var policy int
	if err := s.db.QueryRowContext(ctx, "SELECT name,description,anyone_can_write FROM room_state WHERE singleton_id=1").Scan(&name, &description, &policy); err != nil {
		return err
	}
	if name != state.Name || description != state.Description || (policy != 0) != state.WritePolicy.AnyoneCanWrite {
		return fmt.Errorf("store: metadata projection mismatch")
	}
	roles := func(role string) ([][]byte, error) {
		rows, err := s.db.QueryContext(ctx, "SELECT subject_key FROM roles WHERE role=? ORDER BY subject_key", role)
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
	rows, err := s.db.QueryContext(ctx, "SELECT message_id FROM pins ORDER BY message_id")
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
	rows.Close()
	if !equalKeys(admins, state.Admins) || !equalKeys(moderators, state.Moderators) || !equalLongs(pins, state.PinnedMessages) {
		return fmt.Errorf("store: role or pin projection mismatch")
	}
	return nil
}
