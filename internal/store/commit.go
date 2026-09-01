package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func (s *Store) Commit(ctx context.Context, proposal community.EventProposal, roomPrivate ed25519.PrivateKey, now time.Time) (CommitResult, error) {
	rawProposal, err := community.Encode(proposal)
	if err != nil {
		return CommitResult{}, reject(community.RejectMalformedRequest, "malformed proposal", err)
	}
	eventID, err := proposal.ID()
	if err != nil {
		return CommitResult{}, reject(community.RejectMalformedRequest, "malformed proposal", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot begin commit", err)
	}
	defer tx.Rollback()

	if committed, ok, err := findEventByID(ctx, tx, eventID); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot check duplicate", err)
	} else if ok {
		return CommitResult{Event: committed, Duplicate: true}, nil
	}

	genesis, _, err := genesisTx(ctx, tx)
	if err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot load genesis", err)
	}
	if !bytes.Equal(proposal.RoomID, genesis.RoomKey) {
		return CommitResult{}, reject(community.RejectWrongRoom, "wrong room", community.ErrWrongRoom)
	}
	if len(roomPrivate) != ed25519.PrivateKeySize || !bytes.Equal(roomPrivate.Public().(ed25519.PublicKey), genesis.RoomKey) {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "room authority key mismatch", community.ErrWrongRoom)
	}
	if err := proposal.Verify(genesis.NodeKey, now); err != nil {
		code := community.RejectInvalidSignature
		if errors.Is(err, community.ErrTimestamp) {
			code = community.RejectTimestamp
		}
		return CommitResult{}, reject(code, "proposal verification failed", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM request_nonces WHERE expires_at<=?", now.Unix()); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot expire nonces", err)
	}
	var nonceExists int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM request_nonces WHERE author_key=? AND nonce=? AND expires_at>?)`,
		proposal.AuthorKey, proposal.Nonce, now.Unix()).Scan(&nonceExists); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot check nonce", err)
	}
	if nonceExists != 0 {
		return CommitResult{}, reject(community.RejectReusedNonce, "nonce already used", nil)
	}
	state, err := stateTx(ctx, tx)
	if err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot load room state", err)
	}
	if err := authorize(ctx, tx, genesis, state, proposal); err != nil {
		return CommitResult{}, err
	}

	var headSeqno int64
	var headHash []byte
	if err := tx.QueryRowContext(ctx, "SELECT latest_seqno, latest_hash FROM replica_head WHERE singleton_id=1").Scan(&headSeqno, &headHash); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot load event head", err)
	}
	commit, err := community.SignCommit(roomPrivate, proposal, headSeqno+1, headHash, now)
	if err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot sign commit", err)
	}
	rawCommit, err := community.Encode(commit)
	if err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot encode commit", err)
	}
	commitHash, err := commit.Hash()
	if err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot hash commit", err)
	}
	bodyType, stateChanging := bodyType(proposal.Body)
	if bodyType == "" {
		return CommitResult{}, reject(community.RejectUnsupportedEvent, "unsupported event type", nil)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events
(seqno, event_id, commit_hash, previous_hash, author_key, body_type, raw_proposal, raw_commit, committed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, commit.Seqno, eventID, commitHash, commit.PreviousHash,
		proposal.AuthorKey, bodyType, rawProposal, rawCommit, commit.CommittedAt); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot persist event", err)
	}
	if err := applyProjection(ctx, tx, genesis, commit, rawCommit); err != nil {
		return CommitResult{}, err
	}
	if stateChanging {
		if err := persistStateSnapshot(ctx, tx, roomPrivate, commit.Seqno, commitHash); err != nil {
			return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot persist room state", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO request_nonces(author_key, nonce, accepted_at, expires_at)
VALUES (?, ?, ?, ?)`, proposal.AuthorKey, proposal.Nonce, now.Unix(), now.Add(community.NonceRetention).Unix()); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot persist nonce", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE replica_head SET latest_seqno=?, latest_hash=? WHERE singleton_id=1", commit.Seqno, commitHash); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot advance event head", err)
	}
	if err := tx.Commit(); err != nil {
		return CommitResult{}, reject(community.RejectPersistenceFailure, "cannot commit event", err)
	}
	return CommitResult{Event: commit}, nil
}

func authorize(ctx context.Context, tx *sql.Tx, genesis community.Genesis, state community.RoomState, proposal community.EventProposal) error {
	owner := bytes.Equal(proposal.AuthorKey, genesis.RoomKey)
	admin, err := hasRole(ctx, tx, proposal.AuthorKey, "admin")
	if err != nil {
		return reject(community.RejectPersistenceFailure, "cannot load author role", err)
	}
	moderator, err := hasRole(ctx, tx, proposal.AuthorKey, "moderator")
	if err != nil {
		return reject(community.RejectPersistenceFailure, "cannot load author role", err)
	}
	allowed := false
	switch proposal.Body.(type) {
	case community.EventMessage, *community.EventMessage:
		allowed = state.WritePolicy.AnyoneCanWrite || owner || admin
	case community.EventMetadata, *community.EventMetadata, community.EventWritePolicy, *community.EventWritePolicy:
		allowed = owner || admin
	case community.EventPin, *community.EventPin, community.EventUnpin, *community.EventUnpin:
		allowed = owner || admin || moderator
	case community.EventAdminGrant, *community.EventAdminGrant, community.EventAdminRevoke, *community.EventAdminRevoke:
		allowed = owner
	case community.EventModeratorGrant, *community.EventModeratorGrant, community.EventModeratorRevoke, *community.EventModeratorRevoke:
		allowed = owner || admin
	default:
		return reject(community.RejectUnsupportedEvent, "unsupported event type", nil)
	}
	if !allowed {
		return reject(community.RejectPermissionDenied, "permission denied", nil)
	}
	return nil
}

func applyProjection(ctx context.Context, tx *sql.Tx, genesis community.Genesis, event community.CommittedEvent, rawCommit []byte) error {
	author := event.Proposal.AuthorKey
	switch body := event.Proposal.Body.(type) {
	case community.EventMessage:
		return insertMessage(ctx, tx, event, body, rawCommit)
	case *community.EventMessage:
		return insertMessage(ctx, tx, event, *body, rawCommit)
	case community.EventMetadata:
		_, err := tx.ExecContext(ctx, "UPDATE room_state SET name=?, description=? WHERE singleton_id=1", body.Name, body.Description)
		return persistenceProjection(err)
	case *community.EventMetadata:
		_, err := tx.ExecContext(ctx, "UPDATE room_state SET name=?, description=? WHERE singleton_id=1", body.Name, body.Description)
		return persistenceProjection(err)
	case community.EventWritePolicy:
		_, err := tx.ExecContext(ctx, "UPDATE room_state SET anyone_can_write=? WHERE singleton_id=1", boolInt(body.AnyoneCanWrite))
		return persistenceProjection(err)
	case *community.EventWritePolicy:
		_, err := tx.ExecContext(ctx, "UPDATE room_state SET anyone_can_write=? WHERE singleton_id=1", boolInt(body.AnyoneCanWrite))
		return persistenceProjection(err)
	case community.EventPin:
		return pin(ctx, tx, event.Seqno, body.MessageID, author)
	case *community.EventPin:
		return pin(ctx, tx, event.Seqno, body.MessageID, author)
	case community.EventUnpin:
		return unpin(ctx, tx, body.MessageID)
	case *community.EventUnpin:
		return unpin(ctx, tx, body.MessageID)
	case community.EventAdminGrant:
		return grantRole(ctx, tx, genesis, event.Seqno, body.SubjectKey, author, "admin")
	case *community.EventAdminGrant:
		return grantRole(ctx, tx, genesis, event.Seqno, body.SubjectKey, author, "admin")
	case community.EventAdminRevoke:
		return revokeAdmin(ctx, tx, genesis, body.SubjectKey)
	case *community.EventAdminRevoke:
		return revokeAdmin(ctx, tx, genesis, body.SubjectKey)
	case community.EventModeratorGrant:
		return grantRole(ctx, tx, genesis, event.Seqno, body.SubjectKey, author, "moderator")
	case *community.EventModeratorGrant:
		return grantRole(ctx, tx, genesis, event.Seqno, body.SubjectKey, author, "moderator")
	case community.EventModeratorRevoke:
		return revokeRole(ctx, tx, genesis, body.SubjectKey, "moderator")
	case *community.EventModeratorRevoke:
		return revokeRole(ctx, tx, genesis, body.SubjectKey, "moderator")
	default:
		return reject(community.RejectUnsupportedEvent, "unsupported event type", nil)
	}
}

func insertMessage(ctx context.Context, tx *sql.Tx, event community.CommittedEvent, body community.EventMessage, raw []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO messages
(message_id, creation_seqno, author_key, nick, text, client_ts, committed_at, raw_commit)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, event.MessageID, event.Seqno, event.Proposal.AuthorKey,
		event.Proposal.AuthorName, body.Text, event.Proposal.Timestamp, event.CommittedAt, raw)
	return persistenceProjection(err)
}

func pin(ctx context.Context, tx *sql.Tx, seqno, messageID int64, author []byte) error {
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id=?)", messageID).Scan(&exists); err != nil {
		return persistenceProjection(err)
	}
	if exists == 0 {
		return reject(community.RejectUnknownMessage, "unknown message", nil)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pins").Scan(&count); err != nil {
		return persistenceProjection(err)
	}
	if count >= community.MaxPins {
		return reject(community.RejectLimitExceeded, "pinned-message limit reached", nil)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO pins(message_id, pinned_seqno, pinned_by) VALUES (?, ?, ?)", messageID, seqno, author); err != nil {
		if isConstraint(err) {
			return reject(community.RejectRoleConflict, "message already pinned", err)
		}
		return persistenceProjection(err)
	}
	return nil
}

func unpin(ctx context.Context, tx *sql.Tx, messageID int64) error {
	result, err := tx.ExecContext(ctx, "DELETE FROM pins WHERE message_id=?", messageID)
	if err != nil {
		return persistenceProjection(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return persistenceProjection(err)
	}
	if rows == 0 {
		return reject(community.RejectUnknownMessage, "message is not pinned", nil)
	}
	return nil
}

func grantRole(ctx context.Context, tx *sql.Tx, genesis community.Genesis, seqno int64, subject, author []byte, role string) error {
	if bytes.Equal(subject, genesis.RoomKey) {
		return reject(community.RejectRoleConflict, "owner cannot receive a delegated role", nil)
	}
	limit := community.MaxModerators
	if role == "admin" {
		limit = community.MaxAdmins
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM roles WHERE role=?", role).Scan(&count); err != nil {
		return persistenceProjection(err)
	}
	if count >= limit {
		return reject(community.RejectLimitExceeded, role+" limit reached", nil)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO roles(subject_key, role, granted_seqno, granted_by) VALUES (?, ?, ?, ?)", subject, role, seqno, author); err != nil {
		if isConstraint(err) {
			return reject(community.RejectRoleConflict, "role already granted", err)
		}
		return persistenceProjection(err)
	}
	return nil
}

func revokeAdmin(ctx context.Context, tx *sql.Tx, genesis community.Genesis, subject []byte) error {
	if bytes.Equal(subject, genesis.RoomKey) {
		return reject(community.RejectRoleConflict, "owner cannot be revoked", nil)
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM roles WHERE subject_key=? AND role='admin'", subject)
	if err != nil {
		return persistenceProjection(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return persistenceProjection(err)
	}
	if rows == 0 {
		return reject(community.RejectRoleConflict, "administrator role is not granted", nil)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM roles WHERE subject_key=? AND role='moderator'", subject); err != nil {
		return persistenceProjection(err)
	}
	return nil
}

func revokeRole(ctx context.Context, tx *sql.Tx, genesis community.Genesis, subject []byte, role string) error {
	if bytes.Equal(subject, genesis.RoomKey) {
		return reject(community.RejectRoleConflict, "owner cannot be revoked", nil)
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM roles WHERE subject_key=? AND role=?", subject, role)
	if err != nil {
		return persistenceProjection(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return persistenceProjection(err)
	}
	if rows == 0 {
		return reject(community.RejectRoleConflict, "role is not granted", nil)
	}
	return nil
}

func persistStateSnapshot(ctx context.Context, tx *sql.Tx, roomPrivate ed25519.PrivateKey, seqno int64, revisionHash []byte) error {
	state, err := projectedState(ctx, tx)
	if err != nil {
		return err
	}
	state.RevisionSeqno = seqno
	state.RevisionHash = revisionHash
	state, err = community.SignRoomState(roomPrivate, state)
	if err != nil {
		return err
	}
	raw, err := community.Encode(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE room_state SET revision_seqno=?, revision_hash=?, raw_signed_state=? WHERE singleton_id=1`, seqno, revisionHash, raw)
	return err
}

func projectedState(ctx context.Context, tx *sql.Tx) (community.RoomState, error) {
	genesis, _, err := genesisTx(ctx, tx)
	if err != nil {
		return community.RoomState{}, err
	}
	var name, description string
	var policy int
	if err := tx.QueryRowContext(ctx, "SELECT name, description, anyone_can_write FROM room_state WHERE singleton_id=1").Scan(&name, &description, &policy); err != nil {
		return community.RoomState{}, err
	}
	admins, err := roleKeys(ctx, tx, "admin")
	if err != nil {
		return community.RoomState{}, err
	}
	moderators, err := roleKeys(ctx, tx, "moderator")
	if err != nil {
		return community.RoomState{}, err
	}
	pins, err := pinIDs(ctx, tx)
	if err != nil {
		return community.RoomState{}, err
	}
	return community.RoomState{
		RoomID: genesis.RoomKey, Name: name, Description: description,
		WritePolicy: community.WritePolicy{AnyoneCanWrite: policy != 0},
		Admins:      admins, Moderators: moderators, PinnedMessages: pins,
	}, nil
}

func roleKeys(ctx context.Context, tx *sql.Tx, role string) ([][]byte, error) {
	rows, err := tx.QueryContext(ctx, "SELECT subject_key FROM roles WHERE role=? ORDER BY subject_key", role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values [][]byte
	for rows.Next() {
		var key []byte
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		values = append(values, key)
	}
	return values, rows.Err()
}

func pinIDs(ctx context.Context, tx *sql.Tx) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, "SELECT message_id FROM pins ORDER BY message_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		values = append(values, id)
	}
	return values, rows.Err()
}

func hasRole(ctx context.Context, tx *sql.Tx, key []byte, role string) (bool, error) {
	var exists int
	err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM roles WHERE subject_key=? AND role=?)", key, role).Scan(&exists)
	return exists != 0, err
}

func findEventByID(ctx context.Context, tx *sql.Tx, eventID []byte) (community.CommittedEvent, bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, "SELECT raw_commit FROM events WHERE event_id=?", eventID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return community.CommittedEvent{}, false, nil
	}
	if err != nil {
		return community.CommittedEvent{}, false, err
	}
	event, err := community.DecodeCommittedEvent(raw)
	return event, err == nil, err
}

func genesisTx(ctx context.Context, tx *sql.Tx) (community.Genesis, []byte, error) {
	var raw, hash []byte
	if err := tx.QueryRowContext(ctx, "SELECT raw_tl, genesis_hash FROM room_genesis WHERE singleton_id=1").Scan(&raw, &hash); err != nil {
		return community.Genesis{}, nil, err
	}
	g, err := community.DecodeGenesis(raw)
	return g, hash, err
}

func stateTx(ctx context.Context, tx *sql.Tx) (community.RoomState, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT raw_signed_state FROM room_state WHERE singleton_id=1").Scan(&raw); err != nil {
		return community.RoomState{}, err
	}
	return community.DecodeRoomState(raw)
}

func bodyType(body any) (string, bool) {
	switch body.(type) {
	case community.EventMessage, *community.EventMessage:
		return "message", false
	case community.EventPin, *community.EventPin:
		return "pin", true
	case community.EventUnpin, *community.EventUnpin:
		return "unpin", true
	case community.EventMetadata, *community.EventMetadata:
		return "metadata", true
	case community.EventAdminGrant, *community.EventAdminGrant:
		return "admin_grant", true
	case community.EventAdminRevoke, *community.EventAdminRevoke:
		return "admin_revoke", true
	case community.EventModeratorGrant, *community.EventModeratorGrant:
		return "moderator_grant", true
	case community.EventModeratorRevoke, *community.EventModeratorRevoke:
		return "moderator_revoke", true
	case community.EventWritePolicy, *community.EventWritePolicy:
		return "write_policy", true
	default:
		return "", false
	}
}

func messageBody(body any) (community.EventMessage, bool) {
	switch value := body.(type) {
	case community.EventMessage:
		return value, true
	case *community.EventMessage:
		if value != nil {
			return *value, true
		}
	}
	return community.EventMessage{}, false
}

func persistenceProjection(err error) error {
	if err == nil {
		return nil
	}
	return reject(community.RejectPersistenceFailure, "cannot update room projection", err)
}

func isConstraint(err error) bool {
	return err != nil && (bytes.Contains([]byte(err.Error()), []byte("constraint failed")) || bytes.Contains([]byte(err.Error()), []byte("UNIQUE constraint")))
}
