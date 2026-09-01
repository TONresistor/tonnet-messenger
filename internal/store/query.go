package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

func normalizeLimit(limit int) (int, error) {
	if limit == 0 {
		return community.DefaultPageLimit, nil
	}
	if limit < 1 || limit > community.MaxPageLimit {
		return 0, fmt.Errorf("store: page limit must be in 1..%d", community.MaxPageLimit)
	}
	return limit, nil
}

func (s *Store) Events(ctx context.Context, afterSeqno int64, limit int) (community.EventList, error) {
	limit, err := normalizeLimit(limit)
	if err != nil {
		return community.EventList{}, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT raw_commit FROM events WHERE seqno>? ORDER BY seqno ASC LIMIT ?", afterSeqno, limit+1)
	if err != nil {
		return community.EventList{}, err
	}
	events, err := decodeRows(rows)
	if err != nil {
		return community.EventList{}, err
	}
	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	return community.EventList{Events: events, HasMore: hasMore}, nil
}

func (s *Store) MessagesRecent(ctx context.Context, limit int) (community.MessageList, error) {
	return s.messagesBefore(ctx, 0, limit, true)
}

func (s *Store) MessagesBefore(ctx context.Context, messageID int64, limit int) (community.MessageList, error) {
	if messageID < 1 {
		return community.MessageList{}, fmt.Errorf("store: message id must be positive")
	}
	return s.messagesBefore(ctx, messageID, limit, false)
}

func (s *Store) messagesBefore(ctx context.Context, messageID int64, limit int, recent bool) (community.MessageList, error) {
	limit, err := normalizeLimit(limit)
	if err != nil {
		return community.MessageList{}, err
	}
	query := `SELECT raw_commit FROM (
SELECT message_id, raw_commit FROM messages ORDER BY message_id DESC LIMIT ?
) ORDER BY message_id ASC`
	args := []any{limit + 1}
	if !recent {
		query = `SELECT raw_commit FROM (
SELECT message_id, raw_commit FROM messages WHERE message_id<? ORDER BY message_id DESC LIMIT ?
) ORDER BY message_id ASC`
		args = []any{messageID, limit + 1}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return community.MessageList{}, err
	}
	events, err := decodeRows(rows)
	if err != nil {
		return community.MessageList{}, err
	}
	hasMore := len(events) > limit
	if hasMore {
		events = events[1:]
	}
	return community.MessageList{Messages: events, HasMore: hasMore}, nil
}

func decodeRows(rows *sql.Rows) ([]community.CommittedEvent, error) {
	defer rows.Close()
	var events []community.CommittedEvent
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		event, err := community.DecodeCommittedEvent(raw)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) Checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

func (s *Store) IntegrityCheck(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("store: integrity check: %s", result)
	}
	return nil
}
