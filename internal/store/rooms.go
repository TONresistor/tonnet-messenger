package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

var (
	ErrAmbiguousRoom     = errors.New("store: select a room in a multi-room database")
	ErrMigrationRequired = errors.New("store: writable schema migration required")
)

// ForRoom returns a view of one room, including a room not initialized yet.
// Views share the database and writer lock. Close the original Store to close
// the database; closing a view does not close other rooms.
func (s *Store) ForRoom(roomKey []byte) (*Store, error) {
	if len(roomKey) != ed25519.PublicKeySize {
		return nil, community.ErrMalformedKey
	}
	return &Store{db: s.db, path: s.path, mu: s.mu, roomID: bytes.Clone(roomKey), view: true}, nil
}

type roomTx struct {
	*sql.Tx
	roomID []byte
}

func (s *Store) beginRoom(ctx context.Context, initialize []byte) (*roomTx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	roomID := s.roomID
	if len(initialize) != 0 {
		if len(roomID) != 0 && !bytes.Equal(roomID, initialize) {
			tx.Rollback()
			return nil, community.ErrWrongRoom
		}
		if len(roomID) == 0 {
			var count int
			if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM room_genesis").Scan(&count); err == nil && count != 0 {
				err = ErrAlreadyInitialized
				if count > 1 {
					err = ErrAmbiguousRoom
				}
			}
		}
		roomID = initialize
	} else if len(roomID) == 0 {
		rows, queryErr := tx.QueryContext(ctx, "SELECT room_id FROM room_genesis LIMIT 2")
		err = queryErr
		if err == nil {
			for rows.Next() {
				if len(roomID) != 0 {
					err = ErrAmbiguousRoom
					break
				}
				err = rows.Scan(&roomID)
				if err != nil {
					break
				}
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
		}
		if err == nil && len(roomID) == 0 {
			err = ErrNotInitialized
		}
	}
	if err == nil && len(initialize) == 0 {
		var exists bool
		err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM room_genesis WHERE room_id=?)", roomID).Scan(&exists)
		if err == nil && !exists {
			err = ErrNotInitialized
		}
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	return &roomTx{Tx: tx, roomID: roomID}, nil
}
