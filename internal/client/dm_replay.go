package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
)

func (r *roomHandle) notifyDirectForSession(ctx context.Context, session *replica.Session, epoch uint64, id [32]byte, expires time.Time, params any) error {
	c := r.client
	c.identityOps.Lock()
	defer c.identityOps.Unlock()
	c.mu.RLock()
	currentEpoch := c.identityEpoch
	recipient := c.key.Public().(ed25519.PublicKey)
	c.mu.RUnlock()
	if currentEpoch != epoch || !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-session.Done:
		return errRoomSessionChanged
	default:
	}
	now := time.Now()
	if now.After(expires) {
		return community.ErrTimestamp
	}
	inserted, err := c.store.claimDirectMessage(ctx, recipient, id, expires, now)
	if err != nil {
		// Senders do not control local storage errors; prefer a possible duplicate
		// to losing a verified DM.
		return c.notifyUntil(ctx, session.Done, "dm.message", params)
	}
	if !inserted {
		return nil
	}
	if err := c.notifyUntil(ctx, session.Done, "dm.message", params); err != nil {
		// Notification failure commonly cancels ctx; cleanup must still reach SQLite.
		return errors.Join(err, c.store.deleteDirectMessage(context.WithoutCancel(ctx), recipient, id))
	}
	return nil
}
