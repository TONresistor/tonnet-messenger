package client

import (
	"context"
	"errors"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
)

const maxReceivedDMs = 8192

var errDirectReplayCacheFull = errors.New("direct-message replay cache is full")

type directReplayCache struct {
	entries    map[[32]byte]time.Time
	nextExpiry time.Time
}

func (cache *directReplayCache) prune(now time.Time) {
	if cache.nextExpiry.IsZero() || !now.After(cache.nextExpiry) {
		return
	}
	cache.nextExpiry = time.Time{}
	for id, expires := range cache.entries {
		if now.After(expires) {
			delete(cache.entries, id)
		} else if cache.nextExpiry.IsZero() || expires.Before(cache.nextExpiry) {
			cache.nextExpiry = expires
		}
	}
}

func (cache *directReplayCache) record(id [32]byte, expires time.Time) {
	if cache.entries == nil {
		cache.entries = make(map[[32]byte]time.Time)
	}
	cache.entries[id] = expires
	if cache.nextExpiry.IsZero() || expires.Before(cache.nextExpiry) {
		cache.nextExpiry = expires
	}
}

func (r *roomHandle) notifyDirectForSession(ctx context.Context, session *replica.Session, epoch uint64, id [32]byte, expires time.Time, params any) error {
	c := r.client
	c.identityOps.Lock()
	defer c.identityOps.Unlock()
	c.mu.RLock()
	currentEpoch := c.identityEpoch
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
	c.receivedDMs.prune(now)
	if _, seen := c.receivedDMs.entries[id]; seen {
		return nil
	}
	if len(c.receivedDMs.entries) >= maxReceivedDMs {
		return errDirectReplayCacheFull
	}
	if err := c.notifyUntil(ctx, session.Done, "dm.message", params); err != nil {
		return err
	}
	c.receivedDMs.record(id, expires)
	return nil
}
