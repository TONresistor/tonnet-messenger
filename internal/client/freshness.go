package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
)

const (
	relayFreshnessGrace = time.Minute
	relayExclusionTTL   = 2 * time.Minute
	freshnessTimeout    = 15 * time.Second
)

type headCheckpoint struct {
	seqno    int64
	hash     []byte
	observed time.Time
}

type relayFreshness struct {
	status       string
	reason       string
	lastVerified time.Time
	latest       *headCheckpoint
	pending      *headCheckpoint
	failures     int
}

func (f relayFreshness) view() map[string]any {
	status := f.status
	if status == "" {
		status = "unverified"
	}
	last := int64(0)
	if !f.lastVerified.IsZero() {
		last = f.lastVerified.Unix()
	}
	return map[string]any{"status": status, "reason": f.reason, "last_verified_at": last}
}

func (r *roomHandle) stateView(state community.RoomState, head int64) map[string]any {
	view := stateView(state, head)
	r.mu.RLock()
	view["freshness"] = r.freshness.view()
	r.mu.RUnlock()
	return view
}

func (r *roomHandle) nextFreshnessCheck() time.Duration {
	r.mu.RLock()
	failures := r.freshness.failures
	r.mu.RUnlock()
	// Jitter avoids synchronized joins; failures back off to at most 4.5 minutes.
	return (30*time.Second)<<min(failures, 3) + time.Duration(rand.Int64N(int64(30*time.Second)))
}

func (r *roomHandle) excludedRelayKeys(now time.Time) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var keys [][]byte
	for key, until := range r.excludedRelays {
		if !now.Before(until) {
			delete(r.excludedRelays, key)
			continue
		}
		public, err := ParseKeyText(key)
		if err == nil {
			keys = append(keys, public)
		}
	}
	return keys
}

func (r *roomHandle) sequencerHead(ctx context.Context, session *replica.Session, epoch uint64) (*headCheckpoint, error) {
	snapshot, err := r.client.snapshotRoomIdentity(r)
	if err != nil || snapshot.session != session || snapshot.epoch != epoch {
		return nil, errRoomSessionChanged
	}
	authority := session
	if !bytes.Equal(session.Peer.GetPubKey(), session.Genesis.NodeKey) {
		id, err := community.KeyID(session.Genesis.NodeKey)
		if err != nil {
			return nil, err
		}
		dial := r.dialSequencer
		if dial == nil {
			dial = replica.DialSequencer
		}
		cfg := replica.Config{ConfigURL: r.client.configURL, RoomID: r.key, NodeKey: snapshot.key, BootstrapADNL: id}
		if bytes.Equal(r.client.directPublic, session.Genesis.NodeKey) {
			cfg.DirectAddress, cfg.DirectPublic = r.client.directAddress, r.client.directPublic
		}
		authority, err = dial(ctx, cfg)
		if err != nil {
			return nil, err
		}
		defer authority.Close()
	}
	want, err := session.Genesis.Hash()
	if err != nil {
		return nil, err
	}
	got, err := authority.Genesis.Hash()
	if err != nil || !bytes.Equal(want, got) || !bytes.Equal(authority.Peer.GetPubKey(), session.Genesis.NodeKey) {
		return nil, fmt.Errorf("conflicting sequencer identity or genesis")
	}
	var result community.RoomStateResult
	if err := authority.Peer.Query(ctx, community.GetRoomState{}, &result); err != nil {
		return nil, err
	}
	if result.Stats.NodeRole != community.NodeRoleSequencer || !result.Stats.Ready ||
		result.Stats.ReplicaSeqno < 0 || len(result.Stats.ReplicaHash) != 32 ||
		!bytes.Equal(result.State.RoomID, r.key) || result.State.Verify() != nil {
		return nil, fmt.Errorf("invalid sequencer head")
	}
	head := &headCheckpoint{seqno: result.Stats.ReplicaSeqno, hash: result.Stats.ReplicaHash}
	// Stats are authenticated by the pinned QUIC identity, not signed by RoomState.
	// Verify the commit at that observed head without chasing concurrent new writes.
	if head.seqno == 0 {
		if !bytes.Equal(head.hash, community.Zero256()) {
			return nil, fmt.Errorf("invalid empty sequencer head")
		}
		return head, nil
	}
	var page community.EventList
	if err := authority.Peer.Query(ctx, community.GetEvents{AfterSeqno: head.seqno - 1, Limit: 1}, &page); err != nil {
		return nil, err
	}
	if len(page.Events) != 1 || page.Events[0].Seqno != head.seqno || page.Events[0].Verify(r.key, session.Genesis.NodeKey) != nil {
		return nil, fmt.Errorf("invalid signed sequencer head")
	}
	hash, err := page.Events[0].Hash()
	if err != nil || !bytes.Equal(hash, head.hash) {
		return nil, fmt.Errorf("sequencer head hash mismatch")
	}
	return head, nil
}

func (r *roomHandle) hasCheckpoint(ctx context.Context, checkpoint *headCheckpoint) (bool, error) {
	if checkpoint.seqno == 0 {
		return bytes.Equal(checkpoint.hash, community.Zero256()), nil
	}
	record, err := r.client.store.room(ctx, r.key)
	if err != nil || record.HeadSeqno < checkpoint.seqno {
		return false, err
	}
	if record.HeadSeqno == checkpoint.seqno {
		return bytes.Equal(record.HeadHash, checkpoint.hash), nil
	}
	var raw []byte
	if err := r.client.store.db.QueryRowContext(ctx, "SELECT raw_event FROM room_events WHERE room_key=? AND seqno=?", r.key, checkpoint.seqno).Scan(&raw); err != nil {
		return false, err
	}
	event, err := community.DecodeCommittedEvent(raw)
	if err != nil {
		return false, err
	}
	hash, err := event.Hash()
	return bytes.Equal(hash, checkpoint.hash), err
}

func (r *roomHandle) checkFreshness(ctx context.Context, session *replica.Session, epoch uint64, now time.Time) (returnErr error) {
	defer func() {
		if returnErr != nil && ctx.Err() == nil && r.isCurrentSession(session, epoch) {
			r.mu.Lock()
			r.freshness.status, r.freshness.reason = "unverified", "check_failed"
			r.mu.Unlock()
			returnErr = errors.Join(returnErr, r.emitFreshness(ctx, session, epoch))
		}
	}()
	checkCtx, cancel := context.WithTimeout(ctx, freshnessTimeout)
	defer cancel()
	var head *headCheckpoint
	var checkErr error
	select {
	case r.client.freshnessChecks <- struct{}{}:
		head, checkErr = r.sequencerHead(checkCtx, session, epoch)
		<-r.client.freshnessChecks
	case <-checkCtx.Done():
		checkErr = checkCtx.Err()
	}
	r.historyMu.Lock()
	defer r.historyMu.Unlock()
	if !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	r.mu.Lock()
	f := &r.freshness
	if checkErr == nil && f.latest != nil && (head.seqno < f.latest.seqno ||
		(head.seqno == f.latest.seqno && !bytes.Equal(head.hash, f.latest.hash))) {
		checkErr = fmt.Errorf("sequencer checkpoint regressed or conflicted")
	}
	if checkErr != nil {
		f.status, f.reason = "unverified", "sequencer_unavailable"
		f.failures++
		r.mu.Unlock()
		return r.emitFreshness(ctx, session, epoch)
	}
	f.failures = 0
	if f.latest == nil || head.seqno > f.latest.seqno {
		head.observed = now
		f.latest = head
	}
	latest, pending := f.latest, f.pending
	r.mu.Unlock()
	caughtUp, err := r.hasCheckpoint(checkCtx, latest)
	if err != nil {
		return err
	}
	if pending != nil {
		covered, err := r.hasCheckpoint(checkCtx, pending)
		if err != nil {
			return err
		}
		if covered {
			pending = nil
		}
	}
	if !caughtUp && pending == nil {
		pending = latest
	}
	if !caughtUp && now.Sub(pending.observed) >= relayFreshnessGrace {
		// A missed broadcast does not prove the relay is withholding reads. Repair once
		// through that same relay before excluding its authenticated identity.
		_ = r.syncSessionLocked(checkCtx, session, epoch)
		caughtUp, err = r.hasCheckpoint(ctx, latest)
		if err != nil {
			return err
		}
		if covered, err := r.hasCheckpoint(ctx, pending); err != nil {
			return err
		} else if covered && !caughtUp {
			pending = latest
		}
	}
	r.mu.Lock()
	f = &r.freshness
	f.pending = pending
	f.status, f.reason = "unverified", "relay_lag"
	stale := !caughtUp && now.Sub(pending.observed) >= relayFreshnessGrace
	if caughtUp {
		f.status, f.reason, f.lastVerified, f.pending = "verified", "", now, nil
	} else if stale {
		f.status, f.reason = "stale", "relay_behind"
		if r.excludedRelays == nil {
			r.excludedRelays = make(map[string]time.Time)
		}
		r.excludedRelays[keyText(session.Peer.GetPubKey())] = now.Add(relayExclusionTTL)
	}
	r.mu.Unlock()
	err = r.emitFreshness(ctx, session, epoch)
	if stale {
		r.closeSessionIf(session)
	}
	return err
}

func (r *roomHandle) emitFreshness(ctx context.Context, session *replica.Session, epoch uint64) error {
	r.mu.RLock()
	state, head := r.state.State, r.verifiedHead
	r.mu.RUnlock()
	return r.notifyForSession(ctx, session, epoch, "room.state", r.stateView(state, head))
}
