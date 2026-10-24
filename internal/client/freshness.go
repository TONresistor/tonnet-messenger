package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
)

const (
	relayFreshnessGrace    = time.Minute
	relayExclusionTTL      = 2 * time.Minute
	freshnessTimeout       = 15 * time.Second
	freshnessLockTimeout   = 5 * time.Second
	freshnessRepairTimeout = 15 * time.Second
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
	lastNotice   string
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

var errFreshnessConflict = errors.New("authoritative checkpoint conflict")

func ephemeralReadKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(cryptorand.Reader)
	return key, err
}

func (r *roomHandle) freshnessDelay(now time.Time) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nextFreshnessAt.IsZero() {
		r.nextFreshnessAt = now.Add(30*time.Second + time.Duration(rand.Int64N(int64(30*time.Second))))
	}
	return max(time.Duration(0), r.nextFreshnessAt.Sub(now))
}

func (r *roomHandle) scheduleFreshnessCheck(now time.Time) {
	delay := r.nextFreshnessCheck()
	r.mu.Lock()
	r.nextFreshnessAt = now.Add(delay)
	r.mu.Unlock()
}

func (r *roomHandle) freshnessLoop(ctx context.Context) {
	for ctx.Err() == nil {
		timer := time.NewTimer(r.freshnessDelay(time.Now()))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		r.mu.RLock()
		session, epoch := r.session, r.sessionEpoch
		r.mu.RUnlock()
		if session == nil {
			// Keep the overdue deadline while connection establishment is in progress.
			timer.Reset(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		if err := r.checkFreshness(ctx, session, epoch, time.Now()); errors.Is(err, errRoomSessionChanged) {
			// A reconnect is not a completed check and cannot postpone this deadline.
			timer.Reset(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		r.scheduleFreshnessCheck(time.Now())
	}
}

func (r *roomHandle) lockFreshnessHistory(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.historyMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
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
		readKey, err := ephemeralReadKey()
		if err != nil {
			return nil, err
		}
		cfg := replica.Config{ConfigURL: r.client.configURL, RoomID: r.key, NodeKey: readKey, BootstrapADNL: id, Discovery: r.client.discovery}
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
		return nil, fmt.Errorf("%w: conflicting sequencer identity or genesis", errFreshnessConflict)
	}
	var result community.RoomStateResult
	if err := authority.Peer.Query(ctx, community.GetRoomState{}, &result); err != nil {
		return nil, err
	}
	if result.Stats.NodeRole != community.NodeRoleSequencer || !result.Stats.Ready ||
		result.Stats.ReplicaSeqno < 0 || len(result.Stats.ReplicaHash) != 32 ||
		!bytes.Equal(result.State.RoomID, r.key) || result.State.Verify() != nil {
		return nil, fmt.Errorf("%w: invalid sequencer head", errFreshnessConflict)
	}
	head := &headCheckpoint{seqno: result.Stats.ReplicaSeqno, hash: result.Stats.ReplicaHash}
	// Stats are authenticated by the pinned QUIC identity, not signed by RoomState.
	// Verify the commit at that observed head without chasing concurrent new writes.
	if head.seqno == 0 {
		if !bytes.Equal(head.hash, community.Zero256()) {
			return nil, fmt.Errorf("%w: invalid empty sequencer head", errFreshnessConflict)
		}
		return head, nil
	}
	var page community.EventList
	if err := authority.Peer.Query(ctx, community.GetEvents{AfterSeqno: head.seqno - 1, Limit: 1}, &page); err != nil {
		return nil, err
	}
	if len(page.Events) != 1 || page.Events[0].Seqno != head.seqno || page.Events[0].Verify(r.key, session.Genesis.NodeKey) != nil {
		return nil, fmt.Errorf("%w: invalid signed sequencer head", errFreshnessConflict)
	}
	hash, err := page.Events[0].Hash()
	if err != nil || !bytes.Equal(hash, head.hash) {
		return nil, fmt.Errorf("%w: sequencer head hash mismatch", errFreshnessConflict)
	}
	return head, nil
}

func (r *roomHandle) hasStoredCheckpoint(ctx context.Context, checkpoint *headCheckpoint) (bool, error) {
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

func (r *roomHandle) hasAppliedCheckpoint(ctx context.Context, checkpoint *headCheckpoint) (bool, error) {
	r.mu.RLock()
	projection, state, applied := r.projection, r.state.State, r.verifiedHead
	r.mu.RUnlock()
	if projection == nil || applied < checkpoint.seqno {
		return false, nil
	}
	seqno, hash := projection.Head()
	if seqno != applied || projection.ValidateState(state) != nil {
		return false, nil
	}
	if seqno == checkpoint.seqno {
		if !bytes.Equal(hash, checkpoint.hash) {
			return false, errFreshnessConflict
		}
		return true, nil
	}
	matches, err := r.hasStoredCheckpoint(ctx, checkpoint)
	if err == nil && !matches {
		return false, errFreshnessConflict
	}
	return matches, err
}

func (r *roomHandle) failFreshness(ctx context.Context, session *replica.Session, epoch uint64, reason string, err error) error {
	if !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	if errors.Is(err, errFreshnessConflict) {
		reason = "checkpoint_conflict"
	}
	r.mu.Lock()
	r.freshness.status, r.freshness.reason = "unverified", reason
	r.freshness.failures++
	r.mu.Unlock()
	return r.emitFreshness(ctx, session, epoch)
}

func (r *roomHandle) checkFreshness(ctx context.Context, session *replica.Session, epoch uint64, now time.Time) error {
	// The authority budget ends before waiting for history or attempting relay repair.
	authorityCtx, cancel := context.WithTimeout(ctx, freshnessTimeout)
	var head *headCheckpoint
	var checkErr error
	select {
	case r.client.freshnessChecks <- struct{}{}:
		head, checkErr = r.sequencerHead(authorityCtx, session, epoch)
		<-r.client.freshnessChecks
	case <-authorityCtx.Done():
		checkErr = authorityCtx.Err()
	}
	cancel()
	if checkErr != nil {
		return r.failFreshness(ctx, session, epoch, "sequencer_unavailable", checkErr)
	}
	lockCtx, lockCancel := context.WithTimeout(ctx, freshnessLockTimeout)
	err := r.lockFreshnessHistory(lockCtx)
	lockCancel()
	if err != nil {
		return r.failFreshness(ctx, session, epoch, "history_busy", err)
	}
	defer r.historyMu.Unlock()
	if !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	r.mu.Lock()
	f := &r.freshness
	if f.latest != nil && (head.seqno < f.latest.seqno ||
		(head.seqno == f.latest.seqno && !bytes.Equal(head.hash, f.latest.hash))) {
		r.mu.Unlock()
		return r.failFreshness(ctx, session, epoch, "checkpoint_conflict", errFreshnessConflict)
	}
	f.failures = 0
	if f.latest == nil || head.seqno > f.latest.seqno {
		head.observed = now
		f.latest = head
	}
	latest, pending := f.latest, f.pending
	r.mu.Unlock()
	localCtx, localCancel := context.WithTimeout(ctx, freshnessLockTimeout)
	caughtUp, err := r.hasAppliedCheckpoint(localCtx, latest)
	if err == nil && pending != nil {
		var covered bool
		covered, err = r.hasAppliedCheckpoint(localCtx, pending)
		if covered {
			pending = nil
		}
	}
	localCancel()
	if err != nil {
		return r.failFreshness(ctx, session, epoch, "check_failed", err)
	}
	if !caughtUp && pending == nil {
		pending = latest
	}
	var repairErr error
	if !caughtUp && now.Sub(pending.observed) >= relayFreshnessGrace {
		repairCtx, repairCancel := context.WithTimeout(ctx, freshnessRepairTimeout)
		repairErr = r.syncSessionLocked(repairCtx, session, epoch)
		if repairErr == nil {
			caughtUp, err = r.hasAppliedCheckpoint(repairCtx, latest)
			if err == nil {
				var covered bool
				covered, err = r.hasAppliedCheckpoint(repairCtx, pending)
				if covered && !caughtUp {
					pending = latest
				}
			}
		}
		repairCancel()
		if err != nil {
			return r.failFreshness(ctx, session, epoch, "check_failed", err)
		}
	}
	r.mu.Lock()
	f = &r.freshness
	f.pending = pending
	f.status, f.reason = "unverified", "relay_lag"
	stale := !caughtUp && now.Sub(pending.observed) >= relayFreshnessGrace
	if caughtUp && repairErr == nil {
		f.status, f.reason, f.lastVerified, f.pending = "verified", "", now, nil
	} else if stale {
		f.status, f.reason = "stale", "relay_behind"
		if repairErr != nil {
			f.reason = "repair_failed"
		}
		// An incomplete repair budget is not evidence that the relay misbehaved.
		if repairErr == nil || (!errors.Is(repairErr, context.DeadlineExceeded) && !errors.Is(repairErr, context.Canceled)) {
			if r.excludedRelays == nil {
				r.excludedRelays = make(map[string]time.Time)
			}
			r.excludedRelays[keyText(session.Peer.GetPubKey())] = now.Add(relayExclusionTTL)
		}
	}
	r.mu.Unlock()
	if err := r.emitFreshness(ctx, session, epoch); err != nil {
		return err
	}
	if stale {
		// Keep the old connection usable unless a different relay is fully synchronized.
		return r.replaceStaleRelay(ctx, session, epoch, now)
	}
	return repairErr
}

func (r *roomHandle) replaceStaleRelay(ctx context.Context, old *replica.Session, epoch uint64, now time.Time) error {
	identity, err := r.client.snapshotRoomIdentity(r)
	if err != nil || identity.session != old || identity.epoch != epoch {
		return errRoomSessionChanged
	}
	excluded := append(r.excludedRelayKeys(time.Now()), old.Peer.GetPubKey())
	dialCtx, cancel := context.WithTimeout(ctx, freshnessTimeout)
	defer cancel()
	dial := r.dialRoom
	if dial == nil {
		dial = replica.DialRoom
	}
	candidate, err := dial(dialCtx, replica.Config{
		ConfigURL: r.client.configURL, RoomID: r.key, NodeKey: identity.key,
		BootstrapADNL: r.boot, DirectAddress: r.client.directAddress, DirectPublic: r.client.directPublic,
		ExcludedPublicKeys: excluded, Discovery: r.client.discovery,
	})
	if err != nil {
		return nil // No alternative: continue reading the existing stale relay.
	}
	keepCandidate := false
	defer func() {
		if !keepCandidate {
			candidate.Close()
		}
	}()
	// The old session stays current (including for DMs) throughout candidate validation.
	repairCtx, repairCancel := context.WithTimeout(ctx, freshnessRepairTimeout)
	defer repairCancel()
	if err := r.syncSessionFromLocked(repairCtx, candidate, old, epoch); err != nil {
		return nil
	}
	r.mu.RLock()
	latest := r.freshness.latest
	r.mu.RUnlock()
	caughtUp, err := r.hasAppliedCheckpoint(repairCtx, latest)
	if err != nil {
		return r.failFreshness(ctx, old, epoch, "check_failed", err)
	}
	if !caughtUp {
		r.mu.Lock()
		if r.excludedRelays == nil {
			r.excludedRelays = make(map[string]time.Time)
		}
		r.excludedRelays[keyText(candidate.Peer.GetPubKey())] = now.Add(relayExclusionTTL)
		r.mu.Unlock()
		return nil
	}
	if !r.isCurrentSession(old, epoch) {
		return errRoomSessionChanged
	}
	if err := r.installSession(candidate, identity.key, epoch); err != nil {
		return err
	}
	// The handle now owns candidate; this function always retires the displaced old path.
	keepCandidate = true
	defer old.Close()
	candidate.Peer.SetMessageHandler(func(message any) error { r.ingestSerializable(candidate, epoch, message); return nil })
	r.mu.Lock()
	if r.session != candidate || r.sessionEpoch != epoch {
		r.mu.Unlock()
		return errRoomSessionChanged
	}
	r.freshness.status, r.freshness.reason = "verified", ""
	r.freshness.lastVerified, r.freshness.pending = now, nil
	r.mu.Unlock()
	return r.emitFreshness(ctx, candidate, epoch)
}

func (r *roomHandle) emitFreshness(ctx context.Context, session *replica.Session, epoch uint64) error {
	r.mu.RLock()
	state, head := r.state.State, r.verifiedHead
	f := r.freshness
	notice := fmt.Sprintf("%s/%s/%d", f.status, f.reason, head)
	if f.latest != nil {
		notice += fmt.Sprintf("/%d/%x", f.latest.seqno, f.latest.hash)
	}
	r.mu.RUnlock()
	if notice == f.lastNotice {
		return nil
	}
	view := stateView(state, head)
	view["freshness"] = f.view()
	if err := r.notifyForSession(ctx, session, epoch, "room.state", view); err != nil {
		return err
	}
	r.mu.Lock()
	r.freshness.lastNotice = notice
	r.mu.Unlock()
	return nil
}
