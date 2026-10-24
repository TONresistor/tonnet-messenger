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
	maxFreshnessChecks     = 4
	catchupSlack           = time.Minute
	catchupRecovery        = time.Minute
	relayFreshnessGrace    = time.Minute
	relayExclusionTTL      = 2 * time.Minute
	freshnessTimeout       = 15 * time.Second
	freshnessLockTimeout   = 5 * time.Second
	freshnessRepairTimeout = 15 * time.Second
)

var errCatchupRate = errors.New("relay catch-up rate below minimum")

// For B initially missing events through fixed H, 1s credit per NEW persisted
// event gives at most 60s+B*1s of rate allowance, plus ONE 60s recovery window.
// From the first synchronization toward H, receipt or rejection takes B+120s.
// Finalization has a separate 15s bound per attempt and never moves H. Rejecting a relay cannot guarantee network delivery.
// Accounting belongs to H, never a session; rebuilding known history earns zero.
type catchupRate struct {
	target        int64
	baseline      int64
	credits       int64
	started       time.Time
	recoveryUntil time.Time
	recoveryOwner *replica.Session
}

func (b *catchupRate) baseDeadline() time.Time {
	// Saturate before multiplying untrusted sequence numbers into a duration.
	seconds := min(b.credits, int64((time.Duration(1<<63-1)-catchupSlack)/time.Second))
	return b.started.Add(catchupSlack + time.Duration(seconds)*time.Second)
}

func (b *catchupRate) deadline(now time.Time) (time.Time, error) {
	base := b.baseDeadline()
	if now.After(base) && b.recoveryUntil.IsZero() {
		b.recoveryUntil = base.Add(catchupRecovery)
	}
	deadline := base
	if b.recoveryUntil.IsZero() {
		deadline = base.Add(catchupRecovery) // Reserve the one possible recovery, without rebasing it.
	} else if b.recoveryUntil.After(deadline) {
		deadline = b.recoveryUntil
	}
	if now.After(deadline) {
		return deadline, errCatchupRate
	}
	return deadline, nil
}

// Durable progress is only a catch-up allowance, never applied verification.
type roomSyncProgress struct {
	session         *replica.Session
	seqno           int64
	finalizingUntil time.Time
}

func (r *roomHandle) syncTime() time.Time {
	if r.syncNow != nil {
		return r.syncNow()
	}
	return time.Now()
}

func (r *roomHandle) beginRoomSync(session *replica.Session) *roomSyncProgress {
	progress := &roomSyncProgress{session: session}
	r.mu.Lock()
	r.syncProgress = progress
	r.mu.Unlock()
	return progress
}

func (r *roomHandle) ensureCatchupLocked(target, known int64, now time.Time) *catchupRate {
	r.receivedHead = max(r.receivedHead, known)
	b := r.freshness.rate
	if b == nil || (r.receivedHead >= b.target && target > b.target) {
		b = &catchupRate{target: target, baseline: r.receivedHead, started: now}
		r.freshness.rate = b
		if target > r.receivedHead && r.syncProgress != nil {
			r.syncProgress.finalizingUntil = time.Time{}
		}
	} else if target < b.target {
		b.target = target // An authenticated older target can only shorten the work.
		b.credits = min(b.credits, max(int64(0), target-b.baseline))
	}
	return b
}

func (r *roomHandle) advanceRoomSync(progress *roomSyncProgress, seqno int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if progress != nil && r.syncProgress == progress {
		progress.seqno = max(progress.seqno, seqno)
	}
	if seqno != r.receivedHead+1 {
		return
	}
	r.receivedHead = seqno
	if b := r.freshness.rate; b != nil && seqno > b.baseline && seqno <= b.target {
		// Observe any deficit BEFORE granting credit; late batches cannot erase recovery use.
		unused := b.recoveryUntil.IsZero()
		_, expired := b.deadline(r.syncTime())
		if unused && !b.recoveryUntil.IsZero() {
			b.recoveryOwner = r.session
			if progress != nil {
				b.recoveryOwner = progress.session
			}
		}
		if expired == nil {
			b.credits++
		}
	}
	if progress != nil && r.syncProgress == progress && r.freshness.rate != nil &&
		r.receivedHead >= r.freshness.rate.target && progress.finalizingUntil.IsZero() {
		progress.finalizingUntil = r.syncTime().Add(freshnessRepairTimeout)
	}
}

func (r *roomHandle) endRoomSync(progress *roomSyncProgress) {
	r.mu.Lock()
	if r.syncProgress == progress {
		r.syncProgress = nil
	}
	r.mu.Unlock()
}

func (r *roomHandle) rateDeadlineLocked(b *catchupRate, session *replica.Session, now time.Time) (time.Time, error) {
	unused := b.recoveryUntil.IsZero()
	deadline, err := b.deadline(now)
	if unused && !b.recoveryUntil.IsZero() {
		b.recoveryOwner = session
	}
	if err == nil && b.recoveryOwner == session && now.After(b.baseDeadline()) {
		err = errCatchupRate
	}
	return deadline, err
}

func (r *roomHandle) catchupContext(ctx context.Context, b *catchupRate, session *replica.Session) (context.Context, context.CancelFunc, error) {
	now := r.syncTime()
	r.mu.Lock()
	deadline, err := r.rateDeadlineLocked(b, session, now)
	r.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	queryCtx, cancel := r.freshnessContext(ctx, min(10*time.Second, max(time.Duration(0), deadline.Sub(now))))
	return queryCtx, cancel, nil
}

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
	rate         *catchupRate
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

func (r *roomHandle) failFreshness(ctx context.Context, session *replica.Session, epoch uint64, reason string, err error, now time.Time) error {
	if errors.Is(err, errFreshnessConflict) {
		reason = "checkpoint_conflict"
	}
	r.mu.Lock()
	if r.session != session || r.sessionEpoch != epoch {
		r.mu.Unlock()
		return errRoomSessionChanged
	}
	r.freshness.status, r.freshness.reason = "unverified", reason
	r.freshness.failures++
	pending := r.freshness.pending
	needsRepair := reason == "sequencer_unavailable" && pending != nil && r.verifiedHead < pending.seqno && now.Sub(pending.observed) >= relayFreshnessGrace
	r.mu.Unlock()
	if needsRepair {
		lockCtx, cancel := r.freshnessContext(ctx, freshnessLockTimeout)
		lockErr := r.lockFreshnessHistory(lockCtx)
		cancel()
		covered := false
		if lockErr == nil {
			repairCtx, repairCancel := r.freshnessContext(ctx, freshnessRepairTimeout)
			repairErr := r.syncSessionLocked(repairCtx, session, epoch)
			if repairErr == nil {
				var checkErr error
				covered, checkErr = r.hasAppliedCheckpoint(repairCtx, pending)
				if errors.Is(checkErr, errFreshnessConflict) {
					reason = "checkpoint_conflict"
				}
			} else if errors.Is(repairErr, errFreshnessConflict) {
				reason = "checkpoint_conflict"
			}
			repairCancel()
			r.historyMu.Unlock()
		}
		r.mu.Lock()
		if r.session != session || r.sessionEpoch != epoch {
			r.mu.Unlock()
			return errRoomSessionChanged
		}
		behind := !covered && reason != "checkpoint_conflict" && r.markBehindLocked(session, now)
		r.freshness.reason = reason // Do not hide an unreachable sequencer behind catching_up/relay_behind.
		r.mu.Unlock()
		if behind {
			r.closeSessionIf(session)
			return nil
		}
	}
	return r.emitFreshness(ctx, session, epoch)
}

func (r *roomHandle) freshnessContext(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if r.freshnessBudget != nil {
		return r.freshnessBudget(ctx, budget)
	}
	return context.WithTimeout(ctx, budget)
}

// Retain authenticated evidence even if the relay disconnects during the probe.
func (r *roomHandle) recordFreshnessHead(head *headCheckpoint, session *replica.Session, epoch uint64, now time.Time) error {
	r.client.mu.RLock()
	if r.client.closed || r.client.identityEpoch != epoch {
		r.client.mu.RUnlock()
		return errRoomSessionChanged
	}
	r.mu.Lock()
	f := &r.freshness
	if f.latest != nil && (head.seqno < f.latest.seqno ||
		(head.seqno == f.latest.seqno && !bytes.Equal(head.hash, f.latest.hash))) {
		r.mu.Unlock()
		r.client.mu.RUnlock()
		return errFreshnessConflict
	}
	f.failures = 0
	if f.reason == "sequencer_unavailable" {
		f.reason = "not_checked"
	}
	if f.latest == nil || head.seqno > f.latest.seqno {
		head.observed = now
		f.latest = head
	}
	if f.pending == nil && r.verifiedHead < head.seqno {
		f.pending = f.latest
	}
	var retired *replica.Session
	if r.session != nil && r.session != session && r.sessionEpoch == epoch && bytes.Equal(r.session.Peer.GetPubKey(), session.Peer.GetPubKey()) {
		if r.markBehindLocked(r.session, now) {
			retired = r.session
		}
	}
	r.mu.Unlock()
	r.client.mu.RUnlock()
	if retired != nil {
		r.closeSessionIf(retired)
	}
	return nil
}

// A lower applied head proves lag without reading the mutable projection.
func (r *roomHandle) markBehindLocked(session *replica.Session, now time.Time) bool {
	f := &r.freshness
	if f.pending == nil || r.verifiedHead >= f.pending.seqno || now.Sub(f.pending.observed) < relayFreshnessGrace {
		return false
	}
	if progress := r.syncProgress; progress != nil && progress.session == session {
		budget := r.ensureCatchupLocked(f.pending.seqno, r.receivedHead, now)
		_, err := r.rateDeadlineLocked(budget, session, now)
		finalizing := r.receivedHead >= budget.target && now.Before(progress.finalizingUntil)
		if finalizing || (r.receivedHead < budget.target && err == nil) {
			f.status = "unverified"
			if f.reason != "sequencer_unavailable" {
				f.reason = "catching_up"
			}
			return false
		}
	}
	f.status = "stale"
	if f.reason != "sequencer_unavailable" {
		f.reason = "relay_behind"
	}
	if r.excludedRelays == nil {
		r.excludedRelays = make(map[string]time.Time)
	}
	r.excludedRelays[keyText(session.Peer.GetPubKey())] = now.Add(relayExclusionTTL)
	return true
}

// A busy history lock cannot protect a relay beyond its bounded progress allowance.
func (r *roomHandle) busyFreshness(ctx context.Context, session *replica.Session, epoch uint64, reason string, now time.Time) error {
	r.mu.Lock()
	if r.session != session || r.sessionEpoch != epoch {
		r.mu.Unlock()
		return errRoomSessionChanged
	}
	r.freshness.status = "unverified"
	if r.freshness.reason != "sequencer_unavailable" {
		r.freshness.reason = reason
	}
	behind := r.markBehindLocked(session, now)
	r.mu.Unlock()
	if behind {
		r.closeSessionIf(session) // The retained state remains readable through RoomState.
		return nil
	}
	return r.emitFreshness(ctx, session, epoch)
}

func (r *roomHandle) checkFreshness(ctx context.Context, session *replica.Session, epoch uint64, now time.Time) error {
	// Queueing is local contention, not a sequencer failure; it has its own budget.
	slotCtx, slotCancel := r.freshnessContext(ctx, freshnessLockTimeout)
	select {
	case r.client.freshnessChecks <- struct{}{}:
		slotCancel()
	case <-slotCtx.Done():
		slotCancel()
		return r.busyFreshness(ctx, session, epoch, "check_busy", now)
	}
	authorityCtx, cancel := r.freshnessContext(ctx, freshnessTimeout)
	head, checkErr := r.sequencerHead(authorityCtx, session, epoch)
	cancel()
	<-r.client.freshnessChecks
	if checkErr != nil {
		return r.failFreshness(ctx, session, epoch, "sequencer_unavailable", checkErr, now)
	}
	if err := r.recordFreshnessHead(head, session, epoch, now); err != nil {
		return r.failFreshness(ctx, session, epoch, "checkpoint_conflict", err, now)
	}
	if !r.isCurrentSession(session, epoch) {
		r.mu.RLock()
		current, currentEpoch := r.session, r.sessionEpoch
		r.mu.RUnlock()
		if current != nil && currentEpoch == epoch {
			if err := r.emitFreshness(ctx, current, epoch); err != nil {
				return errors.Join(errRoomSessionChanged, err)
			}
		}
		return errRoomSessionChanged
	}
	lockCtx, lockCancel := r.freshnessContext(ctx, freshnessLockTimeout)
	err := r.lockFreshnessHistory(lockCtx)
	lockCancel()
	if err != nil {
		return r.busyFreshness(ctx, session, epoch, "history_busy", now)
	}
	locked := true
	defer func() {
		if locked {
			r.historyMu.Unlock()
		}
	}()
	if !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	r.mu.RLock()
	latest, pending := r.freshness.latest, r.freshness.pending
	r.mu.RUnlock()
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
		return r.failFreshness(ctx, session, epoch, "check_failed", err, now)
	}
	if !caughtUp && pending == nil {
		pending = latest
	}
	var repairErr error
	if !caughtUp && now.Sub(pending.observed) >= relayFreshnessGrace {
		repairCtx, repairCancel := r.freshnessContext(ctx, freshnessRepairTimeout)
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
			return r.failFreshness(ctx, session, epoch, "check_failed", err, now)
		}
	}
	r.mu.Lock()
	f := &r.freshness
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
		// Dial outside the history lock so the old path can keep ingesting.
		r.historyMu.Unlock()
		locked = false
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
	lockCtx, lockCancel := r.freshnessContext(ctx, freshnessLockTimeout)
	lockErr := r.lockFreshnessHistory(lockCtx)
	lockCancel()
	if lockErr != nil {
		return nil
	}
	defer r.historyMu.Unlock()
	// The old session stays current (including for DMs) throughout candidate validation.
	repairCtx, repairCancel := r.freshnessContext(ctx, freshnessRepairTimeout)
	defer repairCancel()
	if err := r.syncSessionFromLocked(repairCtx, candidate, old, epoch); err != nil {
		return nil
	}
	r.mu.RLock()
	latest := r.freshness.latest
	r.mu.RUnlock()
	caughtUp, err := r.hasAppliedCheckpoint(repairCtx, latest)
	if err != nil {
		return r.failFreshness(ctx, old, epoch, "check_failed", err, now)
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
	candidate.Peer.SetMessageHandler(func(message any) error { r.ingestSerializable(candidate, epoch, message); return nil })
	if err := r.installSession(candidate, identity.key, epoch, old); err != nil {
		return err
	}
	// The handle now owns candidate; this function always retires the displaced old path.
	keepCandidate = true
	defer old.Close()
	r.mu.Lock()
	if r.session != candidate || r.sessionEpoch != epoch {
		r.mu.Unlock()
		return errRoomSessionChanged
	}
	r.freshness.status, r.freshness.reason = "verified", ""
	r.freshness.lastVerified, r.freshness.pending = now, nil
	r.mu.Unlock()
	if err := r.emitConnected(ctx, candidate, epoch); err != nil {
		return err
	}
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
