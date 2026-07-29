package node

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/envelope"
	"github.com/TONresistor/tonnet-messenger/internal/room"
)

const (
	relayTimeout = 8 * time.Second

	nodeFanout = 5

	badScoreSignature = 4
	badScoreRateLimit = 1
)

type outboundJob struct {
	items []tl.Serializable
}

// The tonutils-go gateway invokes its connection handler for both accepted and
// locally dialed ADNL peers. Unknown peers therefore stay outside the Tonnet
// peer table until they actually send Tonnet overlay custom or query traffic;
// this prevents ordinary DHT transport connections from consuming the
// pending-leaf budget.
func (n *Node) wireUntrackedPeer(id string, w *tonoverlay.ADNLOverlayWrapper, raw adnl.Peer) {
	promote := func() (*peer, bool) {
		p, added := n.peers.addInbound(id, w, raw)
		if p == nil {
			raw.Close()
			return nil, false
		}
		if !added && p.raw != raw {
			raw.Close()
			return nil, false
		}
		if added {
			n.wirePeer(p)
		}
		return p, true
	}
	w.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		p, ok := promote()
		if !ok {
			return nil
		}
		n.handleCustomMessage(p, msg.Data, time.Now())
		return nil
	})
	w.SetQueryHandler(func(q *adnl.MessageQuery) error {
		p, ok := promote()
		if !ok {
			return nil
		}
		return n.answerQuery(p, q)
	})
}

func (n *Node) wirePeer(p *peer) {
	id := p.id
	go n.outboundWriter(p)

	p.w.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		n.handleCustomMessage(p, msg.Data, time.Now())
		return nil
	})

	p.w.SetQueryHandler(func(q *adnl.MessageQuery) error {
		return n.answerQuery(p, q)
	})

	p.w.SetDisconnectHandler(func(addr string, _ ed25519.PublicKey) {
		if n.peers.removePeer(id, p) {
			n.devices.removePeer(id)
			p.stopOnce.Do(func() { close(p.stop) })
			log.Printf("peer left    %s… (%s)", short(id), n.countsString())
		}
	})
}

func (n *Node) outboundWriter(p *peer) {
	for {
		select {
		case <-p.stop:
			return
		case job := <-p.out:
			for _, item := range job.items {
				ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
				err := p.w.SendCustomMessage(ctx, item)
				cancel()
				if err != nil {
					log.Printf("relay to %s… failed: %v", short(p.id), err)
					n.peerFailure(p, time.Now(), "relay failed")
					break
				}
			}
		}
	}
}

func (n *Node) enqueue(p *peer, items ...tl.Serializable) bool {
	if p == nil || p.w == nil || len(items) == 0 {
		return false
	}
	job := outboundJob{items: items}
	select {
	case <-p.stop:
		return false
	case p.out <- job:
		return true
	default:
		n.stats.slowPeerDisconnects.Add(1)
		n.peers.removePeer(p.id, p)
		n.devices.removePeer(p.id)
		n.closePeer(p, "outbound queue full")
		return false
	}
}

func (n *Node) handleCustomMessage(p *peer, data tl.Serializable, now time.Time) {
	if p == nil {
		return
	}
	id := p.id
	if n.penalties.banned(id, now) {
		return
	}
	if !p.allowIngress() {
		n.stats.peerRateDrops.Add(1)
		n.scorePeer(p, badScoreRateLimit, now, "rate limited")
		return
	}

	adm, accepted := n.prepareAdmission(p, data, now)
	if !accepted {
		return
	}
	defer n.releaseAdmission(&adm)

	acceptedPeer, joined, ok := n.peers.acceptInbound(p, now)
	if !ok {
		n.closePeer(p, "leaf capacity reached")
		return
	}
	authenticatedDevice := n.commitAdmission(acceptedPeer, &adm, now)
	n.peers.markSeen(id, now)

	env := adm.frame.Envelope
	b := adm.frame.Broadcast
	if joined {
		log.Printf("member joined %s… (%s)", short(id), n.countsString())
	}
	if authenticatedDevice && n.peers.markReplayed(acceptedPeer.id) {
		n.replayHistory(acceptedPeer, env.Key, adm.frame.ID)
	}

	n.relayAccepted(id, env, b)
}

type admission struct {
	frame     broadcast.Frame
	committed bool
}

func (n *Node) admit(p *peer, data tl.Serializable, now time.Time) (envelope.Envelope, broadcast.Broadcast, bool) {
	var zeroEnv envelope.Envelope
	var zeroB broadcast.Broadcast

	adm, ok := n.prepareAdmission(p, data, now)
	if !ok {
		return zeroEnv, zeroB, false
	}
	defer n.releaseAdmission(&adm)
	n.commitAdmission(p, &adm, now)
	return adm.frame.Envelope, adm.frame.Broadcast, true
}

func (n *Node) prepareAdmission(p *peer, data tl.Serializable, now time.Time) (admission, bool) {
	var zero admission

	b, ok := broadcast.AsBroadcast(data)
	if !ok {
		n.stats.invalidDrops.Add(1)
		return zero, false
	}
	if b.Flags != 0 {
		n.stats.invalidDrops.Add(1)
		return zero, false
	}
	raw, err := tl.Serialize(b, true)
	if err != nil || len(raw) > broadcast.MaxSize {
		n.stats.invalidDrops.Add(1)
		return zero, false
	}
	if !broadcast.Fresh(b.Date, now) {
		n.stats.invalidDrops.Add(1)
		return zero, false
	}

	id, err := b.ID()
	if err != nil {
		n.stats.invalidDrops.Add(1)
		if broadcast.ShouldPenalizeFrameError(err) {
			n.punish(p, now)
		}
		return zero, false
	}
	if !n.dedup.Reserve(id) {
		n.stats.duplicateDrops.Add(1)
		return zero, false
	}
	adm := admission{frame: broadcast.Frame{Broadcast: b, ID: id, Raw: raw}}
	owned := false
	defer func() {
		if !owned {
			n.dedup.Release(id)
		}
	}()

	if !n.ingress.allow(len(raw), now) {
		n.stats.globalRateDrops.Add(1)
		return zero, false
	}

	frame, err := broadcast.VerifyFrameObject(b, raw, broadcast.VerifyFrameOptions{
		Room:           n.name.Full,
		Now:            now,
		CheckFreshness: true,
		MaxSize:        broadcast.MaxSize,
	})
	if err != nil {
		n.stats.invalidDrops.Add(1)
		if broadcast.ShouldPenalizeFrameError(err) {
			n.punish(p, now)
		}
		return zero, false
	}
	adm.frame = frame

	if n.name.Mode == room.ModeGated {
		if frame.Envelope.Type == "cert-req" {
			if len(raw) > broadcast.MaxCertReqSize || !n.uncertified.allow() {
				n.stats.invalidDrops.Add(1)
				return zero, false
			}
		} else if !n.certOK(b.Certificate, frame.Source, uint32(len(raw)), now) {
			n.stats.invalidDrops.Add(1)
			return zero, false
		}
	}
	if !n.sources.allow(frame.Envelope.Key, len(raw), now) {
		n.stats.sourceRateDrops.Add(1)
		return zero, false
	}

	owned = true
	return adm, true
}

func (n *Node) releaseAdmission(adm *admission) {
	if adm == nil || adm.committed {
		return
	}
	n.dedup.Release(adm.frame.ID)
}

func (n *Node) commitAdmission(p *peer, adm *admission, now time.Time) bool {
	if adm == nil || adm.committed {
		return false
	}
	n.dedup.Commit(adm.frame.ID)
	adm.committed = true
	n.stats.accepted.Add(1)
	env := adm.frame.Envelope
	b := adm.frame.Broadcast
	n.room.ObserveAcceptedWithID(env, b, adm.frame.ID)
	allowNewBinding := env.Type == "hello" || env.Type == "cert-req"
	authenticatedDevice := n.peers.authenticateDevice(p, env.Key, env.Text, allowNewBinding, now)
	if authenticatedDevice {
		n.devices.bind(env.Key, p.id, now)
	}
	n.wrappers.put(adm.frame.ID, b)
	return authenticatedDevice
}

func (n *Node) punish(p *peer, now time.Time) {
	n.penalties.punish(p.id, now)
	if errs := n.peers.countError(p.id); errs == 1 || errs%16 == 0 {
		log.Printf("invalid authenticated frame from %s… (%d errors, penalized %s)", short(p.id), errs, sigPenalty)
	}
	n.scorePeer(p, badScoreSignature, now, "invalid authenticated frame")
}

func (n *Node) scorePeer(p *peer, score int, now time.Time, reason string) {
	if p == nil {
		return
	}
	total, evicted := n.peers.markBad(p.id, score, now)
	if evicted == nil {
		if total == score || total%peerBadScoreEvict == peerBadScoreEvict-1 {
			log.Printf("peer warning %s…: %s (score %d/%d)", short(p.id), reason, total, peerBadScoreEvict)
		}
		return
	}
	n.closePeer(evicted, reason)
}

func (n *Node) certOK(cert any, src ed25519.PublicKey, size uint32, now time.Time) bool {
	var c tonoverlay.Certificate
	switch v := cert.(type) {
	case tonoverlay.Certificate:
		c = v
	case *tonoverlay.Certificate:
		c = *v
	default:
		return false
	}
	srcID, err := broadcast.KeyID(src)
	if err != nil {
		return false
	}
	certHash, err := tl.Hash(c)
	if err != nil {
		return false
	}
	ck := string(srcID) + string(certHash)
	if e, ok := n.certs.get(ck); ok {
		return now.Unix() < e.expireAt && size <= e.maxSize
	}
	if !n.certs.allowMiss() {
		return false
	}
	if err := room.VerifyCertificate(c, srcID, n.room.OverlayID(), size, n.name.OwnerKey); err != nil {
		return false
	}
	n.certs.put(ck, certEntry{expireAt: int64(c.ExpireAt), maxSize: c.MaxSize})
	return true
}

func addressed(env envelope.Envelope) bool {
	return env.Type == "dm" || env.Type == "cert-grant"
}

func (n *Node) selectTargets(fromID string, env envelope.Envelope, now time.Time) []*peer {
	targets := n.peers.nodeTargets(fromID, nodeFanout)
	if env.Type == "hello" {
		return targets
	}
	if addressed(env) {
		for _, peerID := range n.devices.lookupAll(env.To, now) {
			if peerID == fromID {
				continue
			}
			if p, ok := n.peers.memberLeaf(peerID); ok {
				targets = append(targets, p)
			}
		}
	} else {
		targets = append(targets, n.peers.memberLeaves(fromID)...)
	}
	seen := make(map[string]struct{}, len(targets))
	out := targets[:0]
	for _, p := range targets {
		if _, ok := seen[p.id]; ok {
			continue
		}
		seen[p.id] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (n *Node) relayAccepted(fromID string, env envelope.Envelope, b broadcast.Broadcast) {
	for _, p := range n.selectTargets(fromID, env, time.Now()) {
		n.enqueue(p, b)
	}
}

func replayItems(items []room.Item, key string, excludeIDs ...string) []room.Item {
	excludeID := ""
	if len(excludeIDs) > 0 {
		excludeID = excludeIDs[0]
	}
	out := make([]room.Item, 0, len(items))
	for _, it := range items {
		if it.Obj == nil {
			continue
		}
		if excludeID != "" && it.ID == excludeID {
			continue
		}
		if it.Type == "dm" && (key == "" || (it.To != key && it.From != key)) {
			continue
		}
		out = append(out, it)
	}
	return out
}

func (n *Node) replayHistory(p *peer, key string, excludeID []byte) {
	items := replayItems(n.room.Recent(), key, hex.EncodeToString(excludeID))
	if len(items) == 0 {
		return
	}
	batch := make([]tl.Serializable, 0, len(items))
	for _, it := range items {
		batch = append(batch, it.Obj)
	}
	if n.enqueue(p, batch...) {
		n.stats.replayedItems.Add(uint64(len(batch)))
	}
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
