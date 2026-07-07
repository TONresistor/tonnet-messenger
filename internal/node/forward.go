package node

import (
	"context"
	"crypto/ed25519"
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

func (n *Node) wirePeer(p *peer) {
	id := p.id

	p.w.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		n.handleCustomMessage(p, msg.Data, time.Now())
		return nil
	})

	p.w.SetQueryHandler(func(q *adnl.MessageQuery) error {
		return n.answerQuery(p, q)
	})

	p.w.SetDisconnectHandler(func(addr string, _ ed25519.PublicKey) {
		if n.peers.removePeer(id, p) {
			log.Printf("peer left    %s… (%s)", short(id), n.countsString())
		}
	})
}

func (n *Node) handleCustomMessage(p *peer, data tl.Serializable, now time.Time) {
	if p == nil {
		return
	}
	id := p.id
	n.peers.markSeen(id, now)
	if n.penalties.banned(id, now) {
		return
	}
	if !p.limiter.allow() {
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
	n.commitAdmission(acceptedPeer, &adm, now)

	env := adm.frame.Envelope
	b := adm.frame.Broadcast
	if joined {
		log.Printf("member joined %s… (%s)", short(id), n.countsString())
		n.replayHistory(acceptedPeer, leafKey(env, accepted))
	} else if acceptedPeer.kind == kindLeaf && env.Type == "hello" {
		n.replayHistory(acceptedPeer, env.Key)
	}

	n.relayAccepted(id, env, b)
}

func leafKey(env envelope.Envelope, accepted bool) string {
	if !accepted {
		return ""
	}
	return env.Key
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
		return zero, false
	}
	if b.Flags != 0 {
		return zero, false
	}
	raw, err := tl.Serialize(b, true)
	if err != nil || len(raw) > broadcast.MaxSize {
		return zero, false
	}
	if !broadcast.Fresh(b.Date, now) {
		return zero, false
	}

	frame, err := broadcast.VerifyFrameObject(b, raw, broadcast.VerifyFrameOptions{
		Room:           n.name.Full,
		Now:            now,
		CheckFreshness: true,
		MaxSize:        broadcast.MaxSize,
	})
	if err != nil {
		if broadcast.ShouldPenalizeFrameError(err) {
			n.punish(p, now)
		}
		return zero, false
	}
	if !n.dedup.Reserve(frame.ID) {
		return zero, false
	}
	adm := admission{frame: frame}
	owned := false
	defer func() {
		if !owned {
			n.dedup.Release(frame.ID)
		}
	}()

	if n.name.Mode == room.ModeGated {
		if frame.Envelope.Type == "cert-req" {
			if len(raw) > broadcast.MaxCertReqSize || !n.uncertified.allow() {
				return zero, false
			}
		} else if !n.certOK(b.Certificate, frame.Source, uint32(len(raw)), now) {
			return zero, false
		}
	}
	if !n.sources.allow(frame.Envelope.Key, len(raw), now) {
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

func (n *Node) commitAdmission(p *peer, adm *admission, now time.Time) {
	if adm == nil || adm.committed {
		return
	}
	n.dedup.Commit(adm.frame.ID)
	adm.committed = true
	env := adm.frame.Envelope
	b := adm.frame.Broadcast
	n.room.ObserveAccepted(env, b)
	if p != nil && p.kind == kindLeaf {
		n.devices.bind(env.Key, p.id, now)
	}
	n.wrappers.put(adm.frame.ID, b)
}

func (n *Node) punish(p *peer, now time.Time) {
	n.penalties.punish(p.id, now)
	if errs := n.peers.countError(p.id); errs == 1 || errs%16 == 0 {
		log.Printf("bad signature from %s… (%d errors, penalized %s)", short(p.id), errs, sigPenalty)
	}
	n.scorePeer(p, badScoreSignature, now, "bad signature")
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
	if addressed(env) {
		if peerID, ok := n.devices.lookup(env.To, now); ok && peerID != fromID {
			if p, ok := n.peers.get(peerID); ok && p.kind == kindLeaf && p.member {
				targets = append(targets, p)
			}
		}
	} else {
		targets = append(targets, n.peers.memberLeaves(fromID)...)
	}
	return targets
}

func (n *Node) relayAccepted(fromID string, env envelope.Envelope, b broadcast.Broadcast) {
	for _, p := range n.selectTargets(fromID, env, time.Now()) {
		go func(p *peer) {
			ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
			defer cancel()
			if err := p.w.SendCustomMessage(ctx, b); err != nil {
				log.Printf("relay to %s… failed: %v", short(p.id), err)
				n.peerFailure(p, time.Now(), "relay failed")
			}
		}(p)
	}
}

func replayItems(items []room.Item, key string) []room.Item {
	out := make([]room.Item, 0, len(items))
	for _, it := range items {
		if it.Obj == nil {
			continue
		}
		if it.Type == "dm" && (key == "" || (it.To != key && it.From != key)) {
			continue
		}
		out = append(out, it)
	}
	return out
}

func (n *Node) replayHistory(p *peer, key string) {
	items := replayItems(n.room.Recent(), key)
	if len(items) == 0 {
		return
	}
	go func() {
		for _, it := range items {
			ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
			_ = p.w.SendCustomMessage(ctx, it.Obj)
			cancel()
		}
	}()
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
