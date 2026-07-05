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
)

func (n *Node) wirePeer(p *peer) {
	id := p.id

	p.w.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		now := time.Now()
		if n.penalties.banned(id, now) {
			return nil
		}
		if !p.limiter.allow() {
			return nil
		}

		env, b, accepted := n.admit(p, msg.Data, now)

		if n.peers.markMember(id) {
			log.Printf("member joined %s… (%s)", short(id), n.countsString())
			n.replayHistory(p, leafKey(env, accepted))
		} else if accepted && p.kind == kindLeaf && env.Type == "hello" {
			n.replayHistory(p, env.Key)
		}

		if accepted {
			n.relayAccepted(id, env, b)
		}
		return nil
	})

	p.w.SetQueryHandler(func(q *adnl.MessageQuery) error {
		return n.answerQuery(p, q)
	})

	p.w.SetDisconnectHandler(func(addr string, _ ed25519.PublicKey) {
		n.peers.remove(id)
		log.Printf("peer left    %s… (%s)", short(id), n.countsString())
	})
}

func leafKey(env envelope.Envelope, accepted bool) string {
	if !accepted {
		return ""
	}
	return env.Key
}

func (n *Node) admit(p *peer, data tl.Serializable, now time.Time) (envelope.Envelope, broadcast.Broadcast, bool) {
	var zeroEnv envelope.Envelope
	var zeroB broadcast.Broadcast

	b, ok := asBroadcast(data)
	if !ok {
		return zeroEnv, zeroB, false
	}
	if b.Flags != 0 {
		return zeroEnv, zeroB, false
	}
	raw, err := tl.Serialize(b, true)
	if err != nil || len(raw) > broadcast.MaxSize {
		return zeroEnv, zeroB, false
	}
	if !broadcast.Fresh(b.Date, now) {
		return zeroEnv, zeroB, false
	}
	id, err := b.ID()
	if err != nil {
		return zeroEnv, zeroB, false
	}
	if n.dedup.Contains(id) {
		return zeroEnv, zeroB, false
	}
	if err := b.Verify(); err != nil {
		n.punish(p, now)
		return zeroEnv, zeroB, false
	}
	env, err := envelope.Unmarshal(b.Data)
	if err != nil {
		return zeroEnv, zeroB, false
	}
	src, err := b.SourceKey()
	if err != nil {
		return zeroEnv, zeroB, false
	}
	if env.Key != hex.EncodeToString(src) {
		n.punish(p, now)
		return zeroEnv, zeroB, false
	}
	if env.Verify() != nil {
		return zeroEnv, zeroB, false
	}
	if env.Room != n.name.Full {
		return zeroEnv, zeroB, false
	}
	if n.name.Mode == room.ModeGated {
		if env.Type == "cert-req" {
			if len(raw) > broadcast.MaxCertReqSize || !n.uncertified.allow() {
				return zeroEnv, zeroB, false
			}
		} else if !n.certOK(b.Certificate, src, uint32(len(raw)), now) {
			return zeroEnv, zeroB, false
		}
	}
	if !n.sources.allow(env.Key, len(raw), now) {
		return zeroEnv, zeroB, false
	}

	n.dedup.Seen(id)
	n.room.ObserveAccepted(env, b)
	if p.kind == kindLeaf {
		n.devices.bind(env.Key, p.id, now)
	}
	n.wrappers.put(id, b)
	return env, b, true
}

func (n *Node) punish(p *peer, now time.Time) {
	n.penalties.punish(p.id, now)
	if errs := n.peers.countError(p.id); errs == 1 || errs%16 == 0 {
		log.Printf("bad signature from %s… (%d errors, penalized %s)", short(p.id), errs, sigPenalty)
	}
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

func asBroadcast(data tl.Serializable) (broadcast.Broadcast, bool) {
	switch v := data.(type) {
	case broadcast.Broadcast:
		return v, true
	case *broadcast.Broadcast:
		return *v, true
	}
	return broadcast.Broadcast{}, false
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
