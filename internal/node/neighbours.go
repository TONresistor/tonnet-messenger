package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

const (
	DiscoverEach = 20 * time.Second

	discoverWarmup = 3 * time.Second

	nodeMaxAge = 10 * time.Minute

	maxGossipNodes = 16

	dialTimeout = 15 * time.Second
)

func (n *Node) discoveryLoop(ctx context.Context) {
	timer := time.NewTimer(discoverWarmup)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		n.discoverOnce(ctx)
		timer.Reset(DiscoverEach)
	}
}

func (n *Node) discoverOnce(ctx context.Context) {
	pub := n.publisher()
	if pub == nil {
		return
	}
	if list, err := pub.FindOverlayNodes(ctx, n.overlayKey()); err != nil {
		log.Printf("discover: dht find: %v", err)
	} else if list != nil {
		for i := range capNodes(list.List) {
			n.considerNode(ctx, &list.List[i])
		}
	}

	for _, p := range n.peers.nodePeers() {
		nodes, ok := n.probeNode(ctx, p)
		if !ok {
			continue
		}
		nodes = capNodes(nodes)
		for i := range nodes {
			n.considerNode(ctx, &nodes[i])
		}
	}
}

func capNodes(nodes []tonoverlay.Node) []tonoverlay.Node {
	if len(nodes) > maxGossipNodes {
		return nodes[:maxGossipNodes]
	}
	return nodes
}

func (n *Node) considerNode(ctx context.Context, nd *tonoverlay.Node) {
	pub := n.publisher()
	if pub == nil {
		return
	}
	adnlID, pubKey, err := n.verifyNode(nd)
	if err != nil {
		return
	}
	idHex := hex.EncodeToString(adnlID)
	if idHex == n.myID {
		return
	}

	signed := *nd
	if n.alreadyMeshed(idHex, &signed) {
		return
	}

	if !n.acquireDial() {
		return
	}
	defer n.releaseDial()

	if n.alreadyMeshed(idHex, &signed) {
		return
	}

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	dialAddresses, dialPub, err := pub.ResolveAll(dctx, adnlID)
	if err != nil {
		log.Printf("discover: resolve %s…: %v", short(idHex), err)
		return
	}
	if dialPub != nil {
		resolvedID, err := community.KeyID(dialPub)
		if err != nil || !bytes.Equal(resolvedID, adnlID) {
			log.Printf("discover: resolved key does not match %s…", short(idHex))
			return
		}
		pubKey = dialPub
	}

	if n.alreadyMeshed(idHex, &signed) {
		return
	}

	n.peers.markKnown(idHex)
	for _, dialAddress := range dialAddresses {
		if _, err := n.qgw.DialDefault(dctx, pubKey, dialAddress); err != nil {
			continue
		}
		p, ok := n.peers.get(idHex)
		if !ok {
			continue
		}
		n.peers.setSigned(idHex, &signed)
		if nodes, ok := n.probeNode(ctx, p); ok {
			for i := range capNodes(nodes) {
				nd := nodes[i]
				go n.considerNode(context.Background(), &nd)
			}
		}
		log.Printf("meshed with node %s… at %s (%s)", short(idHex), dialAddress, n.countsString())
		return
	}
	log.Printf("discover: no live QUIC address for %s…", short(idHex))
}

func (n *Node) alreadyMeshed(idHex string, signed *tonoverlay.Node) bool {
	if _, ok := n.peers.get(idHex); ok {
		n.peers.setSigned(idHex, signed)
		return true
	}
	return false
}

func (n *Node) probeNode(ctx context.Context, p *peer) ([]tonoverlay.Node, bool) {
	if p == nil || p.conn == nil {
		return nil, false
	}
	gctx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
	defer cancel()
	nodes, err := p.conn.GetRandomPeers(gctx)
	if err != nil {
		n.peerFailure(p, time.Now(), "peer probe failed")
		return nil, false
	}
	n.peers.markNodeGood(p.id, time.Now())
	return nodes, true
}

func (n *Node) verifyNode(nd *tonoverlay.Node) ([]byte, ed25519.PublicKey, error) {
	if !bytes.Equal(nd.Overlay, n.cfg.OverlayID) {
		return nil, nil, fmt.Errorf("node advertises a different overlay")
	}
	if err := nd.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("bad node signature: %w", err)
	}
	now := time.Now().Unix()
	if age := now - int64(nd.Version); age > int64(nodeMaxAge.Seconds()) {
		return nil, nil, fmt.Errorf("stale node: age=%ds", age)
	}
	if int64(nd.Version) > now+60 {
		return nil, nil, fmt.Errorf("node version is in the future")
	}
	pub, ok := nd.ID.(keys.PublicKeyED25519)
	if !ok {
		return nil, nil, fmt.Errorf("non-ed25519 node id")
	}
	adnlID, err := tl.Hash(nd.ID)
	if err != nil {
		return nil, nil, err
	}
	return adnlID, pub.Key, nil
}

func (n *Node) answerQuery(p *peer, q *roomnet.Query) error {
	now := time.Now()
	if n.penalties.banned(p.id, now) {
		return nil
	}
	if !p.allowIngress() {
		n.stats.peerRateDrops.Add(1)
		n.scorePeer(p, badScoreRateLimit, now, "query rate limited")
		return nil
	}
	if !n.queries.allow() {
		n.stats.queryRateDrops.Add(1)
		return nil
	}
	var advertised tonoverlay.NodesList
	switch req := q.Data.(type) {
	case tonoverlay.GetRandomPeers:
		advertised = req.List
	case *tonoverlay.GetRandomPeers:
		advertised = req.List
	case broadcast.GetTime, *broadcast.GetTime:
		return n.answer(p, q, broadcast.Time{Now: int32(time.Now().Unix())})
	default:
		acceptedPeer, _, accepted := n.peers.acceptInbound(p, now)
		if !accepted {
			return nil
		}
		p = acceptedPeer
		handled, err := n.answerCommunityQuery(p, q, now)
		if handled {
			return err
		}
		return nil
	}
	n.peers.markSeen(p.id, now)

	if err := q.Answer(n.myNodesList()); err != nil {
		n.peerFailure(p, time.Now(), "answer getRandomPeers failed")
		return err
	}
	n.peers.markNodeGood(p.id, time.Now())

	for i := range capNodes(advertised.List) {
		nd := advertised.List[i]
		go n.considerNode(context.Background(), &nd)
	}
	return nil
}

func (n *Node) answer(p *peer, q *roomnet.Query, resp tl.Serializable) error {
	if err := q.Answer(resp); err != nil {
		n.peerFailure(p, time.Now(), "answer query failed")
		return err
	}
	n.peers.markNodeGood(p.id, time.Now())
	return nil
}

func (n *Node) myNodesList() tonoverlay.NodesList {
	list := make([]tonoverlay.Node, 0, 8)
	if self, err := n.selfOverlayNode(); err == nil {
		list = append(list, self)
	}
	for _, nd := range n.peers.signedNodes() {
		list = append(list, nd)
		if len(list) >= 8 {
			break
		}
	}
	return tonoverlay.NodesList{List: list}
}

func (n *Node) selfOverlayNode() (tonoverlay.Node, error) {
	nd := tonoverlay.Node{
		ID:      keys.PublicKeyED25519{Key: n.cfg.Key.Public().(ed25519.PublicKey)},
		Overlay: n.cfg.OverlayID,
		Version: int32(time.Now().Unix()),
	}
	if err := nd.Sign(n.cfg.Key); err != nil {
		return tonoverlay.Node{}, err
	}
	return nd, nil
}
