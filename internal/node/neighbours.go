package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
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
	if list, err := pub.FindOverlayNodes(ctx, []byte(n.cfg.Room)); err != nil {
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
	if n.alreadyMeshed(idHex, adnlID, &signed) {
		return
	}

	if !n.acquireDial() {
		return
	}
	defer n.releaseDial()

	if n.alreadyMeshed(idHex, adnlID, &signed) {
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
		pubKey = dialPub
	}

	if n.alreadyMeshed(idHex, adnlID, &signed) {
		return
	}

	peer, dialStr, reused, ok := pickLiveAddr(dctx, dialAddresses,
		func() adnl.Peer { return n.liveMeshSession(adnlID) },
		func() bool { return n.peers.has(idHex) },
		func(addr string) (adnl.Peer, error) { return n.gw.RegisterClient(addr, pubKey) },
	)
	if reused {
		n.peers.setSigned(idHex, &signed)
		return
	}
	if !ok {
		log.Printf("discover: no live address for %s…", short(idHex))
		return
	}

	n.completeMesh(ctx, idHex, peer, dialStr, &signed)
}

func (n *Node) alreadyMeshed(idHex string, adnlID []byte, signed *tonoverlay.Node) bool {
	if _, ok := n.peers.get(idHex); ok {
		n.peers.setSigned(idHex, signed)
		return true
	}
	if n.liveMeshSession(adnlID) != nil {
		n.peers.setSigned(idHex, signed)
		return true
	}
	return false
}

func (n *Node) liveMeshSession(adnlID []byte) adnl.Peer {
	if n == nil || n.gw == nil || len(adnlID) == 0 {
		return nil
	}
	for _, p := range n.gw.GetActivePeers() {
		if p != nil && bytes.Equal(p.GetID(), adnlID) {
			return p
		}
	}
	return nil
}

func pickLiveAddr(
	ctx context.Context,
	addrs []string,
	live func() adnl.Peer,
	tracked func() bool,
	register func(addr string) (adnl.Peer, error),
) (peer adnl.Peer, addr string, reused bool, ok bool) {
	var ours adnl.Peer
	for _, candidate := range addrs {
		if tracked != nil && tracked() {
			return nil, candidate, true, true
		}
		if live != nil {
			if p := live(); p != nil && ours == nil {
				return p, p.RemoteAddr(), true, true
			}
		}
		if register == nil {
			continue
		}
		p, err := register(candidate)
		if err != nil || p == nil {
			continue
		}
		if ours == nil {
			ours = p
		}
		if tracked != nil && tracked() {
			return p, candidate, true, true
		}
		pingCtx, pingCancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
		_, pingErr := p.Ping(pingCtx)
		pingCancel()
		if pingErr != nil {
			continue
		}
		return p, candidate, false, true
	}
	return nil, "", false, false
}

func (n *Node) completeMesh(ctx context.Context, idHex string, peer adnl.Peer, addr string, signed *tonoverlay.Node) {
	if peer == nil {
		return
	}
	if _, ok := n.peers.get(idHex); ok {
		n.peers.setSigned(idHex, signed)
		return
	}
	p, created := n.peers.addNode(idHex, nil, peer, signed)
	if p == nil || !created {
		return
	}
	w := tonoverlay.CreateExtendedADNL(peer).WithOverlay(n.room.OverlayID())
	if !n.peers.installOverlay(p, w) {
		return
	}
	n.wirePeer(p)
	if nodes, ok := n.probeNode(ctx, p); ok {
		for i := range capNodes(nodes) {
			nd := nodes[i]
			go n.considerNode(context.Background(), &nd)
		}
	}
	log.Printf("meshed with node %s… at %s (%s)", short(idHex), addr, n.countsString())
}

func (n *Node) probeNode(ctx context.Context, p *peer) ([]tonoverlay.Node, bool) {
	if p == nil || p.w == nil {
		return nil, false
	}
	gctx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
	defer cancel()
	nodes, err := p.w.GetRandomPeers(gctx)
	if err != nil {
		n.peerFailure(p, time.Now(), "peer probe failed")
		return nil, false
	}
	n.peers.markNodeGood(p.id, time.Now())
	return nodes, true
}

func (n *Node) verifyNode(nd *tonoverlay.Node) ([]byte, ed25519.PublicKey, error) {
	if !bytes.Equal(nd.Overlay, n.room.OverlayID()) {
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

func (n *Node) answerQuery(p *peer, q *adnl.MessageQuery) error {
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
	case broadcast.GetChallenge, *broadcast.GetChallenge:
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		expires := now.Add(time.Minute)
		if !n.peers.setChallenge(p, nonce, expires) {
			return nil
		}
		return n.answer(p, q, broadcast.Challenge{Nonce: nonce, Expires: int32(expires.Unix())})
	case broadcast.GetSessionChallenge, *broadcast.GetSessionChallenge:
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		expires := now.Add(time.Minute)
		if !n.peers.setSessionChallenge(p, nonce, expires) {
			return nil
		}
		return n.answer(p, q, broadcast.Challenge{Nonce: nonce, Expires: int32(expires.Unix())})
	case broadcast.GetBroadcast:
		return n.answerGetBroadcast(p, q, req.Hash)
	case *broadcast.GetBroadcast:
		return n.answerGetBroadcast(p, q, req.Hash)
	default:
		return nil
	}
	n.peers.markSeen(p.id, now)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.raw.Answer(ctx, q.ID, n.myNodesList()); err != nil {
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

func (n *Node) answer(p *peer, q *adnl.MessageQuery, resp tl.Serializable) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.raw.Answer(ctx, q.ID, resp); err != nil {
		n.peerFailure(p, time.Now(), "answer query failed")
		return err
	}
	n.peers.markNodeGood(p.id, time.Now())
	return nil
}

func (n *Node) answerGetBroadcast(p *peer, q *adnl.MessageQuery, hash []byte) error {
	if b, ok := n.wrappers.get(hash); ok {
		return n.answer(p, q, b)
	}
	return n.answer(p, q, broadcast.NotFound{})
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
		Overlay: n.room.OverlayID(),
		Version: int32(time.Now().Unix()),
	}
	if err := nd.Sign(n.cfg.Key); err != nil {
		return tonoverlay.Node{}, err
	}
	return nd, nil
}
