package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

	nodeMaxAge = 30 * time.Minute

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
		gctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		nodes, err := p.w.GetRandomPeers(gctx)
		cancel()
		if err != nil {
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
	if _, ok := n.peers.get(idHex); ok {
		n.peers.setSigned(idHex, &signed)
		return
	}

	if !n.acquireDial() {
		return
	}
	defer n.releaseDial()

	if _, ok := n.peers.get(idHex); ok {
		n.peers.setSigned(idHex, &signed)
		return
	}

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	dialStr, dialPub, err := pub.Resolve(dctx, adnlID)
	if err != nil {
		log.Printf("discover: resolve %s…: %v", short(idHex), err)
		return
	}
	if dialPub != nil {
		pubKey = dialPub
	}

	n.peers.markKnown(idHex)

	peer, err := n.gw.RegisterClient(dialStr, pubKey)
	if err != nil {
		log.Printf("discover: dial %s… at %s: %v", short(idHex), dialStr, err)
		return
	}

	if _, ok := n.peers.get(idHex); ok {
		n.peers.setSigned(idHex, &signed)
	} else {
		w := tonoverlay.CreateExtendedADNL(peer).WithOverlay(n.room.OverlayID())
		p, created := n.peers.addNode(idHex, w, peer, &signed)
		if created {
			n.wirePeer(p)
		}
	}
	log.Printf("meshed with node %s… at %s (%s)", short(idHex), dialStr, n.countsString())
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
	if !p.limiter.allow() {
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
	case broadcast.GetBroadcast:
		return n.answerGetBroadcast(p, q, req.Hash)
	case *broadcast.GetBroadcast:
		return n.answerGetBroadcast(p, q, req.Hash)
	default:
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.raw.Answer(ctx, q.ID, n.myNodesList()); err != nil {
		return err
	}

	for i := range capNodes(advertised.List) {
		nd := advertised.List[i]
		go n.considerNode(context.Background(), &nd)
	}
	return nil
}

func (n *Node) answer(p *peer, q *adnl.MessageQuery, resp tl.Serializable) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return p.raw.Answer(ctx, q.ID, resp)
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
