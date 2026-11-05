package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
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
		p, err := n.dialNode(dctx, pubKey, dialAddress)
		if err != nil {
			continue
		}
		n.forRoom(n.room).peers.setNode(p, &signed)
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
	if p, ok := n.peers.get(idHex); ok {
		n.forRoom(n.room).peers.setNode(p, signed)
		return n.outboundReady(p)
	}
	return false
}

func (n *roomRuntime) probeNode(ctx context.Context, p *peer) ([]tonoverlay.Node, bool) {
	if p == nil || p.conn == nil {
		return nil, false
	}
	gctx, cancel := context.WithTimeout(ctx, peerKeepaliveTimeout)
	defer cancel()
	var result tonoverlay.NodesList
	self, err := n.selfOverlayNode()
	if err != nil {
		return nil, false
	}
	err = p.queryNodeRoom(gctx, n.room.genesis.RoomKey, tonoverlay.GetRandomPeers{List: tonoverlay.NodesList{List: []tonoverlay.Node{self}}}, &result)
	if err != nil {
		if !errors.Is(err, errOutboundUnprobed) {
			n.peerFailure(p, time.Now(), "peer probe failed")
		}
		return nil, false
	}
	n.Node.peers.markNodeGood(p.id, time.Now())
	n.observeRoomNode(p, result.List)
	return result.List, true
}

func (n *roomRuntime) verifyNode(nd *tonoverlay.Node) ([]byte, ed25519.PublicKey, error) {
	if !bytes.Equal(nd.Overlay, n.room.overlayID) {
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
	switch q.Data.(type) {
	case community.GetCapabilities, *community.GetCapabilities:
		return q.Answer(roomnet.LocalCapabilities())
	}
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
	switch q.Data.(type) {
	case broadcast.GetTime, *broadcast.GetTime:
		return n.answer(p, q, broadcast.Time{Now: int32(now.Unix())})
	}
	var id []byte
	switch wrapper := q.Data.(type) {
	case community.OverlayQueryV1:
		id = wrapper.Overlay
	case *community.OverlayQueryV1:
		id = wrapper.Overlay
	default:
		return roomnet.ErrNoAnswer
	}
	room := n.byOverlay[string(id)]
	if room == nil && n.byOverlay == nil && n.room != nil && bytes.Equal(id, n.room.overlayID) {
		room = n.room
	}
	if room == nil {
		return q.Answer(community.OverlayRejectedV1{Code: community.RejectOverlayNotServed, Message: "overlay not served"})
	}
	selected, err := q.SelectOverlay(room.overlayID)
	if err != nil || !selected {
		return err
	}
	r := n.forRoom(room)
	var advertised tonoverlay.NodesList
	switch request := q.Data.(type) {
	case tonoverlay.GetRandomPeers:
		advertised = request.List
	case *tonoverlay.GetRandomPeers:
		advertised = request.List
	default:
		accepted, _, ok := r.peers.acceptInbound(p, now)
		if !ok {
			return nil
		}
		_, err := r.answerCommunityQuery(accepted, q, now)
		return err
	}
	n.peers.markSeen(p.id, now)
	if err := q.Answer(r.myNodesList()); err != nil {
		return err
	}
	n.peers.markNodeGood(p.id, now)
	for i := range capNodes(advertised.List) {
		nd := advertised.List[i]
		if len(n.roomList()) == 1 {
			go n.considerNode(context.Background(), &nd)
		}
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

func (n *roomRuntime) myNodesList() tonoverlay.NodesList {
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

func (n *roomRuntime) selfOverlayNode() (tonoverlay.Node, error) {
	nd := tonoverlay.Node{
		ID:      keys.PublicKeyED25519{Key: n.cfg.Key.Public().(ed25519.PublicKey)},
		Overlay: n.room.overlayID,
		Version: int32(time.Now().Unix()),
	}
	if err := nd.Sign(n.cfg.Key); err != nil {
		return tonoverlay.Node{}, err
	}
	return nd, nil
}
