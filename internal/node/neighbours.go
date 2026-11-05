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

func (n *roomRuntime) discoveryLoop(ctx context.Context) {
	timer := time.NewTimer(discoverWarmup)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			n.discoverOnce(ctx)
			timer.Reset(DiscoverEach)
		case nd := <-n.room.advertised:
			n.considerNode(ctx, &nd)
		}
	}
}

func (n *roomRuntime) discoverOnce(ctx context.Context) {
	pub := n.publisher()
	if pub == nil {
		return
	}
	if list, err := pub.FindOverlayNodes(ctx, n.room.genesis.RoomKey); err != nil {
		log.Printf("discover: dht find: %v", err)
	} else if list != nil {
		for i := range capNodes(list.List) {
			n.considerNode(ctx, &list.List[i])
		}
	}

	for _, p := range n.Node.peers.nodePeers() {
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

func (n *roomRuntime) considerNode(ctx context.Context, nd *tonoverlay.Node) {
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
	// An authenticated compatible connection can be shared, but the scoped
	// response must independently prove that this endpoint serves this room.
	if p, ok := n.Node.peers.get(idHex); ok && n.outboundReady(p) {
		if nodes, ok := n.probeNode(ctx, p); ok {
			n.queueNodes(nodes)
		}
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

	n.Node.peers.markKnown(idHex)
	for _, dialAddress := range dialAddresses {
		p, err := n.dialNode(dctx, pubKey, dialAddress)
		if err != nil {
			continue
		}
		if nodes, ok := n.probeNode(ctx, p); ok {
			n.queueNodes(nodes)
		}
		log.Printf("meshed with node %s… at %s (%s)", short(idHex), dialAddress, n.countsString())
		return
	}
	log.Printf("discover: no live QUIC address for %s…", short(idHex))
}

func (n *roomRuntime) alreadyMeshed(idHex string, signed *tonoverlay.Node) bool {
	if p, ok := n.peers.get(idHex); ok {
		if n.outboundReady(p) && n.peers.isHealthyNode(p) {
			n.peers.setNode(p, signed)
			return true
		}
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
	err = p.withOutbound(func(conn *roomnet.Peer) error {
		if err := conn.QueryRoomOutbound(gctx, n.room.genesis.RoomKey, tonoverlay.GetRandomPeers{List: tonoverlay.NodesList{List: []tonoverlay.Node{self}}}, &result); err != nil {
			var rejected *roomnet.OverlayRejection
			if errors.As(err, &rejected) && rejected.Code == community.RejectOverlayNotServed {
				n.peers.forgetNode(p)
			}
			return err
		}
		result.List = capNodes(result.List)
		// Keep the strict-outbound lease until the scoped proof is installed;
		// a reconnect cannot make an old reply authorize its replacement.
		n.observeRoomNode(p, result.List)
		return nil
	})
	if err != nil {
		var rejected *roomnet.OverlayRejection
		if errors.As(err, &rejected) && rejected.Code == community.RejectOverlayNotServed {
			return nil, false
		}
		if !errors.Is(err, errOutboundUnprobed) && ctx.Err() == nil {
			n.peerFailure(p, time.Now(), "peer probe failed")
		}
		return nil, false
	}
	n.Node.peers.markNodeGood(p.id, time.Now())
	return result.List, true
}

// Incoming advertisements are bounded, verified hints, processed by the owned
// room loop rather than detached goroutines that survive Run cancellation.
func (n *roomRuntime) queueNodes(nodes []tonoverlay.Node) {
	if n.publisher() == nil {
		return
	}
	for _, nd := range capNodes(nodes) {
		id, _, err := n.verifyNode(&nd)
		if err != nil || hex.EncodeToString(id) == n.myID {
			continue
		}
		select {
		case n.room.advertised <- nd:
		default:
		}
	}
}

func (n *roomRuntime) verifyNode(nd *tonoverlay.Node) ([]byte, ed25519.PublicKey, error) {
	return verifyOverlayNode(nd, n.room.overlayID, time.Now())
}

func verifyOverlayNode(nd *tonoverlay.Node, id []byte, at time.Time) ([]byte, ed25519.PublicKey, error) {
	if !bytes.Equal(nd.Overlay, id) {
		return nil, nil, fmt.Errorf("node advertises a different overlay")
	}
	if err := nd.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("bad node signature: %w", err)
	}
	now := at.Unix()
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
		caps := roomnet.LocalCapabilities()
		if n.inbox != nil {
			caps.Flags = community.RelayServiceDM
		}
		return q.Answer(caps)
	}
	now := time.Now()
	if isInboxQuery(q.Data) {
		return n.answerInbox(p, q, now)
	}
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
	case community.GetRoomCardsV1, *community.GetRoomCardsV1:
		return n.answerRoomCards(q, now)
	case community.GetRelayCardV1, *community.GetRelayCardV1:
		if n.relays == nil {
			return roomnet.ErrNoAnswer
		}
		card, err := n.relays.ownCard(now)
		if err != nil {
			return err
		}
		return q.Answer(card)
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
	for _, global := range n.globalOverlays() {
		if bytes.Equal(id, global.id) {
			return global.answerPeers(q)
		}
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
	r.queueNodes(advertised.List)
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
	return n.signedOverlayNode(n.room.overlayID)
}

func (n *Node) signedOverlayNode(id []byte) (tonoverlay.Node, error) {
	nd := tonoverlay.Node{
		ID:      keys.PublicKeyED25519{Key: n.cfg.Key.Public().(ed25519.PublicKey)},
		Overlay: id,
		Version: int32(time.Now().Unix()),
	}
	if err := nd.Sign(n.cfg.Key); err != nil {
		return tonoverlay.Node{}, err
	}
	return nd, nil
}
